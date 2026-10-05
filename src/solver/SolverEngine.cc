// SolverEngine —— 搜索引擎主体（替换论文的 AFLGo 变异搜索）。
//
// 每轮求解任务（论文 fuzz() OUTPUT 分支的一个调用）：
//   上下文（前缀/目标事件/剩余事件序列/锚点源码窗口/字典/种子/反馈）
//   -> 智能体按 LOCUS 协议输出 SMT2 约束 + 偏移映射（或退回 hex）
//   -> Z3 求解，字节按映射从 model 程序化拼装（消灭手抄错误）
//   -> Executor 执行 前缀+后缀（协议=TCP 注入；普通=直接运行）
//   -> 程序内 monitor（CodeBean，论文原样）判轨迹并回写前缀池；
//      本引擎只回收文本做反馈：目标事件触发即成功；输出含
//      "a counterexample!" 即反例（论文 is_counterexample 同款标记）。
#include <solver/SolverEngine.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <solver/AgentLoop.h>
#include <solver/AnalysisTools.h>
#include <solver/Executor.h>
#include <solver/SourceAnalyzer.h>
#include <solver/Z3Solver.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace solver {

SolverEngine* SolverEngine::s_instance = nullptr;

SolverEngine* SolverEngine::instance() {
    if (!s_instance) s_instance = new SolverEngine();
    return s_instance;
}

// -------------------------------------------------------------- 小工具

static std::string to_hex(const std::string& bytes) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        out += H[c >> 4];
        out += H[c & 0xf];
    }
    return out;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static std::string from_hex(const std::string& hex) {
    std::string out;
    int hi = -1;
    for (char c : hex) {
        int v = hex_val(c);
        if (v < 0) continue;
        if (hi < 0) hi = v;
        else {
            out += static_cast<char>((hi << 4) | v);
            hi = -1;
        }
    }
    return out;
}

// model 值（十进制或 #x..）-> 大端字节串
static std::string value_to_bytes(const std::string& v) {
    unsigned long long val = 0;
    if (v.rfind("#x", 0) == 0 || v.rfind("#b", 0) == 0) {
        int base = v[1] == 'x' ? 16 : 2;
        val = strtoull(v.c_str() + 2, nullptr, base);
    } else {
        val = strtoull(v.c_str(), nullptr, 10);
    }
    int n = 1;
    for (unsigned long long t = val >> 8; t; t >>= 8) ++n;
    std::string b;
    for (int i = n - 1; i >= 0; --i)
        b += static_cast<char>((val >> (8 * i)) & 0xff);
    return b;
}

// "LOCUS_XXX:" 行的字段值（到行尾）
static std::string extract_line_field(const std::string& reply,
                                      const std::string& key) {
    std::string::size_type p = reply.find(key);
    if (p == std::string::npos) return "";
    std::string::size_type e = reply.find('\n', p);
    return reply.substr(p + key.size(),
                        e == std::string::npos ? std::string::npos
                                               : e - p - key.size());
}

// fenced ```smt2 块，或 LOCUS_SMT2: 与下一个 LOCUS_ 标记之间
static std::string extract_smt2(const std::string& reply) {
    std::string::size_type p = reply.find("```smt2");
    if (p != std::string::npos) {
        p = reply.find('\n', p);
        std::string::size_type e = reply.find("```", p);
        if (p != std::string::npos && e != std::string::npos)
            return reply.substr(p + 1, e - p - 1);
    }
    p = reply.find("LOCUS_SMT2:");
    if (p == std::string::npos) return "";
    std::string::size_type e = reply.find("LOCUS_", p + 11);
    return reply.substr(p + 11,
                        e == std::string::npos ? std::string::npos
                                               : e - p - 11);
}

// {"off":"const", ...} 极简解析（成对的 "..." 与数字键）
static std::vector<std::pair<int, std::string>> parse_model_map(
        const std::string& s) {
    std::vector<std::pair<int, std::string>> out;
    std::string t = s;
    std::string::size_type p = t.find('{');
    if (p == std::string::npos) return out;
    std::string::size_type e = t.find('}', p);
    if (e == std::string::npos) e = t.size();
    t = t.substr(p + 1, e - p - 1);
    // 逐对提取 "A":"B"
    std::string::size_type i = 0;
    while (true) {
        std::string::size_type q1 = t.find('"', i);
        if (q1 == std::string::npos) break;
        std::string::size_type q2 = t.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        std::string::size_type colon = t.find(':', q2);
        if (colon == std::string::npos) break;
        std::string::size_type q3 = t.find('"', colon);
        if (q3 == std::string::npos) break;
        std::string::size_type q4 = t.find('"', q3 + 1);
        if (q4 == std::string::npos) break;
        std::string key = t.substr(q1 + 1, q2 - q1 - 1);
        std::string val = t.substr(q3 + 1, q4 - q3 - 1);
        out.emplace_back(atoi(key.c_str()), val);
        i = q4 + 1;
    }
    return out;
}

// 字典 + 种子（论文引擎获得的全部协议知识，信息量对齐）
static std::string protocol_knowledge(const std::string& subject_dir) {
    std::ostringstream out;
    // 论文协议模式硬编码字典名 telnet.dict（LTLFuzzer.cc:101，内容随协议）；
    // dict.txt 为本工程早期名，作兜底。
    std::ifstream dict(subject_dir + "/telnet.dict");
    if (!dict.is_open()) dict.open(subject_dir + "/dict.txt");
    if (dict.is_open()) {
        out << "协议字典（公开协议知识，对应论文 AFL 字典）：\n";
        std::string line;
        while (std::getline(dict, line)) {
            std::string t = line.substr(0, line.find_first_not_of(" \t\r"));
            std::string::size_type b = line.find_last_not_of(" \t\r");
            if (b == std::string::npos || !t.empty() && t[0] == '#') continue;
            if (!line.empty()) out << line << "\n";
        }
    }
    std::ostringstream seeds;
    // 论文协议模式以整个 input_folder 为种子集（AFLGo -i 整目录，
    // LTLFuzzer.cc:97/264），非固定 seedN 文件名；排序取前 8 个限提示词体积。
    {
        std::vector<std::string> names;
        const std::string seed_dir = subject_dir + "/input_folder";
        if (DIR* d = opendir(seed_dir.c_str())) {
            while (struct dirent* e = readdir(d)) {
                std::string n = e->d_name;
                if (n != "." && n != "..") names.push_back(n);
            }
            closedir(d);
        }
        std::sort(names.begin(), names.end());
        for (size_t i = 0; i < names.size() && i < 8; ++i) {
            std::ifstream f(seed_dir + "/" + names[i]);
            if (!f.is_open()) continue;
            std::ostringstream ss;
            ss << f.rdbuf();
            std::string s = ss.str();
            if (!s.empty()) seeds << "--- " << names[i] << "\n" << s << "\n";
        }
    }
    if (!seeds.str().empty())
        out << "种子示例（公开输入形态）：\n" << seeds.str();
    return out.str();
}

static void save_counterexample(const std::string& subject_dir,
                                const std::string& bytes) {
    const std::string dir = subject_dir + "/output_folder/crashes";
    mkdir(dir.c_str(), 0755);
    char ts[64];
    std::time_t now = std::time(nullptr);
    std::strftime(ts, sizeof ts, "%Y%m%d-%H%M%S", std::localtime(&now));
    const std::string file = dir + "/input-" + ts;
    std::ofstream f(file, std::ios::binary | std::ios::trunc);
    f << bytes;
    std::cout << "[solver] 反例已保存: " << file
              << " (" << bytes.size() << "B, hex=" << to_hex(bytes) << ")"
              << std::endl;
}

static const char* SYSTEM_PROMPT = R"(你是输入求解智能体。目标：构造一段【追加后缀】字节，使程序执行时触发指定事件。事件 = 谓词成立；谓词由锚点行位置定义（该行被执行即事件成立，论文 targets.txt 语义）。

你有静态分析工具可用，按需调用（推导谓词到达条件的正道，不要凭空猜）：
- read_source / grep_source：读源码、找符号；
- cpg_backward_slice(var,file,line)：变量的传递数据依赖（CPG=AST+控制流+数据流+def-use）；
- cpg_def_use(var)：变量全部赋值点；
- cpg_literals(file,from,to)：行范围内的源码字面量常量（命令字/协议串的权威来源）；
- dominator_conditions(file,line)：到达该行必经的分支条件与必为假的早退守卫。

求解流程：
1. 用工具推导：锚点行所在分支的控制条件（支配子）、影响条件的变量及其赋值点、涉及的源码常量；
2. 构造 SMT-LIB2 约束：待定字节声明为 (_ BitVec 8) 常量（i0,i1,...）；源码强制的字节逐字节断言相等；谓词结构条件（包含/前缀/范围）断言为约束——必须来自分析事实；
3. Z3 由框架执行：你只输出约束与映射，框架求解并按映射从 model 拼装候选（不要手抄字节值）；
4. 输出格式（缺一不可；映射覆盖 0..LEN-1 每字节）：
LOCUS_SMT2:
```smt2
(declare-fun i0 () (_ BitVec 8))
(assert (= i0 #x50))
...
```
LOCUS_SMT_LEN: <后缀字节数>
LOCUS_SMT_MODEL: {"<起始偏移十进制>": "<SMT常量名>", ...}
连续段可用更宽位向量常量（键为段起始偏移）。无法构造约束时退回：
LOCUS_WITNESS: bytes=<纯十六进制，无空格>

反馈中的服务/程序输出用于定位输入缺陷。

知识库推导（首次求解本目标时必做）：用工具推导并输出 LOCUS_KB——
SKELETON：建立基础状态（如认证）的最短会话字节前缀；CLEAN：可多次
执行且不触发禁止事件的命令行（可多行）；FORBID：触发禁止事件或终止
会话的命令行（可多行）。推导手段：read_source/cpg 系工具分析 + 
probe_input 注入实验验证。引擎缓存 LOCUS_KB，后续任务直接组装复用。
格式：
LOCUS_KB:
SKELETON <hex>
CLEAN <hex>
FORBID <hex>前缀已验证有效：后缀拼在其后，不要重建前缀已建立的状态（除非反馈说明其一次性上下文已耗尽）。

完整会话优先：触发事件的最小输入往往不够（浅层回复就能触发表面事件）。
优先构造能通过认证、深入协议状态的完整会话——种子文件里有真实凭证和
会话形态；反馈若出现认证失败类回复码，先用种子凭证修正前缀再求
解。反例判定需要同一会话内的深层事件序列与状态重复，浅层会话到不了。)";


// ================= 纯范式引擎：推导知识库 + 演绎组装 =================
// 命题：搜索 = 静态分析 + 求解 + 反馈。组装层不使用任何随机字节算子
// （非变异）：见证 = 骨架 + 推导出的触发命令 × k，k 与禁止集全部来自
// 自动机/monitor 语义与执行观测。

struct KnowledgeBase {
    bool ready = false;                    // 骨架已表征
    std::string skeleton;                  // 认证骨架（字节，含行尾）
    std::vector<std::string> clean_lines;  // 可重复且不触发禁止事件的行
    std::vector<std::string> forbid_lines; // 触发禁止事件的行（观测归因）
};

static void kb_save(const std::string& dir, const KnowledgeBase& kb) {
    std::ofstream f(dir + "/output_folder/solver-knowledge.md",
                    std::ios::trunc);
    f << "SKELETON " << to_hex(kb.skeleton) << "\n";
    for (const auto& l : kb.clean_lines)
        f << "CLEAN " << to_hex(l) << "\n";
    for (const auto& l : kb.forbid_lines)
        f << "FORBID " << to_hex(l) << "\n";
}

static KnowledgeBase kb_load(const std::string& dir) {
    KnowledgeBase kb;
    std::ifstream f(dir + "/output_folder/solver-knowledge.md");
    std::string tag, hex;
    while (f >> tag >> hex) {
        std::string b = from_hex(hex);
        if (tag == "SKELETON") { kb.skeleton = b; kb.ready = !b.empty(); }
        else if (tag == "CLEAN") kb.clean_lines.push_back(b);
        else if (tag == "FORBID") kb.forbid_lines.push_back(b);
    }
    return kb;
}

// 按行切分字节串（保留 \r\n）
static std::vector<std::string> split_lines(const std::string& bytes) {
    std::vector<std::string> lines;
    std::string::size_type start = 0;
    while (start < bytes.size()) {
        std::string::size_type nl = bytes.find("\n", start);
        if (nl == std::string::npos) {
            lines.push_back(bytes.substr(start));
            break;
        }
        lines.push_back(bytes.substr(start, nl - start + 1));
        start = nl + 1;
    }
    return lines;
}

// 读 input_folder 种子（L0 用；论文 AFL -i 同一信息源）。
static std::vector<std::string> load_seeds(const std::string& subject_dir) {
    std::vector<std::string> seeds;
    const std::string dir = subject_dir + "/input_folder";
    if (DIR* d = opendir(dir.c_str())) {
        std::vector<std::string> names;
        while (struct dirent* e = readdir(d)) {
            std::string n = e->d_name;
            if (n != "." && n != "..") names.push_back(n);
        }
        closedir(d);
        std::sort(names.begin(), names.end());
        for (size_t i = 0; i < names.size() && i < 4; ++i) {
            std::ifstream f(dir + "/" + names[i], std::ios::binary);
            std::ostringstream ss; ss << f.rdbuf();
            std::string b = ss.str();
            if (!b.empty()) seeds.push_back(b);
        }
    }
    return seeds;
}

// L2 观测笔记：引擎只记录执行反馈里【观测到】的事实并跨任务注入
// （零知识注入；AFL 语料积累的知识层对应物）。
static void append_note(const std::string& subject_dir,
                        const std::string& note) {
    std::ofstream f(subject_dir + "/output_folder/solver-notes.md",
                    std::ios::app);
    f << note << "\n";
}
static std::string read_notes(const std::string& subject_dir,
                              size_t max_chars) {
    std::ifstream f(subject_dir + "/output_folder/solver-notes.md");
    std::ostringstream ss; ss << f.rdbuf();
    std::string s = ss.str();
    if (s.size() > max_chars) s = "……\n" + s.substr(s.size() - max_chars);
    return s;
}

SolveResult SolverEngine::run(const SolveContext& ctx) {
    SolveResult res;
    const char* at = std::getenv("SOLVER_MAX_ATTEMPTS");
    int max_attempts = at ? std::max(1, atoi(at)) : 8;
    // 实验度量：每任务墙钟 + token 差分（进程内累计），落 stats 文件
    const auto t0 = std::chrono::steady_clock::now();
    const TokenUsage u0 = token_usage_snapshot();
    static auto campaign_t0 = std::chrono::steady_clock::now();
    auto log_stats = [&](const char* outcome) {
        const double dt = std::chrono::duration<double>(
                              std::chrono::steady_clock::now() - t0)
                              .count();
        const double total = std::chrono::duration<double>(
                                 std::chrono::steady_clock::now() -
                                 campaign_t0)
                                 .count();
        const TokenUsage u1 = token_usage_snapshot();
        std::ostringstream line;
        line << "event=" << ctx.target_event << " loc=" << ctx.target_loc
             << " outcome=" << outcome
             << " task_s=" << std::fixed << std::setprecision(1) << dt
             << " tokens_prompt=" << (u1.prompt_tokens - u0.prompt_tokens)
             << " tokens_completion="
             << (u1.completion_tokens - u0.completion_tokens)
             << " tokens_hit=" << (u1.prompt_hit - u0.prompt_hit)
             << " tokens_miss=" << (u1.prompt_miss - u0.prompt_miss)
             << " api_calls=" << (u1.api_calls - u0.api_calls)
             << " | campaign_s=" << std::setprecision(0) << total
             << " tokens_total="
             << (u1.prompt_tokens + u1.completion_tokens)
             << " hit_total=" << u1.prompt_hit
             << " miss_total=" << u1.prompt_miss;
        std::cout << "[stats] " << line.str() << std::endl;
        std::ofstream sf(ctx.subject_dir + "/output_folder/solver-stats.log",
                         std::ios::app);
        sf << line.str() << "\n";
    };

    auto anchors = SourceAnalyzer::anchors_for(ctx.subject_dir,
                                               ctx.target_event);
    if (anchors.empty())
        std::cout << "[solver] 警告: 未找到事件 " << ctx.target_event
                  << " 的锚点（targets.txt/源码），仅凭协议知识求解"
                  << std::endl;

    // 会话前缀（引擎侧语料，论文中 AFL 语料演化的等价物——协议模式
    // 前缀池不带字节，见 README）：池前缀优先，否则用本引擎记忆的
    // 最佳会话；按单会话观测事件数棘轮更新，使"登录+多命令"的完整
    // 见证轨迹能在一个会话内组合出来（CE 需要同会话状态重复）。
    static std::map<std::string, std::pair<std::string, size_t>>
        session_base;
    std::string prefix_bytes = Executor::prefix_to_bytes(ctx.prefix);
    {
        auto it = session_base.find(ctx.subject_dir);
        if (prefix_bytes.empty() && it != session_base.end())
            prefix_bytes = it->second.first;
    }
    std::vector<std::string> feedback;

    // ---- 演绎组装层（零 token，非变异）----
    // 知识库就绪后：见证 = 骨架 + 推导出的可重复命令 × k（k 来自
    // monitor 语义：状态重复需 ≥2 次，取 4/6）。库缺失时先做一次
    // 种子表征（对公开种子按行前缀执行，事件差分归因各行作用）。
    {
        KnowledgeBase kb = kb_load(ctx.subject_dir);
        // 组装：骨架（知识库或引擎观测的最佳会话）+ 洁净行 × k。
        // 组装材料全部来自推导/观测（KB 表征、会话基底），无随机算子。
        if (kb.ready) {
            std::vector<std::string> roots;
            {
                auto it = session_base.find(ctx.subject_dir);
                if (it != session_base.end() && !it->second.first.empty())
                    roots.push_back(it->second.first);
            }
            roots.push_back(kb.skeleton);
            for (const auto& root : roots)
            for (const auto& line : kb.clean_lines) {
                for (int k : {4, 6}) {
                    std::string block;
                    for (int r = 0; r < k; ++r) block += line;
                    const std::string cand = root + block;
                    ExecResult ex = Executor::run(
                        ctx.subject_dir, ctx.target_loc, ctx.exec_name,
                        ctx.flag, cand);
                    if (ex.output.find("a counterexample!")
                            != std::string::npos) {
                        res.counterexample = true;
                        save_counterexample(ctx.subject_dir, cand);
                        res.report = "monitor 报告 a counterexample!"
                                     "（演绎组装，零 token）";
                        log_stats("ASSEMBLY_COUNTEREXAMPLE");
                        return res;
                    }
                    bool fired0 =
                        std::find(ex.events.begin(), ex.events.end(),
                                  ctx.target_event) != ex.events.end();
                    if (fired0) {
                        res.advanced = true;
                        res.report = "演绎组装命中（零 token）";
                        auto& sb = session_base[ctx.subject_dir];
                        if (ex.events.size() > sb.second)
                            sb = {cand, ex.events.size()};
                        log_stats("ASSEMBLY_fired");
                        return res;
                    }
                }
            }
        }
    }

    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        std::cout << "[solver] 尝试 " << attempt << "/" << max_attempts
                  << std::endl;

        // ---- 上下文组装 ----
        std::ostringstream u;
        u << "【调度上下文】自动机当前状态 q" << ctx.last_state
          << "，目标事件 `" << ctx.target_event << "`（位置 "
          << ctx.target_loc << "）。\n";
        if (!ctx.path_ahead.empty()) {
            u << "到违规见证（接受态）的剩余事件序列（自动机推导）: ";
            for (size_t i = 0; i < ctx.path_ahead.size(); ++i) {
                if (i) u << " -> ";
                u << ctx.path_ahead[i];
            }
            u << "\n";
        }
        if (ctx.witness_loop || !ctx.forbidden_events.empty()) {
            u << "【见证要求】（以下由 ¬φ 自动机接受态自环标签自动推导）\n";
            if (ctx.witness_loop) {
                u << "- 目标事件位于接受态自环";
                if (!ctx.loop_events.empty()) {
                    u << "（可停留事件：";
                    for (size_t i = 0; i < ctx.loop_events.size(); ++i)
                        u << (i ? "," : "") << ctx.loop_events[i];
                    u << "）";
                }
                u << "：需在【同一会话】内让目标事件连续触发至少 3 次——"
                     "程序内 monitor 需观察到程序状态重复才判反例。\n";
            }
            if (!ctx.forbidden_events.empty()) {
                u << "- 禁止事件（自环标签取反，出现即毁见证，整个输入含"
                     "前缀中不得触发）：";
                for (size_t i = 0; i < ctx.forbidden_events.size(); ++i)
                    u << (i ? "," : "") << ctx.forbidden_events[i];
                u << "。用源码分析与执行反馈确定哪些命令会触发它们并避开。\n";
            }
            u << "- 重复所用的命令必须是会话内可多次执行的：以执行反馈甄别"
                 "——发送后连接终止或后续命令无响应的是终止性命令，不可用于"
                 "重复，也不得内嵌在输入中；若前缀含禁止事件或终止性命令，"
                 "去掉后重建会话。\n";
        }
        u << "公式（原式，violate it）: " << ctx.formula << "\n";
        u << "已验证前缀（hex，" << prefix_bytes.size() << " 字节）: "
          << (prefix_bytes.empty() ? std::string("（空——第一轮）")
                                   : to_hex(prefix_bytes))
          << "\n\n";
        u << "目标事件锚点源码（行位置即谓词；=> 为锚点行）：\n";
        for (const auto& a : anchors)
            u << "-- " << a.file << ":" << a.line << "\n" << a.window << "\n";
        u << "\n" << protocol_knowledge(ctx.subject_dir);
        {
            std::string notes = read_notes(ctx.subject_dir, 900);
            if (!notes.empty())
                u << "\n【已验证事实（引擎从执行观测沉淀，非人工知识）】\n"
                  << notes << "\n";
        }
        for (size_t i = feedback.size() >= 2 ? feedback.size() - 2 : 0;
             i < feedback.size(); ++i)
            u << "\n【反馈 " << (i + 1) << "】\n" << feedback[i] << "\n";
        u << "\n按协议输出候选后缀。\n";

        // ---- 智能体 ----
        // 源码根：SUBJECT/src 优先，其次 SUBJECT
        std::string src_root = ctx.subject_dir + "/src";
        {
            std::ifstream t(src_root + "/.");
            if (!t.good()) src_root = ctx.subject_dir;
        }
        AnalysisTools tools(ctx.subject_dir, src_root);
        std::string err;
        std::string reply = AgentLoop::run(
            SYSTEM_PROMPT, u.str(), tools.tools_json(),
            [&tools](const std::string& n, const std::string& a) {
                return tools.dispatch(n, a);
            }, &err);
        if (reply.empty()) {
            feedback.push_back("LLM 调用失败：" + err);
            std::cout << "[solver] LLM调用失败: " << err << std::endl;
            continue;
        }

        // ---- LOCUS_KB：智能体推导的知识库入库（一次性，之后组装复用）----
        {
            std::string::size_type kp = reply.find("LOCUS_KB:");
            if (kp != std::string::npos) {
                KnowledgeBase nkb;
                std::istringstream ks(reply.substr(kp));
                std::string tag, hexs;
                while (ks >> tag >> hexs) {
                    std::string b = from_hex(hexs);
                    if (tag == "SKELETON" && !b.empty()) {
                        nkb.skeleton = b;
                        nkb.ready = true;
                    } else if (tag == "CLEAN") nkb.clean_lines.push_back(b);
                    else if (tag == "FORBID") nkb.forbid_lines.push_back(b);
                }
                if (nkb.ready) {
                    kb_save(ctx.subject_dir, nkb);
                    std::cout << "[solver] LOCUS_KB 已入库（智能体推导："
                              << nkb.clean_lines.size() << " 洁净行 / "
                              << nkb.forbid_lines.size() << " 禁止行）"
                              << std::endl;
                }
            }
        }

        // ---- 候选构造：优先 SMT 路径（model 拼装），退回 WITNESS hex ----
        std::string cand;
        const std::string smt2 = extract_smt2(reply);
        auto mmap = parse_model_map(
            extract_line_field(reply, "LOCUS_SMT_MODEL:"));
        if (!smt2.empty() && !mmap.empty()) {
            SmtResult sr = Z3Solver::solve(smt2);
            if (sr.status != "sat") {
                std::ostringstream fb;
                fb << "Z3 " << sr.status
                   << (sr.detail.empty() ? "" : ": " + sr.detail)
                   << "——检查约束是否矛盾/语法错误后重试";
                feedback.push_back(fb.str());
                std::cout << "[solver] " << fb.str() << std::endl;
                continue;
            }
            size_t need = 0;
            for (const auto& kv : mmap) {
                auto it = sr.model.find(kv.second);
                if (it == sr.model.end()) continue;
                need = std::max(need,
                                static_cast<size_t>(kv.first) +
                                    value_to_bytes(it->second).size());
            }
            std::string built(need, '\0');
            bool ok = true;
            for (const auto& kv : mmap) {
                auto it = sr.model.find(kv.second);
                if (it == sr.model.end()) {
                    ok = false;
                    break;
                }
                std::string b = value_to_bytes(it->second);
                if (static_cast<size_t>(kv.first) + b.size() > built.size())
                    b.resize(built.size() - kv.first);
                built.replace(kv.first, b.size(), b);
            }
            if (ok && !built.empty()) cand = built;
        }
        if (cand.empty()) {
            std::string hex = extract_line_field(reply, "LOCUS_WITNESS: bytes=");
            std::string clean;
            for (char c : hex)
                if (!std::isspace(static_cast<unsigned char>(c))) clean += c;
            if (!clean.empty()) cand = from_hex(clean);
        }
        if (cand.empty()) {
            feedback.push_back(
                "回复缺少 LOCUS_SMT2+LOCUS_SMT_MODEL（或退回的 "
                "LOCUS_WITNESS）——严格按协议输出");
            std::cout << "[solver] 回复缺LOCUS协议段" << std::endl;
            continue;
        }

        // ---- 执行：前缀 + 后缀（判定与池回写在程序内 monitor）----
        const std::string full = prefix_bytes + cand;
        ExecResult ex = Executor::run(ctx.subject_dir, ctx.target_loc,
                                      ctx.exec_name, ctx.flag, full);
        res.best_input_hex = to_hex(full);

        if (ex.output.find("a counterexample!") != std::string::npos) {
            res.counterexample = true;
            save_counterexample(ctx.subject_dir, full);
            res.report = "monitor 报告 a counterexample!（程序内判定）";
            log_stats("COUNTEREXAMPLE");
            return res;
        }
        bool fired = std::find(ex.events.begin(), ex.events.end(),
                               ctx.target_event) != ex.events.end();
        // 见证洁净判定（自动机推导的隐式惩罚，对应论文"触发 n 则路径
        // 不前进"）：观测到禁止事件的会话不能作为成功/会话基底。
        std::string dirty;
        for (const auto& fe : ctx.forbidden_events) {
            if (std::find(ex.events.begin(), ex.events.end(), fe)
                    != ex.events.end()) {
                dirty = fe;
                break;
            }
        }
        if (!dirty.empty()) {
            std::ostringstream fb;
            fb << "已触发目标事件，但会话观测到禁止事件 " << dirty
               << "（¬φ 自动机接受态自环取反——出现即毁见证）。该会话不可"
                  "作为见证基础；请用源码分析与反馈定位触发它的命令并从"
                  "输入（含前缀）中移除后重建会话。观测事件：";
            for (size_t i = 0; i < ex.events.size(); ++i)
                fb << (i ? "," : "") << ex.events[i];
            feedback.push_back(fb.str());
            append_note(ctx.subject_dir,
                        "- 输入(hex=" + to_hex(full).substr(0, 80) +
                        ") 触发禁止事件 " + dirty + "（拒绝观测）");
            std::cout << "[solver] 会话含禁止事件 " << dirty
                      << "，不采纳（自动机推导）" << std::endl;
            // 基底淘汰（论文对应：毒输入在语料竞争中失利被清除——
            // 种群+覆盖反馈的引擎侧等价）：拒绝发生时丢弃会话基底，
            // 迫使下一轮从种子重建洁净会话。
            {
                auto it = session_base.find(ctx.subject_dir);
                if (it != session_base.end() && !it->second.first.empty()) {
                    it->second = {"", 0};
                    feedback.push_back(
                        "引擎已丢弃被污染的会话基底（其含禁止事件触发源）。"
                        "请从种子重建洁净会话：保留认证，去掉触发禁止事件"
                        "的命令与终止性命令，再用可多次执行的命令达到目标。");
                    std::cout << "[solver] 基底已丢弃（含禁止事件源）"
                              << std::endl;
                }
            }
            continue;
        }
        if (fired) {
            res.advanced = true;
            {
                auto& sb = session_base[ctx.subject_dir];
                if (ex.events.size() > sb.second) sb = {full, ex.events.size()};
            }
            res.report = "目标事件 " + ctx.target_event +
                         " 已触发；新前缀由程序内 monitor 回写池";
            append_note(ctx.subject_dir,
                        "- 输入(hex=" + to_hex(full).substr(0, 80) +
                        ") 触发事件 " + ctx.target_event + "（观测）");
            std::cout << "[solver] fired 输入 hex=" << to_hex(full).substr(0, 200)
                      << " | exec输出=" << ex.output.size() << "B"
                      << " 回收尾段="
                      << ex.output.substr(ex.output.find("[server-log]") !=
                                                  std::string::npos
                                              ? ex.output.find("[server-log]")
                                              : 0,
                                          300)
                      << " serverlog=" << (int)(ex.output.find("[server-log]") != std::string::npos)
                      << " ce=" << (int)(ex.output.find("a counterexample") != std::string::npos)
                      << std::endl;
            log_stats("fired");
            return res;
        }

        // ---- 反馈 ----
        std::ostringstream fb;
        fb << "候选后缀 hex=" << to_hex(cand).substr(0, 160)
           << " -> 观测事件 ";
        if (ex.events.empty()) {
            fb << "(无)";
        } else {
            for (size_t i = 0; i < ex.events.size(); ++i)
                fb << (i ? "," : "") << ex.events[i];
        }
        if (!ex.ok) fb << "；执行失败：" << ex.detail;
        if (!ex.output.empty())
            fb << "\n服务/程序输出（定位输入缺陷）：\n"
               << ex.output.substr(0, 600);
        feedback.push_back(fb.str());
        std::cout << "[solver] 已执行 hex=" << to_hex(cand).substr(0, 80)
                  << " 观测=" << (ex.events.empty() ? std::string("(无)")
                                                    : fb.str().substr(0, 200))
                  << std::endl;
    }
    res.report = "预算内未使 " + ctx.target_event + " 成立（" +
                 std::to_string(max_attempts) + " 次尝试）";
    log_stats("budget_exhausted");
    return res;
}

}  // namespace solver
