#include <solver/AnalysisTools.h>

#include <solver/Executor.h>

#include <cctype>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>

namespace solver {

// ------------------------------------------------------------ 小工具

static std::string popen_read(const std::string& cmd, int* rc = nullptr) {
    FILE* p = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!p) {
        if (rc) *rc = -1;
        return "";
    }
    std::ostringstream out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) out.write(buf, n);
    int code = pclose(p);
    if (rc) *rc = code;
    return out.str();
}

static std::string shell_quote(const std::string& s) {
    std::string q = "'";
    for (char c : s) {
        if (c == '\'') q += "'\\''";
        else q += c;
    }
    return q + "'";
}

static bool read_file(const std::string& path, std::string* out) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    *out = ss.str();
    return true;
}

namespace jsonutil {

static std::string unescape(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char e = s[++i];
            switch (e) {
                case 'n': o += '\n'; break;
                case 't': o += '\t'; break;
                case 'r': o += '\r'; break;
                case '"': o += '"'; break;
                case '\\': o += '\\'; break;
                case '/': o += '/'; break;
                case 'u':
                    if (i + 4 < s.size()) {
                        unsigned code = 0;
                        for (int k = 0; k < 4; ++k) {
                            char h = s[++i];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= h - '0';
                            else if (h >= 'a' && h <= 'f') code |= h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') code |= h - 'A' + 10;
                        }
                        if (code < 0x80) o += static_cast<char>(code);
                        else if (code < 0x800) {
                            o += static_cast<char>(0xC0 | (code >> 6));
                            o += static_cast<char>(0x80 | (code & 0x3F));
                        } else {
                            o += static_cast<char>(0xE0 | (code >> 12));
                            o += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                            o += static_cast<char>(0x80 | (code & 0x3F));
                        }
                    }
                    break;
                default: o += e;
            }
        } else {
            o += s[i];
        }
    }
    return o;
}

std::string get_string(const std::string& json, const std::string& key,
                       const std::string& def) {
    const std::string pat = "\"" + key + "\"";
    std::string::size_type p = json.find(pat);
    while (p != std::string::npos) {
        std::string::size_type c = json.find(':', p + pat.size());
        if (c == std::string::npos) return def;
        std::string::size_type q = json.find('"', c + 1);
        while (q != std::string::npos && json[q - 1] == '\\')
            q = json.find('"', q + 1);
        if (q == std::string::npos) return def;
        std::string::size_type e = json.find('"', q + 1);
        while (e != std::string::npos && json[e - 1] == '\\')
            e = json.find('"', e + 1);
        if (e == std::string::npos) return def;
        return unescape(json.substr(q + 1, e - q - 1));
    }
    return def;
}

int get_int(const std::string& json, const std::string& key, int def) {
    const std::string pat = "\"" + key + "\"";
    std::string::size_type p = json.find(pat);
    if (p == std::string::npos) return def;
    std::string::size_type c = json.find(':', p + pat.size());
    if (c == std::string::npos) return def;
    return atoi(json.c_str() + c + 1);
}

}  // namespace jsonutil

// ------------------------------------------------------------ Scala 脚本
// （与 ltl-locus tools/cpg.py 逐字一致；结果以 @@R@@/@@E@@ 围栏返回）

static const char* SLICE_SC = R"SCALA(@main def exec(cpgFile: String, varName: String, fileName: String, lineNo: Int) = {
  importCpg(cpgFile)
  val start = cpg.identifier.name(varName).where(_.file.name(".*" + fileName + ".*")).filter(_.lineNumber.exists(_ == lineNo)).l
  println("@@R@@")
  val seen = scala.collection.mutable.LinkedHashSet[Any]()
  val frontier = scala.collection.mutable.ArrayBuffer[Any]()
  start.foreach(frontier += _)
  var round = 0
  while (frontier.nonEmpty && round < 32) {
    round += 1
    val next = scala.collection.mutable.ArrayBuffer[Any]()
    frontier.foreach { n =>
      if (seen.add(n)) {
        val in = n match {
          case e: io.shiftleft.codepropertygraph.generated.nodes.Expression => e.ddgIn.l
          case _ => List()
        }
        in.foreach(i => if (!seen.contains(i)) next += i)
      }
    }
    frontier.clear()
    next.foreach(frontier += _)
  }
  seen.foreach { n =>
    n match {
      case a: io.shiftleft.codepropertygraph.generated.nodes.AstNode =>
        println("NODE " + a.file.name.headOption.getOrElse("") + " " + a.lineNumber.getOrElse(-1) + " " + a.code.replace("\n", " ").take(120))
      case _ =>
    }
  }
  val names = scala.collection.mutable.LinkedHashSet[String]()
  seen.foreach { n =>
    n match {
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => names += i.name
      case _ =>
    }
  }
  names.foreach(n => println("VAR " + n))
  println("@@E@@")
}
)SCALA";

static const char* DEFUSE_SC = R"SCALA(@main def exec(cpgFile: String, varName: String) = {
  importCpg(cpgFile)
  println("@@R@@")
  cpg.assignment.where(_.target.code(".*\\b" + varName + "\\b.*")).l.foreach(n =>
    println("ASG " + n.file.name.headOption.getOrElse("") + " " + n.lineNumber.getOrElse(-1) + " " + n.code.replace("\n", " ").take(120)))
  println("@@E@@")
}
)SCALA";

static const char* LITERALS_SC = R"SCALA(@main def exec(cpgFile: String, fileName: String, lineFrom: Int, lineTo: Int) = {
  importCpg(cpgFile)
  println("@@R@@")
  cpg.literal.where(_.file.name(".*" + fileName + ".*")).filter(n => n.lineNumber.exists(l => l >= lineFrom && l <= lineTo)).l.foreach(n =>
    println("LIT " + n.lineNumber.getOrElse(-1) + " " + n.code))
  println("@@E@@")
}
)SCALA";

// ------------------------------------------------------------ 构造与 CPG

AnalysisTools::AnalysisTools(std::string subject_dir, std::string src_root)
    : subject_dir_(std::move(subject_dir)), src_root_(std::move(src_root)) {}

static std::string joern_binary(const char* name, const char* env_suffix) {
    const char* env = getenv(env_suffix);
    if (env && *env) return env;
    std::string home = getenv("HOME") ? getenv("HOME") : "";
    std::string local = home + "/.local/bin/" + name;
    {
        std::ifstream f(local);
        if (f.good()) return local;
    }
    return popen_read("command -v " + std::string(name));
}

std::string AnalysisTools::cpg_path() {
    if (!cpg_path_.empty() || !cpg_error_.empty())
        return cpg_path_;
    // 内容哈希（sha256sum 两级）：源码变更自动失效缓存
    std::string hash = popen_read(
        "cd " + shell_quote(src_root_) + " && find . -type f \\( -name '*.c' "
        "-o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' "
        "-o -name '*.hh' -o -name '*.hpp' \\) | sort | "
        "xargs -r sha256sum 2>/dev/null | sha256sum");
    std::string h = hash.substr(0, hash.find_first_of(" \n"));
    if (h.empty()) h = "nocache";
    const std::string dir = subject_dir_ + "/.cpg-cache";
    popen_read("mkdir -p " + shell_quote(dir));
    cpg_path_ = dir + "/cpg-" + h.substr(0, 16) + ".bin";
    {
        std::ifstream f(cpg_path_, std::ios::binary);
        if (f.good()) return cpg_path_;       // 缓存命中
    }
    std::string jp = joern_binary("joern-parse", "SOLVER_JOERN_PARSE");
    if (jp.empty()) {
        cpg_error_ = "joern-parse 不在 PATH（安装 joern 或设 SOLVER_JOERN_PARSE）";
        cpg_path_.clear();
        return "";
    }
    int rc = 0;
    std::string out = popen_read(
        "timeout 900 " + shell_quote(jp) + " " + shell_quote(src_root_) +
        " -o " + shell_quote(cpg_path_), &rc);
    std::ifstream f(cpg_path_, std::ios::binary);
    if (rc != 0 || !f.good()) {
        cpg_error_ = "joern-parse 失败（rc=" + std::to_string(rc) + "）" +
                     out.substr(0, 300);
        cpg_path_.clear();
    }
    return cpg_path_;
}

std::string AnalysisTools::joern(const std::string& scala,
                                 const std::string& params) {
    std::string cpg = cpg_path();
    if (cpg.empty())
        return "ERROR: CPG 不可用——" + cpg_error_;
    std::string script = "/tmp/ltlsolver-query.sc";
    {
        std::ofstream f(script, std::ios::trunc);
        f << scala;
    }
    int rc = 0;
    std::string out = popen_read(
        "timeout 600 " + shell_quote(joern_binary("joern", "SOLVER_JOERN")) +
        " --script " + script + " --param cpgFile=" +
        shell_quote(cpg) + " " + params, &rc);
    std::string::size_type r = out.find("@@R@@");
    std::string::size_type e = out.find("@@E@@");
    if (rc != 0 || r == std::string::npos || e == std::string::npos ||
        e < r)
        return "ERROR: joern 查询失败（rc=" + std::to_string(rc) +
               "）tail: " + out.substr(out.size() > 300 ? out.size() - 300 : 0);
    return out.substr(r + 6, e - r - 6);
}

std::string AnalysisTools::backward_slice(const std::string& var,
                                          const std::string& file, int line) {
    // 文件名转正则安全（点号等）
    std::string base = file;
    std::string::size_type ps = base.find_last_of('/');
    if (ps != std::string::npos) base = base.substr(ps + 1);
    std::string safe;
    for (char c : base)
        if (strchr(".^$|*+?()[]{}", c)) { safe += '\\'; safe += c; }
        else safe += c;
    return joern(SLICE_SC,
                 "--param varName=" + shell_quote(var) +
                 " --param fileName=" + shell_quote(safe) +
                 " --param lineNo=" + std::to_string(line));
}

std::string AnalysisTools::def_use(const std::string& var) {
    return joern(DEFUSE_SC, "--param varName=" + shell_quote(var));
}

std::string AnalysisTools::literals(const std::string& file, int from,
                                    int to) {
    std::string base = file;
    std::string::size_type ps = base.find_last_of('/');
    if (ps != std::string::npos) base = base.substr(ps + 1);
    std::string safe;
    for (char c : base)
        if (strchr(".^$|*+?()[]{}", c)) { safe += '\\'; safe += c; }
        else safe += c;
    return joern(LITERALS_SC,
                 "--param fileName=" + shell_quote(safe) +
                 " --param lineFrom=" + std::to_string(from) +
                 " --param lineTo=" + std::to_string(to));
}

// --------------------------------------------- 支配子（dominators.py 移植）

namespace {

struct Guard {
    std::string kind;       // if / for / while / switch
    std::string condition;
    int line = 0;
};

bool is_ident_char(char c) {
    return isalnum(static_cast<unsigned char>(c)) || c == '_';
}

// 单出口守卫判定：块体恰为一条 (return|continue|break|goto ...);
// （对应 Python _SINGLE_EXIT_RE）
bool single_exit_body(const std::string& body) {
    size_t b = body.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return false;
    static const char* kinds[] = {"return", "continue", "break", "goto"};
    std::string kw;
    for (const char* k : kinds) {
        size_t len = strlen(k);
        if (body.compare(b, len, k) == 0 &&
            !is_ident_char(body[b + len])) {
            kw = k;
            break;
        }
    }
    if (kw.empty()) return false;
    // 余下部分：无 {} ，恰一个 ; 在结尾（其后仅空白）
    size_t i = b + kw.size();
    int semis = 0;
    bool bad = false;
    for (; i < body.size(); ++i) {
        char c = body[i];
        if (c == '{' || c == '}') bad = true;
        else if (c == ';') ++semis;
        else if (!isspace(static_cast<unsigned char>(c))) {
            if (semis > 0) bad = true;   // ; 后还有内容
        }
    }
    return !bad && semis == 1;
}

}  // namespace

std::string AnalysisTools::dominators(const std::string& file, int line) {
    std::string path = src_root_ + "/" + file;
    std::string src;
    if (!read_file(path, &src))
        return "ERROR: 读不到 " + path;
    // 逐字符扫描（跳注释/字符串），跟踪行号与花括号深度
    struct CodePt { size_t pos; char c; int line; };
    std::vector<CodePt> code;
    {
        int ln = 1;
        size_t i = 0, n = src.size();
        while (i < n) {
            char c = src[i];
            char nxt = i + 1 < n ? src[i + 1] : 0;
            if (c == '\n') { ++ln; ++i; continue; }
            if (c == '/' && nxt == '/') {
                size_t j = src.find('\n', i);
                i = j == std::string::npos ? n : j;
                continue;
            }
            if (c == '/' && nxt == '*') {
                size_t j = src.find("*/", i + 2);
                if (j == std::string::npos) break;
                for (size_t k = i; k <= j + 1; ++k)
                    if (src[k] == '\n') ++ln;
                i = j + 2;
                continue;
            }
            if (c == '"' || c == '\'') {
                size_t j = i + 1;
                while (j < n) {
                    if (src[j] == '\\') { j += 2; continue; }
                    if (src[j] == c || src[j] == '\n') break;
                    ++j;
                }
                i = j + 1;
                continue;
            }
            code.push_back({i, c, ln});
            ++i;
        }
    }

    std::vector<Guard> must_hold, must_not_hold;
    std::vector<std::pair<int, size_t>> live;   // (depth, must_hold idx)
    struct OpenBlk { int depth; size_t m_idx; size_t open_pos; };
    std::vector<OpenBlk> open_blocks;
    Guard pending;
    bool has_pending = false;
    int depth = 0;
    bool in_function = false, seen_target = false, target_in_function = false;

    for (size_t i = 0; i < code.size(); ++i) {
        const CodePt& pt = code[i];
        if (pt.line > line && seen_target) break;
        if (pt.line == line && !seen_target) {
            seen_target = true;
            target_in_function = in_function;
        }
        // 关键字识别（前一个字符不是标识符字符）
        if (!has_pending &&
            (pt.c == 'i' || pt.c == 'f' || pt.c == 'w' || pt.c == 's' ||
             isalpha(static_cast<unsigned char>(pt.c)))) {
            char prev = i > 0 ? code[i - 1].c : 0;
            if (!is_ident_char(prev)) {
                size_t e = pt.pos;
                while (e < src.size() && is_ident_char(src[e])) ++e;
                std::string word = src.substr(pt.pos, e - pt.pos);
                if (word == "if" || word == "for" || word == "while" ||
                    word == "switch") {
                    // 平衡括号组 -> 条件文本（先跳过关键字本身再找 '('）
                    size_t j = i;
                    while (j < code.size() && code[j].pos < e) ++j;
                    while (j < code.size() && (code[j].c == ' ' || code[j].c == '\t')) ++j;
                    if (j < code.size() && code[j].c == '(') {
                        int d = 0;
                        size_t first = 0;
                        size_t endj = std::string::npos;
                        for (size_t k = j; k < code.size(); ++k) {
                            if (code[k].c == '(') {
                                ++d;
                                if (d == 1) first = code[k].pos;
                            } else if (code[k].c == ')') {
                                --d;
                                if (d == 0) { endj = k; break; }
                            }
                        }
                        if (endj != std::string::npos) {
                            std::string cond = src.substr(
                                first + 1, code[endj].pos - first - 1);
                            pending = Guard{word, cond, pt.line};
                            has_pending = true;
                            i = endj;
                            continue;
                        }
                    }
                }
                i += (e - pt.pos) - 1;   // 跳过整个词
                continue;
            }
        }
        if (pt.c == '{') {
            if (has_pending) {
                live.push_back({depth, must_hold.size()});
                must_hold.push_back(pending);
                open_blocks.push_back({depth, must_hold.size() - 1, pt.pos});
                has_pending = false;
            } else if (depth == 0) {
                live.clear();
                must_hold.clear();
                must_not_hold.clear();
                open_blocks.clear();
                in_function = true;
            }
            ++depth;
        } else if (pt.c == '}') {
            int nd = depth - 1;
            for (size_t k = 0; k < open_blocks.size();) {
                if (open_blocks[k].depth == nd) {
                    std::string body = src.substr(
                        open_blocks[k].open_pos + 1, pt.pos - open_blocks[k].open_pos - 1);
                    if (single_exit_body(body) && pt.line <= line)
                        must_not_hold.push_back(must_hold[open_blocks[k].m_idx]);
                    open_blocks.erase(open_blocks.begin() + k);
                } else {
                    ++k;
                }
            }
            while (!live.empty() && live.back().first >= nd) live.pop_back();
            depth = nd;
            if (depth == 0) in_function = false;
        } else if (pt.c == ';' && has_pending) {
            has_pending = false;
        }
    }
    if (!(seen_target && target_in_function))
        return "（目标行不在任何函数体内，无支配条件）";

    auto fmt = [](const Guard& g, bool neg) {
        std::string c;
        for (char ch : g.condition)
            if (!isspace(static_cast<unsigned char>(ch))) c += ch;
            else if (!c.empty() && c.back() != ' ') c += ' ';
        return (neg ? "!(" + c + ")" : c) + "   [" + g.kind + " @line " +
               std::to_string(g.line) + "]";
    };
    std::ostringstream out;
    out << "must_hold（到达该行必经的分支条件）：\n";
    for (auto& kv : live) out << "  " << fmt(must_hold[kv.second], false) << "\n";
    out << "must_not_hold（到达该行必为假的早退守卫）：\n";
    for (auto& g : must_not_hold) out << "  " << fmt(g, true) << "\n";
    return out.str();
}

// ------------------------------------------------------------ 源码工具

std::string AnalysisTools::read_source(const std::string& file, int from,
                                       int to) {
    std::string path = src_root_ + "/" + file;
    std::string src;
    if (!read_file(path, &src))
        return "ERROR: 读不到 " + path;
    std::vector<std::string> lines;
    std::istringstream in(src);
    std::string l;
    while (std::getline(in, l)) lines.push_back(l);
    int lo = std::max(1, from ? from : 1);
    int hi = std::min<int>(lines.size(), to ? to : lines.size());
    if (lo > hi) return "ERROR: 行范围越界";
    std::ostringstream out;
    for (int i = lo; i <= hi; ++i)
        out << i << "\t" << lines[i - 1] << "\n";
    return out.str();
}

std::string AnalysisTools::grep_source(const std::string& pattern) {
    std::string out = popen_read(
        "cd " + shell_quote(src_root_) + " && grep -rn --include='*.c' "
        "--include='*.cc' --include='*.cpp' --include='*.h' "
        "--include='*.hpp' -e " + shell_quote(pattern) +
        " . | head -100");
    return out.empty() ? "（无匹配）" : out;
}

// ------------------------------------------------------------ 工具注册

std::string AnalysisTools::tools_json() const {
    return R"json([
 {"type":"function","function":{
   "name":"read_source",
   "description":"读取源码文件的指定行范围（带行号）。file 为相对 src 的路径",
   "parameters":{"type":"object","properties":{
     "file":{"type":"string"},"from_line":{"type":"integer"},"to_line":{"type":"integer"}},
     "required":["file"]}}},
 {"type":"function","function":{
   "name":"grep_source",
   "description":"在源码树里按模式检索（grep -rn），返回 file:line:内容",
   "parameters":{"type":"object","properties":{
     "pattern":{"type":"string"}},"required":["pattern"]}}},
 {"type":"function","function":{
   "name":"cpg_backward_slice",
   "description":"Joern CPG 反向数据依赖切片：变量在某使用的传递依赖（节点+变量集）。CPG 含 AST/控制流/数据流/def-use",
   "parameters":{"type":"object","properties":{
     "var":{"type":"string"},"file":{"type":"string"},"line":{"type":"integer"}},
     "required":["var","file","line"]}}},
 {"type":"function","function":{
   "name":"cpg_def_use",
   "description":"Joern CPG 定义-使用：某变量的全部赋值点",
   "parameters":{"type":"object","properties":{
     "var":{"type":"string"}},"required":["var"]}}},
 {"type":"function","function":{
   "name":"cpg_literals",
   "description":"Joern CPG：文件内行范围中的字面量常量（命令字/协议串的权威来源）",
   "parameters":{"type":"object","properties":{
     "file":{"type":"string"},"from_line":{"type":"integer"},"to_line":{"type":"integer"}},
     "required":["file","from_line","to_line"]}}},
 {"type":"function","function":{
   "name":"dominator_conditions",
   "description":"支配子必要条件：到达 file:line 必经的分支条件(must_hold)与必为假的早退守卫(must_not_hold)",
   "parameters":{"type":"object","properties":{
     "file":{"type":"string"},"line":{"type":"integer"}},
     "required":["file","line"]}}},
 {"type":"function","function":{
   "name":"probe_input",
   "description":"实验仪器：向目标注入一段字节并回收观测（触发的事件列表 + 服务输出前500字符）。用于验证推导（如某命令是否触发某事件、是否终止会话）",
   "parameters":{"type":"object","properties":{
     "bytes_hex":{"type":"string","description":"纯十六进制字节串（无空格）"}},
     "required":["bytes_hex"]}}}
])json";
}

std::string AnalysisTools::dispatch(const std::string& name,
                                    const std::string& args_json) {
    if (name == "read_source")
        return read_source(jsonutil::get_string(args_json, "file"),
                           jsonutil::get_int(args_json, "from_line", 0),
                           jsonutil::get_int(args_json, "to_line", 0));
    if (name == "grep_source")
        return grep_source(jsonutil::get_string(args_json, "pattern"));
    if (name == "cpg_backward_slice")
        return backward_slice(jsonutil::get_string(args_json, "var"),
                              jsonutil::get_string(args_json, "file"),
                              jsonutil::get_int(args_json, "line"));
    if (name == "cpg_def_use")
        return def_use(jsonutil::get_string(args_json, "var"));
    if (name == "cpg_literals")
        return literals(jsonutil::get_string(args_json, "file"),
                        jsonutil::get_int(args_json, "from_line"),
                        jsonutil::get_int(args_json, "to_line"));
    if (name == "dominator_conditions")
        return dominators(jsonutil::get_string(args_json, "file"),
                          jsonutil::get_int(args_json, "line"));
    if (name == "probe_input") {
        std::string hexs = jsonutil::get_string(args_json, "bytes_hex", "");
        std::string b;
        for (size_t i = 0; i + 1 < hexs.size(); i += 2) {
            int v = 0;
            for (int k = 0; k < 2; ++k) {
                char c = hexs[i + k];
                v <<= 4;
                if (c >= '0' && c <= '9') v |= c - '0';
                else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            }
            b += static_cast<char>(v);
        }
        if (b.empty()) return "ERROR: bytes_hex 为空";
        ExecResult ex = Executor::run(subject_dir_, "", "", 1, b);
        std::ostringstream o;
        o << "观测事件: ";
        if (ex.events.empty()) o << "(无)";
        for (size_t i = 0; i < ex.events.size(); ++i)
            o << (i ? "," : "") << ex.events[i];
        o << "\n服务输出(前500字符):\n" << ex.output.substr(0, 500);
        return o.str();
    }
    return "ERROR: 未知工具 " + name;
}

}  // namespace solver
