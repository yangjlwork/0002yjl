#include <solver/AgentLoop.h>
#include <solver/AnalysisTools.h>
#include <algorithm>
#include <cstring>
#include <vector>

#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace solver {

static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o << buf;
                } else {
                    o << static_cast<char>(c);
                }
        }
    }
    return o.str();
}

// 极简提取 OpenAI 兼容回复的 choices[0].message.content 字段。
// 只处理标准转义（\" \\ \n \t \uXXXX 的 UTF-8 等价直接透传字节）。
static std::string extract_content(const std::string& json) {
    const std::string key = "\"content\":\"";
    std::string::size_type p = json.find(key);
    if (p == std::string::npos) return "";
    p += key.size();
    std::ostringstream out;
    while (p < json.size()) {
        char c = json[p++];
        if (c == '"') break;
        if (c == '\\' && p < json.size()) {
            char e = json[p++];
            switch (e) {
                case 'n':  out << '\n'; break;
                case 't':  out << '\t'; break;
                case 'r':  out << '\r'; break;
                case '"':  out << '"';  break;
                case '\\': out << '\\'; break;
                case '/':  out << '/';  break;
                case 'u':                 // \uXXXX：按码点写 UTF-8
                    if (p + 4 <= json.size()) {
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = json[p++];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= h - '0';
                            else if (h >= 'a' && h <= 'f') code |= h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') code |= h - 'A' + 10;
                        }
                        if (code < 0x80) out << static_cast<char>(code);
                        else if (code < 0x800) {
                            out << static_cast<char>(0xC0 | (code >> 6));
                            out << static_cast<char>(0x80 | (code & 0x3F));
                        } else {
                            out << static_cast<char>(0xE0 | (code >> 12));
                            out << static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                            out << static_cast<char>(0x80 | (code & 0x3F));
                        }
                    }
                    break;
                default: out << '\\' << e;
            }
        } else {
            out << c;
        }
    }
    return out.str();
}


static std::string agent_model() {
    const char* model = std::getenv("SOLVER_MODEL");
    return model ? model : "deepseek-chat";
}

// ---- token 记账（实验度量）----
static long g_prompt_tokens = 0;
static long g_completion_tokens = 0;
static long g_api_calls = 0;
static long g_prompt_hit = 0;
static long g_prompt_miss = 0;
long token_counter_add(long prompt, long completion,
                       long hit = 0, long miss = 0) {
    g_prompt_tokens += prompt;
    g_completion_tokens += completion;
    g_prompt_hit += hit;
    g_prompt_miss += miss;
    ++g_api_calls;
    return g_prompt_tokens;
}
TokenUsage token_usage_snapshot() {
    return TokenUsage{g_prompt_tokens, g_completion_tokens, g_api_calls,
                      g_prompt_hit, g_prompt_miss};
}
// 从响应 JSON 提取 "usage":{"prompt_tokens":N,...,"completion_tokens":M}
static void account_usage(const std::string& resp) {
    std::string::size_type p = resp.find("\"usage\"");
    if (p == std::string::npos) return;
    auto grab = [&](const char* key) -> long {
        std::string::size_type k = resp.find(key, p);
        if (k == std::string::npos) return 0;
        k = resp.find(':', k + strlen(key));
        if (k == std::string::npos) return 0;
        ++k;
        while (k < resp.size() &&
               (resp[k] == ' ' || resp[k] == '\t')) ++k;
        return atol(resp.c_str() + k);
    };
    long pt = grab("\"prompt_tokens\"");
    long ct = grab("\"completion_tokens\"");
    long hit = grab("\"prompt_cache_hit_tokens\"");
    long miss = grab("\"prompt_cache_miss_tokens\"");
    if (hit == 0 && miss == 0 && pt > 0) miss = pt;  // 无细分时按未命中计
    token_counter_add(pt, ct, hit, miss);
}

static std::string agent_url() {
    const char* base = std::getenv("SOLVER_BASE_URL");
    std::string url = base ? base : "https://api.deepseek.com/v1";
    while (!url.empty() && url.back() == '/') url.pop_back();
    return url + "/chat/completions";
}

// 载荷文件 -> 响应文本（空=失败）
static std::string curl_post(const std::string& payload_file) {
    const char* key = std::getenv("SOLVER_API_KEY");
    if (!key || !*key) return "";
    std::ostringstream cmd;
    cmd << "curl -sS --max-time 240 '" << agent_url() << "'"
        << " -H 'Authorization: Bearer " << key << "'"
        << " -H 'Content-Type: application/json'"
        << " --data-binary @" << payload_file << " 2>/tmp/ltlsolver-curl.err";
    FILE* p = popen(cmd.str().c_str(), "r");
    if (!p) return "";
    std::ostringstream out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) out.write(buf, n);
    pclose(p);
    return out.str();
}

static std::string json_escape_value(const std::string& s) {
    return json_escape(s);
}

std::string AgentLoop::complete(const std::string& system_prompt,
                                const std::string& user_prompt,
                                std::string* err) {
    if (!std::getenv("SOLVER_API_KEY")) {
        if (err) *err = "未设置 SOLVER_API_KEY";
        return "";
    }
    std::ostringstream payload;
    payload << "{\"model\":\"" << agent_model() << "\",\"messages\":["
            << "{\"role\":\"system\",\"content\":\""
            << json_escape(system_prompt) << "\"},"
            << "{\"role\":\"user\",\"content\":\""
            << json_escape(user_prompt) << "\"}],"
            << "\"max_tokens\":4096,\"temperature\":0.2}";
    const std::string tmp = "/tmp/ltlsolver-payload.json";
    {
        std::ofstream f(tmp, std::ios::trunc);
        f << payload.str();
    }
    std::string resp = curl_post(tmp);
    if (resp.empty()) {
        if (err) *err = "curl 调用失败（见 /tmp/ltlsolver-curl.err）";
        return "";
    }
    account_usage(resp);
    std::string content = extract_content(resp);
    if (content.empty()) {
        if (err) *err = "LLM 响应无 content：" + resp.substr(0, 400);
    }
    return content;
}

}  // namespace solver

// ============================================================ 工具调用循环

namespace solver {

// 从 choices[0].message 提取原始对象子串（花括号配平）
static std::string extract_message_object(const std::string& json) {
    std::string::size_type p = json.find("\"message\"");
    if (p == std::string::npos) return "";
    p = json.find('{', p);
    if (p == std::string::npos) return "";
    int depth = 0;
    bool in_str = false;
    for (std::string::size_type i = p; i < json.size(); ++i) {
        char c = json[i];
        if (in_str) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{') ++depth;
        else if (c == '}') {
            --depth;
            if (depth == 0) return json.substr(p, i - p + 1);
        }
    }
    return "";
}

// 提取 tool_calls 数组中的各调用：{id, name, arguments}
struct ParsedToolCall {
    std::string id, name, args;
};
// 从已截取的 tool_calls 原始数组文本解析各调用对象（字符串感知配平）。
// 注意：不能用 find(']') 做数组边界——arguments 里的正则类（如 "[0-9]+"）
// 会提前截断，导致解析数 < 回填数，API 以 "insufficient tool messages"
// 拒绝（2026-10-04 实测）。
static std::vector<ParsedToolCall> parse_tool_calls(const std::string& arr) {
    std::vector<ParsedToolCall> out;
    std::string::size_type i = 0;
    while (i < arr.size()) {
        std::string::size_type o = arr.find('{', i);
        if (o == std::string::npos) break;
        int depth = 0;
        bool in_str = false;
        std::string::size_type end = std::string::npos;
        for (std::string::size_type j = o; j < arr.size(); ++j) {
            char c = arr[j];
            if (in_str) {
                if (c == '\\') { ++j; continue; }
                if (c == '"') in_str = false;
                continue;
            }
            if (c == '"') in_str = true;
            else if (c == '{') ++depth;
            else if (c == '}') {
                --depth;
                if (depth == 0) { end = j; break; }
            }
        }
        if (end == std::string::npos) break;
        std::string obj = arr.substr(o, end - o + 1);
        ParsedToolCall tc;
        tc.id = jsonutil::get_string(obj, "id");
        tc.name = jsonutil::get_string(obj, "name");
        tc.args = jsonutil::get_string(obj, "arguments", "{}");
        if (!tc.name.empty()) out.push_back(tc);
        i = end + 1;
    }
    return out;
}
static std::vector<ParsedToolCall> extract_tool_calls(
        const std::string& message) {
    std::string::size_type p = message.find("\"tool_calls\"");
    if (p == std::string::npos) return {};
    p = message.find('[', p);
    if (p == std::string::npos) return {};
    int depth = 0;
    bool in_str = false;
    for (std::string::size_type j = p; j < message.size(); ++j) {
        char c = message[j];
        if (in_str) {
            if (c == '\\') { ++j; continue; }
            if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '[' || c == '{') ++depth;
        else if (c == ']' || c == '}') {
            --depth;
            if (depth == 0)
                return parse_tool_calls(
                    message.substr(p, j - p + 1));
        }
    }
    return {};
}

static std::string json_escape_value(const std::string& s);

std::string AgentLoop::run(const std::string& system_prompt,
                           const std::string& user_prompt,
                           const std::string& tools_json,
                           const ToolExecutor& executor,
                           std::string* err) {
    const char* mt = std::getenv("SOLVER_MAX_TURNS");
    int max_turns = mt ? std::max(1, atoi(mt)) : 16;

    // messages 逐条预序列化（assistant 原文回填保证协议正确）
    std::vector<std::string> messages;
    messages.push_back("{\"role\":\"system\",\"content\":\"" +
                       json_escape_value(system_prompt) + "\"}");
    messages.push_back("{\"role\":\"user\",\"content\":\"" +
                       json_escape_value(user_prompt) + "\"}");

    for (int turn = 0; turn < max_turns; ++turn) {
        std::ostringstream payload;
        payload << "{\"model\":\"" << agent_model() << "\",\"messages\":["
                << [&] {
                       std::string j;
                       for (size_t i = 0; i < messages.size(); ++i)
                           j += (i ? "," : "") + messages[i];
                       return j;
                   }()
                << "]";
        if (!tools_json.empty()) payload << ",\"tools\":" << tools_json;
        payload << ",\"max_tokens\":4096,\"temperature\":0.2}";
        const std::string tmp = "/tmp/ltlsolver-payload.json";
        {
            std::ofstream f(tmp, std::ios::trunc);
            f << payload.str();
        }
        std::string resp = curl_post(tmp);
        if (resp.empty()) {
            if (err) *err = "curl 调用失败（见 /tmp/ltlsolver-curl.err）";
            return "";
        }
        account_usage(resp);
        std::string msg = extract_message_object(resp);
        if (msg.empty()) {
            if (err) *err = "响应无 message 对象：" + resp.substr(0, 300);
            return "";
        }
        auto calls = extract_tool_calls(msg);
        if (calls.empty()) {
            // 最终回复：提取 content；缺 LOCUS 协议段时追逼一轮（不再给工具）
            std::string content = jsonutil::get_string(msg, "content");
            if (content.find("LOCUS_") == std::string::npos &&
                turn + 2 < max_turns) {
                messages.push_back(
                    "{\"role\":\"assistant\",\"content\":\"" +
                    json_escape_value(content) + "\"}");
                messages.push_back(
                    "{\"role\":\"user\",\"content\":\"上一回复缺少 "
                    "LOCUS 协议段。停止分析，立即严格按协议输出候选："
                    "LOCUS_SMT2 + LOCUS_SMT_LEN + LOCUS_SMT_MODEL，或退回 "
                    "LOCUS_WITNESS: bytes=<hex>。\"}");
                continue;
            }
            if (content.empty()) {
                if (err) *err = "最终回复无 content：" + msg.substr(0, 300);
            }
            return content;
        }
        // 回填 assistant 原始消息，执行工具，追加 tool 结果
        messages.push_back("{\"role\":\"assistant\",\"tool_calls\":" +
                           [&] {
                               // 从 msg 里取原始 tool_calls 数组文本
                               std::string::size_type p =
                                   msg.find("\"tool_calls\"");
                               p = msg.find('[', p);
                               int depth = 0;
                               bool in_str = false;
                               for (std::string::size_type j = p;
                                    j < msg.size(); ++j) {
                                   char c = msg[j];
                                   if (in_str) {
                                       if (c == '\\') { ++j; continue; }
                                       if (c == '"') in_str = false;
                                       continue;
                                   }
                                   if (c == '"') in_str = true;
                                   else if (c == '[' || c == '{') ++depth;
                                   else if (c == ']' || c == '}') {
                                       --depth;
                                       if (depth == 0)
                                           return msg.substr(p, j - p + 1);
                                   }
                               }
                               return std::string("[]");
                           }() +
                           "}");
        for (const auto& tc : calls) {
            std::string result;
            try {
                result = executor(tc.name, tc.args);
            } catch (std::exception& ex) {
                result = std::string("ERROR: ") + ex.what();
            }
            if (result.empty()) result = "（空结果）";
            if (result.size() > 6000)
                result = result.substr(0, 6000) + "\n...（截断）";
            result += "\n[工具轮 " + std::to_string(turn + 1) + "/" +
                      std::to_string(max_turns) +
                      "；剩余不足 3 轮时停止分析，按 LOCUS 协议输出候选]";
            messages.push_back("{\"role\":\"tool\",\"tool_call_id\":\"" +
                               tc.id + "\",\"content\":\"" +
                               json_escape_value(result) + "\"}");
        }
    }
    if (err) *err = "达到最大工具调用轮数（SOLVER_MAX_TURNS）";
    return "";
}

}  // namespace solver
