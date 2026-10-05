// AnalysisTools —— 智能体驱动的静态分析工具后端（ltl-locus
// tools/cpg.py + dominators.py 的 C++ 对齐移植）。
//
// 静态分析不是预处理步骤，而是智能体在求解循环中按需调用的工具：
//   cpg_backward_slice / cpg_def_use / cpg_literals  —— Joern CPG 查询
//     （CPG = AST+CFG+数据流+def-use 的统一索引）
//   dominator_conditions —— 文本级支配子必要条件（must_hold/
//     must_not_hold，构造性可靠，直接从 Python 版移植）
//   read_source / grep_source —— 源码阅读与检索
// 工具结果以文本回给智能体（论文风格：外部工具经子进程编排）。
#pragma once
#include <functional>
#include <string>

namespace solver {

class AnalysisTools {
public:
    AnalysisTools(std::string subject_dir, std::string src_root);

    // OpenAI 兼容 tools 数组（函数声明 + JSON schema）
    std::string tools_json() const;

    // 工具执行入口：name + 参数 JSON（如 {"file":"a.c","line":9}）
    // -> 结果文本（出错时 "ERROR: ..."，智能体可读并自纠）
    std::string dispatch(const std::string& name,
                         const std::string& args_json);

    // CPG 路径（惰性构建，内容哈希缓存；失败置空并记错误）
    std::string cpg_path();

private:
    std::string joern(const std::string& scala, const std::string& params);
    std::string backward_slice(const std::string& var,
                               const std::string& file, int line);
    std::string def_use(const std::string& var);
    std::string literals(const std::string& file, int from, int to);
    std::string dominators(const std::string& file, int line);
    std::string read_source(const std::string& file, int from, int to);
    std::string grep_source(const std::string& pattern);

    std::string subject_dir_;
    std::string src_root_;
    std::string cpg_path_;
    std::string cpg_error_;
};

// 供 AgentLoop 用的极简 JSON 字段提取
namespace jsonutil {
std::string get_string(const std::string& json, const std::string& key,
                       const std::string& def = "");
int get_int(const std::string& json, const std::string& key, int def = 0);
}

}  // namespace solver
