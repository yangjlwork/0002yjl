// AgentLoop —— 智能体驱动的求解循环（多轮工具调用，OpenAI 兼容
// function calling）。静态分析工具（CPG/支配子/源码阅读）由智能体
// 在推理中按需调用——分析是智能体驱动的，不是预处理。
// HTTPS 经 popen(curl)（本机无 curl/openssl 开发头文件；与论文大量
// system() 外部工具的代码风格一致）。
// 环境变量：SOLVER_BASE_URL / SOLVER_API_KEY / SOLVER_MODEL /
//           SOLVER_MAX_TURNS（默认 16）。
#pragma once
#include <functional>
#include <string>
#include <vector>

namespace solver {

// 工具执行回调：name + 参数 JSON -> 结果文本
using ToolExecutor =
    std::function<std::string(const std::string& name,
                              const std::string& args_json)>;

// token 记账（实验度量：检测运行时间 + token 消耗）。parse 自每次
// API 响应的 usage 字段，进程内累计；snapshot 取当前值算差分。
struct TokenUsage {
    long prompt_tokens = 0;
    long completion_tokens = 0;
    long api_calls = 0;
    long prompt_hit = 0;    // DeepSeek 缓存命中输入（计费口径）
    long prompt_miss = 0;   // 缓存未命中输入
};
long token_counter_add(long prompt, long completion);  // 累加并返回总值
TokenUsage token_usage_snapshot();

class AgentLoop {
public:
    // 单轮补全（无工具；兼容旧路径）
    static std::string complete(const std::string& system_prompt,
                                const std::string& user_prompt,
                                std::string* err = nullptr);

    // 智能体工具调用循环：模型可多次调用工具（静态分析等），框架
    // 执行并回填结果，直到给出最终文本或轮数上限。
    // 返回最终文本（失败为空，err 给原因）。
    static std::string run(const std::string& system_prompt,
                           const std::string& user_prompt,
                           const std::string& tools_json,
                           const ToolExecutor& executor,
                           std::string* err = nullptr);
};

}  // namespace solver
