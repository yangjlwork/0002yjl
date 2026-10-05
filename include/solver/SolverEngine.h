// SolverEngine —— 搜索引擎（替换论文的 AFLGo，2026-10-04 定稿）。
// 论文框架里 fuzz() 的 OUTPUT 分支原为：前缀写共享内存 + system(afl-fuzz)。
// 此处替换为：组装求解上下文（前缀/目标事件/转移/源码锚点/字典/种子/
// 反馈历史）-> 智能体（静态分析+Z3）产出候选后缀 -> 执行 -> 反馈迭代。
// 其余一切（自动机/monitor/前缀池/调度）保持论文原样。
#pragma once
#include <string>
#include <vector>

namespace solver {

struct SolveContext {
    int flag = 1;                          // 0 普通程序；1 网络协议（论文同款）
    std::string prefix;                    // PathStore 选中的前缀 token
    std::string last_state;                // 自动机当前状态
    std::string target_event;              // AutomataHandler::select_event 结果
    std::string target_loc;                // TargetsStore 目标（file:line）
    std::string exec_name;
    std::vector<std::string> loop_events;      // witness_spec：接受态自环正事件
    std::vector<std::string> forbidden_events; // witness_spec：自环取反事件
    bool witness_loop = false;                 // witness_spec：目标事件在接受态自环上                 // $EXECName
    std::string subject_dir;               // $SUBJECT
    std::string formula;                   // $LTL（原式）
    std::vector<std::string> path_ahead;   // 到接受态的剩余事件序列（find_paths）
};

struct SolveResult {
    bool counterexample = false;           // monitor 报 "a counterexample!"
    bool advanced = false;                 // 目标事件在本次执行中触发
    std::string best_input_hex;
    std::string report;
};

class SolverEngine {
public:
    static SolverEngine* instance();
    SolveResult run(const SolveContext& ctx);

private:
    SolverEngine() = default;
    static SolverEngine* s_instance;
};

}  // namespace solver
