// Executor —— 候选执行（论文 AFL 网络代理 / fork-server 的等价物）。
// 协议模式：TCP 注入（SOLVER_TARGET_HOST/SOLVER_TARGET_PORT，默认
// 127.0.0.1:8554），发送 prefix+suffix，读响应与服务输出；
// 普通模式：候选写临时文件，直接运行 build_dir/<loc>/ 下插桩二进制
// （论文 replace_prefix_run_program 同款方式）。
// 轨迹判定在【程序内 monitor】（CodeBean，论文原样）——Executor 只负责
// 喂字节和回收文本；prop: 行解析仅用于给智能体的反馈。
#pragma once
#include <string>
#include <vector>

namespace solver {

struct ExecResult {
    bool ok = false;
    std::string output;                  // 服务/程序原始输出（含 prop: 行）
    std::vector<std::string> events;     // 从 prop: 行解析的事件序列
    std::string detail;
};

class Executor {
public:
    static ExecResult run(const std::string& subject_dir,
                          const std::string& target_loc,
                          const std::string& exec_name,
                          int flag,
                          const std::string& bytes);

    // 前缀 token -> 字节：全为 {数字,} 形态按字节值表解析（论文
    // write_to_shmem_protocol 的前缀编码），否则按原文字节。
    static std::string prefix_to_bytes(const std::string& token);
};

}  // namespace solver
