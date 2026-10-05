// SourceAnalyzer —— 静态分析上下文（锚点邻域源码窗口）。
// 论文等价物：AFLGo 拿 CFG 距离作引导信号；本引擎拿"谓词成立位置的
// 源码邻域"作引导信号——信息来源同为公开事实（源码 + 事件表）。
#pragma once
#include <string>
#include <vector>

namespace solver {

struct AnchorInfo {
    std::string file;
    int line = 0;
    std::string event;
    std::string anchor_line;   // 锚点行原文（行位置即谓词，论文 targets.txt）
    std::string window;        // 锚点 ±12 行（带行号），供智能体读控制流
};

class SourceAnalyzer {
public:
    // 解析 SUBJECT 下 targets.txt（targets/ 或 target/，论文两种布局），
    // 取指定事件的全部锚点及其源码窗口。源码根依次尝试：
    // SUBJECT/src、SUBJECT 本身、按文件名在树内唯一匹配。
    static std::vector<AnchorInfo> anchors_for(const std::string& subject_dir,
                                               const std::string& event);
};

}  // namespace solver
