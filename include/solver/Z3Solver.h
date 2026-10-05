// Z3Solver —— SMT2 字符串 -> sat/unsat + model（z3++ 原生 API）。
// 约束系统由智能体按 LOCUS 协议产出；字节按 LOCUS_SMT_MODEL 的
// 偏移->常量映射从 model 程序化拼装（手抄字节从机制上消灭，
// 与 Python 参考实现 bridge.py 的主路径同语义）。
#pragma once
#include <map>
#include <string>

namespace solver {

struct SmtResult {
    std::string status;                       // sat | unsat | unknown | error
    std::map<std::string, std::string> model; // 常量名 -> 值（十进制或 #x..）
    std::string detail;
};

class Z3Solver {
public:
    static SmtResult solve(const std::string& smt2);
};

}  // namespace solver
