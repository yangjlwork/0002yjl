# ltlfuzz-solver

LTL-Fuzzer（ICSE'22, Meng et al.）框架的**搜索引擎替换**实现：
框架、插桩、程序内 monitor、前缀池、调度全部论文原样（Apache 2.0，
源出 `原论文/LTL-Fuzzer-main`）；唯一替换——论文的 AFLGo 变异搜索
换成 **静态分析 + Z3 + LLM 智能体**（`src/solver/`），不用 fuzz。

## 与论文代码的差异清单（完整、且仅此而已）

| 位置 | 论文 | 本系统 | 原因 |
|---|---|---|---|
| `src/LTLFuzzer.cc` fuzz() OUTPUT 分支 | 前缀写 shmem + `system(afl-fuzz ...)` | 调 `solver::SolverEngine`（求解+执行） | 引擎替换点 |
| `src/AutomataHandler.cc` | — | 新增 `path_ahead()`（`find_paths` 封装） | 给引擎的引导信号（论文对应物=AFLGo 的 CFG 距离） |
| `src/instrumentation/pathwriter.cc` | 全局对象启动即 `open_only` 共享段 | 惰性打开（段存在时行为不变） | 论文协议模式下无驱动侧建段，原实现进程启动即崩 |
| `llvm-pass/PeEvents.cc` | AFLGo `afl-llvm-pass.so.cc` 的 `-pevents`（混在 AFL/distance pass 里） | 独立化，仅事件插桩 | AFLGo 删除后无覆盖反馈/距离需求 |
| `scripts/instrument-subject.sh` | 两遍编译（BBtargets→distance→pevents） | 单遍（opt-11 加载 PeEvents） | 同上 |
| `include/ltlfuzzer.h` | 含未使用的 `boost/process.hpp` | 删除该 include | boost process v2 需额外链接且未使用 |
| `src/solver/`（新增） | AFLGo | SolverEngine/AgentLoop/Z3Solver/SourceAnalyzer/Executor | 搜索引擎 |

`automata.cc`（spot translator + exclusive_ap + model_check_events）、
`CodeBean.cc`（monitor）、`PathStore/TargetsStore/RandomStrategy/
main/utils` 均论文原样。

## 构建

依赖：cmake、g++（C++17）、boost（仅头文件）、spot（本机
`~/spot` 或重编的 `~/spot-rebuild`）、z3（libz3-dev）、llvm-11（插桩
pass）、curl 命令行（LLM HTTPS）。

```
mkdir build && cd build && cmake .. && make -j4
# LLVM 插桩 pass：
cd ../llvm-pass && g++ -shared -fPIC -std=c++14 \
    $(llvm-config-11 --cxxflags | sed 's/-Wl[^ ]*//g') PeEvents.cc -o PeEvents.so
```

## 运行（论文同款三步）

```
export LTLFuzzer=~/ltlfuzz-solver/
export SUBJECT=~/ltlfuzz-solver/experiment/<目标>/     # 注意尾部斜杠（论文 CodeBean 拼接约定）
export EXECName=<二进制名>
export LTL='<¬φ 公式>'                                 # 论文存否定式
./scripts/instrument-subject.sh $SUBJECT/targets/targets.txt <源码树> $SUBJECT/build_dir
./build/src/ltlfuzz-solver 1                            # 1=协议，0=普通（论文同款）

# 引擎环境变量：
export SOLVER_BASE_URL=https://api.deepseek.com/v1     # OpenAI 兼容端点
export SOLVER_API_KEY=<key>
export SOLVER_MODEL=deepseek-chat
export SOLVER_TARGET_HOST=127.0.0.1 SOLVER_TARGET_PORT=8554   # 协议模式服务地址
export SOLVER_MAX_ATTEMPTS=8
```

## 运行时闭环（论文原样）

选前缀（PathStore，随机）→ select_event（AutomataHandler，偏好新
状态）→ getTarget（TargetsStore，事件→插桩二进制）→ **【替换点】
SolverEngine：上下文（前缀/事件/剩余路径/锚点源码窗口/字典/种子/
反馈）→ 智能体 LOCUS 协议（SMT2+映射）→ Z3 求解拼装字节 → Executor
执行** → 程序内 monitor（CodeBean：proposition_handler →
model_check_events → check_acceptance；接受即抛 "a counterexample!"）
→ 前缀池回写（协议模式 `prefix/<路径>` 文件，RERS 模式 boost shmem）
→ 循环至 24h 预算或反例。反例存 `output_folder/crashes/`。

## 插桩产物（论文同款布局）

每个 `file:line` 一个 `build_dir/<file:line>/` 插桩构建；事件行插
`proposition_handler("<事件>") + evaluate_trace(1)`，main 各 return 前
插 `evaluate_trace(0)`（RERS 态）；编译经 `clang -S -emit-llvm -g →
opt-11 -load PeEvents.so -pevents-instr -pevents=<targets.txt> → clang
-c`（clang 插件直载在本机 clang 11 会崩，故走 opt 离线路线）。

## 语义要点（与论文机制绑定）

- **行位置即谓词**：targets.txt 无谓词列，探针无条件插在匹配行。
- **exclusive 语义**：全部事件单一互斥组（all_events.txt），同一步
  两正命题结构性不可能；合取前件折叠为单事件（论文 PrF4 做法）。
- **safety 判定**：monitor 见轨迹到达 ¬φ 接受态即抛
  "a counterexample!"（论文 §2.2）。
- **$SUBJECT 必须带尾部斜杠**（CodeBean 字符串拼接无分隔符，
  论文 README 同款约定）。
