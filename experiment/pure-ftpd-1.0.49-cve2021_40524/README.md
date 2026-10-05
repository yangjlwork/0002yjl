# Pure-FTPd 1.0.49 — CVE-2021-40524（论文 Table 6 #48 / PuF5，§2.1 running example）

业务规则：If user directory size is larger than the set quota when the quota
mechanism is activated, must finally reply that the quota is exceeded.

性质 φ（Table 6 原式，否定内推写法）：
  ¬F((quota_activated = true) ∧ F((user_dir_size > user_quota) ∧ G(¬(msg_quota_exceeded = true))))

ltl_dir/ltl.txt 存 **¬φ**（论文约定：CodeBean 直接 spot::translator，接受即反例；
论文 §2.2 原文亦写明 "the negation of φ is F(a ∧ F(o ∧ G¬n))"）：
  F(a & F(o & G!n)):a,o,n,l
  （a=quota_activated, o=user_dir_size>user_quota, n=msg_quota_exceeded, l=loop_entry，
   命名照论文 Table 1；l 不在公式 AP 中，作用同 testTelnet 的 Overflow——为 G¬n 提供步进 tick）

## 版本依据

CVE-2021-40524：NVD "In Pure-FTPd **before 1.0.50**, an incorrect max_filesize
quota mechanism ... upload files of unbounded size"——上报版本 1.0.49，修复 1.0.50。
src/ = github.com/jedisct1/pure-ftpd tag 1.0.49（tarball 内层 src/ 已拍平到本目录根，
行号即此坐标系）。

## 事件表标定：论文 Table 1（+Listing 1–4 语义）→ 1.0.49 行号

前置事实：Table 1 的行号（6072/4444/3481/4067/safe_rw 12,43）属论文作者的私有树——
上游 1205 个提交全扫描，[3481,4444] 组合与 safe_read@43 均从未出现（1.0.47 tag 最近：
[3490,4430,41]；1.0.49=[3441,4377,12,41]）。故按论文 Listing 1–4 给出的**语义指纹**
在 1.0.49 重新落位。逐行对照（左=论文 Listing 原文，右=1.0.49 实际行）：

| 事件 | 论文依据（Listing 语义） | 1.0.49 落位 | 到达即谓词成立的证据 |
|---|---|---|---|
| a | L1：`#ifdef QUOTAS / case 'n': { ... user_quota_size *= (1024ULL*1024ULL);`（6072），`if(1)` | **ftpd.c:5943** | main() getopt `-n files:MB` 选项体（5935 `case 'n'` sscanf 配额；5943 `*= 1024*1024`），执行到 = 服务器以 -n 启动 = 配额机制激活；standalone 父进程启动时 fire，fork 出的会话子进程继承该事件轨迹 |
| o | L2：`safe_write` 入口（12 行），条件 `if(user_dir_size > user_quota)` | **safe_rw.c:12** | 1.0.49 与论文树**精确同行**：`12 safe_write(const int fd, ...`（Listing 2 原文）。safe_write 是全部 socket 写（含控制通道回复）的通用泵 |
| o | 同上（读泵 safe_read，论文 43 行） | **safe_rw.c:41** | 论文树的 43 在 1.0.49 对应 **41**（`41 safe_read(const int fd, ...`，2 行漂移）；safe_read 同为控制/数据两通道通用读泵 |
| n | L3：`afterquota: if (overflow>0) addreply(552, MSG_QUOTA_EXCEEDED, name);`（4444），`if(1)` | **ftpd.c:4377** | 上传完成路径，逐字同名调用 |
| n | Table 1 另一行（3481） | **ftpd.c:3441** | domkd()：`addreply(552, MSG_QUOTA_EXCEEDED, name)` |
| l | L4：`for (;;) {`（4066）体首行，`if(1)`；Table 1 标 "..."（多个循环入口，略） | **ftpd.c:4896** | doit()（4856）会话命令分发循环——每条命令一个 tick；违反上传后下一条命令触发 l + record_state，观察程序状态重复 → 反例（论文 "... "略去的其余循环入口可按需增补） |

**行格式证据**：论文自带 experiment/testTelnet/targets/targets.txt 为三段式
`telnetd.c:336:WILLDISABLED`——无谓词列，实现层面即"位置即谓词"（Table 1 的
条件列是概念层，c_p 由选行折叠实现）。

**单通道决策记录（2026-10-04，按论文路线）**：输入仅控制通道单流（论文
network_link 单 tcp 端点 + AFLGo -N 单流注入，无任何数据通道机制；其 FTP
事件选点在通用 I/O 泵，配额状态由环境预置消解谓词条件）。

**o 行照抄论文字面的依据与已知约束**：
- 论文 Table 1 的 o 即 I/O 泵入口两行（Listing 2 带 `if(user_dir_size > user_quota)`
  条件），本表逐行对应（12 精确命中；43→41 为 1.0.49 坐标换算）。
- 已知公开缺口：实现层 targets.txt 无谓词列（testTelnet 实物三段式）且 pass
  无条件插桩——泵入口探针在任何 I/O 动作即 fire。论文的消解方式 = 环境
  预置超配额（跑的会话始终处于 user_dir_size > user_quota 成立的状态，
  fire 即真），本目标运行时同样预置，行为与论文一致；未预置的普通会话
  理论上会误报，不在运行设计内。
- 备选折叠方案（留档，未采用）：o = ftpd.c:4256（do_stor 4248-4255 预检查
  分支体）/ ftpd.c:1216（doallo 1212-1215 比较分支体）——"到达即谓词成立"
  的精确折叠，不依赖环境预置；若运行阶段论文字面行验证受挫可切换。

折叠说明：Listing 2 的 o 带真条件 `user_dir_size > user_quota`（表 1 谓词列），
本实现 targets.txt 无谓词列（行位置即谓词、探针无条件插入，afl-llvm-pass 语义），
故折叠为"比较成立才可达"的分支体（4256/3687）——与 PrF4 复合事件折叠同一做法。
若按 Table 1 字面行取 safe_rw.c:12/41（safe_write/safe_read 入口），无条件探针会在
任何数据泵动作时误报 o，故不取；此差异为论文"谓词级表→实现级表"的已知公开缺口。

违反轨迹（预期）：a(5943，-n 启动) → o(4256/3687，超配额) → n 不发生（缺陷：
无 552 回复）→ l(4896) tick 至程序状态重复 → "a counterexample!"。

## 目录（协议模式，LTLFuzzer.cc else 分支）

- all_event_dir/all_events.txt：a o n l（裸事件名，加载器逐行取首 token，勿加注释）
- targets/targets.txt：`文件:行:事件` × 6（上表）
- telnet.dict：FTP token（论文协议模式硬编码此文件名，LTLFuzzer.cc:101）
- input_folder/：FTP 控制通道 CRLF 种子（input / input-allo / input-appe）
- ltl_dir/ltl.txt：`F(a & F(o & G!n)):a,o,n,l`
- src/：pure-ftpd 1.0.49 源码
- build_dir/<file:line>/、output_folder/、prefix/：插桩与运行产物（本次未生成）

## 运行环境变量（暂不运行，仅备案）

    export SUBJECT=<本目录绝对路径>/     # 尾斜杠必须（CodeBean 字符串拼接无分隔符）
    export EXECName=pure-ftpd
    export LTL='F(a & F(o & G!n))'      # ¬φ

## 插桩构建（2026-10-04 实测通过的完整配方）

    # 0) src/ 树一次性准备（已做，换树才需要）：
    #    configure.ac 首行 dnl AM_ACLOCAL_INCLUDE(m4) 改为
    #    AC_CONFIG_MACRO_DIRS([m4])（否则 autoreconf 不扫 m4/，AX_* 宏不展开）
    #    然后 autoreconf -i 生成 configure / src/Makefile.in
    # 1) 插桩构建（6 行 targets = 6 个 build_dir/<file:line>/）：
    LTLFuzzer=~/ltlfuzz-solver EXECName=pure-ftpd \
      SUBJECT_CONFIGURE_FLAGS="--with-quotas --without-tls --with-puredb" \
      ~/ltlfuzz-solver/scripts/instrument-subject.sh \
      $PWD/targets/targets.txt $PWD/src $PWD/build_dir

- `--with-quotas`：否则全部 QUOTAS ifdef 块不编译，a/o/n 事件全灭；
- `--with-puredb`：默认不开！不开则 auth_list 无 puredb 项，`-l puredb:` 启动即
  "421 Unknown authentication method" 退出（exit 252）——无 root 环境用虚拟用户
  （uid=当前用户）全靠它；
- `--without-tls`：免 OpenSSL 依赖；
- cc-shim：编译走 clang -O0 -emit-llvm → opt-11 装载 PeEvents → clang -c bc
  （clang 直接 -Xclang -load 本机前端段错误，mini 阶段定位的已知问题）；
  链接走 g++ 附加 monitor 三库（clang-11/clang++-11 在本机找不到 libstdc++.so）。

## 部署（2026-10-04 实测）

    # 虚拟用户（无 root）：home + 预置超配额（.ftpquota 格式 "<files> <size>\n"，
    # 写侧 quotas.c:113 顺序 files 在前）
    mkdir -p /tmp/pftpd-home /tmp/pftpd-pw
    printf '20 2000000\n' > /tmp/pftpd-home/.ftpquota          # 20 文件/2MB 已超 -n 10:1
    printf 'qu0ta!\nqu0ta!\n' | pure-pw useradd quotauser -u $(id -u) -g $(id -g) \
        -d /tmp/pftpd-home -f /tmp/pftpd-pw/passwd
    pure-pw mkdb /tmp/pftpd-pw/puredb.pdb -f /tmp/pftpd-pw/passwd
    # 服务器（高位端口免 root；SUBJECT 尾斜杠 + prefix/ 目录给 monitor）
    SUBJECT=<本目录>/ <build_dir>/ftpd.c:5943/src/pure-ftpd \
      -S 127.0.0.1,2121 -n 10:1 -l puredb:/tmp/pftpd-pw/puredb.pdb -p 30000:30010

启动即见 `prop: a`（5943 的 -n 选项事件）；会话中 l=每命令一步（4896）、
o=每次回复写（safe_rw.c:12，预置超配额下 fire 即真）、n=552 MSG_QUOTA_EXCEEDED。

## 连通验证实测（2026-10-04，全部通过）
    会话：banner → USER/PASS（230，"20 files used (200%)"）→ PWD →
          ALLO 999999999（552 Disk full = MSG_NO_DISK_SPACE，非 n 位点）→ NOOP…
    monitor 轨迹：prop: a（启动）→ prop: o（每次回复）→ aPath: 1,2,
    （自动机 0→1→2，2 = ¬φ 的接受态）→ "last state: 2" 反复（record_state
    观察程序状态重复）→ terminate ... what(): a counterexample!
    ——论文机制全链路在真实 CVE 目标上跑通：到达接受态 + 状态重复 + 无 n → 反例。

## 三件套生产者地位修正（2026-10-05 04:12 版）

03:49 版的 5s/0-token 结果存在命题问题：反例由引擎自主探针表征+组装
找到，三件套（静态分析+求解器+智能体）未参与。修正：
- 删除引擎自主表征——KB 只能由智能体产出（LOCUS_KB 协议段入库）；
- 新增 probe_input 工具 = 智能体的实验仪器（注入字节回收观测），
  执行观测从"绕过智能体的路径"变为"智能体的工具"；
- 组装层 = 复用智能体已推导的知识（缓存执行）。

验证（04:12 版）：反例由智能体自身找到——campaign_s=220，
CE 任务 82.7s / 0.89M tokens / 72 api_calls；发现后摊销显现：
后续任务 5-9s / 14-26k tokens。待办：LOCUS_KB 入库未触发（指令在
系统提示里被忽略，需移入任务上下文），触发后组装层接管常规任务。

## 纯范式严格模式：三目标会师（2026-10-05 03:49 修复版）

理论（锁定）：搜索 = 推导知识库 + 演绎组装 + L1 按需推导 + 观测校验；
零漏洞知识、无变异算子。修复三处推导层正确性 bug 后实测：

    KB（种子表征，4 秒，零 token）：
      SKELETON = "USER quotauser\r\n"        （最短合格前缀=最小已建立状态）
      CLEAN    = PASS / TYPE I / PASV        （可重复、不触发禁止事件）
      FORBID   = STOR big.bin（触发 n，观测归因）/ QUIT（保守归因）
    首个反例：campaign_s=5，ASSEMBLY_COUNTEREXAMPLE，task_s=0.5s
              tokens=0，api_calls=0（全程未调 LLM）
    见证 = 骨架 + 洁净行 × k（k 与禁止集来自自动机/monitor 语义推导）

版本对比（Pure-FTPd 1.0.49 / CVE-2021-40524，同环境同目标）：

| 版本 | 到首例 | tokens | 知识边界 |
|---|---|---|---|
| 手写提示 | 75s | 1.03M | 提示含 NOOP/STOR/QUIT（人工调参） |
| 纯智能体 | >1869s 未收敛 | 21M | 零知识但无组装层 |
| 纯智能体+推导引导 | 269s | 3.09M | 零知识（CE=登录+TYPE I×3 自推导） |
| **纯范式（本版）** | **5s** | **0** | 零知识，演绎组装直出 |
| 论文 AFLGo | ~2h 级 campaign | —（CPU） | 零知识（变异） |

修复明细（本轮三处，均通用）：
1. Automata 新增公开 is_state_accepting（内部同 automata.cc:341 调用）；
2. witness_spec：当前态自身接受优先（get_state_paths 只查后继且
   get_state_set 跳自环——自身接受态返回空是表征 bug 根因）；
3. 表征选最短合格前缀为骨架（最小已建立状态），其后行作可复用动作。

## 干净全量重跑度量（2026-10-05，无缓存，官方价计费）

清缓存项：Joern CPG（subject/.cpg-cache）、前缀池、引擎会话记忆（重启）、
旧 crashes/stats（归档 prev-run-20261005/）；插桩二进制保留（campaign 前
的环境准备，同论文口径）。计时口径：驱动启动 → 首个反例。

- 服务器启动：2026-10-05T01:21:44Z；campaign 启动：01:21:44Z
- **首个反例：campaign_s=75（01:22:58Z，crashes/input-20261005-012258）**
- 该轮任务：event=l @ ftpd.c:4896，task_s=51.4s，api_calls=48
- token（至首个反例，DeepSeek 官方计费口径）：
  缓存命中输入 942,336 / 未命中输入 76,250 / 输出 6,880（合计 1,025,466）
- **价格（deepseek-flash，官方 2026-10 价目，本跑为周日=非峰段）**：
  命中 $0.003/M、未命中 $0.15/M、输出 $0.60/M
  → **首个反例成本 = $0.0184（约 ¥0.13）**；若峰时 $0.0368
- 若计至手动停机（459s，驱动在反例后继续运行）：5,966,001 tokens，
  成本 $0.1114（约 ¥0.79）；共落 13 个反例文件
- 注（2026-10-05 更正）：驱动检出后继续运行【与论文一致】——论文原版
  fuzz 循环只认时间预算、不停机（OUTPUT 分支 system() 后仅 break 选择层，
  is_counterexample 检查在预算跑完后的收尾重放里）。liveness 违反对每个
  进入接受态循环的会话都成立，见证随运行积累（crashes/input-<ts> 逐个
  append），同论文 save_input 行为。"到首个反例"为对比实验的检出效率口径。

## 端到端反例闭环（2026-10-05 达成）

最后一轮 campaign（修复"会话 base 内嵌 QUIT 截断"后）完整闭合：

    [solver] 反例已保存: output_folder/crashes/input-20261005-011317
             (36B, hex=4e4f4f500d0a… = "NOOP\r\n"×6 —— 见证后缀；
              完整见证输入 = 引擎会话 base（登录）+ 此后缀)
    [stats] event=l loc=ftpd.c:4896 outcome=COUNTEREXAMPLE
            task_s=21.7 tokens_prompt=295701 tokens_completion=2351 api_calls=25
    驱动打印: there is a counterexample!   ← 论文标志性输出

链路：驱动(论文原样 fuzz 循环) → SolverEngine(智能体+Joern+Z3 求解输入) →
Executor(burst 注入) → 程序内 monitor(论文原样 CodeBean)：a→o→接受态 2 →
NOOP 连发使程序状态原地重复 → throw "a counterexample!" → 引擎回收文本 →
存 crashes/ → 驱动 break。共找到两个反例（011317、011510）。

关键修复（引擎侧，均有论文机制对应物）：
1. 会话前缀棘轮（session_base，按单会话事件数择优）= AFL 语料演化的等价物
   （协议模式前缀池不带字节，CodeBean.cc:175）；
2. 见证会话禁内嵌会话终止命令（QUIT 截断后续字节）——对应 AFL 变异天然
   破坏终止命令 + 覆盖反馈奖励完整会话；
3. liveness 见证提示：接受态自环事件需同会话连续触发≥3 次、禁触发公式
   否定的事件（n）、重复用可多次执行的中性命令；
4. Executor 的 SOLVER_TARGET_LOG 尾读（按发送前后偏移）= AFLGo -N 托管
   目标并回收 stdout 的等价物；
5. 计时+token 记账：AgentLoop 累计 usage，SolverEngine 每任务落
   output_folder/solver-stats.log（task_s / tokens_prompt / tokens_completion /
   api_calls / campaign_s / tokens_total）。

实测度量（2026-10-05 成功轮）：反例出现在 campaign_s=43s，
该任务 21.7s / 295,701 prompt tokens / 2,351 completion tokens / 25 次 API 调用。

## 插桩 pass 修复记录（2026-10-04，PeEvents.cc）

1. **-O0 必须为最后一个 -O 旗标**（shim 曾把它放在 CFLAGS 的 -O1 之前，
   实际按 -O1 编译 → mem2reg 改变 DebugLoc 归属 → safe_rw.c:12/41、
   3441、4896 全部匹配不上）；
2. **状态数组锚点 = 入口块最后一个 alloca 之后**（getFirstInsertionPt 只跳过
   开头连续 alloca，而 -O0 的 alloca 与 dbg.declare 交错 → 填充代码插到
   部分 alloca 之前 → use-before-def，opt verifier 中止）；
3. **行匹配改为论文同款"块内任一指令命中"**（afl-llvm-pass :349-368 逐指令
   比对；原先只取块首 DebugLoc，3441/4896 因块首落在同行前一条语句而漏插）；
4. **幂等标记** `_PeEvents_instrumented`（显式 -pevents-instr 与 EP 回调
   可能双跑导致重复插桩）。
   论文侧不存在 1/2/4：afl-clang-fast 编译器包装器单趟处理旗标、
   state_handler 用全局地址常量表（链接期常量无支配性问题）、pass 单次进管线。
