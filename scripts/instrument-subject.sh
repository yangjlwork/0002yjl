#!/bin/bash
# instrument-subject.sh —— 插桩脚本（论文 instrument-<subject>.sh 的同构版）。
#
# 论文对应物（instrument-telnet.sh）：
#   - 逐行读 targets.txt（file:line:event），每个位置一个 build_dir/<file:line>/，
#     整树拷贝、单独构建——AFLGo 定向调度以目标位置为中心，驱动选中哪个事件
#     就跑哪个 build 的二进制（LTLFuzzer.cc:264）；
#   - 差异（搜索引擎替换的连带，无行为影响）：无 BBtargets/distance 两遍编译
#     （AFLGo 的 CFG 距离只服务变异调度；本引擎引导 = path_ahead）。
#
# monitor 链接机制（论文同款）：proposition_handler/state_handler/evaluate_trace
# 符号定义在 src/instrumentation/（Instrument/CodeBean/pathwriter），由目标构建
# 链接进二进制。实现方式 = cc-shim（automake 用同一 CC 编译与链接）：
#   编译（含 -c）→ 离线三段：clang -O0 -emit-llvm 出 bc → opt-11 装载
#     PeEvents 插桩 → clang -c bc 出 .o（clang 直接 -Xclang -load 在本机
#     clang-11 前端段错误，mini 阶段已定位，故走 opt-11 离线路线；
#     保持 -O0：插桩先于优化，行号忠实）
#   链接 → 附加 libinstrumentation+libautomata+spot（置于对象之后；
#     monitor 为 C++ 代码，补 -lstdc++）
#
# 用法（论文同款三参数）：
#   LTLFuzzer=<ltlfuzz-solver 根> EXECName=<产物二进制名> \
#     [SUBJECT_CONFIGURE_FLAGS="--with-quotas --without-tls"] \
#     ./instrument-subject.sh <Targets_file> <Prj_dir> <Build_dir>
# 三类目标：autotools（有 configure，先 configure 再 make）／Makefile 型／单文件型。
# 环境变量 SPOT_DIR 可覆盖 spot 库目录（默认 ~/spot-rebuild/lib）。

set -e

if [ "$#" -ne 3 ]; then
    echo "Usage: ./instrument-subject.sh Targets_file Prj_dir Build_dir" >&2
    exit 1
fi

Targets_file=$1
Prj_dir=$2
Build_dir=$3
ROOT=${LTLFuzzer:?请 export LTLFuzzer=<ltlfuzz-solver 根目录>}
EXEC=${EXECName:-a.out}

PASS=$ROOT/llvm-pass/PeEvents.so
PAPER_PASS=$HOME/ltlfuzz-agent/原论文/LTL-Fuzzer-main/AFLGo/afl-llvm-pass.so
PAPER_RT=$HOME/ltlfuzz-agent/原论文/LTL-Fuzzer-main/AFLGo/afl-llvm-rt.o
[ -f "$PAPER_PASS" ] || { echo "缺论文 pass：$PAPER_PASS" >&2; exit 1; }
[ -f "$PAPER_RT" ] || { echo "缺论文 runtime：$PAPER_RT" >&2; exit 1; }
INSTR_LIB=$ROOT/build/src/instrumentation/libinstrumentation.a
ATM_LIB=$ROOT/build/src/automata/libautomata.a
SPOT_LIBDIR=${SPOT_DIR:-$HOME/spot-rebuild}/lib
for f in "$PASS" "$INSTR_LIB" "$ATM_LIB"; do
    [ -f "$f" ] || { echo "缺 $f（先 cmake --build build）" >&2; exit 1; }
done
[ -d "$SPOT_LIBDIR" ] || { echo "缺 spot 库目录 $SPOT_LIBDIR" >&2; exit 1; }
Targets_file=$(realpath "$Targets_file")

SHIM=$(mktemp /tmp/pevents-cc-shim.XXXXXX.sh)
trap 'rm -f "$SHIM"' EXIT
cat > "$SHIM" <<EOF
#!/bin/bash
src=""
prev=""
for a in "\$@"; do
    case "\$a" in
        *.c|*.cc|*.cpp|*.C) [ -z "\$src" ] && src="\$a" ;;
    esac
    prev="\$a"
done
if [ -z "\$src" ]; then
    exec g++ -fexceptions "\$@" "$PAPER_RT" \
         $INSTR_LIB $ATM_LIB -L$SPOT_LIBDIR -Wl,-rpath,$SPOT_LIBDIR \
         -lspot -lbddx -lpthread
fi
cxx=clang-11
case "\$src" in *.cc|*.cpp|*.C) cxx=clang++-11 ;; esac
# 论文插桩器：-Xclang -load 论文 pass；-distance 占位文件
# 激活插桩分支（论文 pass 要求 targets/distance 之一；距离值
# 仅服务 AFLGo 变异调度，本引擎不消费，即丢掉多余产物）
printf 'safe_rw.c:12,0\n' > /tmp/pevents-placeholder-dist.cfg
"\$cxx" -Xclang -load -Xclang "$PAPER_PASS" \
    -mllvm -distance=/tmp/pevents-placeholder-dist.cfg \
    -mllvm -pevents="$Targets_file" "\$@" -O0
rm -rf "\$tmp"
EOF
chmod +x "$SHIM"

CFL="-g -O1 -fexceptions"

mkdir -p "$Build_dir"
cd "$Build_dir"
while IFS= read -r raw_line; do
    line=$(echo "$raw_line" | sed 's/[[:space:]]*$//')
    [ -z "$line" ] && continue
    fileName=$(echo "$line" | cut -d: -f1)
    lineNum=$(echo "$line" | cut -d: -f2)
    loc="$fileName:$lineNum"
    [ -d "$loc" ] && rm -rf "$loc"
    mkdir -p "$loc"
    Binary_DIR=$(realpath "$loc")
    (cd "$Binary_DIR" && cp -r "$Prj_dir"/. .)

    (
        cd "$Binary_DIR"
        if [ -x ./configure ]; then
            ./configure $SUBJECT_CONFIGURE_FLAGS CC=clang-11 CFLAGS="$CFL" \
                >/dev/null 2>&1 || { echo "configure 失败（$loc）" >&2; exit 1; }
            # 论文 ⟨l,p,c_p⟩ 的 c_p 目标侧文件：pevents-cond/*.c 用该行
            # 构建目录的 config.h 与 include 路径编译，经 shim 链入目标
            for cf in "$Prj_dir"/../pevents-cond/*.c; do
                [ -f "$cf" ] || continue
                clang-11 -O0 -g -fexceptions -c "$cf" \
                    -I. -I.. -I./src \
                    -o "/tmp/pevents-cond.$(basename "$cf" .c).o" \
                    || { echo "cond 编译失败：$cf" >&2; exit 1; }
            done
            make CC="$SHIM" CXX="$SHIM" -j4 >/dev/null
        elif [ -f Makefile ] || [ -f makefile ]; then
            make clean >/dev/null 2>&1 || true
            make -j4 CC="$SHIM" CXX="$SHIM" >/dev/null
        else
            SRC=$( (ls *.c 2>/dev/null; ls *.cc *.cpp 2>/dev/null) || true)
            [ -z "$SRC" ] && { echo "无 configure/Makefile/源文件（$loc）" >&2; exit 1; }
            objs=""
            for s in $SRC; do
                "$SHIM" $CFL -c "$s" -o "${s%.*}.o" && objs="$objs ${s%.*}.o"
            done
            # shellcheck disable=SC2086
            [ -n "$objs" ] && "$SHIM" $objs -o "$EXEC"
        fi
    )

    BIN=$(find "$Binary_DIR" -name "$EXEC" -type f -perm -u+x | head -1)
    [ -n "$BIN" ] || { echo "构建后未找到 $EXEC（$loc）" >&2; exit 1; }
    echo "[instrumented] $loc -> $BIN"
done < "$Targets_file"
