// PeEvents —— 事件插桩 LLVM pass（论文 AFLGo/llvm_mode/afl-llvm-pass.so.cc
// 的 -pevents 部分的独立化；去掉 AFL coverage 与 distance——搜索引擎已
// 换为 SolverEngine，不再需要覆盖反馈与 CFG 距离）。
//
// 在匹配 (文件:行) 的基本块入口插入（论文三件套中保留两件，
// record_state 的变量向量记录见 TODO-v2）：
//   proposition_handler("<事件名>");
//   evaluate_trace(1);
// 并在 main 的每个 return 前插入 evaluate_trace(0)（论文 RERS 同款）。
//
// 编译：clang++ -shared -fPIC -std=c++14 $(llvm-config-11 --cxxflags) \
//            PeEvents.cc -o PeEvents.so
// 用法：clang -Xclang -load -Xclang ./PeEvents.so -mllvm -pevents=<targets.txt> -g ...
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Pass.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include <cstdio>
#include <fstream>
#include <map>
#include <string>

using namespace llvm;

namespace {

cl::opt<std::string> PEventsFile(
    "pevents",
    cl::desc("Event file: locations of events (file:line:event per line)"),
    cl::value_desc("pevents"));


// 论文 record_state 机制（afl-llvm-pass :586-592 storeGlobalVariables/
// printGlobalVariables/state_handler）：把可记录全局变量的地址与
// 大小编成常量数组，事件点调用 state_handler -> collect_state 哈希
// 入 state_vector。liveness 环见证（接受态 + 同一程序状态重现）依赖
// 此数据；缺省记录全局（定长标量/指针/小数组），局部变量 v2 补。
static void insertEventSite(Module& M, BasicBlock& B, Function& F,
                            const std::string& loc, const std::string& evt,
                            FunctionCallee propHandler,
                            FunctionCallee evaluateTrace,
                            const std::string& cond = "") {
    LLVMContext& C = M.getContext();
    const DataLayout& DL = M.getDataLayout();

    // ---- 可记录变量：模块全局 + 本函数的定长 alloca 局部 ----
    struct Item { Value* ptr; uint64_t size; };
    std::vector<Item> items;
    for (auto& G : M.globals()) {
        if (G.isDeclaration() || G.hasLocalLinkage()) continue;
        if (G.getName().startswith("_PeEvents") ||
            G.getName().startswith(".str")) continue;
        Type* VT = G.getValueType();
        if (isa<PointerType>(VT) || VT->isIntegerTy() ||
            VT->isFloatTy() || VT->isDoubleTy() ||
            (VT->isArrayTy() && DL.getTypeAllocSize(VT) <= 256)) {
            items.push_back({&G, DL.getTypeAllocSize(VT)});
        }
    }
    // 仅入口块 alloca（clang -O0 的具名局部全在入口；其余块的非支配
    // 定义会导致用前定义）
    for (auto& I : F.getEntryBlock()) {
        auto* AI = dyn_cast<AllocaInst>(&I);
        if (!AI || AI->isArrayAllocation()) continue;
        uint64_t sz = DL.getTypeAllocSize(AI->getAllocatedType());
        if (sz == 0 || sz > 256) continue;
        items.push_back({AI, sz});
    }

    // 状态数组先建：锚点 = 入口块【最后一个 alloca 之后】（支配全函数）。
    // 不能用 getFirstInsertionPt——它只跳过开头连续的 alloca，而 clang -O0
    // 的 alloca 与 dbg.declare 交错，锚点会落进 alloca 区中间，导致填充
    // 代码先于其后 alloca（use-before-def；2026-10-04 safe_rw.c:12 实测）。
    // 事件块即入口块时，探针序列接在数组填充之后发射（同因）。
    BasicBlock& Entry = F.getEntryBlock();
    BasicBlock::iterator anchor = Entry.getFirstInsertionPt();
    for (auto I = Entry.begin(), E = Entry.end(); I != E; ++I) {
        if (isa<AllocaInst>(&*I)) anchor = std::next(I);
    }
    IRBuilder<> AB(&*anchor);
    Value* PA = nullptr;
    Value* SA = nullptr;
    if (!items.empty()) {
        Type* I64 = Type::getInt64Ty(C);
        Type* I32 = Type::getInt32Ty(C);
        PA = AB.CreateAlloca(ArrayType::get(I64, items.size()));
        SA = AB.CreateAlloca(ArrayType::get(I32, items.size()));
        for (size_t i = 0; i < items.size(); ++i) {
            Value* pe = AB.CreateConstInBoundsGEP2_32(
                ArrayType::get(I64, items.size()), PA, 0, i);
            Value* se = AB.CreateConstInBoundsGEP2_32(
                ArrayType::get(I32, items.size()), SA, 0, i);
            AB.CreateStore(AB.CreatePtrToInt(items[i].ptr, I64), pe);
            AB.CreateStore(ConstantInt::get(I32, items[i].size), se);
        }
    }

    // 探针插入点：入口块 = 数组填充之后（AB 当前位置，避免探针先于
    // 填充读数组——use-before-def）；其余块 = 块首插入点。
    Instruction* probePt = (&B == &Entry)
        ? &*AB.GetInsertPoint()
        : &*B.getFirstInsertionPt();

    // 条件包裹（论文 §2.2 if(c_p)）：cond_fn() 非 0 才执行三件套——
    // 在探针点求值条件并分裂基本块，三件套入 then 块。
    BasicBlock* probeBB = &B;
    bool probeIsAB = (&B == &Entry);
    if (!cond.empty()) {
        FunctionCallee condFn = M.getOrInsertFunction(
            cond, FunctionType::get(Type::getInt32Ty(M.getContext()),
                                    {}, false));
        IRBuilder<> CB(probePt);
        Value* cv = CB.CreateCall(condFn);
        Value* nz = CB.CreateICmpNE(
            cv, ConstantInt::get(Type::getInt32Ty(M.getContext()), 0));
        BasicBlock* rest = B.splitBasicBlock(
            probePt->getIterator(), "pevents.cond.rest");
        BasicBlock* thenBB = BasicBlock::Create(
            M.getContext(), "pevents.cond.then", &F, rest);
        // split 给 B 生成了无条件 br；删除后在 B 末尾建条件分支。
        // 不能用分裂前的 builder：其插入点已随 probePt 落入 rest，
        // condBr 会插进 rest 中部（Terminator-in-middle，2026-10-05
        // 完整构建旗标下 verifier 实测）。
        B.getTerminator()->eraseFromParent();
        IRBuilder<> EB(&B);
        EB.CreateCondBr(nz, thenBB, rest);
        IRBuilder<> TB(thenBB);
        TB.CreateBr(rest);
        probeBB = thenBB;
        probeIsAB = false;
    }

    // 探针序列：propHandler -> stateHandler -> evaluateTrace(1)
    // （论文 Listing 顺序：generate_event / if(liveness) record_state）
    IRBuilder<>& P = probeIsAB ? AB
        : *new IRBuilder<>(&*probeBB->getFirstInsertionPt());
    Value* str = P.CreateGlobalStringPtr(evt);
    P.CreateCall(propHandler, {str});
    if (PA != nullptr) {
        FunctionCallee stateHandler = M.getOrInsertFunction(
            "state_handler",
            FunctionType::get(Type::getVoidTy(C),
                              {Type::getInt64PtrTy(C),
                               Type::getInt32PtrTy(C),
                               Type::getInt32Ty(C)}, false));
        Value* pc = P.CreateBitCast(PA, Type::getInt64PtrTy(C));
        Value* sc = P.CreateBitCast(SA, Type::getInt32PtrTy(C));
        P.CreateCall(stateHandler,
                     {pc, sc, ConstantInt::get(Type::getInt32Ty(C),
                                               (uint32_t)items.size())});
    }
    P.CreateCall(evaluateTrace,
                 {ConstantInt::get(Type::getInt32Ty(C), 1)});
    if (&P != &AB) delete &P;
}

class PeEventsPass : public ModulePass {
public:
    static char ID;
    PeEventsPass() : ModulePass(ID) {}

    bool runOnModule(Module& M) override {
        if (PEventsFile.empty()) return false;
        // 幂等：同一 pass 经显式 -pevents-instr 与 EP_EarlyAsPossible 回调
        // 可能各跑一遍（2026-10-04 实测双跑导致重复插桩），标记防重入。
        if (M.getGlobalVariable("_PeEvents_instrumented")) return false;
        std::map<std::string, std::pair<std::string, std::string>>
            loc_to_event;  // "file:line" -> (event, cond_fn)
        std::ifstream in(PEventsFile.getValue());
        if (!in.is_open()) {
            errs() << "PeEvents: cannot open " << PEventsFile << "\n";
            return false;
        }
        std::string line;
        while (std::getline(in, line)) {
            // 论文元组 ⟨l, p, c_p⟩：file:line:event[:cond_fn]。
            // 第四列为可选条件函数（论文 §2.2 的 if(c_p) generate_event），
            // 三件套仅在 cond_fn() 非 0 时执行；缺省 = if(1)（论文实现层
            // 的无条件形态，testTelnet targets.txt 三段式）。
            std::vector<std::string> parts;
            std::string cur;
            for (char c : line) {
                if (c == ':') { parts.push_back(cur); cur.clear(); }
                else cur += c;
            }
            parts.push_back(cur);
            if (parts.size() < 3) continue;
            std::string loc = parts[0] + ":" + parts[1];
            std::string evt = parts[2];
            std::string cond = parts.size() > 3 ? parts[3] : "";
            if (!loc.empty() && !evt.empty())
                loc_to_event[loc] = std::make_pair(evt, cond);
        }
        if (loc_to_event.empty()) return false;

        // 插入目标函数声明：proposition_handler / evaluate_trace
        // （定义在链接的 instrumentation 库，论文同款符号名）
        LLVMContext& C = M.getContext();
        FunctionCallee propHandler = M.getOrInsertFunction(
            "proposition_handler",
            FunctionType::get(Type::getVoidTy(C),
                              {Type::getInt8PtrTy(C)}, false));
        FunctionCallee evaluateTrace = M.getOrInsertFunction(
            "evaluate_trace",
            FunctionType::get(Type::getVoidTy(C),
                              {Type::getInt32Ty(C)}, false));

        bool changed = false;
        for (auto& F : M) {
            if (F.isDeclaration()) continue;
            for (auto& B : F) {
                // 条件包裹（if(c_p)）用块分裂实现：分裂出的块仍携带
                // 原行号 DebugLoc，会被重复匹配造成无界重插桩循环
                // （2026-10-05 safe_rw.c:12 实测 1400+ 次）。跳过之。
                if (B.getName().startswith("pevents.cond")) continue;
                // 论文匹配语义（afl-llvm-pass :349-368）：块内【任一】指令的
                // file:line 命中目标即该块为插桩块（逐指令比对，首个命中定
                // 事件；块首 DebugLoc 可能落在同行语句的前一条上）。
                for (auto& I : B) {
                    const DebugLoc& DL = I.getDebugLoc();
                    if (!DL) continue;
                    DILocation* L = DL.get();
                    std::string file = L->getFilename().str();
                    std::string::size_type ps = file.find_last_of('/');
                    if (ps != std::string::npos) file = file.substr(ps + 1);
                    std::string loc = file + ":" + std::to_string(L->getLine());
                    auto it = loc_to_event.find(loc);
                    if (it == loc_to_event.end()) continue;

                    insertEventSite(M, B, F, it->first, it->second.first,
                                    propHandler, evaluateTrace,
                                    it->second.second);
                    errs() << "PeEvents: instrumented " << loc << " -> "
                           << it->second.first
                           << (it->second.second.empty()
                                   ? ""
                                   : "  if(" + it->second.second + "())")
                           << "\n";
                    changed = true;
                    break;
                }
            }
            // main 的 return 前：evaluate_trace(0)（论文 RERS 同款）
            if (F.getName() == "main") {
                for (auto& B : F) {
                    for (auto& I : B) {
                        if (!isa<ReturnInst>(&I)) continue;
                        IRBuilder<> Bld(&I);
                        Bld.CreateCall(
                            evaluateTrace,
                            {ConstantInt::get(Type::getInt32Ty(C), 0)});
                        changed = true;
                    }
                }
            }
        }
        if (changed) {
            new GlobalVariable(M, Type::getInt32Ty(M.getContext()), true,
                               GlobalValue::LinkOnceODRLinkage,
                               ConstantInt::get(Type::getInt32Ty(
                                   M.getContext()), 1),
                               "_PeEvents_instrumented");
        }
        return changed;
    }
};

char PeEventsPass::ID = 0;

RegisterStandardPasses RegisterPeEvents(
    PassManagerBuilder::EP_EarlyAsPossible,
    [](const PassManagerBuilder& Builder,
       legacy::PassManagerBase& PM) { PM.add(new PeEventsPass()); });

}  // namespace

// 独立注册：支持 opt-11 -load PeEvents.so -pevents-instr -pevents=<file>
// （离线插桩路线：clang -S -emit-llvm -> opt -> clang -c）
static RegisterPass<PeEventsPass> X("pevents-instr",
                                    "insert event probes at file:line");
