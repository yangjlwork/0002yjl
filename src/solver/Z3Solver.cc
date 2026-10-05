#include <solver/Z3Solver.h>

#include <z3++.h>

#include <cctype>
#include <sstream>

namespace solver {

// 剥掉 SMT2 里的 set-option/set-logic 行：超时等参数由 z3::params 设置，
// 字符串里的选项可能与外部设置冲突（z3 4.8 会拒绝重复设置）。
static std::string strip_directives(const std::string& smt2) {
    std::ostringstream out;
    std::istringstream in(smt2);
    std::string line;
    while (std::getline(in, line)) {
        std::string s;
        for (char c : line) s += std::tolower(static_cast<unsigned char>(c));
        std::string t = s.substr(0, s.find_first_not_of(" \t\r"));
        if (t.rfind("(set-option", 0) == 0 || t.rfind("(set-logic", 0) == 0)
            continue;
        out << line << "\n";
    }
    return out.str();
}

SmtResult Z3Solver::solve(const std::string& smt2_in) {
    SmtResult r;
    std::string smt2 = strip_directives(smt2_in);
    try {
        z3::context ctx;
        z3::expr_vector asserts = ctx.parse_string(smt2.c_str());
        z3::solver s(ctx);
        for (unsigned i = 0; i < asserts.size(); ++i) s.add(asserts[i]);
        z3::params p(ctx);
        p.set("timeout", 120000u);
        s.set(p);
        z3::check_result cr = s.check();
        if (cr == z3::sat) {
            r.status = "sat";
            z3::model m = s.get_model();
            for (unsigned i = 0; i < m.size(); ++i) {
                z3::func_decl d = m[i];
                if (d.arity() != 0) continue;          // 只取 0 阶常量
                std::ostringstream os;
                os << m.get_const_interp(d);
                r.model[d.name().str()] = os.str();
            }
        } else if (cr == z3::unsat) {
            r.status = "unsat";
        } else {
            r.status = "unknown";
        }
    } catch (z3::exception& ex) {
        r.status = "error";
        r.detail = ex.msg();
    } catch (std::exception& ex) {
        r.status = "error";
        r.detail = ex.what();
    }
    return r;
}

}  // namespace solver
