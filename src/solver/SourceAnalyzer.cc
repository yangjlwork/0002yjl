#include <solver/SourceAnalyzer.h>

#include <algorithm>
#include <dirent.h>
#include <fstream>
#include <sstream>

namespace solver {

static bool file_exists(const std::string& p) {
    std::ifstream f(p);
    return f.good();
}

// 在 root 下按 basename 递归找唯一匹配（与 spec 加载器同规则：
// 唯一命中可用，歧义拒绝）。
static bool find_unique(const std::string& root, const std::string& base,
                        std::string* out) {
    DIR* d = opendir(root.c_str());
    if (!d) return false;
    struct dirent* e;
    std::string hit;
    int hits = 0;
    while ((e = readdir(d)) != nullptr) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        std::string full = root + "/" + name;
        if (name == base) {
            if (!hit.empty()) { hits = 2; break; }
            hit = full;
            ++hits;
            continue;
        }
        // 不跨目录搜索：src 树浅，仅当根下未命中时进入一级子目录找
        if (hits == 0 && e->d_type == DT_DIR) {
            std::string sub;
            if (find_unique(full, base, &sub) ) {
                if (!hit.empty()) { hits = 2; break; }
                hit = sub;
                ++hits;
            }
        }
    }
    closedir(d);
    if (hits == 1 && !hit.empty()) {
        *out = hit;
        return true;
    }
    return false;
}

std::vector<AnchorInfo> SourceAnalyzer::anchors_for(
        const std::string& subject_dir, const std::string& event) {
    std::vector<AnchorInfo> result;
    // 论文两种 targets 布局：协议 targets/targets.txt、普通 target/targets.txt
    std::string tfile = subject_dir + "/targets/targets.txt";
    if (!file_exists(tfile)) tfile = subject_dir + "/target/targets.txt";
    std::ifstream in(tfile);
    if (!in.is_open()) return result;

    std::string line;
    while (std::getline(in, line)) {
        // 格式：文件:行:事件（按最后一个冒号切分，论文同款）
        std::string::size_type p1 = line.rfind(':');
        if (p1 == std::string::npos) continue;
        std::string evt = line.substr(p1 + 1);
        std::string loc = line.substr(0, p1);   // "文件:行"
        if (evt != event) continue;
        std::string::size_type pl = loc.rfind(':');
        if (pl == std::string::npos) continue;
        std::string file = loc.substr(0, pl);
        int lineno = std::atoi(loc.substr(pl + 1).c_str());
        if (lineno <= 0) continue;

        // 源码根：SUBJECT/src 优先，其次 SUBJECT 本身，再按文件名唯一匹配
        std::string src = subject_dir + "/src/" + file;
        if (!file_exists(src)) src = subject_dir + "/" + file;
        if (!file_exists(src)) {
            std::string hit;
            std::string base = file;
            std::string::size_type ps = base.find_last_of('/');
            if (ps != std::string::npos) base = base.substr(ps + 1);
            if (!find_unique(subject_dir + "/src", base, &hit))
                continue;
            src = hit;
        }

        std::ifstream sf(src);
        std::vector<std::string> lines;
        std::string l;
        while (std::getline(sf, l)) lines.push_back(l);
        if (lineno > static_cast<int>(lines.size())) continue;

        AnchorInfo a;
        a.file = file;
        a.line = lineno;
        a.event = evt;
        a.anchor_line = lines[lineno - 1];
        int lo = std::max(1, lineno - 12);
        int hi = std::min(static_cast<int>(lines.size()), lineno + 12);
        std::ostringstream w;
        for (int i = lo; i <= hi; ++i) {
            w << i << (i == lineno ? " => " : "    ") << lines[i - 1] << "\n";
        }
        a.window = w.str();
        result.push_back(a);
    }
    return result;
}

}  // namespace solver
