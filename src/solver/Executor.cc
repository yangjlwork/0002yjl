#include <solver/Executor.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace solver {

std::string Executor::prefix_to_bytes(const std::string& token) {
    // 论文协议模式前缀 = 逗号分隔字节值表（write_to_shmem_protocol 的
    // 编码）；否则按原文字节。
    std::vector<int> vals;
    std::string cur;
    bool numeric = !token.empty();
    for (char c : token) {
        if (c == ',') {
            if (cur.empty()) { numeric = false; break; }
            vals.push_back(std::atoi(cur.c_str()));
            cur.clear();
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            cur += c;
        } else {
            numeric = false;
            break;
        }
    }
    if (numeric && !cur.empty()) vals.push_back(std::atoi(cur.c_str()));
    if (!numeric || vals.empty()) return token;
    std::string bytes;
    for (int v : vals)
        if (v >= 0 && v <= 255) bytes += static_cast<char>(v);
    return bytes;
}

static std::vector<std::string> parse_prop_lines(const std::string& text) {
    std::vector<std::string> events;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        // 去两端空白
        std::string::size_type a = line.find_first_not_of(" \t\r");
        if (a == std::string::npos) continue;
        std::string::size_type b = line.find_last_not_of(" \t\r");
        line = line.substr(a, b - a + 1);
        if (line.rfind("prop: ", 0) == 0) events.push_back(line.substr(6));
        else if (line.rfind("prop:", 0) == 0) events.push_back(line.substr(5));
    }
    return events;
}

// TCP 注入：连接 -> 发送 -> 读到安静（首字节等 3s，其后 0.4s 静默即止，
// 上限 8s）。与参考实现的采集窗口一致（PLAY 响应 ~1s 后才到）。
// 事件回收（论文等价：AFLGo -N 托管目标进程并回收其 stdout——monitor 的
// prop:/counterexample 输出在服务器 stdout 而非 socket）：独立部署的服务器
// stdout 重定向到 SOLVER_TARGET_LOG，按发送前后偏移回收本回合新增段。
static ExecResult run_tcp(const std::string& bytes) {
    ExecResult r;
    const char* host_env = std::getenv("SOLVER_TARGET_HOST");
    const char* port_env = std::getenv("SOLVER_TARGET_PORT");
    std::string host = host_env ? host_env : "127.0.0.1";
    int port = port_env ? std::atoi(port_env) : 8554;
    const char* log_env = std::getenv("SOLVER_TARGET_LOG");
    std::streamoff log_base = 0;
    if (log_env != nullptr) {
        struct stat st;
        if (stat(log_env, &st) == 0) log_base = st.st_size;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        r.detail = "socket() 失败";
        return r;
    }
    timeval connect_to{8, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &connect_to, sizeof connect_to);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &connect_to, sizeof connect_to);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        r.detail = "connect " + host + ":" + std::to_string(port) + " 失败";
        close(fd);
        return r;
    }
    if (!bytes.empty() && send(fd, bytes.data(), bytes.size(), 0) < 0) {
        r.detail = "send 失败";
        close(fd);
        return r;
    }
    std::string out;
    char buf[4096];
    bool first = true;
    while (true) {
        // timeval 单位：tv_sec 秒 + tv_usec 微秒。原 {0,3000} 是 3ms
        // 而非 3s（2026-10-05 定位：recv 窗口过短导致回收截断/竞态）。
        timeval to{first ? 3 : 0, first ? 0 : 400000};  // 首字节 3s，其后 0.4s
        first = false;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        if (out.size() > (1u << 20)) break;
    }
    close(fd);
    if (log_env != nullptr) {
        std::ifstream lf(log_env, std::ios::binary);
        if (lf.is_open()) {
            lf.seekg(log_base);
            std::ostringstream tail;
            tail << lf.rdbuf();
            std::string t = tail.str();
            if (!t.empty()) out += "\n[server-log]\n" + t;
        }
    }
    r.ok = true;
    r.output = out;
    r.events = parse_prop_lines(out);
    return r;
}

// 普通模式：候选写临时文件 -> popen 运行插桩二进制（论文
// replace_prefix_run_program 同款），回收 stdout（monitor 的输出在里面）。
static ExecResult run_common(const std::string& subject_dir,
                             const std::string& target_loc,
                             const std::string& exec_name,
                             const std::string& bytes) {
    ExecResult r;
    const std::string input_file = subject_dir + "/input_folder/solver-input";
    {
        std::ofstream f(input_file, std::ios::binary | std::ios::trunc);
        f << bytes;
    }
    std::ostringstream cmd;
    cmd << "cd " << subject_dir << "/build_dir/" << target_loc
        << " && ./" << exec_name << " " << input_file << " 2>&1";
    FILE* p = popen(cmd.str().c_str(), "r");
    if (!p) {
        r.detail = "popen 失败";
        return r;
    }
    std::ostringstream out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) out.write(buf, n);
    pclose(p);
    r.ok = true;
    r.output = out.str();
    r.events = parse_prop_lines(r.output);
    return r;
}

ExecResult Executor::run(const std::string& subject_dir,
                         const std::string& target_loc,
                         const std::string& exec_name,
                         int flag,
                         const std::string& bytes) {
    if (flag) return run_tcp(bytes);
    return run_common(subject_dir, target_loc, exec_name, bytes);
}

}  // namespace solver
