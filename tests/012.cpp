#include "utils.hpp"

#ifdef SONTAG_MCP

namespace sontag::test {

    namespace detail {
        namespace fs = std::filesystem;

        struct temp_dir {
            fs::path path{};

            explicit temp_dir(std::string_view prefix) {
                auto now = std::chrono::system_clock::now().time_since_epoch().count();
                std::ostringstream dir_name{};
                dir_name << prefix << "_" << static_cast<long>(::getpid()) << "_" << now;
                path = fs::temp_directory_path() / dir_name.str();
                fs::create_directories(path);
            }

            ~temp_dir() {
                std::error_code ec{};
                fs::remove_all(path, ec);
            }

            temp_dir(const temp_dir&) = delete;
            temp_dir& operator=(const temp_dir&) = delete;
        };

        static void write_file(const fs::path& p, std::string_view content) {
            std::ofstream out{p};
            REQUIRE(out.good());
            out << content;
        }

        struct mcp_process {
            pid_t pid{-1};
            int stdin_fd{-1};
            int stdout_fd{-1};
            int stderr_fd{-1};
            std::string read_buf{};

            mcp_process(const mcp_process&) = delete;
            mcp_process& operator=(const mcp_process&) = delete;

            explicit mcp_process(const fs::path& cache_dir) {
                int in_pipe[2]{};
                int out_pipe[2]{};
                int err_pipe[2]{};
                REQUIRE(::pipe(in_pipe) == 0);
                REQUIRE(::pipe(out_pipe) == 0);
                REQUIRE(::pipe(err_pipe) == 0);

                pid = ::fork();
                REQUIRE(pid >= 0);

                if (pid == 0) {
                    ::close(in_pipe[1]);
                    ::close(out_pipe[0]);
                    ::close(err_pipe[0]);
                    ::dup2(in_pipe[0], STDIN_FILENO);
                    ::dup2(out_pipe[1], STDOUT_FILENO);
                    ::dup2(err_pipe[1], STDERR_FILENO);
                    ::close(in_pipe[0]);
                    ::close(out_pipe[1]);
                    ::close(err_pipe[1]);

                    auto cache_str = cache_dir.string();
                    const char* argv[] = {
                            SONTAG_CLI_PATH,
                            "--mcp",
                            "--cache-dir",
                            cache_str.c_str(),
                            nullptr,
                    };
                    ::execvp(argv[0], const_cast<char* const*>(argv));
                    _exit(127);
                }

                ::close(in_pipe[0]);
                ::close(out_pipe[1]);
                ::close(err_pipe[1]);
                stdin_fd = in_pipe[1];
                stdout_fd = out_pipe[0];
                stderr_fd = err_pipe[0];
            }

            ~mcp_process() {
                if (stdin_fd >= 0)
                    ::close(stdin_fd);
                if (pid > 0) {
                    ::kill(pid, SIGTERM);
                    ::waitpid(pid, nullptr, 0);
                }
                if (stdout_fd >= 0)
                    ::close(stdout_fd);
                if (stderr_fd >= 0)
                    ::close(stderr_fd);
            }

            void send_line(std::string_view line) {
                std::string msg{line};
                msg.push_back('\n');
                auto written = ::write(stdin_fd, msg.data(), msg.size());
                REQUIRE(written == static_cast<ssize_t>(msg.size()));
            }

            std::string recv_line(int timeout_ms = 15000) {
                auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

                for (;;) {
                    auto pos = read_buf.find('\n');
                    if (pos != std::string::npos) {
                        auto line = read_buf.substr(0, pos);
                        read_buf.erase(0, pos + 1);
                        return line;
                    }

                    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             deadline - std::chrono::steady_clock::now())
                                             .count();
                    if (remaining <= 0) {
                        FAIL("mcp recv_line timed out after " << timeout_ms << "ms");
                    }

                    int poll_ms = remaining > 1000 ? 1000 : static_cast<int>(remaining);
                    pollfd pfd{.fd = stdout_fd, .events = POLLIN, .revents = 0};
                    int ret = ::poll(&pfd, 1, poll_ms);
                    if (ret < 0 && errno == EINTR)
                        continue;
                    if (ret == 0)
                        continue;
                    REQUIRE(ret > 0);

                    char chunk[4096]{};
                    auto n = ::read(stdout_fd, chunk, sizeof(chunk));
                    REQUIRE(n > 0);
                    read_buf.append(chunk, static_cast<size_t>(n));
                }
            }

            std::string handshake() {
                send_line(
                        R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}})");
                auto resp = recv_line();
                send_line(R"({"jsonrpc":"2.0","method":"notifications/initialized"})");
                return resp;
            }
        };
    }  // namespace detail

    TEST_CASE("012: mcp initialize returns protocol version and server info", "[012][mcp]") {
        detail::temp_dir temp{"sontag_mcp_init"};
        detail::mcp_process mcp{temp.path};
        auto resp = mcp.handshake();

        CHECK(resp.find("\"protocolVersion\":\"2024-11-05\"") != std::string::npos);
        CHECK(resp.find("\"name\":\"sontag\"") != std::string::npos);
        CHECK(resp.find("\"version\":\"0.1.0\"") != std::string::npos);
        CHECK(resp.find("\"capabilities\"") != std::string::npos);
    }

    TEST_CASE("012: mcp tools list returns eval and session_eval", "[012][mcp]") {
        detail::temp_dir temp{"sontag_mcp_tools_list"};
        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        mcp.send_line(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
        auto resp = mcp.recv_line();

        CHECK(resp.find("\"name\":\"eval\"") != std::string::npos);
        CHECK(resp.find("\"name\":\"session_eval\"") != std::string::npos);
        CHECK(resp.find("\"inputSchema\"") != std::string::npos);
    }

    TEST_CASE("012: mcp eval tool returns assembly output", "[012][mcp][eval]") {
        detail::temp_dir temp{"sontag_mcp_eval"};
        auto test_file = temp.path / "test.cpp";
        detail::write_file(
                test_file,
                "int square(int x) { return x * x; }\n"
                "int __sontag_main() { return square(3); }\n");

        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        auto request =
                R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"eval","arguments":{"files":[")" +
                test_file.string() + R"("],"command":":asm"}}})";
        mcp.send_line(request);
        auto resp = mcp.recv_line();

        CHECK(resp.find("\"isError\":false") != std::string::npos);
        CHECK(resp.find("ret") != std::string::npos);
    }

    TEST_CASE("012: mcp eval with declfiles and files", "[012][mcp][eval]") {
        detail::temp_dir temp{"sontag_mcp_eval_decl"};
        auto decl_file = temp.path / "decl.hpp";
        detail::write_file(decl_file, "int square(int x) { return x * x; }\n");
        auto main_file = temp.path / "main.cpp";
        detail::write_file(main_file, "int __sontag_main() { return square(3); }\n");

        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        auto request =
                R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"eval","arguments":{"declfiles":[")" +
                decl_file.string() + R"("],"files":[")" + main_file.string() + R"("],"command":":asm"}}})";
        mcp.send_line(request);
        auto resp = mcp.recv_line();

        CHECK(resp.find("\"isError\":false") != std::string::npos);
        CHECK(resp.find("ret") != std::string::npos);
    }

    TEST_CASE("012: mcp session_eval stateful flow", "[012][mcp][session_eval]") {
        detail::temp_dir temp{"sontag_mcp_session"};
        auto decl_file = temp.path / "funcs.hpp";
        detail::write_file(decl_file, "int square(int x) { return x * x; }\n");

        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        // load declfile
        auto load_cmd =
                R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"session_eval","arguments":{"input":":declfile )" +
                decl_file.string() + R"("}}})";
        mcp.send_line(load_cmd);
        auto resp1 = mcp.recv_line();
        CHECK(resp1.find("\"isError\":false") != std::string::npos);
        CHECK(resp1.find("loaded declfile") != std::string::npos);

        // submit a cell
        mcp.send_line(
                R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"session_eval","arguments":{"input":"return square(5);"}}})");
        auto resp2 = mcp.recv_line();
        CHECK(resp2.find("\"isError\":false") != std::string::npos);

        // get assembly — state persists from previous commands
        mcp.send_line(
                R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"session_eval","arguments":{"input":":asm"}}})");
        auto resp3 = mcp.recv_line();
        CHECK(resp3.find("\"isError\":false") != std::string::npos);
        CHECK(resp3.find("ret") != std::string::npos);
    }

    TEST_CASE("012: mcp session_eval crash recovery after child exit", "[012][mcp][session_eval]") {
        detail::temp_dir temp{"sontag_mcp_crash"};
        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        // :quit makes the child REPL exit cleanly
        mcp.send_line(
                R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"session_eval","arguments":{"input":":quit"}}})");
        auto resp1 = mcp.recv_line();
        CHECK(resp1.find("\"id\":2") != std::string::npos);

        // next command triggers crash detection and respawn
        mcp.send_line(
                R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"session_eval","arguments":{"input":":help"}}})");
        auto resp2 = mcp.recv_line();
        CHECK(resp2.find("crashed") != std::string::npos);
        CHECK(resp2.find("restarted") != std::string::npos);
        CHECK(resp2.find("\"isError\":true") != std::string::npos);

        // subsequent command works on new child
        mcp.send_line(
                R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"session_eval","arguments":{"input":":help"}}})");
        auto resp3 = mcp.recv_line();
        CHECK(resp3.find("\"isError\":false") != std::string::npos);
    }

    TEST_CASE("012: mcp unknown method returns error", "[012][mcp]") {
        detail::temp_dir temp{"sontag_mcp_unknown_method"};
        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        mcp.send_line(R"({"jsonrpc":"2.0","id":2,"method":"bogus/method"})");
        auto resp = mcp.recv_line();

        CHECK(resp.find("\"error\"") != std::string::npos);
        CHECK(resp.find("Unknown method") != std::string::npos);
    }

    TEST_CASE("012: mcp unknown tool returns error", "[012][mcp]") {
        detail::temp_dir temp{"sontag_mcp_unknown_tool"};
        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        mcp.send_line(
                R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bogus_tool","arguments":{}}})");
        auto resp = mcp.recv_line();

        CHECK(resp.find("\"error\"") != std::string::npos);
        CHECK(resp.find("Unknown tool") != std::string::npos);
    }

    TEST_CASE("012: mcp eval with no files returns validation error", "[012][mcp][eval]") {
        detail::temp_dir temp{"sontag_mcp_eval_nofiles"};
        detail::mcp_process mcp{temp.path};
        mcp.handshake();

        mcp.send_line(
                R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"eval","arguments":{"command":":asm"}}})");
        auto resp = mcp.recv_line();

        CHECK(resp.find("\"error\"") != std::string::npos);
        CHECK(resp.find("requires at least one file") != std::string::npos);
    }

}  // namespace sontag::test

#endif  // SONTAG_MCP
