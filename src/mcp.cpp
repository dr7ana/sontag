#include "sontag/mcp.hpp"

#include "sontag/format.hpp"

#include "internal/platform.hpp"

#include <glaze/ext/jsonrpc.hpp>
#include <glaze/glaze.hpp>

#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if SONTAG_PLATFORM_MACOS
#include <mach-o/dyld.h>

#include <climits>
#endif

using namespace sontag::literals;
using namespace std::string_view_literals;
namespace fs = std::filesystem;

namespace sontag::mcp {

    namespace detail {

        // ── MCP protocol types ──────────────────────────────────────────

        struct client_info {
            std::string name{};
            std::string version{};
            struct glaze {
                using T = client_info;
                static constexpr auto value = glz::object(&T::name, &T::version);
            };
        };

        struct initialize_params {
            std::string protocolVersion{};
            client_info clientInfo{};
            struct glaze {
                using T = initialize_params;
                static constexpr auto value =
                        glz::object("protocolVersion", &T::protocolVersion, "clientInfo", &T::clientInfo);
            };
        };

        struct server_info {
            std::string name{};
            std::string version{};
            struct glaze {
                using T = server_info;
                static constexpr auto value = glz::object(&T::name, &T::version);
            };
        };

        struct tools_capability {
            struct glaze {
                using T = tools_capability;
                static constexpr auto value = glz::object();
            };
        };

        struct server_capabilities {
            tools_capability tools{};
            struct glaze {
                using T = server_capabilities;
                static constexpr auto value = glz::object(&T::tools);
            };
        };

        struct initialize_result {
            std::string protocolVersion{};
            server_capabilities capabilities{};
            server_info serverInfo{};
            struct glaze {
                using T = initialize_result;
                static constexpr auto value = glz::object(
                        "protocolVersion",
                        &T::protocolVersion,
                        "capabilities",
                        &T::capabilities,
                        "serverInfo",
                        &T::serverInfo);
            };
        };

        struct tool_definition {
            std::string name{};
            std::string description{};
            glz::raw_json inputSchema{};
            struct glaze {
                using T = tool_definition;
                static constexpr auto value = glz::object(&T::name, &T::description, "inputSchema", &T::inputSchema);
            };
        };

        struct tools_list_result {
            std::vector<tool_definition> tools{};
            struct glaze {
                using T = tools_list_result;
                static constexpr auto value = glz::object(&T::tools);
            };
        };

        struct tool_call_params {
            std::string name{};
            glz::raw_json arguments{};
            struct glaze {
                using T = tool_call_params;
                static constexpr auto value = glz::object(&T::name, &T::arguments);
            };
        };

        struct text_content {
            std::string type{"text"};
            std::string text{};
            struct glaze {
                using T = text_content;
                static constexpr auto value = glz::object(&T::type, &T::text);
            };
        };

        struct tool_call_result {
            std::vector<text_content> content{};
            bool isError{false};
            struct glaze {
                using T = tool_call_result;
                static constexpr auto value = glz::object(&T::content, "isError", &T::isError);
            };
        };

        // ── Tool schemas ────────────────────────────────────────────────

        static constexpr auto eval_description =
                R"(Load C++ source files and execute a sontag REPL command in an isolated subprocess. Files are specified as ordered arrays of paths — declfiles for headers/declarations, files for executable code. No state persists between calls.)";
        static constexpr auto eval_input_schema =
                R"json({"type": "object","properties": {"declfiles": {"type": "array","items": { "type": "string" },"description": "Paths to declaration/header files (loaded as --declfile, in order). Loaded before files."},"files": {"type": "array","items": { "type": "string" },"description": "Paths to executable source files (loaded as --file, in order). Loaded after declfiles."},"command": {"type": "string","description": "REPL command to execute, e.g. ':asm', ':ir', ':inspect asm', ':inspect mem', ':delta O3', ':symbols', ':mca', ':graph cfg'"},"opt_level": {"type": "string","enum": ["O0","O1","O2","O3","Ofast","Oz"]},"standard": {"type": "string","enum": ["c++20","c++23","c++2c"]},"target": {"type": "string","description": "LLVM target triple"},"cpu": {"type": "string","description": "Target CPU model"},"color": {"type": "boolean","description": "ANSI color output. Default false.","default": false}},"required": ["files", "command"]})json"sv;

        static constexpr auto session_eval_description =
                R"(Send a command to the persistent sontag session. Commands start with ':' (e.g. ':asm', ':inspect mem', ':config opt=O2', ':reset', ':file path', ':declfile path', ':mark name', ':delta snapshot_name'). Single-line expressions can be sent directly to add executable cells. For multi-line code, write a file and use ':file path'.)";
        static constexpr auto session_eval_input_schema =
                R"json({"type": "object","properties": {"input": {"type": "string","description": "REPL command or single-line expression"}},"required": ["input"]})json"sv;

        // ── Eval tool argument type ──────────────────────────────────────

        struct eval_args {
            std::vector<std::string> declfiles{};
            std::vector<std::string> files{};
            std::string command{};
            std::optional<std::string> opt_level{};
            std::optional<std::string> standard{};
            std::optional<std::string> target{};
            std::optional<std::string> cpu{};
            std::optional<bool> color{};
            struct glaze {
                using T = eval_args;
                static constexpr auto value = glz::object(
                        &T::declfiles,
                        &T::files,
                        &T::command,
                        &T::opt_level,
                        &T::standard,
                        &T::target,
                        &T::cpu,
                        &T::color);
            };
        };

        // ── Subprocess execution ────────────────────────────────────────

        struct subprocess_result {
            int exit_code{};
            std::string stdout_output{};
            std::string stderr_output{};
        };

        static std::string drain_fd(int fd) {
            std::string buf{};
            char chunk[4096]{};
            for (;;) {
                auto n = ::read(fd, chunk, sizeof(chunk));
                if (n <= 0) {
                    break;
                }
                buf.append(chunk, static_cast<size_t>(n));
            }
            return buf;
        }

        static subprocess_result run_subprocess(const std::vector<std::string>& args, int timeout_ms) {
            int stdout_pipe[2]{};
            int stderr_pipe[2]{};
            if (::pipe(stdout_pipe) != 0 || ::pipe(stderr_pipe) != 0) {
                return {.exit_code = 1, .stderr_output = "pipe() failed"};
            }

            auto pid = ::fork();
            if (pid < 0) {
                ::close(stdout_pipe[0]);
                ::close(stdout_pipe[1]);
                ::close(stderr_pipe[0]);
                ::close(stderr_pipe[1]);
                return {.exit_code = 1, .stderr_output = "fork() failed"};
            }

            if (pid == 0) {
                ::close(stdout_pipe[0]);
                ::close(stderr_pipe[0]);
                ::dup2(stdout_pipe[1], STDOUT_FILENO);
                ::dup2(stderr_pipe[1], STDERR_FILENO);
                ::close(stdout_pipe[1]);
                ::close(stderr_pipe[1]);

                std::vector<char*> argv{};
                argv.reserve(args.size() + 1);
                for (const auto& arg : args) {
                    argv.push_back(const_cast<char*>(arg.c_str()));
                }
                argv.push_back(nullptr);
                ::execvp(argv[0], argv.data());
                _exit(127);
            }

            // parent
            ::close(stdout_pipe[1]);
            ::close(stderr_pipe[1]);

            // poll both pipes with timeout
            std::string out_buf{};
            std::string err_buf{};
            bool timed_out = false;
            int fds_open = 2;

            pollfd fds[2]{};
            fds[0] = {.fd = stdout_pipe[0], .events = POLLIN, .revents = 0};
            fds[1] = {.fd = stderr_pipe[0], .events = POLLIN, .revents = 0};

            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

            while (fds_open > 0) {
                auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         deadline - std::chrono::steady_clock::now())
                                         .count();
                if (remaining <= 0) {
                    timed_out = true;
                    break;
                }

                int ret = ::poll(fds, 2, static_cast<int>(remaining));
                if (ret < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    break;
                }
                if (ret == 0) {
                    timed_out = true;
                    break;
                }

                char chunk[4096]{};
                for (int i = 0; i < 2; ++i) {
                    if (fds[i].fd < 0) {
                        continue;
                    }
                    if ((fds[i].revents & (POLLIN | POLLHUP)) != 0) {
                        auto n = ::read(fds[i].fd, chunk, sizeof(chunk));
                        if (n > 0) {
                            (i == 0 ? out_buf : err_buf).append(chunk, static_cast<size_t>(n));
                        }
                        else {
                            ::close(fds[i].fd);
                            fds[i].fd = -1;
                            --fds_open;
                        }
                    }
                }
            }

            if (timed_out) {
                ::kill(pid, SIGKILL);
            }

            // close any remaining pipe fds
            if (fds[0].fd >= 0) {
                ::close(fds[0].fd);
            }
            if (fds[1].fd >= 0) {
                ::close(fds[1].fd);
            }

            int status = 0;
            ::waitpid(pid, &status, 0);

            if (timed_out) {
                return {.exit_code = 1, .stdout_output = std::move(out_buf), .stderr_output = "subprocess timed out"};
            }

            int exit_code = 1;
            if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
            }
            else if (WIFSIGNALED(status)) {
                exit_code = 128 + WTERMSIG(status);
            }

            return {.exit_code = exit_code, .stdout_output = std::move(out_buf), .stderr_output = std::move(err_buf)};
        }

        // ── Eval tool command builder ───────────────────────────────────

        static std::vector<std::string> build_eval_command(
                const fs::path& self_exe, const eval_args& args, const startup_config& cfg) {
            std::vector<std::string> cmd{};
            cmd.push_back(self_exe.string());
            cmd.push_back("--banner");
            cmd.push_back("false");

            bool use_color = args.color.value_or(false);
            cmd.push_back("--color");
            cmd.push_back(use_color ? "always" : "never");

            if (args.opt_level) {
                cmd.push_back("--opt");
                cmd.push_back(*args.opt_level);
            }
            if (args.standard) {
                cmd.push_back("--std");
                cmd.push_back(*args.standard);
            }
            if (args.target) {
                cmd.push_back("--target");
                cmd.push_back(*args.target);
            }
            if (args.cpu) {
                cmd.push_back("--cpu");
                cmd.push_back(*args.cpu);
            }

            // pass through mca if parent has it enabled
            if (cfg.mca_enabled) {
                cmd.push_back("--mca");
            }

            for (const auto& path : args.declfiles) {
                cmd.push_back("--declfile");
                cmd.push_back(path);
            }
            for (const auto& path : args.files) {
                cmd.push_back("--file");
                cmd.push_back(path);
            }

            cmd.push_back("--eval");
            cmd.push_back(args.command);

            return cmd;
        }

        // ── Binary path resolution ──────────────────────────────────────

        static fs::path resolve_self_exe() {
            if constexpr (internal::platform::is_linux) {
                std::error_code ec{};
                auto path = fs::read_symlink("/proc/self/exe", ec);
                if (!ec) {
                    return path;
                }
            }
#if SONTAG_PLATFORM_MACOS
            if constexpr (internal::platform::is_macos) {
                char buf[PATH_MAX]{};
                uint32_t size = sizeof(buf);
                if (_NSGetExecutablePath(buf, &size) == 0) {
                    return fs::canonical(buf);
                }
            }
#endif
            return "sontag";
        }

        // ── Instance ID management ──────────────────────────────────────

        struct instance_handle {
            int id{};
            fs::path cache_dir{};
        };

        static void write_pid_file(const fs::path& path) {
            std::ofstream out(path);
            out << getpid() << '\n';
        }

        static std::optional<pid_t> read_pid_file(const fs::path& path) {
            std::ifstream in(path);
            pid_t pid{};
            if (in >> pid) {
                return pid;
            }
            return std::nullopt;
        }

        static bool process_alive(pid_t pid) {
            return kill(pid, 0) == 0 || errno == EPERM;
        }

        static void cleanup_stale_instances(const fs::path& base_dir) {
            std::error_code ec{};
            for (auto& entry : fs::directory_iterator(base_dir, ec)) {
                if (!entry.is_directory()) {
                    continue;
                }
                auto name = entry.path().filename().string();
                if (!name.starts_with("mcp-")) {
                    continue;
                }
                auto pid_path = entry.path() / "pid";
                auto pid = read_pid_file(pid_path);
                if (!pid || !process_alive(*pid)) {
                    fs::remove_all(entry.path(), ec);
                }
            }
        }

        static instance_handle claim_instance(const fs::path& base_dir) {
            fs::create_directories(base_dir);

            auto lock_path = base_dir / "mcp-instances.lock";
            int fd = open(lock_path.c_str(), O_CREAT | O_RDWR, 0644);
            if (fd < 0) {
                throw std::runtime_error("failed to open lockfile: {}"_format(lock_path.string()));
            }
            if (flock(fd, LOCK_EX) != 0) {
                close(fd);
                throw std::runtime_error("failed to lock: {}"_format(lock_path.string()));
            }

            cleanup_stale_instances(base_dir);

            int next_id = 1;
            std::error_code ec{};
            for (auto& entry : fs::directory_iterator(base_dir, ec)) {
                if (!entry.is_directory()) {
                    continue;
                }
                auto name = entry.path().filename().string();
                if (!name.starts_with("mcp-")) {
                    continue;
                }
                auto suffix = name.substr(4);
                try {
                    int id = std::stoi(suffix);
                    if (id >= next_id) {
                        next_id = id + 1;
                    }
                } catch (...) {
                }
            }

            auto instance_dir = base_dir / "mcp-{}"_format(next_id);
            fs::create_directories(instance_dir);
            write_pid_file(instance_dir / "pid");

            flock(fd, LOCK_UN);
            close(fd);

            return {next_id, instance_dir};
        }

        static void release_instance(const instance_handle& inst) {
            std::error_code ec{};
            fs::remove_all(inst.cache_dir, ec);
        }

        // ── Session eval argument type ───────────────────────────────────

        struct session_eval_args {
            std::string input{};
            struct glaze {
                using T = session_eval_args;
                static constexpr auto value = glz::object(&T::input);
            };
        };

        // ── Persistent child process ────────────────────────────────────

        struct persistent_child {
            pid_t pid{-1};
            int stdin_fd{-1};
            int stdout_fd{-1};
            int stderr_fd{-1};
        };

        static void close_child_fds(persistent_child& child) {
            if (child.stdin_fd >= 0) {
                ::close(child.stdin_fd);
            }
            if (child.stdout_fd >= 0) {
                ::close(child.stdout_fd);
            }
            if (child.stderr_fd >= 0) {
                ::close(child.stderr_fd);
            }
            child.stdin_fd = -1;
            child.stdout_fd = -1;
            child.stderr_fd = -1;
        }

        static void kill_persistent_child(persistent_child& child) {
            if (child.pid > 0) {
                ::kill(child.pid, SIGTERM);
                ::waitpid(child.pid, nullptr, 0);
            }
            close_child_fds(child);
            child.pid = -1;
        }

        static persistent_child spawn_persistent_child(
                const fs::path& self_exe, const instance_handle& instance, const startup_config& cfg) {
            int in_pipe[2]{};
            int out_pipe[2]{};
            int err_pipe[2]{};
            if (::pipe(in_pipe) != 0 || ::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
                throw std::runtime_error("pipe() failed for persistent child");
            }

            auto pid = ::fork();
            if (pid < 0) {
                ::close(in_pipe[0]);
                ::close(in_pipe[1]);
                ::close(out_pipe[0]);
                ::close(out_pipe[1]);
                ::close(err_pipe[0]);
                ::close(err_pipe[1]);
                throw std::runtime_error("fork() failed for persistent child");
            }

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

                std::vector<std::string> args{
                        self_exe.string(),
                        "--banner",
                        "false",
                        "--quiet",
                        "--color",
                        "never",
                        "--frame-delimiter",
                        "--cache-dir",
                        instance.cache_dir.string(),
                };
                if (cfg.mca_enabled) {
                    args.emplace_back("--mca");
                }

                std::vector<char*> argv{};
                argv.reserve(args.size() + 1);
                for (auto& arg : args) {
                    argv.push_back(arg.data());
                }
                argv.push_back(nullptr);
                ::execvp(argv[0], argv.data());
                _exit(127);
            }

            ::close(in_pipe[0]);
            ::close(out_pipe[1]);
            ::close(err_pipe[1]);

            return {.pid = pid, .stdin_fd = in_pipe[1], .stdout_fd = out_pipe[0], .stderr_fd = err_pipe[0]};
        }

        static std::string drain_fd_nonblocking(int fd) {
            std::string buf{};
            char chunk[4096]{};
            for (;;) {
                pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
                if (::poll(&pfd, 1, 0) <= 0) {
                    break;
                }
                auto n = ::read(fd, chunk, sizeof(chunk));
                if (n <= 0) {
                    break;
                }
                buf.append(chunk, static_cast<size_t>(n));
            }
            return buf;
        }

        struct framed_response {
            std::string stdout_text{};
            std::string stderr_text{};
            bool timed_out{false};
            bool child_died{false};
        };

        static framed_response read_until_frame_delimiter(persistent_child& child, int timeout_ms) {
            std::string out_buf{};
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            static constexpr std::string_view delimiter = "\x1e\n";

            for (;;) {
                auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         deadline - std::chrono::steady_clock::now())
                                         .count();
                if (remaining <= 0) {
                    auto err = drain_fd_nonblocking(child.stderr_fd);
                    return {.stdout_text = std::move(out_buf), .stderr_text = std::move(err), .timed_out = true};
                }

                pollfd pfd{.fd = child.stdout_fd, .events = POLLIN, .revents = 0};
                int ret = ::poll(&pfd, 1, static_cast<int>(remaining));
                if (ret < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    auto err = drain_fd_nonblocking(child.stderr_fd);
                    return {.stdout_text = std::move(out_buf), .stderr_text = std::move(err), .child_died = true};
                }
                if (ret == 0) {
                    auto err = drain_fd_nonblocking(child.stderr_fd);
                    return {.stdout_text = std::move(out_buf), .stderr_text = std::move(err), .timed_out = true};
                }

                char chunk[4096]{};
                auto n = ::read(child.stdout_fd, chunk, sizeof(chunk));
                if (n <= 0) {
                    auto err = drain_fd_nonblocking(child.stderr_fd);
                    return {.stdout_text = std::move(out_buf), .stderr_text = std::move(err), .child_died = true};
                }
                out_buf.append(chunk, static_cast<size_t>(n));

                if (out_buf.size() >= delimiter.size()) {
                    auto pos = out_buf.rfind(delimiter);
                    if (pos != std::string::npos) {
                        out_buf.resize(pos);
                        auto err = drain_fd_nonblocking(child.stderr_fd);
                        return {.stdout_text = std::move(out_buf), .stderr_text = std::move(err)};
                    }
                }
            }
        }

        static constexpr auto crash_message = "session crashed and was restarted — previous state was lost"sv;

        // ── Response helpers ────────────────────────────────────────────

        template <typename T>
        static std::string make_response(const glz::rpc::id_t& id, T&& result) {
            glz::rpc::response_t<std::decay_t<T>> resp{};
            resp.id = id;
            resp.result = std::forward<T>(result);
            std::string json{};
            (void)glz::write_json(resp, json);
            return json;
        }

        static std::string make_error_response(
                const glz::rpc::id_t& id, glz::rpc::error_e code, const std::string& message) {
            glz::rpc::response_t<glz::raw_json> resp{};
            resp.id = id;
            resp.error = glz::rpc::error{code, std::nullopt, message};
            std::string json{};
            (void)glz::write_json(resp, json);
            return json;
        }

        static void send(const std::string& json) {
            std::cout << json << '\n';
            std::cout.flush();
        }

        // ── Handlers ────────────────────────────────────────────────────

        static std::string handle_initialize(const glz::rpc::id_t& id, glz::raw_json_view raw_params) {
            initialize_params params{};
            (void)glz::read<glz::opts{.error_on_unknown_keys = false}>(params, raw_params.str);

            initialize_result result{};
            result.protocolVersion = "2024-11-05";
            result.capabilities = server_capabilities{};
            result.serverInfo = server_info{.name = "sontag", .version = "0.1.0"};

            return make_response(id, std::move(result));
        }

        static std::string handle_tools_list(const glz::rpc::id_t& id) {
            tools_list_result result{};
            result.tools.push_back(
                    tool_definition{
                            .name = "eval",
                            .description = eval_description,
                            .inputSchema = glz::raw_json{eval_input_schema},
                    });
            result.tools.push_back(
                    tool_definition{
                            .name = "session_eval",
                            .description = session_eval_description,
                            .inputSchema = glz::raw_json{session_eval_input_schema},
                    });

            return make_response(id, std::move(result));
        }

        static std::string handle_eval(
                const glz::rpc::id_t& id,
                const glz::raw_json& raw_arguments,
                const fs::path& self_exe,
                const startup_config& cfg) {
            eval_args args{};
            auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(args, raw_arguments.str);
            if (ec) {
                return make_error_response(id, glz::rpc::error_e::invalid_params, "Failed to parse eval arguments");
            }

            if (args.files.empty() && args.declfiles.empty()) {
                return make_error_response(
                        id, glz::rpc::error_e::invalid_params, "eval requires at least one file or declfile");
            }
            if (args.command.empty()) {
                return make_error_response(id, glz::rpc::error_e::invalid_params, "eval requires a command");
            }

            auto cmd = build_eval_command(self_exe, args, cfg);
            auto proc = run_subprocess(cmd, cfg.mcp_timeout_ms);

            tool_call_result result{};
            if (!proc.stdout_output.empty()) {
                result.content.push_back(text_content{.text = std::move(proc.stdout_output)});
            }
            if (!proc.stderr_output.empty()) {
                result.content.push_back(text_content{.text = std::move(proc.stderr_output)});
            }
            if (result.content.empty()) {
                result.content.push_back(text_content{.text = "(no output)"});
            }
            result.isError = proc.exit_code != 0;

            return make_response(id, std::move(result));
        }

        static std::string handle_session_eval(
                const glz::rpc::id_t& id,
                const glz::raw_json& raw_arguments,
                persistent_child& child,
                const fs::path& self_exe,
                const instance_handle& instance,
                const startup_config& cfg) {
            session_eval_args args{};
            auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(args, raw_arguments.str);
            if (ec) {
                return make_error_response(
                        id, glz::rpc::error_e::invalid_params, "Failed to parse session_eval arguments");
            }
            if (args.input.empty()) {
                return make_error_response(id, glz::rpc::error_e::invalid_params, "session_eval requires input");
            }

            // detect dead child and respawn
            if (child.pid <= 0 || !process_alive(child.pid)) {
                if (child.pid > 0) {
                    ::waitpid(child.pid, nullptr, WNOHANG);
                }
                kill_persistent_child(child);
                child = spawn_persistent_child(self_exe, instance, cfg);

                tool_call_result result{};
                result.content.push_back(text_content{.text = std::string{crash_message}});
                result.isError = true;
                return make_response(id, std::move(result));
            }

            // write command to child stdin
            auto line = args.input + "\n";
            auto written = ::write(child.stdin_fd, line.data(), line.size());
            if (written < 0) {
                kill_persistent_child(child);
                child = spawn_persistent_child(self_exe, instance, cfg);

                tool_call_result result{};
                result.content.push_back(text_content{.text = std::string{crash_message}});
                result.isError = true;
                return make_response(id, std::move(result));
            }

            // read until frame delimiter
            auto resp = read_until_frame_delimiter(child, cfg.mcp_timeout_ms);

            if (resp.child_died) {
                kill_persistent_child(child);
                child = spawn_persistent_child(self_exe, instance, cfg);

                tool_call_result result{};
                if (!resp.stdout_text.empty()) {
                    result.content.push_back(text_content{.text = std::move(resp.stdout_text)});
                }
                result.content.push_back(text_content{.text = std::string{crash_message}});
                result.isError = true;
                return make_response(id, std::move(result));
            }

            if (resp.timed_out) {
                tool_call_result result{};
                if (!resp.stdout_text.empty()) {
                    result.content.push_back(text_content{.text = std::move(resp.stdout_text)});
                }
                result.content.push_back(text_content{.text = "command timed out"});
                result.isError = true;
                return make_response(id, std::move(result));
            }

            // success
            tool_call_result result{};
            if (!resp.stdout_text.empty()) {
                result.content.push_back(text_content{.text = std::move(resp.stdout_text)});
            }
            if (!resp.stderr_text.empty()) {
                result.content.push_back(text_content{.text = std::move(resp.stderr_text)});
            }
            if (result.content.empty()) {
                result.content.push_back(text_content{.text = "(no output)"});
            }
            return make_response(id, std::move(result));
        }

        static std::string handle_tools_call(
                const glz::rpc::id_t& id,
                glz::raw_json_view raw_params,
                const fs::path& self_exe,
                const startup_config& cfg,
                persistent_child& child,
                const instance_handle& instance) {
            tool_call_params params{};
            auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(params, raw_params.str);
            if (ec) {
                return make_error_response(id, glz::rpc::error_e::invalid_params, "Failed to parse tool call params");
            }

            if (params.name == "eval") {
                return handle_eval(id, params.arguments, self_exe, cfg);
            }
            if (params.name == "session_eval") {
                return handle_session_eval(id, params.arguments, child, self_exe, instance, cfg);
            }

            return make_error_response(id, glz::rpc::error_e::invalid_params, "Unknown tool: {}"_format(params.name));
        }

    }  // namespace detail

    // ── Server entry point ──────────────────────────────────────────

    int run_mcp_server(startup_config& cfg) {
        ::signal(SIGPIPE, SIG_IGN);

        auto self_exe = detail::resolve_self_exe();
        auto instance = detail::claim_instance(cfg.cache_dir);
        auto child = detail::spawn_persistent_child(self_exe, instance, cfg);

        std::string line{};
        while (std::getline(std::cin, line)) {
            if (line.empty()) {
                continue;
            }

            glz::rpc::generic_request_t request{};
            auto ec = glz::read_json(request, line);
            if (ec) {
                detail::send(detail::make_error_response({}, glz::rpc::error_e::parse_error, "JSON parse error"));
                continue;
            }

            bool is_notification = std::holds_alternative<glz::generic::null_t>(request.id);

            if (request.method == "initialize"sv) {
                detail::send(detail::handle_initialize(request.id, request.params));
            }
            else if (request.method == "notifications/initialized"sv) {
                // notification — no response
            }
            else if (request.method == "tools/list"sv) {
                detail::send(detail::handle_tools_list(request.id));
            }
            else if (request.method == "tools/call"sv) {
                detail::send(detail::handle_tools_call(request.id, request.params, self_exe, cfg, child, instance));
            }
            else if (!is_notification) {
                detail::send(
                        detail::make_error_response(
                                request.id,
                                glz::rpc::error_e::method_not_found,
                                "Unknown method: {}"_format(std::string{request.method})));
            }
        }

        detail::kill_persistent_child(child);
        detail::release_instance(instance);
        return 0;
    }

}  // namespace sontag::mcp
