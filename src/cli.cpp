#include "sontag/cli.hpp"

#include "sontag/analysis.hpp"
#include "sontag/format.hpp"
#include "sontag/utils.hpp"

#include "internal/delta.hpp"
#include "internal/editor.hpp"
#include "internal/explorer.hpp"
#include "internal/opcode.hpp"
#include "internal/platform.hpp"
#include "internal/tables.hpp"
#include "internal/types.hpp"

#include <glaze/glaze.hpp>

#include <CLI/CLI.hpp>
#include <cxxabi.h>

extern "C" {
#include <sys/wait.h>
#include <unistd.h>
}

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <flat_map>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace sontag::literals;

namespace sontag::cli { namespace detail {

    using namespace std::string_view_literals;
    namespace fs = std::filesystem;

    using internal::cell_kind;
    using internal::cell_record;
    using internal::mutation_transaction;
    using internal::persisted_cells;
    using internal::persisted_config;
    using internal::persisted_snapshots;
    using internal::snapshot_record;
    using internal::transaction_kind;

    static void apply_build_tool_paths(startup_config& cfg) {
        cfg.clang_path = fs::path{internal::platform::tool::clangxx_path};
        cfg.mca_path = fs::path{internal::platform::tool::llvm_mca_path};
        cfg.nm_path = fs::path{internal::platform::tool::llvm_nm_path};
    }

    struct repl_state {
        std::flat_map<uint64_t, cell_record> cells{};
        std::set<uint64_t> decl_ids{};
        std::set<uint64_t> exec_ids{};
        uint64_t next_cell_id{1U};
        std::vector<mutation_transaction> transactions{};
        uint64_t next_tx_id{1U};
        persisted_snapshots snapshot_data{};
        fs::path session_dir{};
        fs::path config_path{};
        fs::path snapshots_path{};
        fs::path cells_path{};
        std::string session_id{};
    };

    struct code_balance_state {
        int paren_depth{0};
        int brace_depth{0};
        int bracket_depth{0};

        bool in_single_quote{false};
        bool in_double_quote{false};
        bool escape_next{false};
        bool in_line_comment{false};
        bool in_block_comment{false};
    };

    struct metric_output_record {
        std::string name{};
        double value{};
        std::string unit{};
        std::string status{};
    };

    struct analysis_output_record {
        std::string command{};
        bool success{false};
        int exit_code{-1};
        std::string source_path{};
        std::string artifact_path{};
        std::string stderr_path{};
        std::string text{};
        std::vector<std::string> clang_command{};
        std::vector<analysis_opcode_entry> opcode_table{};
        std::vector<analysis_operation_entry> operations{};
        std::vector<metric_output_record> metrics{};
    };

    struct delta_operation_output_record {
        uint64_t ordinal{};
        uint64_t opcode_uid{};
        std::string opcode{};
        std::string triplet{};
    };

    struct delta_level_output_record {
        std::string level{};
        bool success{false};
        int exit_code{-1};
        std::string artifact_path{};
        std::vector<delta_operation_output_record> operations{};
        std::vector<metric_output_record> metrics{};
        std::string diagnostics_text{};
    };

    struct delta_output_record {
        std::string command{"delta"};
        std::string mode{};
        bool success{false};
        std::string symbol{};
        std::string symbol_display{};
        std::string baseline{};
        std::string target{};
        std::vector<delta_opcode_entry> opcode_table{};
        std::vector<delta_level_output_record> levels{};
        delta_change_counters counters{};
    };

    struct source_location {
        size_t line{0U};
        size_t col{0U};
    };

    struct source_range {
        source_location begin{};
        source_location end{};
    };

    struct driver_ast_info {
        std::string name{};
        source_range function_range{};
        source_range body_range{};
    };

    struct command_capture_result {
        int exit_code{-1};
        std::string output{};
    };

    struct file_load_plan {
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
    };

    struct ast_probe_result {
        bool success{true};
        bool found{false};
        driver_ast_info driver{};
        std::string message{};
    };

}}  // namespace sontag::cli::detail

namespace glz {

    template <>
    struct meta<sontag::analysis_opcode_entry> {
        using T = sontag::analysis_opcode_entry;
        static constexpr auto value = object("opcode_uid", &T::opcode_uid, "opcode", &T::opcode);
    };

    template <>
    struct meta<sontag::analysis_operation_entry> {
        using T = sontag::analysis_operation_entry;
        static constexpr auto value = object(
                "ordinal", &T::ordinal, "opcode_uid", &T::opcode_uid, "opcode", &T::opcode, "stream", &T::stream);
    };

    template <>
    struct meta<sontag::cli::detail::metric_output_record> {
        using T = sontag::cli::detail::metric_output_record;
        static constexpr auto value =
                object("name", &T::name, "value", &T::value, "unit", &T::unit, "status", &T::status);
    };

    template <>
    struct meta<sontag::delta_opcode_entry> {
        using T = sontag::delta_opcode_entry;
        static constexpr auto value = object("opcode_uid", &T::opcode_uid, "opcode", &T::opcode);
    };

    template <>
    struct meta<sontag::delta_change_counters> {
        using T = sontag::delta_change_counters;
        static constexpr auto value =
                object("unchanged_count",
                       &T::unchanged_count,
                       "modified_count",
                       &T::modified_count,
                       "inserted_count",
                       &T::inserted_count,
                       "removed_count",
                       &T::removed_count,
                       "moved_count",
                       &T::moved_count);
    };

    template <>
    struct meta<sontag::cli::detail::delta_operation_output_record> {
        using T = sontag::cli::detail::delta_operation_output_record;
        static constexpr auto value = object(
                "ordinal", &T::ordinal, "opcode_uid", &T::opcode_uid, "opcode", &T::opcode, "triplet", &T::triplet);
    };

    template <>
    struct meta<sontag::cli::detail::delta_level_output_record> {
        using T = sontag::cli::detail::delta_level_output_record;
        static constexpr auto value =
                object("level",
                       &T::level,
                       "success",
                       &T::success,
                       "exit_code",
                       &T::exit_code,
                       "artifact_path",
                       &T::artifact_path,
                       "operations",
                       &T::operations,
                       "metrics",
                       &T::metrics,
                       "diagnostics_text",
                       &T::diagnostics_text);
    };

    template <>
    struct meta<sontag::cli::detail::delta_output_record> {
        using T = sontag::cli::detail::delta_output_record;
        static constexpr auto value =
                object("command",
                       &T::command,
                       "mode",
                       &T::mode,
                       "success",
                       &T::success,
                       "symbol",
                       &T::symbol,
                       "symbol_display",
                       &T::symbol_display,
                       "baseline",
                       &T::baseline,
                       "target",
                       &T::target,
                       "opcode_table",
                       &T::opcode_table,
                       "levels",
                       &T::levels,
                       "counters",
                       &T::counters);
    };

    template <>
    struct meta<sontag::cli::detail::analysis_output_record> {
        using T = sontag::cli::detail::analysis_output_record;
        static constexpr auto value =
                object("command",
                       &T::command,
                       "success",
                       &T::success,
                       "exit_code",
                       &T::exit_code,
                       "source_path",
                       &T::source_path,
                       "artifact_path",
                       &T::artifact_path,
                       "stderr_path",
                       &T::stderr_path,
                       "text",
                       &T::text,
                       "clang_command",
                       &T::clang_command,
                       "opcode_table",
                       &T::opcode_table,
                       "operations",
                       &T::operations,
                       "metrics",
                       &T::metrics);
    };

}  // namespace glz

namespace sontag::cli {

    namespace detail {

        static std::optional<std::string> resolve_editor_executable(const startup_config& cfg);
        static std::string read_text_file(const fs::path& path);

        static constexpr std::string_view host_cpu_literal() {
            if constexpr (internal::platform::is_x86_64) {
                return "x86_64"sv;
            }
            if constexpr (internal::platform::is_arm64) {
                return "arm64"sv;
            }
            return "unknown"sv;
        }

        static constexpr std::string_view host_target_literal() {
            if constexpr (internal::platform::is_linux && internal::platform::is_x86_64) {
                return "x86_64-pc-linux-gnu"sv;
            }
            if constexpr (internal::platform::is_linux && internal::platform::is_arm64) {
                return "aarch64-pc-linux-gnu"sv;
            }
            if constexpr (internal::platform::is_macos && internal::platform::is_x86_64) {
                return "x86_64-apple-darwin"sv;
            }
            if constexpr (internal::platform::is_macos && internal::platform::is_arm64) {
                return "arm64-apple-darwin"sv;
            }
            return "unknown-target"sv;
        }

        static std::string_view effective_target_value(const startup_config& cfg) {
            if (cfg.target_triple) {
                return *cfg.target_triple;
            }
            return host_target_literal();
        }

        static std::string_view effective_cpu_value(const startup_config& cfg) {
            if (cfg.cpu) {
                return *cfg.cpu;
            }
            return host_cpu_literal();
        }

        static std::string_view effective_mca_cpu_value(const startup_config& cfg) {
            if (cfg.mca_cpu) {
                return *cfg.mca_cpu;
            }
            return effective_cpu_value(cfg);
        }

        static std::string effective_editor_value(const startup_config& cfg) {
            if (auto editor = resolve_editor_executable(cfg)) {
                return *editor;
            }
            return "unavailable";
        }

        static std::string display_absolute_path(const fs::path& path) {
            std::error_code ec{};
            auto absolute = fs::absolute(path, ec);
            if (ec) {
                return path.string();
            }
            return absolute.lexically_normal().string();
        }

        static constexpr std::string_view trim_view(std::string_view value) {
            auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return {};
            }
            auto last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, (last - first) + 1U);
        }

        static constexpr std::string_view trim_newline_edges(std::string_view value) {
            while (!value.empty() && (value.front() == '\n' || value.front() == '\r')) {
                value.remove_prefix(1U);
            }
            while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
                value.remove_suffix(1U);
            }
            return value;
        }

        static constexpr std::optional<size_t> parse_size_t_token(std::string_view token) {
            auto trimmed = trim_view(token);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            size_t value = 0U;
            auto begin = trimmed.data();
            auto end = trimmed.data() + trimmed.size();
            return utils::parse_arithmetic<size_t>(std::string_view{begin, end});
        }

        static constexpr std::optional<source_location> parse_location_token(
                std::string_view token, std::optional<size_t> fallback_line) {
            auto trimmed = trim_view(token);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            if (trimmed.starts_with("line:"sv)) {
                auto payload = trimmed.substr("line:"sv.size());
                auto colon = payload.find(':');
                if (colon == std::string_view::npos) {
                    return std::nullopt;
                }
                auto line = parse_size_t_token(payload.substr(0U, colon));
                auto col = parse_size_t_token(payload.substr(colon + 1U));
                if (!line || !col) {
                    return std::nullopt;
                }
                return source_location{.line = *line, .col = *col};
            }

            if (trimmed.starts_with("col:"sv)) {
                if (!fallback_line) {
                    return std::nullopt;
                }
                auto col = parse_size_t_token(trimmed.substr("col:"sv.size()));
                if (!col) {
                    return std::nullopt;
                }
                return source_location{.line = *fallback_line, .col = *col};
            }

            auto last_colon = trimmed.rfind(':');
            if (last_colon == std::string_view::npos || last_colon + 1U >= trimmed.size()) {
                return std::nullopt;
            }
            auto prev_colon = trimmed.rfind(':', last_colon - 1U);
            if (prev_colon == std::string_view::npos || prev_colon + 1U >= last_colon) {
                return std::nullopt;
            }

            auto line = parse_size_t_token(trimmed.substr(prev_colon + 1U, (last_colon - prev_colon) - 1U));
            auto col = parse_size_t_token(trimmed.substr(last_colon + 1U));
            if (!line || !col) {
                return std::nullopt;
            }
            return source_location{.line = *line, .col = *col};
        }

        static constexpr std::optional<source_range> parse_angle_range(
                std::string_view line, std::optional<size_t> begin_line_hint = std::nullopt) {
            auto left = line.find('<');
            if (left == std::string_view::npos) {
                return std::nullopt;
            }
            auto right = line.find('>', left + 1U);
            if (right == std::string_view::npos) {
                return std::nullopt;
            }

            auto payload = line.substr(left + 1U, (right - left) - 1U);
            auto comma = payload.find(',');
            if (comma == std::string_view::npos) {
                return std::nullopt;
            }

            auto begin = parse_location_token(payload.substr(0U, comma), begin_line_hint);
            if (!begin) {
                return std::nullopt;
            }
            auto end = parse_location_token(payload.substr(comma + 1U), begin->line);
            if (!end) {
                return std::nullopt;
            }

            return source_range{.begin = *begin, .end = *end};
        }

        static constexpr std::optional<std::string_view> parse_function_decl_name(std::string_view line) {
            auto first_quote = line.find('\'');
            if (first_quote == std::string_view::npos) {
                return std::nullopt;
            }

            auto prefix = trim_view(line.substr(0U, first_quote));
            auto last_space = prefix.find_last_of(" \t");
            if (last_space == std::string_view::npos || last_space + 1U >= prefix.size()) {
                return std::nullopt;
            }
            return prefix.substr(last_space + 1U);
        }

        static constexpr std::optional<size_t> parse_first_line_number(std::string_view line) {
            auto marker = line.rfind("line:"sv);
            if (marker == std::string_view::npos) {
                return std::nullopt;
            }
            auto value_start = marker + "line:"sv.size();
            auto value_end = line.find(':', value_start);
            if (value_end == std::string_view::npos) {
                return std::nullopt;
            }
            return parse_size_t_token(line.substr(value_start, value_end - value_start));
        }

        static std::vector<size_t> build_line_offsets(std::string_view source) {
            std::vector<size_t> line_offsets{};
            line_offsets.push_back(0U);
            for (size_t i = 0U; i < source.size(); ++i) {
                if (source[i] == '\n' && i + 1U <= source.size()) {
                    line_offsets.push_back(i + 1U);
                }
            }
            return line_offsets;
        }

        static constexpr std::optional<size_t> source_offset_from_location(
                std::string_view source, std::span<size_t> line_offsets, const source_location& location) {
            if (location.line == 0U || location.col == 0U) {
                return std::nullopt;
            }
            if (location.line > line_offsets.size()) {
                return std::nullopt;
            }

            auto line_start = line_offsets[location.line - 1U];
            auto offset = line_start + (location.col - 1U);
            if (offset > source.size()) {
                return std::nullopt;
            }
            return offset;
        }

        static constexpr std::optional<fs::path> parse_path_argument(
                std::string_view command_name, std::string_view raw_argument, std::ostream& err) {
            auto value = trim_view(raw_argument);
            if (value.empty()) {
                err << "invalid {}, expected path after command\n"_format(command_name);
                return std::nullopt;
            }

            auto has_double_quotes = value.size() >= 2U && value.front() == '"' && value.back() == '"';
            auto has_single_quotes = value.size() >= 2U && value.front() == '\'' && value.back() == '\'';
            if (has_double_quotes || has_single_quotes) {
                value = value.substr(1U, value.size() - 2U);
            }

            if (value.empty()) {
                err << "invalid {}, expected non-empty path\n"_format(command_name);
                return std::nullopt;
            }

            auto path = fs::path{value}.lexically_normal();
            if (path.empty()) {
                err << "invalid {}, expected non-empty path\n"_format(command_name);
                return std::nullopt;
            }

            if (path.is_relative()) {
                std::error_code ec{};
                auto cwd = fs::current_path(ec);
                if (ec) {
                    err << "failed to resolve current directory for {}: {}\n"_format(command_name, ec.message());
                    return std::nullopt;
                }
                path = (cwd / path).lexically_normal();
            }

            return path;
        }

        static std::string read_fd_all(int fd) {
            std::string output{};
            char buffer[4096]{};

            while (true) {
                auto bytes = ::read(fd, buffer, sizeof(buffer));
                if (bytes == 0) {
                    break;
                }
                if (bytes < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    throw std::runtime_error("read failed while capturing command output");
                }
                output.append(buffer, static_cast<size_t>(bytes));
            }

            return output;
        }

        static constexpr int wait_for_child_exit_code(pid_t pid) {
            int status = 0;
            if (::waitpid(pid, &status, 0) < 0) {
                throw std::runtime_error("waitpid failed");
            }

            auto exit_code = 1;
            if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
            }
            else if (WIFSIGNALED(status)) {
                exit_code = 128 + WTERMSIG(status);
            }
            return exit_code;
        }

        static constexpr int run_command_interactive(std::span<std::string> args) {
            if (args.empty()) {
                throw std::runtime_error("command args cannot be empty");
            }

            auto pid = ::fork();
            if (pid < 0) {
                throw std::runtime_error("fork failed");
            }

            if (pid == 0) {
                std::vector<char*> argv{};
                argv.reserve(args.size() + 1U);
                for (auto& arg : args) {
                    argv.push_back(const_cast<char*>(arg.c_str()));
                }
                argv.push_back(nullptr);

                ::execvp(argv[0], argv.data());
                _exit(127);
            }

            return wait_for_child_exit_code(pid);
        }

        static constexpr command_capture_result run_command_capture(std::span<std::string> args) {
            if (args.empty()) {
                throw std::runtime_error("command args cannot be empty");
            }

            int pipe_fds[2]{-1, -1};
            if (::pipe(pipe_fds) != 0) {
                throw std::runtime_error("pipe failed");
            }

            auto pid = ::fork();
            if (pid < 0) {
                ::close(pipe_fds[0]);
                ::close(pipe_fds[1]);
                throw std::runtime_error("fork failed");
            }

            if (pid == 0) {
                if (::dup2(pipe_fds[1], STDOUT_FILENO) < 0) {
                    _exit(127);
                }
                if (::dup2(pipe_fds[1], STDERR_FILENO) < 0) {
                    _exit(127);
                }
                ::close(pipe_fds[0]);
                ::close(pipe_fds[1]);

                std::vector<char*> argv{};
                argv.reserve(args.size() + 1U);
                for (auto& arg : args) {
                    argv.push_back(const_cast<char*>(arg.c_str()));
                }
                argv.push_back(nullptr);

                ::execvp(argv[0], argv.data());
                _exit(127);
            }

            ::close(pipe_fds[1]);
            auto output = read_fd_all(pipe_fds[0]);
            ::close(pipe_fds[0]);

            return command_capture_result{.exit_code = wait_for_child_exit_code(pid), .output = std::move(output)};
        }

        static bool is_executable_file(const fs::path& path) {
            std::error_code ec{};
            auto status = fs::status(path, ec);
            if (ec || !fs::exists(status) || fs::is_directory(status)) {
                return false;
            }

            auto perms = status.permissions();
            auto has_owner = (perms & fs::perms::owner_exec) != fs::perms::none;
            auto has_group = (perms & fs::perms::group_exec) != fs::perms::none;
            auto has_others = (perms & fs::perms::others_exec) != fs::perms::none;
            return has_owner || has_group || has_others;
        }

        static std::optional<fs::path> find_command_on_path(std::string_view command) {
            auto command_name = trim_view(command);
            if (command_name.empty()) {
                return std::nullopt;
            }

            if (command_name.find('/') != std::string_view::npos) {
                auto explicit_path = fs::path{command_name};
                if (is_executable_file(explicit_path)) {
                    return explicit_path;
                }
                return std::nullopt;
            }

            auto path_env = std::getenv("PATH");
            if (path_env == nullptr || *path_env == '\0') {
                return std::nullopt;
            }

            auto path_view = std::string_view{path_env};
            size_t begin = 0U;
            while (begin <= path_view.size()) {
                auto end = path_view.find(':', begin);
                if (end == std::string_view::npos) {
                    end = path_view.size();
                }

                auto segment = path_view.substr(begin, end - begin);
                auto base_dir = segment.empty() ? fs::path{"."} : fs::path{segment};
                auto candidate = base_dir / std::string{command_name};
                if (is_executable_file(candidate)) {
                    return candidate;
                }

                if (end == path_view.size()) {
                    break;
                }
                begin = end + 1U;
            }

            return std::nullopt;
        }

        static std::optional<std::string> parse_editor_env_value(const char* key) {
            auto value_ptr = std::getenv(key);
            if (value_ptr == nullptr) {
                return std::nullopt;
            }

            auto value = trim_view(std::string_view{value_ptr});
            if (value.empty()) {
                return std::nullopt;
            }

            auto token_end = value.find_first_of(" \t\r\n");
            if (token_end != std::string_view::npos) {
                value = value.substr(0U, token_end);
            }
            if (value.empty()) {
                return std::nullopt;
            }

            return std::string{value};
        }

        static std::optional<std::string> resolve_editor_executable(const startup_config& cfg) {
            if (cfg.editor && !trim_view(*cfg.editor).empty()) {
                return *cfg.editor;
            }

            if (auto visual = parse_editor_env_value("VISUAL")) {
                return visual;
            }
            if (auto editor = parse_editor_env_value("EDITOR")) {
                return editor;
            }

            if (find_command_on_path("hx"sv)) {
                return std::string{"hx"};
            }
            if (find_command_on_path("neovim"sv)) {
                return std::string{"neovim"};
            }
            if (find_command_on_path("nvim"sv)) {
                return std::string{"nvim"};
            }
            if (find_command_on_path("vim"sv)) {
                return std::string{"vim"};
            }
            if (find_command_on_path("nano"sv)) {
                return std::string{"nano"};
            }

            return std::nullopt;
        }

        static std::optional<fs::path> find_clang_format_config_path() {
            std::error_code ec{};
            auto current = fs::current_path(ec);
            if (ec) {
                return std::nullopt;
            }

            while (true) {
                auto candidate = current / ".clang-format";
                if (fs::is_regular_file(candidate, ec)) {
                    if (!ec) {
                        return candidate;
                    }
                    ec.clear();
                }

                auto parent = current.parent_path();
                if (parent.empty() || parent == current) {
                    break;
                }
                current = parent;
            }

            return std::nullopt;
        }

        static bool run_clang_format_for_file(const startup_config& cfg, const fs::path& path, std::ostream& err) {
            auto style_path = find_clang_format_config_path();
            if (!style_path) {
                err << "failed to locate repository .clang-format, state unchanged\n";
                return false;
            }

            auto args = std::vector<std::string>{};
            args.emplace_back(cfg.formatter.string());
            args.emplace_back("-style=file:{}"_format(style_path->string()));
            args.emplace_back("-i");
            args.emplace_back(path.string());

            auto result = run_command_capture(args);
            if (result.exit_code == 0) {
                return true;
            }

            err << "{} failed for {} (exit_code={})\n"_format(cfg.formatter.string(), path.string(), result.exit_code);
            if (!result.output.empty()) {
                err << result.output;
                if (!result.output.ends_with('\n')) {
                    err << '\n';
                }
            }
            err << "state unchanged\n";
            return false;
        }

        static bool open_path_in_editor(
                const startup_config& cfg, const fs::path& path, std::ostream& out, std::ostream& err) {
            auto editor = resolve_editor_executable(cfg);
            if (!editor) {
                err << "failed to resolve editor (tried configured editor, VISUAL, EDITOR, hx, neovim, vim, nano)\n";
                err << "state unchanged\n";
                return false;
            }

            auto args = std::vector<std::string>{*editor, path.string()};
            auto exit_code = run_command_interactive(args);
            if (exit_code == 0) {
                return true;
            }

            out << "editor exited with code {}, state unchanged\n"_format(exit_code);
            return false;
        }

        static std::vector<std::string> build_ast_dump_command(
                const startup_config& cfg, const fs::path& source_path, std::string_view driver_name) {
            std::vector<std::string> args{};
            args.emplace_back(cfg.clang_path.string());
            args.emplace_back("-std={}"_format(cfg.language_standard));
            args.emplace_back("-fsyntax-only");
            if (cfg.target_triple) {
                args.emplace_back("--target={}"_format(*cfg.target_triple));
            }
            if (cfg.cpu) {
                args.emplace_back("-mcpu={}"_format(*cfg.cpu));
            }
            args.emplace_back("-Xclang");
            args.emplace_back("-ast-dump");
            args.emplace_back("-Xclang");
            args.emplace_back("-ast-dump-filter={}"_format(driver_name));
            args.emplace_back(source_path.string());
            return args;
        }

        static constexpr std::optional<driver_ast_info> parse_driver_ast_dump(
                std::string_view ast_dump_output, std::string_view driver_name) {
            std::istringstream input{std::string{ast_dump_output}};
            std::vector<std::string> lines{};
            std::string line{};
            while (std::getline(input, line)) {
                lines.emplace_back(line);
            }

            for (size_t i = 0U; i < lines.size(); ++i) {
                auto line_view = trim_view(lines[i]);
                if (!line_view.contains("FunctionDecl"sv)) {
                    continue;
                }

                auto parsed_name = parse_function_decl_name(line_view);
                if (!parsed_name || *parsed_name != driver_name) {
                    continue;
                }

                auto function_range = parse_angle_range(line_view);
                if (!function_range) {
                    continue;
                }

                auto function_line_hint = parse_first_line_number(line_view).value_or(function_range->begin.line);
                for (size_t j = i + 1U; j < lines.size(); ++j) {
                    auto nested = trim_view(lines[j]);
                    if (nested.empty()) {
                        continue;
                    }
                    if (nested.starts_with("FunctionDecl "sv)) {
                        break;
                    }
                    if (!nested.contains("CompoundStmt"sv)) {
                        continue;
                    }

                    auto body_range = parse_angle_range(nested, function_line_hint);
                    if (!body_range) {
                        continue;
                    }

                    return driver_ast_info{
                            .name = std::string{driver_name},
                            .function_range = *function_range,
                            .body_range = *body_range};
                }
            }

            return std::nullopt;
        }

        static constexpr ast_probe_result probe_driver_ast(
                const startup_config& cfg, const fs::path& source_path, std::string_view driver_name) {
            auto command = build_ast_dump_command(cfg, source_path, driver_name);
            auto capture = run_command_capture(command);

            if (capture.exit_code != 0) {
                return ast_probe_result{
                        .success = false, .found = false, .driver = {}, .message = std::move(capture.output)};
            }

            auto parsed = parse_driver_ast_dump(capture.output, driver_name);
            if (!parsed) {
                return ast_probe_result{.success = true, .found = false, .driver = {}, .message = {}};
            }

            return ast_probe_result{.success = true, .found = true, .driver = std::move(*parsed), .message = {}};
        }

        static bool check_regular_file(const fs::path& path, std::ostream& err) {
            std::error_code ec{};
            if (!fs::exists(path, ec) || ec) {
                err << "file not found: {}\n"_format(path.string());
                return false;
            }
            if (!fs::is_regular_file(path, ec) || ec) {
                err << "path is not a regular file: {}\n"_format(path.string());
                return false;
            }
            return true;
        }

        static std::optional<file_load_plan> build_file_load_plan(
                const startup_config& cfg, const fs::path& source_path, std::ostream& err) {
            if (!check_regular_file(source_path, err)) {
                return std::nullopt;
            }

            auto source_text = read_text_file(source_path);
            auto sontag_probe = probe_driver_ast(cfg, source_path, "__sontag_main"sv);
            if (!sontag_probe.success) {
                if (!sontag_probe.message.empty()) {
                    err << sontag_probe.message;
                    if (!sontag_probe.message.ends_with('\n')) {
                        err << '\n';
                    }
                }
                return std::nullopt;
            }

            auto main_probe = probe_driver_ast(cfg, source_path, "main"sv);
            if (!main_probe.success) {
                if (!main_probe.message.empty()) {
                    err << main_probe.message;
                    if (!main_probe.message.ends_with('\n')) {
                        err << '\n';
                    }
                }
                return std::nullopt;
            }

            if (sontag_probe.found && main_probe.found) {
                err << "file contains both __sontag_main and main; keep only one driver function\n";
                return std::nullopt;
            }

            const auto* selected = static_cast<const ast_probe_result*>(nullptr);
            if (sontag_probe.found) {
                selected = &sontag_probe;
            }
            else if (main_probe.found) {
                selected = &main_probe;
            }
            else {
                err << "no driver function found (expected main or __sontag_main); "
                       "use :declfile <path> for declarative-only imports\n";
                return std::nullopt;
            }

            auto line_offsets = build_line_offsets(source_text);
            auto function_start_offset =
                    source_offset_from_location(source_text, line_offsets, selected->driver.function_range.begin);
            auto body_open_offset =
                    source_offset_from_location(source_text, line_offsets, selected->driver.body_range.begin);
            auto body_close_offset =
                    source_offset_from_location(source_text, line_offsets, selected->driver.body_range.end);
            if (!function_start_offset || !body_open_offset || !body_close_offset) {
                err << "failed to map AST source ranges to file offsets for {}\n"_format(source_path.string());
                return std::nullopt;
            }
            if (*function_start_offset > source_text.size() || *body_open_offset >= source_text.size() ||
                *body_close_offset >= source_text.size()) {
                err << "AST source ranges are out of bounds for {}\n"_format(source_path.string());
                return std::nullopt;
            }
            if (*body_open_offset >= *body_close_offset || source_text[*body_open_offset] != '{' ||
                source_text[*body_close_offset] != '}') {
                err << "failed to extract driver body from AST range for {}\n"_format(source_path.string());
                return std::nullopt;
            }

            auto decl_text = trim_view(std::string_view{source_text}.substr(0U, *function_start_offset));
            auto body_text = trim_newline_edges(
                    std::string_view{source_text}.substr(
                            *body_open_offset + 1U, (*body_close_offset - *body_open_offset) - 1U));

            file_load_plan plan{};
            if (!decl_text.empty()) {
                plan.decl_cells.emplace_back(decl_text);
            }
            plan.exec_cells.emplace_back(body_text);
            return plan;
        }

        static constexpr void update_depth(int& depth, int delta) {
            depth += delta;
            if (depth < 0) {
                depth = 0;
            }
        }

        static constexpr void update_code_balance_state(code_balance_state& state, std::string_view line) {
            size_t i = 0U;
            while (i < line.size()) {
                auto c = line[i];
                auto next = (i + 1U < line.size()) ? line[i + 1U] : '\0';

                if (state.in_line_comment) {
                    break;
                }

                if (state.in_block_comment) {
                    if (c == '*' && next == '/') {
                        state.in_block_comment = false;
                        i += 2U;
                        continue;
                    }
                    ++i;
                    continue;
                }

                if (state.in_single_quote) {
                    if (state.escape_next) {
                        state.escape_next = false;
                        ++i;
                        continue;
                    }
                    if (c == '\\') {
                        state.escape_next = true;
                        ++i;
                        continue;
                    }
                    if (c == '\'') {
                        state.in_single_quote = false;
                    }
                    ++i;
                    continue;
                }

                if (state.in_double_quote) {
                    if (state.escape_next) {
                        state.escape_next = false;
                        ++i;
                        continue;
                    }
                    if (c == '\\') {
                        state.escape_next = true;
                        ++i;
                        continue;
                    }
                    if (c == '"') {
                        state.in_double_quote = false;
                    }
                    ++i;
                    continue;
                }

                if (c == '/' && next == '/') {
                    state.in_line_comment = true;
                    break;
                }
                if (c == '/' && next == '*') {
                    state.in_block_comment = true;
                    i += 2U;
                    continue;
                }

                if (c == '\'') {
                    state.in_single_quote = true;
                    ++i;
                    continue;
                }
                if (c == '"') {
                    state.in_double_quote = true;
                    ++i;
                    continue;
                }

                switch (c) {
                    case '(':
                        update_depth(state.paren_depth, 1);
                        break;
                    case ')':
                        update_depth(state.paren_depth, -1);
                        break;
                    case '{':
                        update_depth(state.brace_depth, 1);
                        break;
                    case '}':
                        update_depth(state.brace_depth, -1);
                        break;
                    case '[':
                        update_depth(state.bracket_depth, 1);
                        break;
                    case ']':
                        update_depth(state.bracket_depth, -1);
                        break;
                    default:
                        break;
                }

                ++i;
            }

            state.in_line_comment = false;
        }

        static constexpr bool cell_is_complete(const code_balance_state& state) {
            return state.paren_depth == 0 && state.brace_depth == 0 && state.bracket_depth == 0 &&
                   !state.in_single_quote && !state.in_double_quote && !state.in_block_comment;
        }

        static persisted_config make_persisted_config(const startup_config& cfg) {
            persisted_config data{};
            data.clang = cfg.clang_path.string();
            data.cxx_standard = "{}"_format(cfg.language_standard);
            data.opt_level = "{}"_format(cfg.opt_level);
            data.target = cfg.target_triple;
            data.cpu = cfg.cpu;
            data.mca_cpu = cfg.mca_cpu;
            data.mca_path = cfg.mca_path.string();
            data.nm_path = cfg.nm_path.string();
            data.cache_dir = cfg.cache_dir.string();
            data.history_file = cfg.history_file.string();
            data.output = "{}"_format(cfg.output);
            data.color = "{}"_format(cfg.color);
            data.color_scheme = "{}"_format(cfg.delta_color_scheme);
            data.editor = cfg.editor;
            data.formatter = cfg.formatter.string();
            return data;
        }

        static void apply_persisted_config(const persisted_config& data, startup_config& cfg) {
            if (!try_parse_cxx_standard(data.cxx_standard, cfg.language_standard)) {
                throw std::runtime_error("invalid cxx_standard in persisted config: " + data.cxx_standard);
            }
            if (!try_parse_optimization_level(data.opt_level, cfg.opt_level)) {
                throw std::runtime_error("invalid opt_level in persisted config: " + data.opt_level);
            }
            if (!try_parse_output_mode(data.output, cfg.output)) {
                throw std::runtime_error("invalid output in persisted config: " + data.output);
            }
            if (!try_parse_color_mode(data.color, cfg.color)) {
                throw std::runtime_error("invalid color in persisted config: " + data.color);
            }
            if (!try_parse_color_scheme(data.color_scheme, cfg.delta_color_scheme)) {
                throw std::runtime_error("invalid color_scheme in persisted config: " + data.color_scheme);
            }

            cfg.target_triple = data.target;
            cfg.cpu = data.cpu;
            cfg.mca_cpu = data.mca_cpu;
            apply_build_tool_paths(cfg);
            cfg.cache_dir = data.cache_dir;
            if (!data.history_file.empty()) {
                cfg.history_file = data.history_file;
            }
            cfg.editor = data.editor;
            if (data.formatter.empty()) {
                cfg.formatter = "clang-format";
            }
            else {
                cfg.formatter = data.formatter;
            }
        }

        static std::string read_text_file(const fs::path& path) {
            std::ifstream in{path};
            if (!in) {
                throw std::runtime_error("failed to open " + path.string());
            }
            std::ostringstream ss{};
            ss << in.rdbuf();
            if (!in.good() && !in.eof()) {
                throw std::runtime_error("failed to read " + path.string());
            }
            return ss.str();
        }

        template <typename T>
        static void write_json_file(const T& value, const fs::path& path) {
            std::string json{};
            auto ec = glz::write_json(value, json);
            if (ec) {
                throw std::runtime_error("failed to serialize json for {}"_format(path.string()));
            }

            std::ofstream out{path};
            if (!out) {
                throw std::runtime_error("failed to open {}"_format(path.string()));
            }
            out << json << '\n';
            if (!out) {
                throw std::runtime_error("failed to write {}"_format(path.string()));
            }
        }

        template <typename T>
        static T read_json_file(const fs::path& path, bool allow_unknown_keys = false) {
            T value{};
            auto json = read_text_file(path);
            if (allow_unknown_keys) {
                auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(value, json);
                if (ec) {
                    throw std::runtime_error("failed to parse json file {}"_format(path.string()));
                }
            }
            else {
                auto ec = glz::read_json(value, json);
                if (ec) {
                    throw std::runtime_error("failed to parse json file {}"_format(path.string()));
                }
            }
            return value;
        }

        static void validate_supported_schema_version(int schema_version, const fs::path& path) {
            constexpr int supported_schema_version = 1;
            if (schema_version > supported_schema_version) {
                throw std::runtime_error(
                        "unsupported schema_version in {}: {} > {}"_format(
                                path.string(), schema_version, supported_schema_version));
            }
        }

        static std::string make_session_id() {
            auto now = std::chrono::system_clock::now();
            auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
            auto timestamp_ms = static_cast<long long>(epoch_ms % 1000LL);
            auto timestamp_s = std::chrono::system_clock::to_time_t(now);

            std::tm local_tm{};
            localtime_r(&timestamp_s, &local_tm);

            std::ostringstream os{};
            os << std::put_time(&local_tm, "%Y%m%d_%H%M%S");
            os << '_' << std::setw(3) << std::setfill('0') << timestamp_ms;
            os << "_pid" << static_cast<long>(::getpid());
            return os.str();
        }

        static void upsert_snapshot(
                persisted_snapshots& data,
                std::string_view name,
                const std::vector<std::string>& decl_cells,
                const std::vector<std::string>& exec_cells) {
            auto cell_count = decl_cells.size() + exec_cells.size();
            auto it = std::find_if(data.snapshots.begin(), data.snapshots.end(), [name](const snapshot_record& entry) {
                return entry.name == name;
            });
            if (it == data.snapshots.end()) {
                data.snapshots.push_back(
                        snapshot_record{
                                .name = std::string{name},
                                .cell_count = cell_count,
                                .decl_cells = decl_cells,
                                .exec_cells = exec_cells});
                return;
            }
            it->cell_count = cell_count;
            it->decl_cells = decl_cells;
            it->exec_cells = exec_cells;
        }

        static void persist_snapshots(const repl_state& state) {
            write_json_file(state.snapshot_data, state.snapshots_path);
        }

        static constexpr size_t total_cell_count(const repl_state& state) noexcept {
            return state.cells.size();
        }

        static constexpr size_t kind_cell_count(const repl_state& state, cell_kind kind) noexcept {
            if (kind == cell_kind::decl) {
                return state.decl_ids.size();
            }
            return state.exec_ids.size();
        }

        static std::vector<std::string> collect_cells_by_kind(const repl_state& state, cell_kind kind) {
            auto* ids = &state.exec_ids;
            if (kind == cell_kind::decl) {
                ids = &state.decl_ids;
            }

            std::vector<std::string> cells{};
            cells.reserve(ids->size());
            for (auto cell_id : *ids) {
                if (auto it = state.cells.find(cell_id); it != state.cells.end()) {
                    cells.push_back(it->second.text);
                }
            }
            return cells;
        }

        static void clear_cells(repl_state& state) {
            state.cells.clear();
            state.decl_ids.clear();
            state.exec_ids.clear();
        }

        static void clear_transactions(repl_state& state) {
            state.transactions.clear();
        }

        static void add_cell_with_id(repl_state& state, uint64_t cell_id, cell_kind kind, std::string text) {
            auto inserted = state.cells.emplace(
                    cell_id, cell_record{.cell_id = cell_id, .kind = kind, .text = std::move(text)});
            if (!inserted.second) {
                throw std::runtime_error("duplicate cell id while rebuilding state: {}"_format(cell_id));
            }

            if (kind == cell_kind::decl) {
                state.decl_ids.insert(cell_id);
            }
            else {
                state.exec_ids.insert(cell_id);
            }

            if (cell_id >= state.next_cell_id) {
                state.next_cell_id = cell_id + 1U;
            }
        }

        static uint64_t append_cell(repl_state& state, std::string text, cell_kind kind) {
            auto cell_id = state.next_cell_id++;
            auto inserted = state.cells.emplace(
                    cell_id, cell_record{.cell_id = cell_id, .kind = kind, .text = std::move(text)});
            if (!inserted.second) {
                throw std::runtime_error("duplicate cell id while appending state: {}"_format(cell_id));
            }
            if (kind == cell_kind::decl) {
                state.decl_ids.insert(cell_id);
            }
            else {
                state.exec_ids.insert(cell_id);
            }
            return cell_id;
        }

        static uint64_t append_transaction(
                repl_state& state,
                transaction_kind kind,
                std::optional<std::string> source_key,
                std::vector<uint64_t> cell_ids) {
            auto tx_id = state.next_tx_id++;
            state.transactions.push_back(
                    mutation_transaction{
                            .tx_id = tx_id,
                            .kind = kind,
                            .source_key = std::move(source_key),
                            .cell_ids = std::move(cell_ids)});
            return tx_id;
        }

        static constexpr bool transaction_kind_is_import(transaction_kind kind) noexcept {
            return kind == transaction_kind::file || kind == transaction_kind::declfile;
        }

        static std::optional<std::string> normalize_source_key(const fs::path& path) {
            if (path.empty()) {
                return std::nullopt;
            }

            std::error_code ec{};
            auto weak = fs::weakly_canonical(path, ec);
            if (!ec) {
                return weak.lexically_normal().string();
            }
            return path.lexically_normal().string();
        }

        static std::vector<std::string> collect_cells_by_kind_excluding_ids(
                const repl_state& state, cell_kind kind, const std::set<uint64_t>& excluded_cell_ids) {
            auto* ids = &state.exec_ids;
            if (kind == cell_kind::decl) {
                ids = &state.decl_ids;
            }

            std::vector<std::string> cells{};
            cells.reserve(ids->size());
            for (auto cell_id : *ids) {
                if (excluded_cell_ids.contains(cell_id)) {
                    continue;
                }
                if (auto it = state.cells.find(cell_id); it != state.cells.end()) {
                    cells.push_back(it->second.text);
                }
            }
            return cells;
        }

        static std::vector<uint64_t> filter_existing_cell_ids(
                const repl_state& state, const std::vector<uint64_t>& cell_ids) {
            std::vector<uint64_t> filtered{};
            filtered.reserve(cell_ids.size());
            for (auto cell_id : cell_ids) {
                if (!state.cells.contains(cell_id)) {
                    continue;
                }
                if (std::ranges::find(filtered, cell_id) != filtered.end()) {
                    continue;
                }
                filtered.push_back(cell_id);
            }
            return filtered;
        }

        static void synthesize_transactions_from_cells(repl_state& state) {
            clear_transactions(state);
            state.next_tx_id = 1U;
            for (const auto& [cell_id, cell] : state.cells) {
                auto kind = cell.kind == cell_kind::decl ? transaction_kind::decl : transaction_kind::exec;
                (void)append_transaction(state, kind, std::nullopt, std::vector<uint64_t>{cell_id});
            }
        }

        static void persist_cells(const repl_state& state) {
            persisted_cells data{};
            data.next_cell_id = state.next_cell_id;
            data.next_tx_id = state.next_tx_id;
            data.cells.reserve(state.cells.size());
            for (const auto& [cell_id, cell] : state.cells) {
                data.cells.push_back(cell);
            }
            data.transactions = state.transactions;
            data.decl_cells = collect_cells_by_kind(state, cell_kind::decl);
            data.exec_cells = collect_cells_by_kind(state, cell_kind::exec);
            write_json_file(data, state.cells_path);
        }

        static void persist_current_snapshot(repl_state& state) {
            auto decl_cells = collect_cells_by_kind(state, cell_kind::decl);
            auto exec_cells = collect_cells_by_kind(state, cell_kind::exec);
            upsert_snapshot(state.snapshot_data, "current"sv, decl_cells, exec_cells);
            persist_snapshots(state);
        }

        static fs::path session_root(const startup_config& cfg) {
            return cfg.cache_dir / "sessions";
        }

        static repl_state make_state_paths(const fs::path& session_dir) {
            repl_state state{};
            state.session_dir = session_dir;
            state.session_id = session_dir.filename().string();
            state.config_path = state.session_dir / "config.json";
            state.snapshots_path = state.session_dir / "snapshots.json";
            state.cells_path = state.session_dir / "cells.json";
            return state;
        }

        static std::optional<fs::path> find_latest_session(const fs::path& sessions_root) {
            std::error_code ec{};
            if (!fs::exists(sessions_root, ec) || ec) {
                return std::nullopt;
            }

            std::optional<fs::path> latest{};
            for (const auto& entry : fs::directory_iterator(sessions_root, ec)) {
                if (ec) {
                    throw std::runtime_error("failed to enumerate {}"_format(sessions_root.string()));
                }
                if (!entry.is_directory()) {
                    continue;
                }
                if (!latest || entry.path().filename().string() > latest->filename().string()) {
                    latest = entry.path();
                }
            }
            return latest;
        }

        static repl_state bootstrap_session(const startup_config& cfg) {
            auto sessions_root = cfg.cache_dir / "sessions";
            std::error_code ec{};
            fs::create_directories(sessions_root, ec);
            if (ec) {
                throw std::runtime_error("failed to create sessions root: {}"_format(sessions_root.string()));
            }

            auto session_id = make_session_id();
            auto session_dir = sessions_root / session_id;

            fs::create_directories(session_dir, ec);
            if (ec) {
                throw std::runtime_error("failed to create session dir: {}"_format(session_dir.string()));
            }

            auto state = make_state_paths(session_dir);

            write_json_file(make_persisted_config(cfg), state.config_path);
            write_json_file(state.snapshot_data, state.snapshots_path);
            persist_cells(state);

            return state;
        }

        static repl_state resume_session(startup_config& cfg, std::string_view resume_id) {
            auto sessions_root = session_root(cfg);

            std::optional<fs::path> session_dir{};
            if (resume_id == "latest"sv) {
                session_dir = find_latest_session(sessions_root);
            }
            else {
                auto candidate = sessions_root / std::string(resume_id);
                std::error_code ec{};
                if (fs::exists(candidate, ec) && !ec && fs::is_directory(candidate, ec) && !ec) {
                    session_dir = candidate;
                }
            }

            if (!session_dir) {
                throw std::runtime_error("unable to resolve --resume target: {}"_format(resume_id));
            }

            auto state = make_state_paths(*session_dir);
            auto persisted_cfg = read_json_file<persisted_config>(state.config_path, true);
            validate_supported_schema_version(persisted_cfg.schema_version, state.config_path);
            apply_persisted_config(persisted_cfg, cfg);

            if (fs::exists(state.snapshots_path)) {
                auto snapshot_data = read_json_file<persisted_snapshots>(state.snapshots_path, true);
                validate_supported_schema_version(snapshot_data.schema_version, state.snapshots_path);
                state.snapshot_data = std::move(snapshot_data);
            }
            if (fs::exists(state.cells_path)) {
                auto cell_data = read_json_file<persisted_cells>(state.cells_path, true);
                validate_supported_schema_version(cell_data.schema_version, state.cells_path);
                clear_cells(state);
                clear_transactions(state);
                state.next_cell_id = 1U;
                state.next_tx_id = 1U;

                if (!cell_data.cells.empty()) {
                    for (auto& persisted_cell : cell_data.cells) {
                        add_cell_with_id(
                                state, persisted_cell.cell_id, persisted_cell.kind, std::move(persisted_cell.text));
                    }
                    if (cell_data.next_cell_id > state.next_cell_id) {
                        state.next_cell_id = cell_data.next_cell_id;
                    }
                }
                else {
                    for (auto& cell : cell_data.decl_cells) {
                        append_cell(state, std::move(cell), cell_kind::decl);
                    }
                    for (auto& cell : cell_data.exec_cells) {
                        append_cell(state, std::move(cell), cell_kind::exec);
                    }
                }

                if (!cell_data.transactions.empty()) {
                    state.transactions.clear();
                    state.transactions.reserve(cell_data.transactions.size());
                    auto max_tx_id = uint64_t{0U};
                    for (auto& tx : cell_data.transactions) {
                        auto filtered_cell_ids = filter_existing_cell_ids(state, tx.cell_ids);
                        if (filtered_cell_ids.empty()) {
                            continue;
                        }
                        tx.cell_ids = std::move(filtered_cell_ids);
                        state.transactions.push_back(std::move(tx));
                        if (state.transactions.back().tx_id > max_tx_id) {
                            max_tx_id = state.transactions.back().tx_id;
                        }
                    }
                    if (!state.transactions.empty()) {
                        state.next_tx_id = std::max(cell_data.next_tx_id, max_tx_id + 1U);
                    }
                    else {
                        synthesize_transactions_from_cells(state);
                    }
                }
                else {
                    synthesize_transactions_from_cells(state);
                }
            }

            persist_current_snapshot(state);
            persist_cells(state);
            return state;
        }

        static repl_state start_session(startup_config& cfg) {
            if (cfg.resume_session) {
                return resume_session(cfg, *cfg.resume_session);
            }
            return bootstrap_session(cfg);
        }

        static void print_config(const startup_config& cfg, std::ostream& os) {
            auto editor_value = effective_editor_value(cfg);
            os << ("  language_standard={}\n"
                   "  opt_level={}\n"
                   "  editor={}\n"
                   "  formatter={}\n"
                   "  target={}\n"
                   "  cpu={}\n"
                   "  toolchain_dir={}\n"
                   "  mca_cpu={}\n"
                   "  cache_dir={}\n"
                   "  output={}\n"
                   "  banner={}\n"
                   "  color={}\n"
                   "  color_scheme={}\n"_format(
                           cfg.language_standard,
                           cfg.opt_level,
                           editor_value,
                           cfg.formatter.string(),
                           effective_target_value(cfg),
                           effective_cpu_value(cfg),
                           internal::platform::toolchain_bin_prefix,
                           effective_mca_cpu_value(cfg),
                           display_absolute_path(cfg.cache_dir),
                           cfg.output,
                           cfg.banner_enabled,
                           cfg.color,
                           cfg.delta_color_scheme));
        }

        static void print_snapshots(const repl_state& state, std::ostream& os) {
            os << "snapshots:\n";
            for (const auto& entry : state.snapshot_data.snapshots) {
                os << "  " << entry.name << " (cells=" << entry.cell_count << ")";
                if (entry.name == "current") {
                    os << " [current]";
                }
                os << '\n';
            }
        }

        static void print_cells(
                const std::vector<std::string>& cells, std::ostream& os, std::string_view empty_message) {
            if (cells.empty()) {
                os << empty_message << '\n';
                return;
            }

            for (size_t i = 0U; i < cells.size(); ++i) {
                auto& cell = cells[i];
                os << cell;
                if (!cell.ends_with('\n')) {
                    os << '\n';
                }
                if (i + 1U < cells.size()) {
                    os << '\n';
                }
            }
        }

        static void print_decl_cells(const repl_state& state, std::ostream& os) {
            print_cells(collect_cells_by_kind(state, cell_kind::decl), os, "no declarative cells");
        }

        static void print_exec_cells(const repl_state& state, std::ostream& os) {
            print_cells(collect_cells_by_kind(state, cell_kind::exec), os, "no executable cells");
        }

        static void print_all_cells(const repl_state& state, std::ostream& os) {
            analysis_request request{};
            request.decl_cells = collect_cells_by_kind(state, cell_kind::decl);
            request.exec_cells = collect_cells_by_kind(state, cell_kind::exec);
            os << synthesize_source(request);
        }

        static void print_symbols(const std::vector<analysis_symbol>& symbols, bool verbose, std::ostream& os) {
            if (symbols.empty()) {
                os << "no symbols found\n";
                return;
            }

            os << "symbols:\n";
            for (const auto& symbol : symbols) {
                os << "  [" << symbol.kind << "] " << symbol.demangled;
                if (verbose && symbol.demangled != symbol.mangled) {
                    os << " <" << symbol.mangled << '>';
                }
                os << '\n';
            }
        }

        static bool print_config_category(const startup_config& cfg, std::string_view category, std::ostream& os);
        static bool print_config_category_key(
                const startup_config& cfg, std::string_view category, std::string_view key, std::ostream& os);
        static bool apply_config_assignment(startup_config& cfg, std::string_view assignment, std::ostream& err);

        static std::array<const char*, 6> config_category_menu_completions{
                "ui", "build", "editor", "session", "q", nullptr};
        static std::array<const char*, 17> config_build_menu_completions{
                "std",
                "std=c++20",
                "std=c++23",
                "std=c++2c",
                "opt",
                "opt=O0",
                "opt=O1",
                "opt=O2",
                "opt=O3",
                "opt=Ofast",
                "opt=Oz",
                "target",
                "cpu",
                "toolchain_dir",
                "mca_cpu",
                "q",
                nullptr};
        static std::array<const char*, 12> config_ui_menu_completions{
                "output",
                "output=table",
                "output=json",
                "color",
                "color=auto",
                "color=always",
                "color=never",
                "color_scheme",
                "color_scheme=classic",
                "color_scheme=vaporwave",
                "q",
                nullptr};
        static std::array<const char*, 4> config_session_menu_completions{"cache_dir", "history_file", "q", nullptr};
        static std::array<const char*, 9> config_editor_menu_completions{
                "editor",
                "editor=auto",
                "editor=hx",
                "editor=nvim",
                "editor=vim",
                "editor=nano",
                "formatter",
                "q",
                nullptr};

        static std::array<const char*, 4> config_build_std_value_completions{"c++20", "c++23", "c++2c", nullptr};
        static std::array<const char*, 7> config_build_opt_value_completions{
                "O0", "O1", "O2", "O3", "Ofast", "Oz", nullptr};
        static std::array<const char*, 3> config_ui_output_value_completions{"table", "json", nullptr};
        static std::array<const char*, 4> config_ui_color_value_completions{"auto", "always", "never", nullptr};
        static std::array<const char*, 3> config_ui_color_scheme_value_completions{"classic", "vaporwave", nullptr};
        static std::array<const char*, 6> config_editor_editor_value_completions{
                "auto", "hx", "nvim", "vim", "nano", nullptr};

        static std::optional<std::string_view> config_menu_category_from_choice(std::string_view choice) {
            if (utils::str_case_eq(choice, "build"sv)) {
                return "build"sv;
            }
            if (utils::str_case_eq(choice, "ui"sv)) {
                return "ui"sv;
            }
            if (utils::str_case_eq(choice, "session"sv)) {
                return "session"sv;
            }
            if (utils::str_case_eq(choice, "editor"sv)) {
                return "editor"sv;
            }
            return std::nullopt;
        }

        static const char** config_submenu_completions(std::string_view category) {
            if (category == "build"sv) {
                return config_build_menu_completions.data();
            }
            if (category == "ui"sv) {
                return config_ui_menu_completions.data();
            }
            if (category == "session"sv) {
                return config_session_menu_completions.data();
            }
            if (category == "editor"sv) {
                return config_editor_menu_completions.data();
            }
            return nullptr;
        }

        static std::string_view config_key_without_category_prefix(std::string_view category, std::string_view key) {
            auto trimmed = trim_view(key);
            if (trimmed.starts_with(category) && trimmed.size() > category.size() && trimmed[category.size()] == '.') {
                return trimmed.substr(category.size() + 1U);
            }
            return trimmed;
        }

        static void clear_previous_menu_line(std::ostream& os) {
            if (!::isatty(STDOUT_FILENO)) {
                return;
            }
            os << "\x1b[1A\x1b[2K\r";
            os.flush();
        }

        static std::optional<std::string> make_category_assignment(
                std::string_view category, std::string_view selection) {
            auto eq = selection.find('=');
            if (eq == std::string_view::npos) {
                return std::nullopt;
            }

            auto key = trim_view(selection.substr(0, eq));
            auto value = trim_view(selection.substr(eq + 1U));
            if (key.empty() || value.empty()) {
                return std::nullopt;
            }

            auto category_prefix_len = category.size();
            if (key.find('.') != std::string_view::npos) {
                if (key.size() <= category_prefix_len || !key.starts_with(category) ||
                    key[category_prefix_len] != '.') {
                    return std::nullopt;
                }
                return "{}={}"_format(key, value);
            }
            return "{}.{}={}"_format(category, key, value);
        }

        static bool is_config_cancel_choice(std::string_view choice) {
            return choice.empty() || utils::str_case_eq(choice, "q"sv) || utils::str_case_eq(choice, "quit"sv) ||
                   utils::str_case_eq(choice, "cancel"sv) || utils::str_case_eq(choice, "exit"sv);
        }

        static const char** config_value_completions(std::string_view category, std::string_view key) {
            if (category == "build"sv) {
                if (key == "std"sv) {
                    return config_build_std_value_completions.data();
                }
                if (key == "opt"sv) {
                    return config_build_opt_value_completions.data();
                }
                return nullptr;
            }
            if (category == "ui"sv) {
                if (key == "output"sv) {
                    return config_ui_output_value_completions.data();
                }
                if (key == "color"sv) {
                    return config_ui_color_value_completions.data();
                }
                if (key == "color_scheme"sv) {
                    return config_ui_color_scheme_value_completions.data();
                }
                return nullptr;
            }
            if (category == "editor"sv && key == "editor"sv) {
                return config_editor_editor_value_completions.data();
            }
            return nullptr;
        }

        static bool is_valid_config_key_for_category(std::string_view category, std::string_view key) {
            if (category == "build"sv) {
                return key == "std"sv || key == "opt"sv || key == "target"sv || key == "cpu"sv || key == "mca_cpu"sv;
            }
            if (category == "ui"sv) {
                return key == "output"sv || key == "color"sv || key == "color_scheme"sv;
            }
            if (category == "session"sv) {
                return key == "cache_dir"sv || key == "history_file"sv;
            }
            if (category == "editor"sv) {
                return key == "editor"sv || key == "formatter"sv;
            }
            return false;
        }

        static std::optional<std::string> read_config_value(
                line_editor& editor, std::string_view category, std::string_view key) {
            auto prompt = "{}="_format(key);
            auto value_completion = config_value_completions(category, key);
            auto value_line = value_completion != nullptr ? editor.read_menu_line(prompt, value_completion)
                                                          : editor.read_line(prompt);
            if (!value_line) {
                return std::nullopt;
            }
            auto value = trim_view(*value_line);
            if (is_config_cancel_choice(value)) {
                return std::nullopt;
            }
            return "{}={}"_format(key, value);
        }

        static bool run_config_menu(line_editor& editor, startup_config& cfg, std::ostream& out, std::ostream& err) {
            auto category_line = editor.read_menu_line(""sv, config_category_menu_completions.data());
            if (!category_line) {
                return true;
            }

            auto category_choice = trim_view(*category_line);
            if (is_config_cancel_choice(category_choice)) {
                return true;
            }

            if (category_choice.starts_with(":config"sv)) {
                category_choice = trim_view(category_choice.substr(":config"sv.size()));
            }

            auto category = config_menu_category_from_choice(category_choice);
            if (!category) {
                err << "invalid config category selection: {} (expected build|ui|session|editor)\n"_format(
                        category_choice);
                return true;
            }

            auto category_key = *category;
            clear_previous_menu_line(out);
            (void)print_config_category(cfg, category_key, out);

            auto submenu = config_submenu_completions(category_key);
            if (submenu == nullptr) {
                return true;
            }

            auto key_line = editor.read_menu_line(""sv, submenu);
            if (!key_line) {
                return true;
            }

            auto selected_key = config_key_without_category_prefix(category_key, *key_line);
            if (is_config_cancel_choice(selected_key)) {
                return true;
            }

            if (selected_key.starts_with(':')) {
                return true;
            }

            clear_previous_menu_line(out);
            if (selected_key.contains('=')) {
                auto assignment = make_category_assignment(category_key, selected_key);
                if (!assignment) {
                    err << "invalid :config, key and value must be non-empty\n";
                    return true;
                }
                if (apply_config_assignment(cfg, *assignment, err)) {
                    out << "updated {}\n"_format(*assignment);
                }
                return true;
            }

            if (is_valid_config_key_for_category(category_key, selected_key)) {
                auto pending_assignment = read_config_value(editor, category_key, selected_key);
                if (!pending_assignment) {
                    return true;
                }
                auto assignment = make_category_assignment(category_key, *pending_assignment);
                if (!assignment) {
                    err << "invalid :config, key and value must be non-empty\n";
                    return true;
                }
                if (apply_config_assignment(cfg, *assignment, err)) {
                    out << "updated {}\n"_format(*assignment);
                }
                return true;
            }

            if (print_config_category_key(cfg, category_key, selected_key, out)) {
                return true;
            }

            err << "invalid {} config key selection: {}\n"_format(category_key, selected_key);
            return true;
        }

        static bool print_config_category(const startup_config& cfg, std::string_view category, std::ostream& os) {
            auto key = trim_view(category);
            if (key == "build"sv) {
                os << "build:\n";
                os << "  std={}\n"_format(cfg.language_standard);
                os << "  opt={}\n"_format(cfg.opt_level);
                os << "  target={}\n"_format(effective_target_value(cfg));
                os << "  cpu={}\n"_format(effective_cpu_value(cfg));
                os << "  toolchain_dir={}\n"_format(internal::platform::toolchain_bin_prefix);
                os << "  mca_cpu={}\n"_format(effective_mca_cpu_value(cfg));
                return true;
            }
            if (key == "ui"sv) {
                os << "ui:\n";
                os << "  output={}\n"_format(cfg.output);
                os << "  color={}\n"_format(cfg.color);
                os << "  color_scheme={}\n"_format(cfg.delta_color_scheme);
                return true;
            }
            if (key == "session"sv) {
                os << "session:\n";
                os << "  cache_dir={}\n"_format(display_absolute_path(cfg.cache_dir));
                os << "  history_file={}\n"_format(cfg.history_file.string());
                return true;
            }
            if (key == "editor"sv) {
                auto editor_value = effective_editor_value(cfg);
                os << "editor:\n";
                os << "  editor={}\n"_format(editor_value);
                os << "  formatter={}\n"_format(cfg.formatter.string());
                return true;
            }
            return false;
        }

        static bool print_config_category_key(
                const startup_config& cfg, std::string_view category, std::string_view key, std::ostream& os) {
            auto category_key = trim_view(category);
            auto selected_key = trim_view(key);
            if (category_key == "build"sv) {
                if (selected_key == "std"sv) {
                    os << "build:\n  std={}\n"_format(cfg.language_standard);
                    return true;
                }
                if (selected_key == "opt"sv) {
                    os << "build:\n  opt={}\n"_format(cfg.opt_level);
                    return true;
                }
                if (selected_key == "target"sv) {
                    os << "build:\n  target={}\n"_format(effective_target_value(cfg));
                    return true;
                }
                if (selected_key == "cpu"sv) {
                    os << "build:\n  cpu={}\n"_format(effective_cpu_value(cfg));
                    return true;
                }
                if (selected_key == "toolchain_dir"sv) {
                    os << "build:\n  toolchain_dir={}\n"_format(internal::platform::toolchain_bin_prefix);
                    return true;
                }
                if (selected_key == "mca_cpu"sv) {
                    os << "build:\n  mca_cpu={}\n"_format(effective_mca_cpu_value(cfg));
                    return true;
                }
                return false;
            }
            if (category_key == "ui"sv) {
                if (selected_key == "output"sv) {
                    os << "ui:\n  output={}\n"_format(cfg.output);
                    return true;
                }
                if (selected_key == "color"sv) {
                    os << "ui:\n  color={}\n"_format(cfg.color);
                    return true;
                }
                if (selected_key == "color_scheme"sv) {
                    os << "ui:\n  color_scheme={}\n"_format(cfg.delta_color_scheme);
                    return true;
                }
                return false;
            }
            if (category_key == "session"sv) {
                if (selected_key == "cache_dir"sv) {
                    os << "session:\n  cache_dir={}\n"_format(display_absolute_path(cfg.cache_dir));
                    return true;
                }
                if (selected_key == "history_file"sv) {
                    os << "session:\n  history_file={}\n"_format(cfg.history_file.string());
                    return true;
                }
                return false;
            }
            if (category_key == "editor"sv) {
                if (selected_key == "editor"sv) {
                    auto editor_value = effective_editor_value(cfg);
                    os << "editor:\n  editor={}\n"_format(editor_value);
                    return true;
                }
                if (selected_key == "formatter"sv) {
                    os << "editor:\n  formatter={}\n"_format(cfg.formatter.string());
                    return true;
                }
                return false;
            }
            return false;
        }

        static void reset_config_defaults(startup_config& cfg) {
            auto defaults = startup_config{};
            cfg.language_standard = defaults.language_standard;
            cfg.opt_level = defaults.opt_level;
            cfg.target_triple = defaults.target_triple;
            cfg.cpu = defaults.cpu;
            cfg.mca_cpu = defaults.mca_cpu;
            apply_build_tool_paths(cfg);
            cfg.output = defaults.output;
            cfg.color = defaults.color;
            cfg.delta_color_scheme = defaults.delta_color_scheme;
            cfg.cache_dir = defaults.cache_dir;
            cfg.history_file = defaults.history_file;
            cfg.editor = defaults.editor;
            cfg.formatter = defaults.formatter;
        }

        static std::optional<std::string> parse_optional_config_value(std::string_view value) {
            auto trimmed = trim_view(value);
            if (trimmed.empty()) {
                return std::nullopt;
            }
            if (utils::str_case_eq(trimmed, "<default>"sv) || utils::str_case_eq(trimmed, "default"sv) ||
                utils::str_case_eq(trimmed, "none"sv) || utils::str_case_eq(trimmed, "null"sv) ||
                utils::str_case_eq(trimmed, "auto"sv)) {
                return std::nullopt;
            }
            return std::string{trimmed};
        }

        static bool apply_config_assignment(startup_config& cfg, std::string_view assignment, std::ostream& err) {
            auto eq = assignment.find('=');
            if (eq == std::string_view::npos) {
                err << "invalid :config, expected key=value\n";
                return false;
            }

            auto key = trim_view(assignment.substr(0, eq));
            auto value = trim_view(assignment.substr(eq + 1U));
            if (key.empty() || value.empty()) {
                err << "invalid :config, key and value must be non-empty\n";
                return false;
            }

            if (key == "build.std"sv) {
                if (!try_parse_cxx_standard(value, cfg.language_standard)) {
                    err << "invalid build.std: {} (expected c++20|c++23|c++2c)\n"_format(value);
                    return false;
                }
                return true;
            }
            if (key == "build.opt"sv) {
                if (!try_parse_optimization_level(value, cfg.opt_level)) {
                    err << "invalid build.opt: {} (expected O0|O1|O2|O3|Ofast|Oz)\n"_format(value);
                    return false;
                }
                return true;
            }
            if (key == "build.target"sv) {
                cfg.target_triple = parse_optional_config_value(value);
                return true;
            }
            if (key == "build.cpu"sv) {
                cfg.cpu = parse_optional_config_value(value);
                return true;
            }
            if (key == "build.mca_cpu"sv) {
                cfg.mca_cpu = parse_optional_config_value(value);
                return true;
            }
            if (key == "ui.output"sv) {
                if (!try_parse_output_mode(value, cfg.output)) {
                    err << "invalid ui.output: {} (expected table|json)\n"_format(value);
                    return false;
                }
                return true;
            }
            if (key == "ui.color"sv) {
                if (!try_parse_color_mode(value, cfg.color)) {
                    err << "invalid ui.color: {} (expected auto|always|never)\n"_format(value);
                    return false;
                }
                return true;
            }
            if (key == "ui.color_scheme"sv) {
                if (!try_parse_color_scheme(value, cfg.delta_color_scheme)) {
                    err << "invalid ui.color_scheme: {} (expected classic|vaporwave)\n"_format(value);
                    return false;
                }
                return true;
            }
            if (key == "session.cache_dir"sv) {
                cfg.cache_dir = fs::path{value};
                return true;
            }
            if (key == "session.history_file"sv) {
                cfg.history_file = fs::path{value};
                return true;
            }
            if (key == "editor.editor"sv) {
                cfg.editor = parse_optional_config_value(value);
                return true;
            }
            if (key == "editor.formatter"sv) {
                cfg.formatter = fs::path{value};
                return true;
            }

            err << "unknown :config key: {}\n"_format(key);
            return false;
        }

        static void print_help(std::ostream& os) {
            static constexpr auto help_text = R"(commands:
  :help
  :clear
  :show <config|decl|exec|all>
  :symbols
  :decl <code>
  :declfile <path>
  :file <path>
  :openfile <path>
  :config
  :config <category>
  :config <key>=<value>
  :config reset
  :reset
  :reset last
  :reset snapshots
  :reset file <path>
  :mark <name>
  :snapshots
  :asm [symbol|@last] (default: __sontag_main)
  :asm explore [symbol|@last]
  :ir [symbol|@last]
  :diag [symbol|@last]
  :mca [symbol|@last]
  :delta [spectrum] [target_opt] [symbol|@last]
  :delta <snapshot> [target_opt]
  :inspect asm [symbol|@last]
  :inspect mca [summary|heatmap] [symbol|@last]
  :graph cfg [symbol|@last]
  :graph call [symbol|@last]
  :graph defuse [symbol|@last]
  :quit
examples:
  :decl #include <cstdint>
  :decl struct point { int x; int y; };
  :declfile examples/common.hpp
  :file examples/program.cpp
  :openfile examples/program.cpp
  :config
  :config build
  :config build.opt=O3
  :config reset
  :reset file examples/program.cpp
  :reset snapshots
  :show all
  :symbols
  :mark baseline
  :asm
  :asm explore
  :delta
  :delta spectrum
  :delta O3
  :delta spectrum O3
  :delta snap1
  :delta add
  :inspect asm
  :inspect mca
  :graph cfg
  :graph call
)";
            os << help_text;
        }

        static void clear_terminal(std::ostream& os) {
            os << "\x1b[2J\x1b[H";
            os.flush();
        }

        static constexpr bool is_command_separator(char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r';
        }

        static constexpr bool matches_command(std::string_view cmd, std::string_view name) {
            if (!cmd.starts_with(name)) {
                return false;
            }
            if (cmd.size() == name.size()) {
                return true;
            }
            auto next = cmd[name.size()];
            return is_command_separator(next);
        }

        static constexpr std::optional<std::string_view> command_argument(std::string_view cmd, std::string_view name) {
            if (!matches_command(cmd, name)) {
                return std::nullopt;
            }
            auto tail = trim_view(cmd.substr(name.size()));
            if (tail.empty()) {
                return std::optional<std::string_view>{std::string_view{}};
            }
            return std::optional<std::string_view>{tail};
        }

        static analysis_request make_analysis_request(const startup_config& cfg, const repl_state& state) {
            analysis_request request{};
            request.clang_path = cfg.clang_path;
            request.session_dir = state.session_dir;
            request.decl_cells = collect_cells_by_kind(state, cell_kind::decl);
            request.exec_cells = collect_cells_by_kind(state, cell_kind::exec);
            request.language_standard = cfg.language_standard;
            request.opt_level = cfg.opt_level;
            request.target_triple = cfg.target_triple;
            request.cpu = cfg.cpu;
            request.asm_syntax = cfg.asm_syntax;
            request.mca_cpu = cfg.mca_cpu;
            request.mca_path = cfg.mca_path;
            request.objdump_path = fs::path{internal::platform::tool::llvm_objdump_path};
            request.nm_path = cfg.nm_path;
            request.graph_format = cfg.graph_format;
            request.dot_path = cfg.dot_path;
            request.verbose = cfg.verbose;
            return request;
        }

        struct validation_result {
            bool success{true};
            std::string diagnostics{};
        };

        static validation_result validate_candidate_state(
                const startup_config& cfg, const repl_state& state, std::string_view candidate_cell, bool declarative) {
            auto request = make_analysis_request(cfg, state);
            request.symbol = std::nullopt;
            if (declarative) {
                request.decl_cells.emplace_back(candidate_cell);
            }
            else {
                request.exec_cells.emplace_back(candidate_cell);
            }

            auto diag = run_analysis(request, analysis_kind::diag);
            return validation_result{.success = diag.success, .diagnostics = std::move(diag.artifact_text)};
        }

        static validation_result validate_state_cells(
                const startup_config& cfg,
                const repl_state& state,
                const std::vector<std::string>& decl_cells,
                const std::vector<std::string>& exec_cells) {
            if (decl_cells.empty() && exec_cells.empty()) {
                return validation_result{.success = true, .diagnostics = {}};
            }

            auto request = make_analysis_request(cfg, state);
            request.symbol = std::nullopt;
            request.decl_cells = decl_cells;
            request.exec_cells = exec_cells;

            auto diag = run_analysis(request, analysis_kind::diag);
            return validation_result{.success = diag.success, .diagnostics = std::move(diag.artifact_text)};
        }

        static bool emit_validation_failure(const validation_result& validation, std::ostream& err) {
            if (!validation.success && !validation.diagnostics.empty()) {
                err << validation.diagnostics;
                if (!validation.diagnostics.ends_with('\n')) {
                    err << '\n';
                }
            }
            if (!validation.success) {
                err << "state unchanged\n";
                return true;
            }
            return false;
        }

        static bool append_validated_transaction(
                startup_config& cfg,
                repl_state& state,
                std::vector<std::string> decl_cells,
                std::vector<std::string> exec_cells,
                transaction_kind transaction_kind_value,
                std::optional<std::string> source_key,
                std::string_view success_message,
                std::ostream& out,
                std::ostream& err) {
            try {
                auto candidate_decl_cells = collect_cells_by_kind(state, cell_kind::decl);
                auto candidate_exec_cells = collect_cells_by_kind(state, cell_kind::exec);
                for (const auto& cell : decl_cells) {
                    candidate_decl_cells.push_back(cell);
                }
                for (const auto& cell : exec_cells) {
                    candidate_exec_cells.push_back(cell);
                }

                auto validation = validate_state_cells(cfg, state, candidate_decl_cells, candidate_exec_cells);
                if (emit_validation_failure(validation, err)) {
                    return false;
                }
            } catch (const std::exception& e) {
                err << "state validation error: {}\n"_format(e.what());
                return false;
            }

            std::vector<uint64_t> cell_ids{};
            cell_ids.reserve(decl_cells.size() + exec_cells.size());
            for (auto& cell : decl_cells) {
                cell_ids.push_back(append_cell(state, std::move(cell), cell_kind::decl));
            }
            for (auto& cell : exec_cells) {
                cell_ids.push_back(append_cell(state, std::move(cell), cell_kind::exec));
            }
            (void)append_transaction(state, transaction_kind_value, std::move(source_key), std::move(cell_ids));
            persist_cells(state);
            persist_current_snapshot(state);
            out << success_message << " -> state: valid\n";
            return true;
        }

        static bool append_validated_cell(
                startup_config& cfg,
                repl_state& state,
                std::string_view cell,
                bool declarative,
                std::ostream& out,
                std::ostream& err) {
            auto transaction_kind_value = declarative ? transaction_kind::decl : transaction_kind::exec;
            auto success_message = std::string{};
            if (declarative) {
                success_message = "stored decl #{}"_format(kind_cell_count(state, cell_kind::decl) + 1U);
            }
            else {
                success_message = "stored cell #{}"_format(kind_cell_count(state, cell_kind::exec) + 1U);
            }

            auto decl_cells = std::vector<std::string>{};
            auto exec_cells = std::vector<std::string>{};
            if (declarative) {
                decl_cells.emplace_back(cell);
            }
            else {
                exec_cells.emplace_back(cell);
            }

            return append_validated_transaction(
                    cfg,
                    state,
                    std::move(decl_cells),
                    std::move(exec_cells),
                    transaction_kind_value,
                    std::nullopt,
                    success_message,
                    out,
                    err);
        }

        struct cell_kind_counts {
            size_t decl{};
            size_t exec{};
        };

        static cell_kind_counts count_transaction_cells(const repl_state& state, const mutation_transaction& tx) {
            auto counts = cell_kind_counts{};
            auto seen = std::set<uint64_t>{};
            for (auto cell_id : tx.cell_ids) {
                if (seen.contains(cell_id)) {
                    continue;
                }
                seen.insert(cell_id);
                if (auto it = state.cells.find(cell_id); it != state.cells.end()) {
                    if (it->second.kind == cell_kind::decl) {
                        ++counts.decl;
                    }
                    else {
                        ++counts.exec;
                    }
                }
            }
            return counts;
        }

        static bool remove_transaction_by_index(
                startup_config& cfg,
                repl_state& state,
                size_t transaction_index,
                std::string_view success_message_prefix,
                std::ostream& out,
                std::ostream& err) {
            if (transaction_index >= state.transactions.size()) {
                err << "invalid transaction index\n";
                return false;
            }

            const auto& tx = state.transactions[transaction_index];
            auto counts = count_transaction_cells(state, tx);
            auto excluded_cell_ids = std::set<uint64_t>{tx.cell_ids.begin(), tx.cell_ids.end()};

            try {
                auto candidate_decl_cells =
                        collect_cells_by_kind_excluding_ids(state, cell_kind::decl, excluded_cell_ids);
                auto candidate_exec_cells =
                        collect_cells_by_kind_excluding_ids(state, cell_kind::exec, excluded_cell_ids);
                auto validation = validate_state_cells(cfg, state, candidate_decl_cells, candidate_exec_cells);
                if (emit_validation_failure(validation, err)) {
                    return false;
                }
            } catch (const std::exception& e) {
                err << "state validation error: {}\n"_format(e.what());
                return false;
            }

            for (auto cell_id : excluded_cell_ids) {
                auto it = state.cells.find(cell_id);
                if (it == state.cells.end()) {
                    continue;
                }
                if (it->second.kind == cell_kind::decl) {
                    state.decl_ids.erase(cell_id);
                }
                else {
                    state.exec_ids.erase(cell_id);
                }
                state.cells.erase(it);
            }

            auto tx_it = state.transactions.begin();
            std::advance(tx_it, static_cast<long>(transaction_index));
            state.transactions.erase(tx_it);
            persist_cells(state);
            persist_current_snapshot(state);
            out << success_message_prefix << " (cleared decl={}, exec={})"_format(counts.decl, counts.exec)
                << " -> state: valid\n";
            return true;
        }

        static bool clear_last_transaction(
                startup_config& cfg, repl_state& state, std::ostream& out, std::ostream& err) {
            if (state.transactions.empty()) {
                out << "no transactions to clear\n";
                return true;
            }

            return remove_transaction_by_index(
                    cfg, state, state.transactions.size() - 1U, "cleared last transaction", out, err);
        }

        static bool clear_file_transaction(
                std::string_view raw_argument,
                startup_config& cfg,
                repl_state& state,
                std::ostream& out,
                std::ostream& err) {
            auto path = parse_path_argument(":reset file"sv, raw_argument, err);
            if (!path) {
                return true;
            }

            auto source_key = normalize_source_key(*path);
            if (!source_key) {
                err << "failed to normalize path for :reset file\n";
                return true;
            }

            auto found = std::optional<size_t>{};
            for (size_t i = state.transactions.size(); i > 0U; --i) {
                auto index = i - 1U;
                auto& tx = state.transactions[index];
                if (!transaction_kind_is_import(tx.kind) || !tx.source_key) {
                    continue;
                }
                if (*tx.source_key == *source_key) {
                    found = index;
                    break;
                }
            }

            if (!found) {
                out << "no matching file import found for {}\n"_format(path->string());
                return true;
            }

            auto message = "cleared file import {}"_format(path->string());
            (void)remove_transaction_by_index(cfg, state, *found, message, out, err);
            return true;
        }

        static bool process_declfile_command(std::string_view cmd, startup_config& cfg, repl_state& state) {
            auto arg = command_argument(cmd, ":declfile"sv);
            if (!arg) {
                return false;
            }

            auto path = parse_path_argument(":declfile"sv, *arg, std::cerr);
            if (!path) {
                return true;
            }
            if (!check_regular_file(*path, std::cerr)) {
                return true;
            }

            try {
                auto content = read_text_file(*path);
                if (content.empty()) {
                    std::cerr << "declfile is empty: {}\n"_format(path->string());
                    return true;
                }
                auto success_message = "loaded declfile {} (decl=1, exec=0)"_format(path->string());
                (void)append_validated_transaction(
                        cfg,
                        state,
                        std::vector<std::string>{std::move(content)},
                        {},
                        transaction_kind::declfile,
                        normalize_source_key(*path),
                        success_message,
                        std::cout,
                        std::cerr);
            } catch (const std::exception& e) {
                std::cerr << "declfile error: {}\n"_format(e.what());
            }

            return true;
        }

        static bool load_file_into_state(const fs::path& path, startup_config& cfg, repl_state& state) {
            auto plan = build_file_load_plan(cfg, path, std::cerr);
            if (!plan) {
                return true;
            }

            auto success_message = "loaded file {} (decl={}, exec={})"_format(
                    path.string(), plan->decl_cells.size(), plan->exec_cells.size());
            (void)append_validated_transaction(
                    cfg,
                    state,
                    std::move(plan->decl_cells),
                    std::move(plan->exec_cells),
                    transaction_kind::file,
                    normalize_source_key(path),
                    success_message,
                    std::cout,
                    std::cerr);
            return true;
        }

        static bool process_file_command(std::string_view cmd, startup_config& cfg, repl_state& state) {
            auto arg = command_argument(cmd, ":file"sv);
            if (!arg) {
                return false;
            }

            auto path = parse_path_argument(":file"sv, *arg, std::cerr);
            if (!path) {
                return true;
            }

            try {
                (void)load_file_into_state(*path, cfg, state);
            } catch (const std::exception& e) {
                std::cerr << "file load error: {}\n"_format(e.what());
            }

            return true;
        }

        static bool process_openfile_command(std::string_view cmd, startup_config& cfg, repl_state& state) {
            auto arg = command_argument(cmd, ":openfile"sv);
            if (!arg) {
                return false;
            }

            auto path = parse_path_argument(":openfile"sv, *arg, std::cerr);
            if (!path) {
                return true;
            }

            try {
                auto parent = path->parent_path();
                if (!parent.empty()) {
                    std::error_code ec{};
                    fs::create_directories(parent, ec);
                    if (ec) {
                        std::cerr << "failed to create parent directory for :openfile: {}\n"_format(ec.message());
                        std::cerr << "state unchanged\n";
                        return true;
                    }
                }

                if (fs::exists(*path) && !fs::is_regular_file(*path)) {
                    std::cerr << "path is not a regular file: {}\n"_format(path->string());
                    std::cerr << "state unchanged\n";
                    return true;
                }

                std::ofstream touch{*path, std::ios::app};
                if (!touch.good()) {
                    std::cerr << "failed to open file for :openfile: {}\n"_format(path->string());
                    std::cerr << "state unchanged\n";
                    return true;
                }
                touch.close();

                std::cout << "opened file {} in editor\n"_format(path->string());
                if (!open_path_in_editor(cfg, *path, std::cout, std::cerr)) {
                    return true;
                }
                if (!run_clang_format_for_file(cfg, *path, std::cerr)) {
                    return true;
                }

                (void)load_file_into_state(*path, cfg, state);
            } catch (const std::exception& e) {
                std::cerr << "openfile error: {}\n"_format(e.what());
                std::cerr << "state unchanged\n";
            }

            return true;
        }

        static metric_output_record make_metric_output_record(const analysis_metric_entry& metric) {
            return metric_output_record{
                    .name = metric.name,
                    .value = metric.value,
                    .unit = metric.unit,
                    .status = "{}"_format(metric.status)};
        }

        static metric_output_record make_metric_output_record(const delta_metric_entry& metric) {
            return metric_output_record{
                    .name = metric.name,
                    .value = metric.value,
                    .unit = metric.unit,
                    .status = "{}"_format(metric.status)};
        }

        static delta_output_record make_delta_output_record(const delta_report& report) {
            auto payload = delta_output_record{};
            payload.mode = "{}"_format(report.mode);
            payload.success = report.success;
            payload.symbol = report.symbol;
            payload.symbol_display = report.symbol_display;
            payload.baseline = report.baseline_label;
            payload.target = report.target_label;
            payload.opcode_table = report.opcode_table;
            payload.counters = report.counters;
            payload.levels.reserve(report.levels.size());

            for (const auto& level : report.levels) {
                auto level_payload = delta_level_output_record{
                        .level = level.label.empty() ? "{}"_format(level.level) : level.label,
                        .success = level.success,
                        .exit_code = level.exit_code,
                        .artifact_path = level.artifact_path.string(),
                        .diagnostics_text = level.diagnostics_text};
                level_payload.operations.reserve(level.operations.size());
                for (const auto& operation : level.operations) {
                    level_payload.operations.push_back(
                            delta_operation_output_record{
                                    .ordinal = static_cast<uint64_t>(operation.ordinal),
                                    .opcode_uid = operation.opcode_uid,
                                    .opcode = operation.opcode,
                                    .triplet = operation.triplet});
                }
                level_payload.metrics.reserve(level.metrics.size());
                for (const auto& metric : level.metrics) {
                    level_payload.metrics.push_back(make_metric_output_record(metric));
                }
                payload.levels.push_back(std::move(level_payload));
            }

            return payload;
        }

        struct delta_color_palette {
            std::string_view unchanged{};
            std::string_view modified{};
            std::string_view removed{};
            std::string_view inserted{};
        };

        enum class delta_row_kind : uint8_t { unchanged, modified, removed, inserted };

        static constexpr auto classic_color_scheme = delta_color_palette{
                .unchanged = "\x1b[38;5;22m"sv,
                .modified = "\x1b[33m"sv,
                .removed = "\x1b[31m"sv,
                .inserted = "\x1b[38;5;117m"sv};
        static constexpr auto vaporwave_color_scheme = delta_color_palette{
                .unchanged = "\x1b[38;5;117m"sv,
                .modified = "\x1b[38;5;141m"sv,
                .removed = "\x1b[38;5;204m"sv,
                .inserted = "\x1b[38;5;51m"sv};

        static constexpr delta_color_palette resolve_delta_color_palette(color_scheme scheme) {
            switch (scheme) {
                case color_scheme::classic:
                    return classic_color_scheme;
                case color_scheme::vaporwave:
                    return vaporwave_color_scheme;
            }
            return classic_color_scheme;
        }

        struct delta_alignment {
            bool anchored{false};
            size_t baseline_index{0U};
            size_t target_index{0U};
            long long shift{0LL};
        };

        static std::vector<std::pair<std::string, size_t>> summarize_level_opcodes(
                const std::vector<delta_operation>& operations) {
            std::vector<std::pair<std::string, size_t>> counts{};
            for (const auto& operation : operations) {
                auto it = std::find_if(counts.begin(), counts.end(), [&](const std::pair<std::string, size_t>& entry) {
                    return entry.first == operation.opcode;
                });
                if (it == counts.end()) {
                    counts.push_back({operation.opcode, 1U});
                }
                else {
                    ++it->second;
                }
            }
            return counts;
        }

        static std::string summarize_opcode_counts_inline(
                std::span<const std::pair<std::string, size_t>> opcode_counts) {
            if (opcode_counts.empty()) {
                return "opcodes: <none>";
            }

            std::string summary{"opcodes:"};
            auto preview_count = std::min<size_t>(opcode_counts.size(), 8U);
            for (size_t i = 0U; i < preview_count; ++i) {
                summary.append(" {}({})"_format(opcode_counts[i].first, opcode_counts[i].second));
            }
            if (opcode_counts.size() > preview_count) {
                summary.append(" ...");
            }
            return summary;
        }

        struct asm_summary {
            size_t operations{};
            std::vector<std::pair<std::string, size_t>> opcode_counts{};
            std::vector<internal::explorer::asm_row> rows{};
        };

        static void append_opcode_count(
                std::vector<std::pair<std::string, size_t>>& opcode_counts, std::string_view opcode) {
            for (auto& entry : opcode_counts) {
                if (entry.first == opcode) {
                    ++entry.second;
                    return;
                }
            }
            opcode_counts.push_back({std::string{opcode}, 1U});
        }

        static constexpr bool is_symbol_token_char(char c) noexcept {
            auto lower = utils::char_tolower(c);
            return (c >= '0' && c <= '9') || (lower >= 'a' && lower <= 'z') || c == '_' || c == '$' || c == '.';
        }

        static constexpr bool looks_like_itanium_symbol(std::string_view token) noexcept {
            if (token.size() >= 2U && token[0] == '_' && (token[1] == 'Z' || token[1] == 'z')) {
                return true;
            }
            return token.size() >= 3U && token[0] == '_' && token[1] == '_' && (token[2] == 'Z' || token[2] == 'z');
        }

        static std::string canonicalize_itanium_symbol(std::string_view token) {
            std::string canonical{token};
            if (canonical.size() >= 2U && canonical[0] == '_' && canonical[1] == 'z') {
                canonical[1] = 'Z';
                return canonical;
            }
            if (canonical.size() >= 3U && canonical[0] == '_' && canonical[1] == '_' && canonical[2] == 'z') {
                canonical[2] = 'Z';
            }
            return canonical;
        }

        static std::optional<std::string> demangle_itanium_name(const char* name) {
            auto status = 0;
            auto* demangled_ptr = abi::__cxa_demangle(name, nullptr, nullptr, &status);
            if (demangled_ptr == nullptr || status != 0) {
                std::free(demangled_ptr);
                return std::nullopt;
            }
            std::string demangled{demangled_ptr};
            std::free(demangled_ptr);
            return demangled;
        }

        static std::optional<std::string> demangle_itanium_token(std::string_view token) {
            if (!looks_like_itanium_symbol(token)) {
                return std::nullopt;
            }
            auto canonical = canonicalize_itanium_symbol(token);
            if (auto demangled = demangle_itanium_name(canonical.c_str())) {
                return demangled;
            }
            if (!canonical.empty() && canonical.front() == '_') {
                if (auto demangled = demangle_itanium_name(canonical.c_str() + 1U)) {
                    return demangled;
                }
            }
            return std::nullopt;
        }

        static std::string demangle_symbols_in_signature(std::string_view signature) {
            std::string demangled_signature{};
            demangled_signature.reserve(signature.size());
            size_t i = 0U;
            while (i < signature.size()) {
                if (signature[i] != '_') {
                    demangled_signature.push_back(signature[i]);
                    ++i;
                    continue;
                }

                auto end = i + 1U;
                while (end < signature.size() && is_symbol_token_char(signature[end])) {
                    ++end;
                }

                auto token = signature.substr(i, end - i);
                if (auto demangled = demangle_itanium_token(token)) {
                    demangled_signature.append(*demangled);
                }
                else {
                    demangled_signature.append(token);
                }
                i = end;
            }
            return demangled_signature;
        }

        static std::string normalize_instruction_whitespace(std::string_view value) {
            std::string normalized{};
            normalized.reserve(value.size());

            auto pending_space = false;
            for (char c : value) {
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    pending_space = true;
                    continue;
                }
                if (pending_space && !normalized.empty()) {
                    normalized.push_back(' ');
                }
                normalized.push_back(c);
                pending_space = false;
            }
            return normalized;
        }

        static std::string format_asm_instruction_text(const opcode::operation_node& operation) {
            return normalize_instruction_whitespace(demangle_symbols_in_signature(operation.signature));
        }

        static bool is_hex_offset_token(std::string_view token) {
            if (token.empty()) {
                return false;
            }
            return std::ranges::all_of(token, opcode::ascii_is_hex_digit);
        }

        static std::optional<internal::explorer::asm_row> parse_dump_row(std::string_view line) {
            auto trimmed = trim_view(line);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            auto colon = trimmed.find(':');
            if (colon == std::string_view::npos) {
                return std::nullopt;
            }

            auto offset = trim_view(trimmed.substr(0U, colon));
            if (!is_hex_offset_token(offset)) {
                return std::nullopt;
            }

            auto tail = trimmed.substr(colon + 1U);
            size_t cursor = 0U;
            std::vector<std::string_view> encodings{};
            encodings.reserve(8U);
            std::optional<size_t> instruction_start{};

            while (cursor < tail.size()) {
                while (cursor < tail.size() &&
                       (tail[cursor] == ' ' || tail[cursor] == '\t' || tail[cursor] == '\r' || tail[cursor] == '\n')) {
                    ++cursor;
                }
                if (cursor >= tail.size()) {
                    break;
                }

                auto token_end = cursor;
                while (token_end < tail.size() && tail[token_end] != ' ' && tail[token_end] != '\t' &&
                       tail[token_end] != '\r' && tail[token_end] != '\n') {
                    ++token_end;
                }

                auto token = tail.substr(cursor, token_end - cursor);
                if (opcode::is_hex_blob_token(token)) {
                    encodings.push_back(token);
                    cursor = token_end;
                    continue;
                }

                instruction_start = cursor;
                break;
            }

            if (encodings.empty() || !instruction_start.has_value()) {
                return std::nullopt;
            }

            auto instruction = trim_view(tail.substr(*instruction_start));
            if (instruction.empty()) {
                return std::nullopt;
            }

            auto encoding = std::string{encodings.front()};
            for (size_t i = 1U; i < encodings.size(); ++i) {
                encoding.append(" ");
                encoding.append(encodings[i]);
            }

            return internal::explorer::asm_row{
                    .offset = std::string{offset},
                    .encodings = std::move(encoding),
                    .instruction = normalize_instruction_whitespace(demangle_symbols_in_signature(instruction))};
        }

        static std::vector<internal::explorer::asm_row> parse_dump_rows(std::string_view dump_text) {
            std::vector<internal::explorer::asm_row> rows{};
            size_t begin = 0U;
            while (begin <= dump_text.size()) {
                auto end = dump_text.find('\n', begin);
                if (end == std::string_view::npos) {
                    end = dump_text.size();
                }
                if (auto parsed = parse_dump_row(dump_text.substr(begin, end - begin)); parsed.has_value()) {
                    rows.push_back(std::move(*parsed));
                }
                if (end == dump_text.size()) {
                    break;
                }
                begin = end + 1U;
            }
            return rows;
        }

        struct mca_instruction_table_layout {
            std::array<size_t, 7U> starts{};
            size_t encodings_start{};
            size_t instructions_start{};
            bool valid{false};
        };

        static std::optional<mca_instruction_table_layout> find_mca_instruction_table_layout(std::string_view text) {
            size_t begin = 0U;
            while (begin <= text.size()) {
                auto end = text.find('\n', begin);
                if (end == std::string_view::npos) {
                    end = text.size();
                }
                auto line = text.substr(begin, end - begin);
                if (line.find("[1]"sv) != std::string_view::npos && line.find("[7]"sv) != std::string_view::npos &&
                    line.find("Encodings:"sv) != std::string_view::npos &&
                    line.find("Instructions:"sv) != std::string_view::npos) {
                    mca_instruction_table_layout layout{};
                    for (size_t i = 0U; i < 7U; ++i) {
                        auto marker = "[{}]"_format(i + 1U);
                        auto position = line.find(marker);
                        if (position == std::string_view::npos) {
                            return std::nullopt;
                        }
                        layout.starts[i] = position;
                    }
                    layout.encodings_start = line.find("Encodings:"sv);
                    layout.instructions_start = line.find("Instructions:"sv);
                    layout.valid = layout.instructions_start > layout.encodings_start &&
                                   layout.encodings_start > layout.starts[6];
                    if (!layout.valid) {
                        return std::nullopt;
                    }
                    return layout;
                }
                if (end == text.size()) {
                    break;
                }
                begin = end + 1U;
            }
            return std::nullopt;
        }

        static bool is_numeric_token(std::string_view token) {
            token = trim_view(token);
            if (token.empty()) {
                return false;
            }
            bool has_digit = false;
            for (char c : token) {
                if (c >= '0' && c <= '9') {
                    has_digit = true;
                    continue;
                }
                if (c == '.') {
                    continue;
                }
                return false;
            }
            return has_digit;
        }

        static bool is_numeric_or_dash_token(std::string_view token) {
            token = trim_view(token);
            if (token == "-"sv) {
                return true;
            }
            return is_numeric_token(token);
        }

        static std::vector<std::string_view> split_ascii_whitespace_tokens(std::string_view line) {
            std::vector<std::string_view> tokens{};
            auto cursor = size_t{0U};
            while (cursor < line.size()) {
                while (cursor < line.size() &&
                       (line[cursor] == ' ' || line[cursor] == '\t' || line[cursor] == '\r' || line[cursor] == '\n')) {
                    ++cursor;
                }
                if (cursor >= line.size()) {
                    break;
                }
                auto end = cursor;
                while (end < line.size() && line[end] != ' ' && line[end] != '\t' && line[end] != '\r' &&
                       line[end] != '\n') {
                    ++end;
                }
                tokens.push_back(line.substr(cursor, end - cursor));
                cursor = end;
            }
            return tokens;
        }

        static std::vector<std::string> parse_resource_header_labels(std::string_view line) {
            std::vector<std::string> labels{};
            auto instructions = line.find("Instructions:"sv);
            if (instructions == std::string_view::npos) {
                return labels;
            }

            auto header = line.substr(0U, instructions);
            auto cursor = size_t{0U};
            while (cursor < header.size()) {
                auto open = header.find('[', cursor);
                if (open == std::string_view::npos) {
                    break;
                }
                auto close = header.find(']', open + 1U);
                if (close == std::string_view::npos) {
                    break;
                }
                auto label = trim_view(header.substr(open + 1U, close - open - 1U));
                if (!label.empty()) {
                    labels.push_back(std::string{label});
                }
                cursor = close + 1U;
            }
            return labels;
        }

        static internal::explorer::resource_pressure_table parse_mca_resource_pressure_rows(std::string_view mca_text) {
            auto table = internal::explorer::resource_pressure_table{};
            auto in_section = false;
            auto header_parsed = false;

            size_t begin = 0U;
            while (begin <= mca_text.size()) {
                auto end = mca_text.find('\n', begin);
                if (end == std::string_view::npos) {
                    end = mca_text.size();
                }
                auto line = mca_text.substr(begin, end - begin);
                auto trimmed = trim_view(line);

                if (!in_section) {
                    if (trimmed == "Resource pressure by instruction:"sv) {
                        in_section = true;
                    }
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                if (!header_parsed) {
                    if (trimmed.empty()) {
                        if (end == mca_text.size()) {
                            break;
                        }
                        begin = end + 1U;
                        continue;
                    }
                    table.resources = parse_resource_header_labels(trimmed);
                    header_parsed = !table.resources.empty();
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                if (trimmed.empty()) {
                    if (!table.row_values.empty()) {
                        break;
                    }
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                auto tokens = split_ascii_whitespace_tokens(trimmed);
                if (tokens.size() <= table.resources.size()) {
                    if (!table.row_values.empty()) {
                        break;
                    }
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                auto row_values = std::vector<std::string>{};
                row_values.reserve(table.resources.size());
                auto row_valid = true;
                for (size_t i = 0U; i < table.resources.size(); ++i) {
                    if (!is_numeric_or_dash_token(tokens[i])) {
                        row_valid = false;
                        break;
                    }
                    row_values.emplace_back(tokens[i] == "-"sv ? "-" : std::string{tokens[i]});
                }

                if (!row_valid) {
                    if (!table.row_values.empty()) {
                        break;
                    }
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                table.row_values.push_back(std::move(row_values));

                if (end == mca_text.size()) {
                    break;
                }
                begin = end + 1U;
            }

            if (table.resources.empty()) {
                table.row_values.clear();
            }
            return table;
        }

        static std::vector<internal::explorer::instruction_info> parse_mca_instruction_info_rows(
                std::string_view mca_text) {
            std::vector<internal::explorer::instruction_info> rows{};
            auto layout = find_mca_instruction_table_layout(mca_text);
            if (!layout.has_value()) {
                return rows;
            }

            size_t begin = 0U;
            bool in_table = false;
            while (begin <= mca_text.size()) {
                auto end = mca_text.find('\n', begin);
                if (end == std::string_view::npos) {
                    end = mca_text.size();
                }
                auto line = mca_text.substr(begin, end - begin);

                if (!in_table) {
                    if (line.find("[1]"sv) != std::string_view::npos &&
                        line.find("Encodings:"sv) != std::string_view::npos &&
                        line.find("Instructions:"sv) != std::string_view::npos) {
                        in_table = true;
                    }
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                auto trimmed = trim_view(line);
                if (trimmed.empty()) {
                    if (!rows.empty()) {
                        break;
                    }
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                auto safe_substring = [&](size_t start, size_t stop) {
                    if (start >= line.size() || stop <= start) {
                        return std::string_view{};
                    }
                    return line.substr(start, std::min(stop, line.size()) - start);
                };

                auto c1 = trim_view(safe_substring(layout->starts[0], layout->starts[1]));
                auto c2 = trim_view(safe_substring(layout->starts[1], layout->starts[2]));
                auto c3 = trim_view(safe_substring(layout->starts[2], layout->starts[3]));
                auto c4 = trim_view(safe_substring(layout->starts[3], layout->starts[4]));
                auto c5 = trim_view(safe_substring(layout->starts[4], layout->starts[5]));
                auto c6 = trim_view(safe_substring(layout->starts[5], layout->starts[6]));
                auto c7 = trim_view(safe_substring(layout->starts[6], layout->encodings_start));
                auto instruction = trim_view(safe_substring(layout->instructions_start, line.size()));

                // Skip non-data lines in/after the section.
                if (!is_numeric_token(c1) || instruction.empty()) {
                    if (!rows.empty()) {
                        break;
                    }
                    if (end == mca_text.size()) {
                        break;
                    }
                    begin = end + 1U;
                    continue;
                }

                rows.push_back(
                        internal::explorer::instruction_info{
                                .uops = std::string{c1},
                                .latency = std::string{c2},
                                .rthroughput = std::string{c3},
                                .may_load = c4 == "*"sv,
                                .may_store = c5 == "*"sv,
                                .has_side_effects = c6.find('U') != std::string_view::npos,
                                .encoding_size = std::string{c7},
                                .instruction =
                                        normalize_instruction_whitespace(demangle_symbols_in_signature(instruction))});

                if (end == mca_text.size()) {
                    break;
                }
                begin = end + 1U;
            }

            return rows;
        }

        static void overlay_rows_with_mca_instruction_text(
                std::vector<internal::explorer::asm_row>& rows,
                std::span<const internal::explorer::instruction_info> row_info) {
            auto row_count = std::min(rows.size(), row_info.size());
            for (size_t i = 0U; i < row_count; ++i) {
                if (!row_info[i].instruction.empty()) {
                    rows[i].instruction = row_info[i].instruction;
                }
            }
        }

        static std::optional<std::string> extract_asm_display_symbol(std::string_view asm_text) {
            static constexpr auto marker = "Begin function "sv;
            size_t begin = 0U;
            while (begin <= asm_text.size()) {
                auto end = asm_text.find('\n', begin);
                if (end == std::string_view::npos) {
                    end = asm_text.size();
                }
                auto line = trim_view(asm_text.substr(begin, end - begin));
                if (auto marker_pos = line.find(marker); marker_pos != std::string_view::npos) {
                    auto symbol = trim_view(line.substr(marker_pos + marker.size()));
                    auto symbol_end = symbol.find_first_of(" \t\r\n");
                    if (symbol_end != std::string_view::npos) {
                        symbol = symbol.substr(0U, symbol_end);
                    }
                    if (!symbol.empty()) {
                        if (auto demangled = demangle_itanium_token(symbol)) {
                            return demangled;
                        }
                        return std::string{symbol};
                    }
                }
                if (end == asm_text.size()) {
                    break;
                }
                begin = end + 1U;
            }
            return std::nullopt;
        }

        static std::string pad_asm_cell(std::string_view text, size_t width) {
            std::string cell{text};
            if (cell.size() < width) {
                cell.append(width - cell.size(), ' ');
            }
            return cell;
        }

        static std::pair<std::string_view, std::string_view> split_asm_instruction_parts(std::string_view instruction) {
            auto trimmed = trim_view(instruction);
            if (trimmed.empty()) {
                return {};
            }

            auto end = trimmed.find_first_of(" \t\r\n");
            if (end == std::string_view::npos) {
                return {trimmed, {}};
            }
            auto mnemonic = trimmed.substr(0U, end);
            auto operands = trim_view(trimmed.substr(end));
            return {mnemonic, operands};
        }

        static std::string align_asm_instruction_mnemonic_slot(std::string_view instruction, size_t mnemonic_width) {
            auto [mnemonic, operands] = split_asm_instruction_parts(instruction);
            if (mnemonic.empty()) {
                return std::string{instruction};
            }

            std::string aligned{};
            aligned.reserve(
                    instruction.size() +
                    (mnemonic_width > mnemonic.size() ? mnemonic_width - mnemonic.size() : size_t{0U}) + 1U);
            aligned.append(mnemonic);
            if (mnemonic.size() < mnemonic_width) {
                aligned.append(mnemonic_width - mnemonic.size(), ' ');
            }
            if (!operands.empty()) {
                aligned.push_back(' ');
                aligned.append(operands);
            }
            return aligned;
        }

        static std::string to_upper_ascii(std::string_view value) {
            std::string out{};
            out.reserve(value.size());
            for (char c : value) {
                if (c >= 'a' && c <= 'z') {
                    out.push_back(static_cast<char>(c - ('a' - 'A')));
                }
                else {
                    out.push_back(c);
                }
            }
            return out;
        }

        static std::string extract_instruction_mnemonic(std::string_view instruction) {
            auto trimmed = trim_view(instruction);
            if (trimmed.empty()) {
                return {};
            }

            auto end = trimmed.find_first_of(" \t\r\n,");
            auto token = end == std::string_view::npos ? trimmed : trimmed.substr(0U, end);
            while (!token.empty() && (token.back() == ':' || token.back() == ',')) {
                token.remove_suffix(1U);
            }
            return to_upper_ascii(token);
        }

        static std::optional<std::string_view> find_instruction_definition_exact(
                std::string_view mnemonic, const std::flat_map<std::string, std::string>& table) {
            if (mnemonic.empty()) {
                return std::nullopt;
            }
            auto it = table.find(std::string{mnemonic});
            if (it == table.end()) {
                return std::nullopt;
            }
            return it->second;
        }

        static std::optional<std::string_view> lookup_instruction_definition_in_table(
                std::string_view mnemonic, const std::flat_map<std::string, std::string>& table) {
            if (auto hit = find_instruction_definition_exact(mnemonic, table)) {
                return hit;
            }

            auto dot = mnemonic.find('.');
            if (dot != std::string_view::npos && dot > 0U) {
                if (auto hit = find_instruction_definition_exact(mnemonic.substr(0U, dot), table)) {
                    return hit;
                }
            }
            return std::nullopt;
        }

        static size_t count_instruction_definition_hits(
                std::span<const internal::explorer::asm_row> rows,
                const std::flat_map<std::string, std::string>& table) {
            auto hits = size_t{0U};
            for (const auto& row : rows) {
                auto mnemonic = extract_instruction_mnemonic(row.instruction);
                if (!mnemonic.empty() && lookup_instruction_definition_in_table(mnemonic, table).has_value()) {
                    ++hits;
                }
            }
            return hits;
        }

        static const std::flat_map<std::string, std::string>& select_instruction_definition_table(
                std::span<const internal::explorer::asm_row> rows) {
            auto arm_hits = count_instruction_definition_hits(rows, tables::ARM);
            auto x86_hits = count_instruction_definition_hits(rows, tables::X86);
            if (arm_hits > x86_hits) {
                return tables::ARM;
            }
            if (x86_hits > arm_hits) {
                return tables::X86;
            }
            if constexpr (internal::platform::is_arm64) {
                return tables::ARM;
            }
            return tables::X86;
        }

        static std::vector<std::string> build_instruction_definitions(
                std::span<const internal::explorer::asm_row> rows) {
            std::vector<std::string> definitions{};
            definitions.reserve(rows.size());
            if (rows.empty()) {
                return definitions;
            }

            auto* primary = &select_instruction_definition_table(rows);
            auto* secondary = primary == &tables::ARM ? &tables::X86 : &tables::ARM;
            for (const auto& row : rows) {
                auto mnemonic = extract_instruction_mnemonic(row.instruction);
                if (mnemonic.empty()) {
                    definitions.emplace_back();
                    continue;
                }

                auto definition = lookup_instruction_definition_in_table(mnemonic, *primary);
                if (!definition) {
                    definition = lookup_instruction_definition_in_table(mnemonic, *secondary);
                }
                definitions.push_back(definition ? std::string{*definition} : std::string{});
            }
            return definitions;
        }

        static asm_summary summarize_asm_artifact(std::string_view asm_text, std::string_view dump_text) {
            auto summary = asm_summary{};
            if (asm_text.empty()) {
                return summary;
            }

            auto streams = std::array{opcode::operation_stream_input{.name = "asm", .disassembly = asm_text}};
            auto mapped = opcode::map_operation_streams(streams);
            if (mapped.streams.empty()) {
                return summary;
            }

            auto& operations = mapped.streams.front().operations;
            summary.operations = operations.size();
            summary.opcode_counts.reserve(mapped.opcode_table.size());
            for (const auto& operation : operations) {
                append_opcode_count(summary.opcode_counts, operation.mnemonic);
            }

            summary.rows = parse_dump_rows(dump_text);
            if (summary.rows.empty()) {
                summary.rows.reserve(operations.size());
                for (const auto& operation : operations) {
                    summary.rows.push_back(
                            internal::explorer::asm_row{
                                    .offset = {},
                                    .encodings = {},
                                    .instruction = format_asm_instruction_text(operation)});
                }
            }
            return summary;
        }

        static void render_asm_opcode_table(const asm_summary& summary, std::ostream& os) {
            constexpr auto diff_indent = "\t"sv;
            auto opcode_width = std::string_view{"  opcode"}.size();
            auto count_width = std::string_view{"count"}.size();

            for (const auto& [opcode, count] : summary.opcode_counts) {
                opcode_width = std::max(opcode_width, opcode.size() + 2U);
                count_width = std::max(count_width, "{}"_format(count).size());
            }

            os << diff_indent << pad_asm_cell("  opcode", opcode_width) << " | " << pad_asm_cell("count", count_width)
               << '\n';
            os << diff_indent << std::string(opcode_width, '-') << "-+-" << std::string(count_width, '-') << '\n';

            if (summary.opcode_counts.empty()) {
                os << diff_indent << pad_asm_cell("  <none>", opcode_width) << " | " << pad_asm_cell("0", count_width)
                   << '\n';
                return;
            }

            for (const auto& [opcode, count] : summary.opcode_counts) {
                os << diff_indent << pad_asm_cell("  {}"_format(opcode), opcode_width) << " | "
                   << pad_asm_cell("{}"_format(count), count_width) << '\n';
            }
        }

        static void render_asm_instruction_rows(const asm_summary& summary, std::ostream& os) {
            constexpr auto diff_indent = "\t"sv;
            auto line_width = std::string_view{"  line"}.size();
            auto offset_width = std::string_view{"offset"}.size();
            auto encoding_width = std::string_view{"encodings"}.size();
            auto instruction_width = std::string_view{"instruction"}.size();
            auto mnemonic_width = size_t{0U};
            for (size_t i = 0U; i < summary.rows.size(); ++i) {
                auto [mnemonic, _] = split_asm_instruction_parts(summary.rows[i].instruction);
                mnemonic_width = std::max(mnemonic_width, mnemonic.size());
            }
            for (size_t i = 0U; i < summary.rows.size(); ++i) {
                auto aligned_instruction =
                        align_asm_instruction_mnemonic_slot(summary.rows[i].instruction, mnemonic_width);
                line_width = std::max(line_width, "  [{}]"_format(i).size());
                offset_width = std::max(offset_width, summary.rows[i].offset.size());
                encoding_width = std::max(encoding_width, summary.rows[i].encodings.size());
                instruction_width = std::max(instruction_width, aligned_instruction.size());
            }

            os << '\n';
            os << "assembly:\n";
            os << diff_indent << pad_asm_cell("  line", line_width) << " | " << pad_asm_cell("offset", offset_width)
               << " | " << pad_asm_cell("encodings", encoding_width) << " | "
               << pad_asm_cell("instruction", instruction_width) << '\n';
            os << diff_indent << std::string(line_width, '-') << "-+-" << std::string(offset_width, '-') << "-+-"
               << std::string(encoding_width, '-') << "-+-" << std::string(instruction_width, '-') << '\n';

            if (summary.rows.empty()) {
                os << diff_indent << pad_asm_cell("  <none>", line_width) << " | " << pad_asm_cell("", offset_width)
                   << " | " << pad_asm_cell("", encoding_width) << " | " << pad_asm_cell("", instruction_width) << '\n';
                return;
            }

            for (size_t i = 0U; i < summary.rows.size(); ++i) {
                auto aligned_instruction =
                        align_asm_instruction_mnemonic_slot(summary.rows[i].instruction, mnemonic_width);
                os << diff_indent << pad_asm_cell("  [{}]"_format(i), line_width) << " | "
                   << pad_asm_cell(summary.rows[i].offset, offset_width) << " | "
                   << pad_asm_cell(summary.rows[i].encodings, encoding_width) << " | "
                   << pad_asm_cell(aligned_instruction, instruction_width) << '\n';
            }
        }

        static void render_asm_artifact_summary_and_body(
                const analysis_result& result,
                std::string_view dump_text,
                std::span<const internal::explorer::instruction_info> row_info,
                std::ostream& os) {
            auto summary = summarize_asm_artifact(result.artifact_text, dump_text);
            overlay_rows_with_mca_instruction_text(summary.rows, row_info);
            os << "asm:\n";
            if (auto symbol = extract_asm_display_symbol(result.artifact_text)) {
                os << "symbol: {}\n"_format(*symbol);
            }
            os << "operations: {}\n"_format(summary.operations);
            render_asm_opcode_table(summary, os);
            render_asm_instruction_rows(summary, os);
        }

        static std::string format_delta_level_summary_line(const delta_level_record& level) {
            auto label = level.label.empty() ? "{}"_format(level.level) : level.label;
            auto line = "  {} success={}"_format(label, level.success ? "true"sv : "false"sv);
            if (!level.success) {
                line.append(" | exit_code={}"_format(level.exit_code));
            }
            line.append(" | operations={}"_format(level.operations.size()));
            auto opcode_counts = summarize_level_opcodes(level.operations);
            line.append(" | ");
            line.append(summarize_opcode_counts_inline(opcode_counts));
            return line;
        }

        static constexpr char delta_row_marker(delta_row_kind kind) {
            switch (kind) {
                case delta_row_kind::unchanged:
                    return '=';
                case delta_row_kind::modified:
                    return '*';
                case delta_row_kind::removed:
                    return '-';
                case delta_row_kind::inserted:
                    return '+';
            }
            return '?';
        }

        static std::string truncate_ellipsis(std::string_view text, size_t max_width) {
            if (max_width == 0U) {
                return std::string{};
            }
            if (text.size() <= max_width) {
                return std::string{text};
            }
            if (max_width <= 3U) {
                return std::string{text.substr(0U, max_width)};
            }
            std::string out{text.substr(0U, max_width - 3U)};
            out.append("...");
            return out;
        }

        static std::string padded_column(std::string_view text, size_t width) {
            auto col = truncate_ellipsis(text, width);
            if (col.size() < width) {
                col.append(width - col.size(), ' ');
            }
            return col;
        }

        static std::string summarize_operation(const delta_operation& operation) {
            auto body = operation.triplet.empty() ? operation.opcode : operation.triplet;
            return "[{}] {}:{}"_format(operation.ordinal, operation.opcode_uid, body);
        }

        struct delta_match_key {
            std::string_view mnemonic{};
            std::string_view dst_bucket{"none"sv};
            std::string_view src_bucket{"none"sv};
            bool valid{false};
        };

        static constexpr bool ascii_is_space(char c) noexcept {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }

        static constexpr bool ascii_is_digit(char c) noexcept {
            return c >= '0' && c <= '9';
        }

        static std::string_view trim_ascii(std::string_view value) {
            while (!value.empty() && ascii_is_space(value.front())) {
                value.remove_prefix(1U);
            }
            while (!value.empty() && ascii_is_space(value.back())) {
                value.remove_suffix(1U);
            }
            return value;
        }

        static std::string_view first_token(std::string_view value) {
            value = trim_ascii(value);
            if (value.empty()) {
                return {};
            }

            auto end = value.find_first_of(" \t");
            if (end == std::string_view::npos) {
                return value;
            }
            return value.substr(0U, end);
        }

        static std::string_view lower_token(std::string_view token, std::array<char, 32>& scratch) {
            auto trimmed = trim_ascii(token);
            while (!trimmed.empty() && (trimmed.front() == '*' || trimmed.front() == '%')) {
                trimmed.remove_prefix(1U);
            }
            while (!trimmed.empty() &&
                   (trimmed.back() == ',' || trimmed.back() == ':' || trimmed.back() == ')' || trimmed.back() == '(')) {
                trimmed.remove_suffix(1U);
            }
            if (trimmed.empty()) {
                return {};
            }

            auto count = std::min(trimmed.size(), scratch.size());
            for (size_t i = 0U; i < count; ++i) {
                scratch[i] = utils::char_tolower(trimmed[i]);
            }
            return std::string_view{scratch.data(), count};
        }

        static std::string_view classify_register_bucket(std::string_view token) {
            if (token.empty()) {
                return "other"sv;
            }

            if (token.starts_with("xmm"sv)) {
                return "vec128"sv;
            }
            if (token.starts_with("ymm"sv)) {
                return "vec256"sv;
            }
            if (token.starts_with("zmm"sv)) {
                return "vec512"sv;
            }

            static constexpr auto gpr64_named =
                    std::array{"rax"sv, "rbx"sv, "rcx"sv, "rdx"sv, "rsi"sv, "rdi"sv, "rbp"sv, "rsp"sv, "rip"sv};
            if (std::ranges::find(gpr64_named, token) != gpr64_named.end()) {
                return "gpr64"sv;
            }

            static constexpr auto gpr32_named =
                    std::array{"eax"sv, "ebx"sv, "ecx"sv, "edx"sv, "esi"sv, "edi"sv, "ebp"sv, "esp"sv, "eip"sv};
            if (std::ranges::find(gpr32_named, token) != gpr32_named.end()) {
                return "gpr32"sv;
            }

            static constexpr auto gpr16_named =
                    std::array{"ax"sv, "bx"sv, "cx"sv, "dx"sv, "si"sv, "di"sv, "bp"sv, "sp"sv, "ip"sv};
            if (std::ranges::find(gpr16_named, token) != gpr16_named.end()) {
                return "gpr16"sv;
            }

            static constexpr auto gpr8_named = std::array{
                    "al"sv, "ah"sv, "bl"sv, "bh"sv, "cl"sv, "ch"sv, "dl"sv, "dh"sv, "sil"sv, "dil"sv, "spl"sv, "bpl"sv};
            if (std::ranges::find(gpr8_named, token) != gpr8_named.end()) {
                return "gpr8"sv;
            }

            if (token.size() >= 2U && token[0] == 'r') {
                auto suffix = token.back();
                auto digits = token.substr(1U, token.size() - 1U);
                if (suffix == 'd') {
                    digits = token.substr(1U, token.size() - 2U);
                    if (!digits.empty() && std::ranges::all_of(digits, ascii_is_digit)) {
                        return "gpr32"sv;
                    }
                }
                if (suffix == 'w') {
                    digits = token.substr(1U, token.size() - 2U);
                    if (!digits.empty() && std::ranges::all_of(digits, ascii_is_digit)) {
                        return "gpr16"sv;
                    }
                }
                if (suffix == 'b') {
                    digits = token.substr(1U, token.size() - 2U);
                    if (!digits.empty() && std::ranges::all_of(digits, ascii_is_digit)) {
                        return "gpr8"sv;
                    }
                }
                if (std::ranges::all_of(digits, ascii_is_digit)) {
                    return "gpr64"sv;
                }
            }

            return "other"sv;
        }

        static std::string_view classify_operand_bucket(std::string_view operand) {
            auto trimmed = trim_ascii(operand);
            if (trimmed.empty()) {
                return "none"sv;
            }

            if (trimmed.find('[') != std::string_view::npos && trimmed.find(']') != std::string_view::npos) {
                return "mem"sv;
            }

            auto token = first_token(trimmed);
            std::array<char, 32> lowered{};
            auto key = lower_token(token, lowered);
            if (key.empty()) {
                return "other"sv;
            }

            static constexpr auto memory_prefixes = std::array{
                    "byte"sv, "word"sv, "dword"sv, "qword"sv, "xmmword"sv, "ymmword"sv, "zmmword"sv, "ptr"sv};
            if (std::ranges::find(memory_prefixes, key) != memory_prefixes.end()) {
                return "mem"sv;
            }

            if (key.starts_with("0x"sv) || key.starts_with("-0x"sv) || ascii_is_digit(key.front()) ||
                (key.front() == '-' && key.size() >= 2U && ascii_is_digit(key[1]))) {
                return "imm"sv;
            }

            if (key.front() == '<') {
                return "other"sv;
            }

            auto reg_bucket = classify_register_bucket(key);
            if (reg_bucket != "other"sv) {
                return reg_bucket;
            }

            return "other"sv;
        }

        static delta_match_key make_match_key(std::string_view operation_text) {
            operation_text = trim_ascii(operation_text);
            if (operation_text.empty()) {
                return {};
            }

            auto mnemonic = first_token(operation_text);
            if (mnemonic.empty()) {
                return {};
            }

            std::array<char, 32> lowered{};
            auto normalized_mnemonic = lower_token(mnemonic, lowered);
            if (normalized_mnemonic.empty()) {
                return {};
            }

            auto operands_text = trim_ascii(operation_text.substr(mnemonic.size()));
            auto comma = operands_text.find(',');
            auto dst_operand = comma == std::string_view::npos ? operands_text : operands_text.substr(0U, comma);
            auto src_operand = comma == std::string_view::npos ? std::string_view{} : operands_text.substr(comma + 1U);

            return delta_match_key{
                    .mnemonic = normalized_mnemonic,
                    .dst_bucket = classify_operand_bucket(dst_operand),
                    .src_bucket = classify_operand_bucket(src_operand),
                    .valid = true};
        }

        static std::vector<delta_match_key> build_match_keys(const std::vector<delta_operation>& operations) {
            std::vector<delta_match_key> keys{};
            keys.reserve(operations.size());
            for (const auto& operation : operations) {
                auto text = operation.triplet.empty() ? std::string_view{operation.opcode}
                                                      : std::string_view{operation.triplet};
                keys.push_back(make_match_key(text));
            }
            return keys;
        }

        static constexpr bool match_keys_equal(const delta_match_key& lhs, const delta_match_key& rhs) {
            return lhs.valid && rhs.valid && lhs.mnemonic == rhs.mnemonic && lhs.dst_bucket == rhs.dst_bucket &&
                   lhs.src_bucket == rhs.src_bucket;
        }

        static delta_alignment find_alignment(
                const std::vector<delta_operation>& baseline, const std::vector<delta_operation>& target) {
            auto alignment = delta_alignment{};
            auto baseline_keys = build_match_keys(baseline);
            auto target_keys = build_match_keys(target);
            for (size_t i = 0U; i < baseline.size(); ++i) {
                if (!baseline_keys[i].valid) {
                    continue;
                }
                for (size_t j = 0U; j < target.size(); ++j) {
                    if (!target_keys[j].valid) {
                        continue;
                    }
                    if (!match_keys_equal(baseline_keys[i], target_keys[j])) {
                        continue;
                    }
                    alignment.anchored = true;
                    alignment.baseline_index = i;
                    alignment.target_index = j;
                    alignment.shift = static_cast<long long>(j) - static_cast<long long>(i);
                    return alignment;
                }
            }
            return alignment;
        }

        static std::optional<size_t> find_first_match_key_match(
                std::span<const delta_match_key> operation_keys, const delta_match_key& wanted_key) {
            for (size_t i = 0U; i < operation_keys.size(); ++i) {
                if (!operation_keys[i].valid) {
                    continue;
                }
                if (match_keys_equal(operation_keys[i], wanted_key)) {
                    return i;
                }
            }
            return std::nullopt;
        }

        struct delta_common_anchor {
            size_t baseline_index{};
            std::vector<size_t> target_indices{};
            uint64_t target_index_score{};
        };

        static std::optional<delta_common_anchor> find_common_spectrum_anchor(
                std::span<const delta_level_record* const> levels) {
            if (levels.size() < 3U || levels.front() == nullptr) {
                return std::nullopt;
            }

            auto* baseline = levels.front();
            std::vector<std::vector<delta_match_key>> level_keys{};
            level_keys.reserve(levels.size());
            for (size_t i = 0U; i < levels.size(); ++i) {
                if (levels[i] == nullptr) {
                    return std::nullopt;
                }
                level_keys.push_back(build_match_keys(levels[i]->operations));
            }

            std::optional<delta_common_anchor> best{};
            for (size_t i = 0U; i < baseline->operations.size(); ++i) {
                auto wanted_key = level_keys.front()[i];
                if (!wanted_key.valid) {
                    continue;
                }

                delta_common_anchor candidate{};
                candidate.baseline_index = i;
                candidate.target_indices.reserve(levels.size() - 1U);
                candidate.target_index_score = 0U;

                auto valid = true;
                for (size_t j = 1U; j < levels.size(); ++j) {
                    auto target_index = find_first_match_key_match(level_keys[j], wanted_key);
                    if (!target_index) {
                        valid = false;
                        break;
                    }
                    candidate.target_indices.push_back(*target_index);
                    candidate.target_index_score += static_cast<uint64_t>(*target_index);
                }

                if (!valid) {
                    continue;
                }
                if (!best || candidate.target_index_score < best->target_index_score ||
                    (candidate.target_index_score == best->target_index_score &&
                     candidate.baseline_index < best->baseline_index)) {
                    best = std::move(candidate);
                }
            }

            return best;
        }

        static bool should_use_color(color_mode mode) {
            switch (mode) {
                case color_mode::automatic:
                    return ::isatty(STDOUT_FILENO) == 1;
                case color_mode::always:
                    return true;
                case color_mode::never:
                    return false;
            }
            return false;
        }

        struct delta_render_column {
            const delta_level_record* level{nullptr};
            std::string header{};
            delta_alignment alignment{};
            long long shift{0LL};
            size_t width{0U};
        };

        static const delta_level_record* lookup_delta_level(const delta_report& report, optimization_level level) {
            for (const auto& record : report.levels) {
                if (record.level == level) {
                    return &record;
                }
            }
            return nullptr;
        }

        static std::vector<const delta_level_record*> select_delta_side_by_side_levels(const delta_report& report) {
            std::vector<const delta_level_record*> levels{};
            if (report.mode == delta_mode::pairwise) {
                auto* baseline = lookup_delta_level(report, report.baseline);
                auto* target = lookup_delta_level(report, report.target);
                if (baseline != nullptr) {
                    levels.push_back(baseline);
                }
                if (target != nullptr && target != baseline) {
                    levels.push_back(target);
                }
                return levels;
            }

            levels.reserve(report.levels.size());
            for (const auto& level : report.levels) {
                levels.push_back(&level);
            }
            return levels;
        }

        static bool all_delta_levels_successful(std::span<const delta_render_column> columns) {
            for (const auto& column : columns) {
                if (column.level == nullptr || !column.level->success) {
                    return false;
                }
            }
            return true;
        }

        static delta_row_kind classify_delta_row_kind(
                bool baseline_has, bool current_has, uint64_t baseline_uid, uint64_t current_uid) {
            if (baseline_has && current_has) {
                return baseline_uid == current_uid ? delta_row_kind::unchanged : delta_row_kind::modified;
            }
            if (baseline_has) {
                return delta_row_kind::removed;
            }
            if (current_has) {
                return delta_row_kind::inserted;
            }
            return delta_row_kind::unchanged;
        }

        static std::string marker_prefixed(std::string_view text, char marker) {
            std::string out{};
            out.reserve(text.size() + 2U);
            out.push_back(marker);
            out.push_back(' ');
            out.append(text);
            return out;
        }

        static std::vector<delta_render_column> build_delta_render_columns(
                std::span<const delta_level_record* const> levels) {
            std::vector<delta_render_column> columns{};
            if (levels.empty()) {
                return columns;
            }

            columns.reserve(levels.size());
            auto* baseline = levels.front();
            auto min_width = levels.size() >= 3U ? static_cast<size_t>(24U) : static_cast<size_t>(34U);
            auto max_width = levels.size() >= 3U ? static_cast<size_t>(34U) : static_cast<size_t>(40U);
            auto common_anchor = find_common_spectrum_anchor(levels);

            for (size_t i = 0U; i < levels.size(); ++i) {
                auto* level = levels[i];
                auto alignment = delta_alignment{};
                if (i == 0U) {
                    alignment.anchored = true;
                    alignment.baseline_index = common_anchor ? common_anchor->baseline_index : 0U;
                    alignment.target_index = alignment.baseline_index;
                    alignment.shift = 0LL;
                }
                else if (common_anchor) {
                    auto target_index = common_anchor->target_indices[i - 1U];
                    alignment.anchored = true;
                    alignment.baseline_index = common_anchor->baseline_index;
                    alignment.target_index = target_index;
                    alignment.shift =
                            static_cast<long long>(target_index) - static_cast<long long>(alignment.baseline_index);
                }
                else {
                    alignment = find_alignment(baseline->operations, level->operations);
                }

                auto column = delta_render_column{
                        .level = level,
                        .header = level->label.empty() ? "{}"_format(level->level) : level->label,
                        .alignment = alignment,
                        .shift = alignment.shift};

                size_t max_data_width = 0U;
                for (const auto& operation : level->operations) {
                    max_data_width = std::max(max_data_width, summarize_operation(operation).size());
                }
                column.width =
                        std::clamp(std::max(column.header.size() + 6U, max_data_width + 1U), min_width, max_width);
                columns.push_back(std::move(column));
            }

            return columns;
        }

        static delta_row_kind aggregate_baseline_kind(std::span<const delta_row_kind> compared_kinds) {
            if (compared_kinds.empty()) {
                return delta_row_kind::unchanged;
            }

            auto all_unchanged = true;
            auto any_removed = false;
            auto any_modified = false;
            for (auto kind : compared_kinds) {
                all_unchanged = all_unchanged && (kind == delta_row_kind::unchanged);
                any_removed = any_removed || (kind == delta_row_kind::removed);
                any_modified = any_modified || (kind == delta_row_kind::modified || kind == delta_row_kind::inserted);
            }

            if (all_unchanged) {
                return delta_row_kind::unchanged;
            }
            if (any_removed) {
                return delta_row_kind::removed;
            }
            if (any_modified) {
                return delta_row_kind::modified;
            }
            return delta_row_kind::unchanged;
        }

        static void render_delta_alignment_anchors(
                const delta_report& report,
                std::span<const delta_render_column> columns,
                std::string_view diff_indent,
                std::ostream& os) {
            if (report.mode == delta_mode::pairwise && columns.size() == 2U) {
                auto& target = columns[1];
                if (target.alignment.anchored) {
                    os << ("{}alignment anchor: {}[{}] <-> {}[{}]\n"_format(
                            diff_indent,
                            report.baseline_label,
                            target.alignment.baseline_index,
                            report.target_label,
                            target.alignment.target_index));
                }
                else {
                    os << "{}alignment anchor: none (ordinal alignment)\n"_format(diff_indent);
                }
                return;
            }

            os << "{}alignment anchors:"_format(diff_indent);
            auto anchored_count = 0U;
            std::optional<size_t> shared_baseline_index{};
            auto shared_baseline = true;
            for (size_t i = 1U; i < columns.size(); ++i) {
                auto& column = columns[i];
                if (!column.alignment.anchored) {
                    continue;
                }
                ++anchored_count;
                if (!shared_baseline_index) {
                    shared_baseline_index = column.alignment.baseline_index;
                }
                else if (*shared_baseline_index != column.alignment.baseline_index) {
                    shared_baseline = false;
                }
            }

            if (anchored_count == 0U) {
                os << " none (ordinal alignment)";
                os << '\n';
                return;
            }

            auto baseline_label = report.baseline_label;
            if (shared_baseline && shared_baseline_index.has_value()) {
                os << " {}[{}]"_format(baseline_label, *shared_baseline_index);
                for (size_t i = 1U; i < columns.size(); ++i) {
                    auto& column = columns[i];
                    os << " <-> {}["_format(column.header);
                    if (column.alignment.anchored) {
                        os << column.alignment.target_index;
                    }
                    else {
                        os << "none";
                    }
                    os << "]";
                }
                os << '\n';
                return;
            }

            // Fallback when per-level anchors exist but do not share one baseline index.
            for (size_t i = 1U; i < columns.size(); ++i) {
                auto& column = columns[i];
                if (!column.alignment.anchored) {
                    continue;
                }
                os << " {}[{}] <-> {}[{}]"_format(
                        baseline_label, column.alignment.baseline_index, column.header, column.alignment.target_index);
            }
            os << '\n';
        }

        static std::string diff_heading(const delta_report& report) {
            if (report.mode == delta_mode::spectrum) {
                return "spectrum ({} -> {}):"_format(report.baseline_label, report.target_label);
            }
            return "diff ({} -> {}, full side-by-side):"_format(report.baseline_label, report.target_label);
        }

        struct metric_descriptor {
            std::string name{};
            std::string unit{};
        };

        static const delta_metric_entry* find_metric_entry(const delta_level_record& level, std::string_view name) {
            for (const auto& metric : level.metrics) {
                if (metric.name == name) {
                    return &metric;
                }
            }
            return nullptr;
        }

        static std::vector<metric_descriptor> collect_metric_descriptors(std::span<const delta_render_column> columns) {
            std::vector<metric_descriptor> descriptors{};
            for (const auto& column : columns) {
                if (column.level == nullptr) {
                    continue;
                }
                for (const auto& metric : column.level->metrics) {
                    auto it = std::find_if(
                            descriptors.begin(), descriptors.end(), [&](const metric_descriptor& descriptor) {
                                return descriptor.name == metric.name;
                            });
                    if (it == descriptors.end()) {
                        descriptors.push_back(metric_descriptor{.name = metric.name, .unit = metric.unit});
                    }
                    else if (it->unit.empty() && !metric.unit.empty()) {
                        it->unit = metric.unit;
                    }
                }
            }
            return descriptors;
        }

        static std::string format_metric_cell_value(const delta_metric_entry& metric) {
            if (metric.status != metric_status::ok) {
                return "{}"_format(metric.status);
            }

            if (metric.unit == "count"sv || metric.unit == "bytes"sv) {
                return "{:.0f}"_format(metric.value);
            }
            if (metric.unit == "ms"sv) {
                return "{:.3f}"_format(metric.value);
            }
            return "{:.4f}"_format(metric.value);
        }

        static std::string format_metric_label(const metric_descriptor& metric) {
            if (metric.unit.empty()) {
                return metric.name;
            }
            return "{} ({})"_format(metric.name, metric.unit);
        }

        static void render_delta_metrics_table(std::span<const delta_render_column> columns, std::ostream& os) {
            auto descriptors = collect_metric_descriptors(columns);
            if (columns.empty() || descriptors.empty()) {
                return;
            }

            constexpr auto diff_indent = "\t"sv;
            auto metric_width = std::string_view{"  metric"}.size();
            auto value_width = std::string_view{"status"}.size();

            for (const auto& descriptor : descriptors) {
                metric_width = std::max(metric_width, format_metric_label(descriptor).size() + 2U);
            }

            for (const auto& column : columns) {
                value_width = std::max(value_width, column.header.size());
                if (column.level == nullptr) {
                    continue;
                }
                for (const auto& descriptor : descriptors) {
                    auto metric = find_metric_entry(*column.level, descriptor.name);
                    auto cell = metric != nullptr ? format_metric_cell_value(*metric) : std::string{"na"};
                    value_width = std::max(value_width, cell.size());
                }
            }
            value_width = std::max(value_width, static_cast<size_t>(10U));

            os << '\n';
            os << "metrics:\n";
            os << diff_indent << padded_column("  metric", metric_width);
            for (const auto& column : columns) {
                os << " | " << padded_column(column.header, value_width);
            }
            os << '\n';
            os << diff_indent << std::string(metric_width, '-');
            for (size_t i = 0U; i < columns.size(); ++i) {
                os << "-+-" << std::string(value_width, '-');
            }
            os << '\n';

            for (const auto& descriptor : descriptors) {
                os << diff_indent << padded_column("  {}"_format(format_metric_label(descriptor)), metric_width);
                for (const auto& column : columns) {
                    auto cell = std::string{"na"};
                    if (column.level != nullptr) {
                        if (auto metric = find_metric_entry(*column.level, descriptor.name); metric != nullptr) {
                            cell = format_metric_cell_value(*metric);
                        }
                    }
                    os << " | " << padded_column(cell, value_width);
                }
                os << '\n';
            }
        }

        static void render_delta_side_by_side(
                const delta_report& report,
                std::span<const delta_render_column> columns,
                bool show_color,
                color_scheme delta_color_scheme_value,
                std::ostream& os) {
            if (columns.size() < 2U || !all_delta_levels_successful(columns)) {
                return;
            }

            auto palette = resolve_delta_color_palette(delta_color_scheme_value);
            auto row_colors = std::array{palette.unchanged, palette.modified, palette.removed, palette.inserted};
            constexpr auto diff_indent = "\t"sv;
            constexpr size_t row_lead_width = 2U;

            os << '\n';
            os << diff_heading(report) << '\n';
            render_delta_alignment_anchors(report, columns, diff_indent, os);

            os << diff_indent << padded_column("  {}"_format(columns[0].header), columns[0].width + row_lead_width);
            for (size_t i = 1U; i < columns.size(); ++i) {
                os << " | " << padded_column(columns[i].header, columns[i].width + row_lead_width);
            }
            os << '\n';
            os << diff_indent << std::string(columns[0].width + row_lead_width, '-');
            for (size_t i = 1U; i < columns.size(); ++i) {
                os << "-+-" << std::string(columns[i].width + row_lead_width, '-');
            }
            os << '\n';

            auto baseline_size = static_cast<long long>(columns[0].level->operations.size());
            auto row_start = 0LL;
            auto row_end = baseline_size - 1LL;

            for (const auto& column : columns) {
                auto size = static_cast<long long>(column.level->operations.size());
                row_start = std::min(row_start, -column.shift);
                row_end = std::max(row_end, size - 1LL - column.shift);
            }

            for (auto row = row_start; row <= row_end; ++row) {
                auto baseline_index = row;
                auto baseline_has = baseline_index >= 0LL && baseline_index < baseline_size;
                uint64_t baseline_uid{};
                if (baseline_has) {
                    baseline_uid = columns[0].level->operations[static_cast<size_t>(baseline_index)].opcode_uid;
                }

                std::vector<delta_row_kind> row_kinds(columns.size(), delta_row_kind::unchanged);
                for (size_t i = 1U; i < columns.size(); ++i) {
                    auto& column = columns[i];
                    auto level_size = static_cast<long long>(column.level->operations.size());
                    auto level_index = row + column.shift;
                    auto level_has = level_index >= 0LL && level_index < level_size;
                    uint64_t level_uid{};
                    if (level_has) {
                        auto& operation = column.level->operations[static_cast<size_t>(level_index)];
                        level_uid = operation.opcode_uid;
                    }
                    row_kinds[i] = classify_delta_row_kind(baseline_has, level_has, baseline_uid, level_uid);
                }
                row_kinds[0] = baseline_has
                                     ? aggregate_baseline_kind(std::span<const delta_row_kind>{row_kinds}.subspan(1U))
                                     : delta_row_kind::unchanged;

                os << diff_indent;
                for (size_t i = 0U; i < columns.size(); ++i) {
                    if (i > 0U) {
                        os << " | ";
                    }

                    auto& column = columns[i];
                    auto level_size = static_cast<long long>(column.level->operations.size());
                    auto level_index = row + column.shift;
                    auto level_has = level_index >= 0LL && level_index < level_size;
                    std::string summary{};
                    if (level_has) {
                        auto& operation = column.level->operations[static_cast<size_t>(level_index)];
                        summary = summarize_operation(operation);
                    }

                    auto kind = row_kinds[i];
                    auto marker = level_has ? delta_row_marker(kind) : '-';
                    auto text = padded_column(marker_prefixed(summary, marker), column.width + row_lead_width);

                    if (show_color && level_has) {
                        os << row_colors[static_cast<size_t>(kind)] << text << "\x1b[0m";
                    }
                    else {
                        os << text;
                    }
                }
                os << '\n';
            }
        }

        static void render_delta_report_table(
                const delta_report& report,
                bool verbose,
                color_mode color_mode_value,
                color_scheme delta_color_scheme_value,
                std::ostream& os) {
            os << "delta: {}\n"_format(report.success ? "valid"sv : "invalid"sv);
            os << "mode: {}\n"_format(report.mode);
            os << "symbol: {}\n"_format(report.symbol_display);
            os << "baseline: {}\n"_format(report.baseline_label);
            os << "target: {}\n"_format(report.target_label);
            os << ("changes: unchanged={} modified={} inserted={} removed={} moved={}\n"_format(
                    report.counters.unchanged_count,
                    report.counters.modified_count,
                    report.counters.inserted_count,
                    report.counters.removed_count,
                    report.counters.moved_count));
            os << "opcode table entries: {}\n"_format(report.opcode_table.size());

            os << "levels:\n";
            for (const auto& level : report.levels) {
                os << "{}\n"_format(format_delta_level_summary_line(level));
            }

            if (!report.success) {
                os << "delta is invalid; skipping diff and metrics\n";
                if (verbose) {
                    for (const auto& level : report.levels) {
                        if (level.diagnostics_text.empty()) {
                            continue;
                        }
                        os << "diagnostics:\n";
                        os << level.diagnostics_text;
                        if (!level.diagnostics_text.ends_with('\n')) {
                            os << '\n';
                        }
                    }
                }
                return;
            }

            auto levels = select_delta_side_by_side_levels(report);
            auto render_columns = build_delta_render_columns(levels);
            auto show_color = should_use_color(color_mode_value);
            render_delta_side_by_side(report, render_columns, show_color, delta_color_scheme_value, os);
            render_delta_metrics_table(render_columns, os);

            if (!verbose) {
                return;
            }

            if (!report.opcode_table.empty()) {
                os << "opcode table:\n";
                for (const auto& entry : report.opcode_table) {
                    os << "  [{}] {}\n"_format(entry.opcode_uid, entry.opcode);
                }
            }

            for (const auto& level : report.levels) {
                auto label = level.label.empty() ? "{}"_format(level.level) : level.label;
                os << "{} operations:\n"_format(label);
                if (level.operations.empty()) {
                    os << "  <none>\n";
                }
                for (const auto& op : level.operations) {
                    os << ("  {}: uid={} opcode={} triplet={}\n"_format(
                            op.ordinal, op.opcode_uid, op.opcode, op.triplet));
                }
                if (!level.diagnostics_text.empty()) {
                    os << "diagnostics:\n";
                    os << level.diagnostics_text;
                    if (!level.diagnostics_text.ends_with('\n')) {
                        os << '\n';
                    }
                }
            }
        }

        static void render_delta_report_json(const delta_report& report, std::ostream& os) {
            auto payload = make_delta_output_record(report);
            std::string json{};
            auto ec = glz::write_json(payload, json);
            if (ec) {
                throw std::runtime_error("failed to serialize delta output");
            }
            os << json << '\n';
        }

        static void render_delta_report(
                const delta_report& report,
                output_mode mode,
                bool verbose,
                color_mode color_mode_value,
                color_scheme delta_color_scheme_value,
                std::ostream& os) {
            if (mode == output_mode::json) {
                render_delta_report_json(report, os);
                return;
            }
            render_delta_report_table(report, verbose, color_mode_value, delta_color_scheme_value, os);
        }

        static const snapshot_record* find_snapshot_record(const repl_state& state, std::string_view name) {
            for (const auto& snapshot : state.snapshot_data.snapshots) {
                if (snapshot.name == name) {
                    return &snapshot;
                }
            }
            return nullptr;
        }

        static const delta_level_record* find_delta_level_record(const delta_report& report, optimization_level level) {
            for (const auto& level_record : report.levels) {
                if (level_record.level == level) {
                    return &level_record;
                }
            }
            return nullptr;
        }

        static void remap_delta_level_operations(
                std::vector<delta_level_record>& levels, std::vector<delta_opcode_entry>& opcode_table) {
            auto interner = opcode::opcode_interner{};
            for (auto& level_record : levels) {
                for (auto& operation : level_record.operations) {
                    operation.opcode_uid = interner.intern(operation.opcode);
                }
            }

            opcode_table.clear();
            auto entries = interner.opcode_entries();
            opcode_table.reserve(entries.size());
            for (const auto& entry : entries) {
                opcode_table.push_back(delta_opcode_entry{.opcode_uid = entry.uid, .opcode = entry.mnemonic});
            }
        }

        static delta_change_counters compute_pairwise_delta_counters(
                const delta_level_record& baseline_level, const delta_level_record& target_level) {
            auto counters = delta_change_counters{};
            if (!baseline_level.success || !target_level.success) {
                return counters;
            }

            auto overlap = std::min(baseline_level.operations.size(), target_level.operations.size());
            for (size_t i = 0U; i < overlap; ++i) {
                if (baseline_level.operations[i].opcode_uid == target_level.operations[i].opcode_uid) {
                    ++counters.unchanged_count;
                }
                else {
                    ++counters.modified_count;
                }
            }

            if (baseline_level.operations.size() > overlap) {
                counters.removed_count = baseline_level.operations.size() - overlap;
            }
            if (target_level.operations.size() > overlap) {
                counters.inserted_count = target_level.operations.size() - overlap;
            }
            return counters;
        }

        static delta_report collect_snapshot_pairwise_delta_report(
                const startup_config& cfg,
                const repl_state& state,
                std::string_view snapshot_name,
                optimization_level compare_opt) {
            auto* snapshot = find_snapshot_record(state, snapshot_name);
            if (snapshot == nullptr) {
                throw std::runtime_error("unknown snapshot: {}"_format(snapshot_name));
            }

            auto current_request = make_analysis_request(cfg, state);
            auto snapshot_request = current_request;
            snapshot_request.decl_cells = snapshot->decl_cells;
            snapshot_request.exec_cells = snapshot->exec_cells;

            auto delta = delta_request{.mode = delta_mode::pairwise, .symbol = std::nullopt, .target = compare_opt};
            auto current_report = collect_delta_report(current_request, delta);
            auto snapshot_report = collect_delta_report(snapshot_request, delta);

            auto* current_level = find_delta_level_record(current_report, compare_opt);
            auto* snapshot_level = find_delta_level_record(snapshot_report, compare_opt);
            if (current_level == nullptr || snapshot_level == nullptr) {
                throw std::runtime_error("failed to collect delta levels for {}"_format(compare_opt));
            }

            auto report = delta_report{};
            report.mode = delta_mode::pairwise;
            report.baseline = optimization_level::o0;
            report.target = optimization_level::o2;
            report.baseline_label = "current";
            report.target_label = std::string{snapshot_name};
            report.symbol = current_report.symbol.empty() ? snapshot_report.symbol : current_report.symbol;
            report.symbol_display = current_report.symbol_display.empty() ? snapshot_report.symbol_display
                                                                          : current_report.symbol_display;

            auto current_level_record = *current_level;
            current_level_record.level = report.baseline;
            current_level_record.label = report.baseline_label;
            auto snapshot_level_record = *snapshot_level;
            snapshot_level_record.level = report.target;
            snapshot_level_record.label = report.target_label;

            report.levels = {std::move(current_level_record), std::move(snapshot_level_record)};
            remap_delta_level_operations(report.levels, report.opcode_table);
            report.success = report.levels[0].success && report.levels[1].success;
            if (report.success) {
                report.counters = compute_pairwise_delta_counters(report.levels[0], report.levels[1]);
            }
            else {
                report.counters = {};
            }
            return report;
        }

        static bool parse_delta_command_args(
                std::string_view raw_arg, delta_request& delta, bool& target_explicit, std::ostream& err) {
            auto args = trim_view(raw_arg);
            target_explicit = false;
            if (args.empty()) {
                return true;
            }

            std::optional<std::string> symbol{};
            std::optional<optimization_level> target{};
            while (!args.empty()) {
                auto split = args.find_first_of(" \t\r\n");
                auto token = split == std::string_view::npos ? args : args.substr(0U, split);
                args = split == std::string_view::npos ? std::string_view{} : trim_view(args.substr(split + 1U));
                token = trim_view(token);
                if (token.empty() || token == "@last"sv) {
                    continue;
                }

                if (utils::str_case_eq(token, "spectrum"sv)) {
                    delta.mode = delta_mode::spectrum;
                    continue;
                }

                optimization_level parsed_level{};
                if (try_parse_optimization_level(token, parsed_level)) {
                    if (target && *target != parsed_level) {
                        err << "invalid :delta, multiple optimization targets provided\n";
                        return false;
                    }
                    target = parsed_level;
                    target_explicit = true;
                    continue;
                }

                if (symbol) {
                    err << "invalid :delta, expected at most one symbol token\n";
                    return false;
                }
                symbol = std::string{token};
            }

            if (target) {
                delta.target = *target;
            }
            delta.symbol = symbol;
            return true;
        }

        static bool process_delta_command(
                std::string_view cmd, startup_config& cfg, repl_state& state, std::ostream& out, std::ostream& err) {
            auto arg = command_argument(cmd, ":delta"sv);
            if (!arg) {
                return false;
            }

            if (state.cells.empty()) {
                err << "no stored cells available for delta analysis\n";
                return true;
            }

            auto delta = delta_request{};
            auto target_explicit = false;
            if (!parse_delta_command_args(*arg, delta, target_explicit, err)) {
                return true;
            }

            auto snapshot_name = std::optional<std::string>{};
            if (delta.symbol.has_value()) {
                if (find_snapshot_record(state, *delta.symbol) != nullptr) {
                    snapshot_name = *delta.symbol;
                }
            }

            try {
                auto report = delta_report{};
                if (snapshot_name.has_value()) {
                    if (delta.mode == delta_mode::spectrum) {
                        err << "invalid :delta, snapshot comparison does not support spectrum mode\n";
                        return true;
                    }
                    auto compare_opt = target_explicit ? delta.target : cfg.opt_level;
                    report = collect_snapshot_pairwise_delta_report(cfg, state, *snapshot_name, compare_opt);
                }
                else {
                    auto request = make_analysis_request(cfg, state);
                    report = collect_delta_report(request, delta);
                }
                render_delta_report(report, cfg.output, cfg.verbose, cfg.color, cfg.delta_color_scheme, out);
            } catch (const std::exception& e) {
                err << "delta analysis error: {}\n"_format(e.what());
            }

            return true;
        }

        static void render_analysis_result_compact(const analysis_result& result, std::ostream& os) {
            if (result.kind == analysis_kind::diag) {
                if (result.artifact_text.empty()) {
                    os << "no diagnostics\n";
                    return;
                }
                os << result.artifact_text;
                if (!result.artifact_text.ends_with('\n')) {
                    os << '\n';
                }
                return;
            }

            if (result.kind == analysis_kind::mca || result.kind == analysis_kind::dump ||
                result.kind == analysis_kind::inspect_asm_map || result.kind == analysis_kind::inspect_mca_summary ||
                result.kind == analysis_kind::inspect_mca_heatmap || result.kind == analysis_kind::graph_cfg ||
                result.kind == analysis_kind::graph_call || result.kind == analysis_kind::graph_defuse) {
                os << "{}: {}\n"_format(result.kind, result.success ? "success"sv : "failed"sv);
            }

            if (!result.success && !result.diagnostics_text.empty()) {
                os << result.diagnostics_text;
                if (!result.diagnostics_text.ends_with('\n')) {
                    os << '\n';
                }
                return;
            }

            if (result.artifact_text.empty()) {
                os << "artifact is empty\n";
                return;
            }

            if (result.kind == analysis_kind::asm_text) {
                render_asm_artifact_summary_and_body(result, {} /* dump_text */, {} /* row_info */, os);
                return;
            }

            os << result.artifact_text;
            if (!result.artifact_text.ends_with('\n')) {
                os << '\n';
            }
        }

        static void render_analysis_result_table(const analysis_result& result, bool verbose, std::ostream& os) {
            if (!verbose) {
                render_analysis_result_compact(result, os);
                return;
            }

            os << ("{} result:\n"
                   "  success: {}\n"
                   "  exit_code: {}\n"
                   "  source: {}\n"
                   "  artifact: {}\n"
                   "  stderr: {}\n"_format(
                           result.kind,
                           result.success ? "true"sv : "false"sv,
                           result.exit_code,
                           result.source_path.string(),
                           result.artifact_path.string(),
                           result.stderr_path.string()));

            if (result.kind != analysis_kind::diag && !result.diagnostics_text.empty()) {
                os << "diagnostics:\n";
                os << result.diagnostics_text;
                if (!result.diagnostics_text.ends_with('\n')) {
                    os << '\n';
                }
            }

            if (result.kind == analysis_kind::diag) {
                if (result.artifact_text.empty()) {
                    os << "no diagnostics\n";
                    return;
                }
                os << result.artifact_text;
                if (!result.artifact_text.ends_with('\n')) {
                    os << '\n';
                }
                return;
            }

            if (result.artifact_text.empty()) {
                os << "artifact is empty\n";
                return;
            }

            if (result.kind == analysis_kind::asm_text) {
                render_asm_artifact_summary_and_body(result, {} /* dump_text */, {} /* row_info */, os);
                return;
            }

            os << result.artifact_text;
            if (!result.artifact_text.ends_with('\n')) {
                os << '\n';
            }
        }

        static void render_analysis_result_json(const analysis_result& result, std::ostream& os) {
            analysis_output_record payload{};
            payload.command = "{}"_format(result.kind);
            payload.success = result.success;
            payload.exit_code = result.exit_code;
            payload.source_path = result.source_path.string();
            payload.artifact_path = result.artifact_path.string();
            payload.stderr_path = result.stderr_path.string();
            payload.text = result.artifact_text;
            payload.clang_command = result.command;
            payload.opcode_table = result.opcode_table;
            payload.operations = result.operations;
            payload.metrics.reserve(result.metrics.size());
            for (const auto& metric : result.metrics) {
                payload.metrics.push_back(make_metric_output_record(metric));
            }

            std::string json{};
            auto ec = glz::write_json(payload, json);
            if (ec) {
                throw std::runtime_error("failed to serialize analysis output");
            }
            os << json << '\n';
        }

        static void render_analysis_result(
                const analysis_result& result, output_mode mode, bool verbose, std::ostream& os) {
            if (mode == output_mode::json) {
                render_analysis_result_json(result, os);
                return;
            }
            render_analysis_result_table(result, verbose, os);
        }

        static bool process_analysis_command(
                std::string_view cmd,
                std::string_view command_name,
                analysis_kind kind,
                startup_config& cfg,
                repl_state& state,
                std::ostream& out,
                std::ostream& err) {
            auto arg = command_argument(cmd, command_name);
            if (!arg) {
                return false;
            }

            if (state.cells.empty()) {
                err << "no stored cells available for analysis\n";
                return true;
            }

            try {
                auto request = make_analysis_request(cfg, state);
                if (!arg->empty() && *arg != "@last"sv) {
                    request.symbol = std::string(*arg);
                }
                else if (
                        (kind == analysis_kind::asm_text || kind == analysis_kind::dump || kind == analysis_kind::ir ||
                         kind == analysis_kind::mca) &&
                        arg->empty()) {
                    request.symbol = std::string{"__sontag_main"};
                }

                if (kind == analysis_kind::asm_text && cfg.output != output_mode::json) {
                    auto asm_result = run_analysis(request, kind);
                    if (!asm_result.success) {
                        render_analysis_result(asm_result, cfg.output, cfg.verbose, out);
                        return true;
                    }

                    auto dump_result = run_analysis(request, analysis_kind::dump);
                    auto dump_text =
                            dump_result.success ? std::string_view{dump_result.artifact_text} : std::string_view{};
                    std::vector<internal::explorer::instruction_info> row_info{};
                    auto mca_result = run_analysis(request, analysis_kind::mca);
                    if (mca_result.success) {
                        row_info = parse_mca_instruction_info_rows(mca_result.artifact_text);
                    }
                    render_asm_artifact_summary_and_body(asm_result, dump_text, row_info, out);
                    return true;
                }

                auto result = run_analysis(request, kind);
                render_analysis_result(result, cfg.output, cfg.verbose, out);
            } catch (const std::exception& e) {
                err << "analysis error: {}\n"_format(e.what());
            }

            return true;
        }

        static bool process_asm_explore_command(
                std::string_view cmd, startup_config& cfg, repl_state& state, std::ostream& out, std::ostream& err) {
            auto arg = command_argument(cmd, ":asm"sv);
            if (!arg) {
                return false;
            }

            auto tail = trim_view(*arg);
            if (!tail.starts_with("explore"sv) ||
                (tail.size() > "explore"sv.size() && !is_command_separator(tail["explore"sv.size()]))) {
                return false;
            }

            if (state.cells.empty()) {
                err << "no stored cells available for analysis\n";
                return true;
            }

            auto symbol_arg = trim_view(tail.substr("explore"sv.size()));
            std::optional<std::string> symbol{};
            if (!symbol_arg.empty()) {
                auto split = symbol_arg.find_first_of(" \t\r\n");
                auto token = split == std::string_view::npos ? symbol_arg : trim_view(symbol_arg.substr(0U, split));
                auto extra =
                        split == std::string_view::npos ? std::string_view{} : trim_view(symbol_arg.substr(split + 1U));
                if (!extra.empty()) {
                    err << "invalid :asm explore, expected :asm explore [symbol|@last]\n";
                    return true;
                }
                if (!token.empty() && token != "@last"sv) {
                    symbol = std::string{token};
                }
            }

            try {
                auto request = make_analysis_request(cfg, state);
                request.symbol = symbol.has_value() ? symbol : std::optional<std::string>{"__sontag_main"};
                auto asm_result = run_analysis(request, analysis_kind::asm_text);
                if (!asm_result.success) {
                    render_analysis_result(asm_result, cfg.output, cfg.verbose, out);
                    return true;
                }

                auto dump_result = run_analysis(request, analysis_kind::dump);
                auto dump_text = dump_result.success ? std::string_view{dump_result.artifact_text} : std::string_view{};
                auto summary = summarize_asm_artifact(asm_result.artifact_text, dump_text);
                std::vector<internal::explorer::instruction_info> row_info{};
                auto resource_pressure = internal::explorer::resource_pressure_table{};

                auto mca_result = run_analysis(request, analysis_kind::mca);
                if (mca_result.success) {
                    row_info = parse_mca_instruction_info_rows(mca_result.artifact_text);
                    resource_pressure = parse_mca_resource_pressure_rows(mca_result.artifact_text);
                }
                overlay_rows_with_mca_instruction_text(summary.rows, row_info);

                auto instruction_definitions = build_instruction_definitions(summary.rows);
                std::string_view selected_line_color{};
                std::string_view selected_definition_color{};
                if (should_use_color(cfg.color)) {
                    auto palette = resolve_delta_color_palette(cfg.delta_color_scheme);
                    selected_line_color = palette.inserted;
                    selected_definition_color = palette.modified;
                }
                auto model = internal::explorer::model{
                        .symbol_display =
                                extract_asm_display_symbol(asm_result.artifact_text).value_or("__sontag_main()"),
                        .operations_total = summary.operations,
                        .opcode_counts = summary.opcode_counts,
                        .rows = summary.rows,
                        .row_info = std::move(row_info),
                        .resource_pressure = std::move(resource_pressure),
                        .instruction_definitions = std::move(instruction_definitions),
                        .selected_line_color = selected_line_color,
                        .selected_definition_color = selected_definition_color};
                auto launch = internal::explorer::run(model, out);
                if (launch.status == internal::explorer::launch_status::fallback) {
                    out << "{}\n"_format(launch.message);
                    render_asm_artifact_summary_and_body(asm_result, dump_text, row_info, out);
                }
            } catch (const std::exception& e) {
                err << "analysis error: {}\n"_format(e.what());
            }

            return true;
        }

        static bool process_command(
                std::string_view line, startup_config& cfg, repl_state& state, line_editor& editor, bool& should_quit) {
            auto cmd = trim_view(line);
            if (cmd == ":quit"sv || cmd == ":q"sv) {
                should_quit = true;
                return true;
            }
            if (cmd == ":help"sv) {
                print_help(std::cout);
                return true;
            }
            if (auto clear_arg = command_argument(cmd, ":clear"sv)) {
                if (!clear_arg->empty()) {
                    std::cerr << "invalid :clear, expected no arguments\n";
                    return true;
                }
                clear_terminal(std::cout);
                return true;
            }
            if (auto show_arg = command_argument(cmd, ":show"sv)) {
                if (show_arg->empty()) {
                    std::cerr << "invalid :show, expected config|decl|exec|all\n";
                    return true;
                }

                if (*show_arg == "config"sv) {
                    print_config(cfg, std::cout);
                    return true;
                }

                if (*show_arg == "decl"sv) {
                    print_decl_cells(state, std::cout);
                    std::cout << '\n';
                    return true;
                }

                if (*show_arg == "exec"sv) {
                    print_exec_cells(state, std::cout);
                    std::cout << '\n';
                    return true;
                }

                if (*show_arg == "all"sv || *show_arg == "code"sv || *show_arg == "cells"sv) {
                    print_all_cells(state, std::cout);
                    std::cout << '\n';
                    return true;
                }

                std::cerr << "unknown :show value: {} (expected config|decl|exec|all)\n"_format(*show_arg);
                return true;
            }
            if (auto config_arg = command_argument(cmd, ":config"sv)) {
                if (config_arg->empty()) {
                    (void)run_config_menu(editor, cfg, std::cout, std::cerr);
                    return true;
                }

                auto argument = trim_view(*config_arg);
                if (argument == "reset"sv) {
                    reset_config_defaults(cfg);
                    std::cout << "config reset\n";
                    return true;
                }

                if (argument.contains('=')) {
                    if (apply_config_assignment(cfg, argument, std::cerr)) {
                        std::cout << "updated {}\n"_format(argument);
                    }
                    return true;
                }

                if (print_config_category(cfg, argument, std::cout)) {
                    return true;
                }

                std::cerr << "invalid :config, expected category|key=value|reset\n";
                return true;
            }
            if (auto decl_arg = command_argument(cmd, ":decl"sv)) {
                if (decl_arg->empty()) {
                    std::cerr << "invalid :decl, expected code after command\n";
                    return true;
                }
                (void)append_validated_cell(cfg, state, *decl_arg, true, std::cout, std::cerr);
                return true;
            }
            if (process_declfile_command(cmd, cfg, state)) {
                return true;
            }
            if (process_file_command(cmd, cfg, state)) {
                return true;
            }
            if (process_openfile_command(cmd, cfg, state)) {
                return true;
            }
            if (auto reset_arg = command_argument(cmd, ":reset"sv)) {
                if (reset_arg->empty()) {
                    clear_cells(state);
                    clear_transactions(state);
                    state.next_cell_id = 1U;
                    state.next_tx_id = 1U;
                    persist_cells(state);
                    persist_current_snapshot(state);
                    std::cout << "session reset\n";
                    return true;
                }
                if (*reset_arg == "last"sv) {
                    (void)clear_last_transaction(cfg, state, std::cout, std::cerr);
                    return true;
                }
                if (*reset_arg == "snapshots"sv) {
                    state.snapshot_data = persisted_snapshots{};
                    persist_current_snapshot(state);
                    std::cout << "snapshots reset\n";
                    return true;
                }
                if (auto file_arg = command_argument(*reset_arg, "file"sv)) {
                    if (file_arg->empty()) {
                        std::cerr << "invalid :reset file, expected path after command\n";
                        return true;
                    }
                    (void)clear_file_transaction(*file_arg, cfg, state, std::cout, std::cerr);
                    return true;
                }

                std::cerr << "invalid :reset, expected last|snapshots|file <path>\n";
                return true;
            }
            if (cmd == ":snapshots"sv) {
                print_snapshots(state, std::cout);
                return true;
            }
            if (cmd == ":symbols"sv) {
                if (state.cells.empty()) {
                    std::cerr << "no stored cells available for symbol listing\n";
                    return true;
                }

                try {
                    auto request = make_analysis_request(cfg, state);
                    auto symbols = list_symbols(request);
                    print_symbols(symbols, cfg.verbose, std::cout);
                } catch (const std::exception& e) {
                    std::cerr << "symbol listing error: {}\n"_format(e.what());
                }
                return true;
            }
            if (auto mark_arg = command_argument(cmd, ":mark"sv)) {
                auto name = trim_view(*mark_arg);
                if (name.empty()) {
                    std::cerr << "invalid :mark, expected a snapshot name\n";
                    return true;
                }
                auto decl_cells = collect_cells_by_kind(state, cell_kind::decl);
                auto exec_cells = collect_cells_by_kind(state, cell_kind::exec);
                upsert_snapshot(state.snapshot_data, name, decl_cells, exec_cells);
                persist_snapshots(state);
                std::cout << "marked snapshot '{}' at cell_count={}\n"_format(name, total_cell_count(state));
                return true;
            }
            if (process_delta_command(cmd, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_asm_explore_command(cmd, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":asm"sv, analysis_kind::asm_text, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":ir"sv, analysis_kind::ir, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":diag"sv, analysis_kind::diag, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":mca"sv, analysis_kind::mca, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(
                        cmd, ":inspect asm"sv, analysis_kind::inspect_asm_map, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(
                        cmd,
                        ":inspect mca heatmap"sv,
                        analysis_kind::inspect_mca_heatmap,
                        cfg,
                        state,
                        std::cout,
                        std::cerr)) {
                return true;
            }
            if (process_analysis_command(
                        cmd,
                        ":inspect mca summary"sv,
                        analysis_kind::inspect_mca_summary,
                        cfg,
                        state,
                        std::cout,
                        std::cerr)) {
                return true;
            }
            if (process_analysis_command(
                        cmd, ":inspect mca"sv, analysis_kind::inspect_mca_summary, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(
                        cmd, ":graph cfg"sv, analysis_kind::graph_cfg, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(
                        cmd, ":graph call"sv, analysis_kind::graph_call, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(
                        cmd, ":graph defuse"sv, analysis_kind::graph_defuse, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (cmd.starts_with(":"sv)) {
                std::cerr << "unknown command: {}\n"_format(cmd);
                return true;
            }
            return false;
        }

        static std::optional<std::string> normalize_optional(std::string value) {
            auto trimmed = trim_view(value);
            if (trimmed.empty()) {
                return std::nullopt;
            }
            return std::string(trimmed);
        }

        static constexpr bool try_parse_bool(std::string_view value, bool& out) {
            auto trimmed = trim_view(value);
            if (utils::str_case_eq(trimmed, "true"sv) || utils::str_case_eq(trimmed, "1"sv) ||
                utils::str_case_eq(trimmed, "yes"sv) || utils::str_case_eq(trimmed, "on"sv)) {
                out = true;
                return true;
            }
            if (utils::str_case_eq(trimmed, "false"sv) || utils::str_case_eq(trimmed, "0"sv) ||
                utils::str_case_eq(trimmed, "no"sv) || utils::str_case_eq(trimmed, "off"sv)) {
                out = false;
                return true;
            }
            return false;
        }

    }  // namespace detail

    static constexpr auto banner = R"(
███████╗ ██████╗ ███╗   ██╗████████╗ █████╗  ██████╗ 
██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ 
███████╗██║   ██║██╔██╗ ██║   ██║   ███████║██║  ███╗
╚════██║██║   ██║██║╚██╗██║   ██║   ██╔══██║██║   ██║
███████║╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╔╝
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ 
)";

    void run_repl(startup_config& cfg) {
        detail::apply_build_tool_paths(cfg);
        auto resumed_session = cfg.resume_session;
        auto state = detail::start_session(cfg);
        line_editor editor{cfg};
        std::string line{};
        std::string pending_cell{};
        detail::code_balance_state balance{};
        bool should_quit = false;

        if (cfg.banner_enabled) {
            if (detail::should_use_color(cfg.color)) {
                auto palette = detail::resolve_delta_color_palette(cfg.delta_color_scheme);
                std::cout << palette.inserted << banner << "\x1b[0m\n";
            }
            else {
                std::cout << banner << '\n';
            }
        }
        if (resumed_session) {
            std::cout << "resumed session from: {}\n"_format(*resumed_session);
        }
        std::cout << "session: {}\n"_format(state.session_id);
        std::cout << "session dir: {}\n"_format(state.session_dir.string());
        std::cout << "type :help for commands\n";

        while (!should_quit) {
            std::string prompt{};
            if (pending_cell.empty()) {
                if (detail::should_use_color(cfg.color)) {
                    auto palette = detail::resolve_delta_color_palette(cfg.delta_color_scheme);
                    prompt = "{}sontag > \x1b[0m"_format(palette.inserted);
                }
                else {
                    prompt = "sontag > ";
                }
            }
            else {
                prompt = "...> ";
            }
            auto next_line = editor.read_line(prompt);
            if (!next_line) {
                if (!pending_cell.empty()) {
                    std::cerr << "warning: discarding incomplete cell at EOF\n";
                }
                std::cout << '\n';
                break;
            }
            line = std::move(*next_line);

            if (line.empty()) {
                if (!pending_cell.empty()) {
                    pending_cell.push_back('\n');
                }
                continue;
            }

            if (pending_cell.empty() && detail::process_command(line, cfg, state, editor, should_quit)) {
                continue;
            }

            if (!pending_cell.empty()) {
                pending_cell.push_back('\n');
            }
            pending_cell += line;
            detail::update_code_balance_state(balance, line);

            if (!detail::cell_is_complete(balance)) {
                continue;
            }

            (void)detail::append_validated_cell(cfg, state, pending_cell, false, std::cout, std::cerr);
            pending_cell.clear();
            balance = detail::code_balance_state{};
        }

        return;
    }

    std::optional<int> parse_cli(int argc, char** argv, startup_config& cfg) {
        detail::apply_build_tool_paths(cfg);
        CLI::App app{"sontag"};

        bool show_version = false;
        std::string std_arg{"{}"_format(cfg.language_standard)};
        std::string opt_arg{"{}"_format(cfg.opt_level)};
        std::string output_arg{"{}"_format(cfg.output)};
        std::string color_arg{"{}"_format(cfg.color)};
        std::string color_scheme_arg{"{}"_format(cfg.delta_color_scheme)};
        std::string target_arg{};
        std::string cpu_arg{};
        std::string mca_cpu_arg{};
        std::string resume_arg{};
        std::string cache_dir_arg{cfg.cache_dir.string()};
        std::string history_file_arg{cfg.history_file.string()};
        std::string banner_arg{cfg.banner_enabled ? "true" : "false"};
        bool no_history = false;
        bool no_banner = false;

        app.add_flag("--version", show_version, "Print version and exit");
        app.add_option("--std", std_arg, "C++ standard: c++20|c++23|c++2c");
        app.add_option("-O,--opt", opt_arg, "Optimization level: O0|O1|O2|O3|Ofast|Oz");
        app.add_option("--target", target_arg, "LLVM target triple");
        app.add_option("--cpu", cpu_arg, "Target CPU");
        app.add_option("--mca-cpu", mca_cpu_arg, "CPU model override for llvm-mca");
        app.add_flag("--mca", cfg.mca_enabled, "Enable llvm-mca command support");
        app.add_option("--resume", resume_arg, "Resume session id or latest");
        app.add_option("--cache-dir", cache_dir_arg, "Cache/artifact directory");
        app.add_option("--history-file", history_file_arg, "Persistent REPL history path");
        app.add_flag("--no-history", no_history, "Disable persistent REPL history");
        app.add_option("--banner", banner_arg, "Show startup banner: true|false");
        app.add_flag("--no-banner", no_banner, "Disable startup banner");
        app.add_option("--output", output_arg, "Output mode: table|json");
        app.add_option("--color", color_arg, "Color mode: auto|always|never");
        app.add_option("--color-scheme", color_scheme_arg, "Color scheme: classic|vaporwave");
        app.add_flag("--no-color", "Force color mode to never");
        app.add_flag("--print-config", cfg.print_config, "Print resolved config and exit");
        app.add_flag("--quiet", cfg.quiet, "Suppress non-essential output");
        app.add_flag("--verbose", cfg.verbose, "Enable verbose output");

        try {
            app.parse(argc, argv);
        } catch (const CLI::ParseError& e) {
            return std::optional<int>{app.exit(e)};
        }

        if (cfg.quiet && cfg.verbose) {
            std::cerr << "--quiet and --verbose are mutually exclusive\n";
            return std::optional<int>{2};
        }

        if (!try_parse_cxx_standard(std_arg, cfg.language_standard)) {
            std::cerr << "invalid --std value: {} (expected c++20|c++23|c++2c)\n"_format(std_arg);
            return std::optional<int>{2};
        }
        if (!try_parse_optimization_level(opt_arg, cfg.opt_level)) {
            std::cerr << "invalid --opt value: {} (expected O0|O1|O2|O3|Ofast|Oz)\n"_format(opt_arg);
            return std::optional<int>{2};
        }
        if (!try_parse_output_mode(output_arg, cfg.output)) {
            std::cerr << "invalid --output value: {} (expected table|json)\n"_format(output_arg);
            return std::optional<int>{2};
        }
        if (!try_parse_color_mode(color_arg, cfg.color)) {
            std::cerr << "invalid --color value: {} (expected auto|always|never)\n"_format(color_arg);
            return std::optional<int>{2};
        }
        if (!try_parse_color_scheme(color_scheme_arg, cfg.delta_color_scheme)) {
            std::cerr << "invalid --color-scheme value: {} (expected classic|vaporwave)\n"_format(color_scheme_arg);
            return std::optional<int>{2};
        }
        if (!detail::try_parse_bool(banner_arg, cfg.banner_enabled)) {
            std::cerr << "invalid --banner value: {} (expected true|false)\n"_format(banner_arg);
            return std::optional<int>{2};
        }

        cfg.target_triple = detail::normalize_optional(target_arg);
        cfg.cpu = detail::normalize_optional(cpu_arg);
        cfg.mca_cpu = detail::normalize_optional(mca_cpu_arg);
        cfg.resume_session = detail::normalize_optional(resume_arg);
        cfg.cache_dir = cache_dir_arg;
        cfg.history_file = history_file_arg;
        if (no_history) {
            cfg.history_enabled = false;
        }
        if (no_banner) {
            cfg.banner_enabled = false;
        }

        if (app.get_option("--no-color")->count() > 0U) {
            cfg.color = color_mode::never;
        }

        if (show_version) {
            std::cout << "sontag 0.1.0\n";
            return std::optional<int>{0};
        }

        if (cfg.print_config) {
            detail::print_config(cfg, std::cout);
            return std::optional<int>{0};
        }

        return std::nullopt;
    }

}  // namespace sontag::cli
