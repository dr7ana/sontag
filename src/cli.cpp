#include "sontag/cli.hpp"

#include "editor.hpp"

#include "sontag/analysis.hpp"
#include "sontag/format.hpp"

#include <glaze/glaze.hpp>

#include <CLI/CLI.hpp>

extern "C" {
#include <sys/wait.h>
#include <unistd.h>
}

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
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

    struct persisted_config {
        int schema_version{1};
        std::string clang{};
        std::string cxx_standard{};
        std::string opt_level{};
        std::optional<std::string> target{};
        std::optional<std::string> cpu{};
        std::optional<std::string> mca_cpu{};
        std::string mca_path{"llvm-mca"};
        std::string cache_dir{};
        std::string output{};
        std::string color{};
    };

    struct snapshot_record {
        std::string name{};
        size_t cell_count{};
    };

    struct persisted_snapshots {
        int schema_version{1};
        std::string active_snapshot{"current"};
        std::vector<snapshot_record> snapshots{{snapshot_record{"current", 0U}}};
    };

    struct persisted_cells {
        int schema_version{1};
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
    };

    struct repl_state {
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
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

    struct analysis_output_record {
        std::string command{};
        bool success{false};
        int exit_code{-1};
        std::string source_path{};
        std::string artifact_path{};
        std::string stderr_path{};
        std::string text{};
        std::vector<std::string> clang_command{};
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
    struct meta<sontag::cli::detail::persisted_config> {
        using T = sontag::cli::detail::persisted_config;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "clang",
                       &T::clang,
                       "cxx_standard",
                       &T::cxx_standard,
                       "opt_level",
                       &T::opt_level,
                       "target",
                       &T::target,
                       "cpu",
                       &T::cpu,
                       "mca_cpu",
                       &T::mca_cpu,
                       "mca_path",
                       &T::mca_path,
                       "cache_dir",
                       &T::cache_dir,
                       "output",
                       &T::output,
                       "color",
                       &T::color);
    };

    template <>
    struct meta<sontag::cli::detail::snapshot_record> {
        using T = sontag::cli::detail::snapshot_record;
        static constexpr auto value = object("name", &T::name, "cell_count", &T::cell_count);
    };

    template <>
    struct meta<sontag::cli::detail::persisted_snapshots> {
        using T = sontag::cli::detail::persisted_snapshots;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "active_snapshot",
                       &T::active_snapshot,
                       "snapshots",
                       &T::snapshots);
    };

    template <>
    struct meta<sontag::cli::detail::persisted_cells> {
        using T = sontag::cli::detail::persisted_cells;
        static constexpr auto value = object(
                "schema_version", &T::schema_version, "decl_cells", &T::decl_cells, "exec_cells", &T::exec_cells);
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
                       &T::clang_command);
    };

}  // namespace glz

namespace sontag::cli {

    namespace detail {

        static constexpr auto default_value = "<default>"sv;
        static std::string read_text_file(const fs::path& path);

        static std::string_view optional_or_default(const std::optional<std::string>& value) {
            if (value) {
                return *value;
            }
            return default_value;
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

        static std::optional<size_t> parse_size_t_token(std::string_view token) {
            auto trimmed = trim_view(token);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            size_t value = 0U;
            auto begin = trimmed.data();
            auto end = trimmed.data() + trimmed.size();
            auto [ptr, ec] = std::from_chars(begin, end, value);
            if (ec != std::errc{} || ptr != end) {
                return std::nullopt;
            }
            return value;
        }

        static std::optional<source_location> parse_location_token(
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

        static std::optional<source_range> parse_angle_range(
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

        static std::optional<std::string_view> parse_function_decl_name(std::string_view line) {
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

        static std::optional<size_t> parse_first_line_number(std::string_view line) {
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

        static std::optional<size_t> source_offset_from_location(
                std::string_view source, const std::vector<size_t>& line_offsets, const source_location& location) {
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

        static std::optional<fs::path> parse_path_argument(
                std::string_view command_name, std::string_view raw_argument, std::ostream& err) {
            auto value = trim_view(raw_argument);
            if (value.empty()) {
                err << "invalid " << command_name << ", expected path after command\n";
                return std::nullopt;
            }

            auto has_double_quotes = value.size() >= 2U && value.front() == '"' && value.back() == '"';
            auto has_single_quotes = value.size() >= 2U && value.front() == '\'' && value.back() == '\'';
            if (has_double_quotes || has_single_quotes) {
                value = value.substr(1U, value.size() - 2U);
            }

            if (value.empty()) {
                err << "invalid " << command_name << ", expected non-empty path\n";
                return std::nullopt;
            }

            auto path = fs::path{std::string{value}}.lexically_normal();
            if (path.empty()) {
                err << "invalid " << command_name << ", expected non-empty path\n";
                return std::nullopt;
            }

            if (path.is_relative()) {
                std::error_code ec{};
                auto cwd = fs::current_path(ec);
                if (ec) {
                    err << "failed to resolve current directory for " << command_name << ": " << ec.message() << '\n';
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

        static command_capture_result run_command_capture(const std::vector<std::string>& args) {
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

            return command_capture_result{.exit_code = exit_code, .output = std::move(output)};
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

        static std::optional<driver_ast_info> parse_driver_ast_dump(
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

        static ast_probe_result probe_driver_ast(
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
                err << "file not found: " << path << '\n';
                return false;
            }
            if (!fs::is_regular_file(path, ec) || ec) {
                err << "path is not a regular file: " << path << '\n';
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
                err << "failed to map AST source ranges to file offsets for " << source_path << '\n';
                return std::nullopt;
            }
            if (*function_start_offset > source_text.size() || *body_open_offset >= source_text.size() ||
                *body_close_offset >= source_text.size()) {
                err << "AST source ranges are out of bounds for " << source_path << '\n';
                return std::nullopt;
            }
            if (*body_open_offset >= *body_close_offset || source_text[*body_open_offset] != '{' ||
                source_text[*body_close_offset] != '}') {
                err << "failed to extract driver body from AST range for " << source_path << '\n';
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
            data.cache_dir = cfg.cache_dir.string();
            data.output = "{}"_format(cfg.output);
            data.color = "{}"_format(cfg.color);
            return data;
        }

        static void apply_persisted_config(const persisted_config& data, startup_config& cfg) {
            cfg.clang_path = data.clang;

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

            cfg.target_triple = data.target;
            cfg.cpu = data.cpu;
            cfg.mca_cpu = data.mca_cpu;
            if (data.mca_path.empty()) {
                cfg.mca_path = "llvm-mca";
            }
            else {
                cfg.mca_path = data.mca_path;
            }
            cfg.cache_dir = data.cache_dir;
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

        static void upsert_snapshot(persisted_snapshots& data, std::string_view name, size_t cell_count) {
            auto it = std::find_if(data.snapshots.begin(), data.snapshots.end(), [name](const snapshot_record& entry) {
                return entry.name == name;
            });
            if (it == data.snapshots.end()) {
                data.snapshots.push_back(snapshot_record{std::string(name), cell_count});
                return;
            }
            it->cell_count = cell_count;
        }

        static void persist_snapshots(const repl_state& state) {
            write_json_file(state.snapshot_data, state.snapshots_path);
        }

        static size_t total_cell_count(const repl_state& state) {
            return state.decl_cells.size() + state.exec_cells.size();
        }

        static void persist_cells(const repl_state& state) {
            persisted_cells data{};
            data.decl_cells = state.decl_cells;
            data.exec_cells = state.exec_cells;
            write_json_file(data, state.cells_path);
        }

        static void persist_current_snapshot(repl_state& state) {
            upsert_snapshot(state.snapshot_data, "current"sv, total_cell_count(state));
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
                state.decl_cells = std::move(cell_data.decl_cells);
                state.exec_cells = std::move(cell_data.exec_cells);
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
            os << ("  language_standard={}\n"
                   "  opt_level={}\n"
                   "  target={}\n"
                   "  cpu={}\n"
                   "  clang={}\n"
                   "  mca_cpu={}\n"
                   "  mca_path={}\n"
                   "  cache_dir={}\n"
                   "  output={}\n"
                   "  banner={}\n"
                   "  color={}\n"_format(
                           cfg.language_standard,
                           cfg.opt_level,
                           optional_or_default(cfg.target_triple),
                           optional_or_default(cfg.cpu),
                           cfg.clang_path.string(),
                           optional_or_default(cfg.mca_cpu),
                           cfg.mca_path.string(),
                           cfg.cache_dir.string(),
                           cfg.output,
                           cfg.banner_enabled,
                           cfg.color));
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
            print_cells(state.decl_cells, os, "no declarative cells");
        }

        static void print_exec_cells(const repl_state& state, std::ostream& os) {
            print_cells(state.exec_cells, os, "no executable cells");
        }

        static void print_all_cells(const repl_state& state, std::ostream& os) {
            analysis_request request{};
            request.decl_cells = state.decl_cells;
            request.exec_cells = state.exec_cells;
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

        static bool apply_set_command(startup_config& cfg, std::string_view assignment, std::ostream& err) {
            auto eq = assignment.find('=');
            if (eq == std::string_view::npos) {
                err << "invalid :set, expected key=value\n";
                return false;
            }

            auto key = trim_view(assignment.substr(0, eq));
            auto value = trim_view(assignment.substr(eq + 1U));
            if (key.empty() || value.empty()) {
                err << "invalid :set, key and value must be non-empty\n";
                return false;
            }

            if (key == "std"sv || key == "lang.std"sv) {
                if (!try_parse_cxx_standard(value, cfg.language_standard)) {
                    err << "invalid std: " << value << " (expected c++20|c++23|c++2c)\n";
                    return false;
                }
                return true;
            }

            if (key == "opt"sv || key == "build.opt"sv) {
                if (!try_parse_optimization_level(value, cfg.opt_level)) {
                    err << "invalid opt: " << value << " (expected O0|O1|O2|O3|Ofast|Oz)\n";
                    return false;
                }
                return true;
            }

            if (key == "target"sv || key == "build.target"sv) {
                cfg.target_triple = std::string(value);
                return true;
            }

            if (key == "cpu"sv || key == "build.cpu"sv) {
                cfg.cpu = std::string(value);
                return true;
            }

            if (key == "output"sv) {
                if (!try_parse_output_mode(value, cfg.output)) {
                    err << "invalid output: " << value << " (expected table|json)\n";
                    return false;
                }
                return true;
            }

            if (key == "color"sv) {
                if (!try_parse_color_mode(value, cfg.color)) {
                    err << "invalid color: " << value << " (expected auto|always|never)\n";
                    return false;
                }
                return true;
            }

            err << "unknown :set key: " << key << '\n';
            return false;
        }

        static void print_help(std::ostream& os) {
            static constexpr auto help_text = R"(commands:
  :help
  :clear
  :clear last
  :show <config|decl|exec|all>
  :symbols
  :decl <code>
  :declfile <path>
  :file <path>
  :set <key>=<value>
  :reset
  :mark <name>
  :snapshots
  :asm [symbol|@last]
  :dump [symbol|@last]
  :ir [symbol|@last]
  :diag [symbol|@last]
  :mca [symbol|@last]
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
  :set std=c++23
  :set opt=O3
  :set output=json
  :show all
  :symbols
  :mark baseline
  :asm
  :dump
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
            request.decl_cells = state.decl_cells;
            request.exec_cells = state.exec_cells;
            request.language_standard = cfg.language_standard;
            request.opt_level = cfg.opt_level;
            request.target_triple = cfg.target_triple;
            request.cpu = cfg.cpu;
            request.asm_syntax = cfg.asm_syntax;
            request.mca_cpu = cfg.mca_cpu;
            request.mca_path = cfg.mca_path;
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
            auto request = make_analysis_request(cfg, state);
            request.symbol = std::nullopt;
            request.decl_cells = decl_cells;
            request.exec_cells = exec_cells;

            auto diag = run_analysis(request, analysis_kind::diag);
            return validation_result{.success = diag.success, .diagnostics = std::move(diag.artifact_text)};
        }

        static bool append_validated_cell(
                startup_config& cfg,
                repl_state& state,
                std::string_view cell,
                bool declarative,
                std::ostream& out,
                std::ostream& err) {
            try {
                auto validation = validate_candidate_state(cfg, state, cell, declarative);
                if (!validation.success && !validation.diagnostics.empty()) {
                    err << validation.diagnostics;
                    if (!validation.diagnostics.ends_with('\n')) {
                        err << '\n';
                    }
                }
                if (!validation.success) {
                    err << "cell rejected, state unchanged\n";
                    return false;
                }
            } catch (const std::exception& e) {
                err << "state validation error: " << e.what() << '\n';
                return false;
            }

            if (declarative) {
                state.decl_cells.emplace_back(cell);
                persist_cells(state);
                persist_current_snapshot(state);
                out << "stored decl #" << state.decl_cells.size() << " (state: valid)\n";
                return true;
            }

            state.exec_cells.emplace_back(cell);
            persist_cells(state);
            persist_current_snapshot(state);
            out << "stored cell #" << state.exec_cells.size() << " (state: valid)\n";
            return true;
        }

        static bool replace_with_validated_cells(
                startup_config& cfg,
                repl_state& state,
                std::vector<std::string> decl_cells,
                std::vector<std::string> exec_cells,
                std::string_view success_message,
                std::ostream& out,
                std::ostream& err) {
            try {
                auto validation = validate_state_cells(cfg, state, decl_cells, exec_cells);
                if (!validation.success && !validation.diagnostics.empty()) {
                    err << validation.diagnostics;
                    if (!validation.diagnostics.ends_with('\n')) {
                        err << '\n';
                    }
                }
                if (!validation.success) {
                    err << "cell rejected, state unchanged\n";
                    return false;
                }
            } catch (const std::exception& e) {
                err << "state validation error: " << e.what() << '\n';
                return false;
            }

            state.decl_cells = std::move(decl_cells);
            state.exec_cells = std::move(exec_cells);
            persist_cells(state);
            persist_current_snapshot(state);
            out << success_message << " (state: valid)\n";
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
                    std::cerr << "declfile is empty: " << *path << '\n';
                    return true;
                }
                (void)append_validated_cell(cfg, state, content, true, std::cout, std::cerr);
            } catch (const std::exception& e) {
                std::cerr << "declfile error: " << e.what() << '\n';
            }

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
                auto plan = build_file_load_plan(cfg, *path, std::cerr);
                if (!plan) {
                    return true;
                }

                auto success_message = "loaded file {} (decl_cells={}, exec_cells={})"_format(
                        path->string(), plan->decl_cells.size(), plan->exec_cells.size());
                (void)replace_with_validated_cells(
                        cfg,
                        state,
                        std::move(plan->decl_cells),
                        std::move(plan->exec_cells),
                        success_message,
                        std::cout,
                        std::cerr);
            } catch (const std::exception& e) {
                std::cerr << "file load error: " << e.what() << '\n';
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

            if (state.decl_cells.empty() && state.exec_cells.empty()) {
                err << "no stored cells available for analysis\n";
                return true;
            }

            try {
                auto request = make_analysis_request(cfg, state);
                if (!arg->empty() && *arg != "@last"sv) {
                    request.symbol = std::string(*arg);
                }
                auto result = run_analysis(request, kind);
                render_analysis_result(result, cfg.output, cfg.verbose, out);
            } catch (const std::exception& e) {
                err << "analysis error: " << e.what() << '\n';
            }

            return true;
        }

        static bool process_command(
                const std::string& line, startup_config& cfg, repl_state& state, bool& should_quit) {
            auto cmd = trim_view(line);
            if (cmd == ":quit"sv || cmd == ":q"sv) {
                should_quit = true;
                return true;
            }
            if (cmd == ":help"sv) {
                print_help(std::cout);
                return true;
            }
            if (cmd == ":clear last"sv) {
                if (state.exec_cells.empty()) {
                    std::cout << "no executable cells to clear\n";
                    return true;
                }
                state.exec_cells.pop_back();
                persist_cells(state);
                persist_current_snapshot(state);
                std::cout << "cleared last executable cell\n";
                return true;
            }
            if (cmd == ":clear"sv) {
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

                std::cerr << "unknown :show value: " << *show_arg << " (expected config|decl|exec|all)\n";
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
            if (cmd == ":reset"sv) {
                state.decl_cells.clear();
                state.exec_cells.clear();
                persist_cells(state);
                persist_current_snapshot(state);
                std::cout << "session reset\n";
                return true;
            }
            if (cmd == ":snapshots"sv) {
                print_snapshots(state, std::cout);
                return true;
            }
            if (cmd == ":symbols"sv) {
                if (state.decl_cells.empty() && state.exec_cells.empty()) {
                    std::cerr << "no stored cells available for symbol listing\n";
                    return true;
                }

                try {
                    auto request = make_analysis_request(cfg, state);
                    auto symbols = list_symbols(request);
                    print_symbols(symbols, cfg.verbose, std::cout);
                } catch (const std::exception& e) {
                    std::cerr << "symbol listing error: " << e.what() << '\n';
                }
                return true;
            }
            if (auto mark_arg = command_argument(cmd, ":mark"sv)) {
                auto name = trim_view(*mark_arg);
                if (name.empty()) {
                    std::cerr << "invalid :mark, expected a snapshot name\n";
                    return true;
                }
                upsert_snapshot(state.snapshot_data, name, total_cell_count(state));
                persist_snapshots(state);
                std::cout << "marked snapshot '" << name << "' at cell_count=" << total_cell_count(state) << '\n';
                return true;
            }
            if (auto set_arg = command_argument(cmd, ":set"sv)) {
                auto assignment = trim_view(*set_arg);
                if (apply_set_command(cfg, assignment, std::cerr)) {
                    std::cout << "updated " << assignment << '\n';
                }
                return true;
            }
            if (process_analysis_command(cmd, ":asm"sv, analysis_kind::asm_text, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":dump"sv, analysis_kind::dump, cfg, state, std::cout, std::cerr)) {
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
                std::cerr << "unknown command: " << cmd << '\n';
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

        static bool try_parse_bool(std::string_view value, bool& out) {
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
        auto resumed_session = cfg.resume_session;
        auto state = detail::start_session(cfg);
        line_editor editor{cfg};
        std::string line{};
        std::string pending_cell{};
        detail::code_balance_state balance{};
        bool should_quit = false;

        if (cfg.banner_enabled) {
            std::cout << banner << '\n';
        }
        if (resumed_session) {
            std::cout << "resumed session from: " << *resumed_session << '\n';
        }
        std::cout << "session: " << state.session_id << '\n';
        std::cout << "session dir: " << state.session_dir.string() << '\n';
        std::cout << "type :help for commands\n";

        while (!should_quit) {
            std::string_view prompt = pending_cell.empty() ? "sontag > "sv : "...> "sv;
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

            if (pending_cell.empty() && detail::process_command(line, cfg, state, should_quit)) {
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
        CLI::App app{"sontag"};

        bool show_version = false;
        std::string std_arg{"{}"_format(cfg.language_standard)};
        std::string opt_arg{"{}"_format(cfg.opt_level)};
        std::string output_arg{"{}"_format(cfg.output)};
        std::string color_arg{"{}"_format(cfg.color)};
        std::string target_arg{};
        std::string cpu_arg{};
        std::string mca_cpu_arg{};
        std::string resume_arg{};
        std::string clang_arg{cfg.clang_path.string()};
        std::string mca_path_arg{cfg.mca_path.string()};
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
        app.add_option("--mca-path", mca_path_arg, "llvm-mca executable path");
        app.add_flag("--mca", cfg.mca_enabled, "Enable llvm-mca command support");
        app.add_option("--resume", resume_arg, "Resume session id or latest");
        app.add_option("--clang", clang_arg, "clang++ executable path");
        app.add_option("--cache-dir", cache_dir_arg, "Cache/artifact directory");
        app.add_option("--history-file", history_file_arg, "Persistent REPL history path");
        app.add_flag("--no-history", no_history, "Disable persistent REPL history");
        app.add_option("--banner", banner_arg, "Show startup banner: true|false");
        app.add_flag("--no-banner", no_banner, "Disable startup banner");
        app.add_option("--output", output_arg, "Output mode: table|json");
        app.add_option("--color", color_arg, "Color mode: auto|always|never");
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
            std::cerr << "invalid --std value: " << std_arg << " (expected c++20|c++23|c++2c)\n";
            return std::optional<int>{2};
        }
        if (!try_parse_optimization_level(opt_arg, cfg.opt_level)) {
            std::cerr << "invalid --opt value: " << opt_arg << " (expected O0|O1|O2|O3|Ofast|Oz)\n";
            return std::optional<int>{2};
        }
        if (!try_parse_output_mode(output_arg, cfg.output)) {
            std::cerr << "invalid --output value: " << output_arg << " (expected table|json)\n";
            return std::optional<int>{2};
        }
        if (!try_parse_color_mode(color_arg, cfg.color)) {
            std::cerr << "invalid --color value: " << color_arg << " (expected auto|always|never)\n";
            return std::optional<int>{2};
        }
        if (!detail::try_parse_bool(banner_arg, cfg.banner_enabled)) {
            std::cerr << "invalid --banner value: " << banner_arg << " (expected true|false)\n";
            return std::optional<int>{2};
        }

        cfg.target_triple = detail::normalize_optional(target_arg);
        cfg.cpu = detail::normalize_optional(cpu_arg);
        cfg.mca_cpu = detail::normalize_optional(mca_cpu_arg);
        cfg.resume_session = detail::normalize_optional(resume_arg);
        cfg.clang_path = clang_arg;
        cfg.mca_path = mca_path_arg;
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
