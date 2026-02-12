#include "sontag/analysis.hpp"

#include "sontag/config.hpp"
#include "sontag/graph.hpp"

#include <glaze/glaze.hpp>

#include <cxxabi.h>
extern "C" {
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
}

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
using namespace sontag::literals;

namespace sontag::detail {

    struct inspect_line_record {
        size_t line{};
        std::string text{};
    };

    struct inspect_asm_map_payload {
        int schema_version{1};
        std::string symbol{};
        std::string symbol_display{};
        std::vector<inspect_line_record> source{};
        std::vector<inspect_line_record> ir{};
        std::vector<inspect_line_record> asm_lines{};
    };

    struct inspect_mca_summary_payload {
        int schema_version{1};
        std::string symbol{};
        std::string symbol_display{};
        std::string source_path{};
        int iterations{};
        int instructions{};
        int total_cycles{};
        int total_uops{};
        double dispatch_width{};
        double uops_per_cycle{};
        double ipc{};
        double block_rthroughput{};
        std::vector<std::string> warnings{};
    };

    struct inspect_mca_heatmap_row {
        std::string label{};
        double value{};
        std::string bar{};
    };

    struct inspect_mca_heatmap_payload {
        int schema_version{1};
        std::string symbol{};
        std::string symbol_display{};
        std::vector<inspect_mca_heatmap_row> rows{};
    };

}  // namespace sontag::detail

namespace glz {

    template <>
    struct meta<sontag::detail::inspect_line_record> {
        using T = sontag::detail::inspect_line_record;
        static constexpr auto value = object("line", &T::line, "text", &T::text);
    };

    template <>
    struct meta<sontag::detail::inspect_asm_map_payload> {
        using T = sontag::detail::inspect_asm_map_payload;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "symbol",
                       &T::symbol,
                       "symbol_display",
                       &T::symbol_display,
                       "source",
                       &T::source,
                       "ir",
                       &T::ir,
                       "asm",
                       &T::asm_lines);
    };

    template <>
    struct meta<sontag::detail::inspect_mca_summary_payload> {
        using T = sontag::detail::inspect_mca_summary_payload;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "symbol",
                       &T::symbol,
                       "symbol_display",
                       &T::symbol_display,
                       "source_path",
                       &T::source_path,
                       "iterations",
                       &T::iterations,
                       "instructions",
                       &T::instructions,
                       "total_cycles",
                       &T::total_cycles,
                       "total_uops",
                       &T::total_uops,
                       "dispatch_width",
                       &T::dispatch_width,
                       "uops_per_cycle",
                       &T::uops_per_cycle,
                       "ipc",
                       &T::ipc,
                       "block_rthroughput",
                       &T::block_rthroughput,
                       "warnings",
                       &T::warnings);
    };

    template <>
    struct meta<sontag::detail::inspect_mca_heatmap_row> {
        using T = sontag::detail::inspect_mca_heatmap_row;
        static constexpr auto value = object("label", &T::label, "value", &T::value, "bar", &T::bar);
    };

    template <>
    struct meta<sontag::detail::inspect_mca_heatmap_payload> {
        using T = sontag::detail::inspect_mca_heatmap_payload;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "symbol",
                       &T::symbol,
                       "symbol_display",
                       &T::symbol_display,
                       "rows",
                       &T::rows);
    };

}  // namespace glz

namespace sontag {
    namespace detail {

        using namespace std::string_view_literals;

        static std::string_view trim_ascii(std::string_view value);

        static bool is_identifier_char(char c) {
            return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
        }

        static std::string strip_comments_and_string_literals(std::string_view text) {
            std::string out{};
            out.reserve(text.size());

            bool in_single_quote = false;
            bool in_double_quote = false;
            bool in_line_comment = false;
            bool in_block_comment = false;
            bool escape_next = false;
            bool in_raw_string = false;
            std::string raw_delimiter{};

            size_t i = 0U;
            while (i < text.size()) {
                auto c = text[i];
                auto next = (i + 1U < text.size()) ? text[i + 1U] : '\0';

                if (in_line_comment) {
                    if (c == '\n') {
                        in_line_comment = false;
                        out.push_back('\n');
                    }
                    else {
                        out.push_back(' ');
                    }
                    ++i;
                    continue;
                }

                if (in_block_comment) {
                    if (c == '*' && next == '/') {
                        out.push_back(' ');
                        out.push_back(' ');
                        i += 2U;
                        in_block_comment = false;
                        continue;
                    }
                    out.push_back(c == '\n' ? '\n' : ' ');
                    ++i;
                    continue;
                }

                if (in_raw_string) {
                    if (c == ')' && i + raw_delimiter.size() + 1U < text.size() &&
                        text.substr(i + 1U, raw_delimiter.size()) == raw_delimiter &&
                        text[i + 1U + raw_delimiter.size()] == '"') {
                        out.push_back(' ');
                        for (size_t k = 0U; k < raw_delimiter.size(); ++k) {
                            out.push_back(' ');
                        }
                        out.push_back(' ');
                        i += raw_delimiter.size() + 2U;
                        in_raw_string = false;
                        raw_delimiter.clear();
                        continue;
                    }
                    out.push_back(c == '\n' ? '\n' : ' ');
                    ++i;
                    continue;
                }

                if (in_single_quote) {
                    if (escape_next) {
                        escape_next = false;
                        out.push_back(' ');
                        ++i;
                        continue;
                    }
                    if (c == '\\') {
                        escape_next = true;
                        out.push_back(' ');
                        ++i;
                        continue;
                    }
                    if (c == '\'') {
                        in_single_quote = false;
                    }
                    out.push_back(c == '\n' ? '\n' : ' ');
                    ++i;
                    continue;
                }

                if (in_double_quote) {
                    if (escape_next) {
                        escape_next = false;
                        out.push_back(' ');
                        ++i;
                        continue;
                    }
                    if (c == '\\') {
                        escape_next = true;
                        out.push_back(' ');
                        ++i;
                        continue;
                    }
                    if (c == '"') {
                        in_double_quote = false;
                    }
                    out.push_back(c == '\n' ? '\n' : ' ');
                    ++i;
                    continue;
                }

                if (c == '/' && next == '/') {
                    in_line_comment = true;
                    out.push_back(' ');
                    out.push_back(' ');
                    i += 2U;
                    continue;
                }
                if (c == '/' && next == '*') {
                    in_block_comment = true;
                    out.push_back(' ');
                    out.push_back(' ');
                    i += 2U;
                    continue;
                }

                if (c == 'R' && next == '"') {
                    auto open_paren = text.find('(', i + 2U);
                    if (open_paren != std::string_view::npos) {
                        bool valid_delimiter = true;
                        for (size_t k = i + 2U; k < open_paren; ++k) {
                            auto delimiter_char = text[k];
                            if (delimiter_char == '\\' || delimiter_char == ')' || delimiter_char == '(' ||
                                std::isspace(static_cast<unsigned char>(delimiter_char))) {
                                valid_delimiter = false;
                                break;
                            }
                        }
                        if (valid_delimiter) {
                            raw_delimiter = std::string{text.substr(i + 2U, open_paren - (i + 2U))};
                            in_raw_string = true;
                            for (size_t k = i; k <= open_paren; ++k) {
                                out.push_back(' ');
                            }
                            i = open_paren + 1U;
                            continue;
                        }
                    }
                }

                if (c == '\'') {
                    in_single_quote = true;
                    out.push_back(' ');
                    ++i;
                    continue;
                }
                if (c == '"') {
                    in_double_quote = true;
                    out.push_back(' ');
                    ++i;
                    continue;
                }

                out.push_back(c);
                ++i;
            }

            return out;
        }

        static bool has_trailing_return_statement(const std::vector<std::string>& exec_cells) {
            if (exec_cells.empty()) {
                return false;
            }

            std::string joined_exec{};
            for (size_t i = 0U; i < exec_cells.size(); ++i) {
                joined_exec.append(exec_cells[i]);
                if (i + 1U < exec_cells.size()) {
                    joined_exec.push_back('\n');
                }
            }

            auto sanitized = strip_comments_and_string_literals(joined_exec);
            auto text = trim_ascii(sanitized);
            if (text.empty() || !text.ends_with(';')) {
                return false;
            }

            auto last_semicolon = text.rfind(';');
            if (last_semicolon == std::string_view::npos) {
                return false;
            }

            auto before = text.substr(0U, last_semicolon);
            auto statement_separator = before.find_last_of(";{}");
            auto statement =
                    statement_separator == std::string_view::npos ? before : before.substr(statement_separator + 1U);
            statement = trim_ascii(statement);

            constexpr auto return_keyword = "return"sv;
            if (!statement.starts_with(return_keyword)) {
                return false;
            }
            if (statement.size() == return_keyword.size()) {
                return true;
            }

            return !is_identifier_char(statement[return_keyword.size()]);
        }

        static void write_exec_cell(std::ostringstream& source, std::string_view cell) {
            size_t cursor = 0U;
            while (cursor <= cell.size()) {
                auto line_end = cell.find('\n', cursor);
                auto line = line_end == std::string_view::npos ? cell.substr(cursor)
                                                               : cell.substr(cursor, line_end - cursor);

                if (line.empty()) {
                    source << '\n';
                }
                else if (line.front() == ' ' || line.front() == '\t') {
                    source << line << '\n';
                }
                else {
                    source << "    " << line << '\n';
                }

                if (line_end == std::string_view::npos) {
                    break;
                }
                cursor = line_end + 1U;
            }
        }

        static std::string read_text_file(const fs::path& path) {
            std::ifstream in{path};
            if (!in) {
                return {};
            }
            std::ostringstream ss{};
            ss << in.rdbuf();
            return ss.str();
        }

        static void write_text_file(const fs::path& path, std::string_view text) {
            std::ofstream out{path};
            if (!out) {
                throw std::runtime_error("failed to open file for write: {}"_format(path.string()));
            }
            out << text;
            if (!out) {
                throw std::runtime_error("failed to write file: {}"_format(path.string()));
            }
        }

        static std::string render_source(
                const std::vector<std::string>& decl_cells, const std::vector<std::string>& exec_cells) {
            std::ostringstream source{};
            source << "// generated by sontag m1\n";
            for (size_t i = 0U; i < decl_cells.size(); ++i) {
                source << "// decl cell " << (i + 1U) << '\n';
                source << decl_cells[i] << "\n\n";
            }

            source << "int __sontag_main() {\n";
            for (size_t i = 0U; i < exec_cells.size(); ++i) {
                source << "    // exec cell " << (i + 1U) << '\n';
                write_exec_cell(source, exec_cells[i]);
                if (i + 1U < exec_cells.size()) {
                    source << '\n';
                }
            }
            if (!has_trailing_return_statement(exec_cells)) {
                if (!exec_cells.empty()) {
                    source << '\n';
                }
                source << "    return 0;\n";
            }
            source << "}\n";
            return source.str();
        }

        static std::string make_artifact_id(const analysis_request& request, analysis_kind kind) {
            std::ostringstream key{};
            key << "{}\n{}\n{}\n"_format(kind, request.language_standard, request.opt_level);
            key << request.asm_syntax << '\n';
            if (request.symbol) {
                key << *request.symbol << '\n';
            }
            if (request.target_triple) {
                key << *request.target_triple << '\n';
            }
            if (request.cpu) {
                key << *request.cpu << '\n';
            }
            if (request.mca_cpu) {
                key << *request.mca_cpu << '\n';
            }
            for (const auto& cell : request.decl_cells) {
                key << "decl:" << cell << '\n';
            }
            for (const auto& cell : request.exec_cells) {
                key << "exec:" << cell << '\n';
            }

            auto hash_value = std::hash<std::string>{}(key.str());
            std::ostringstream id{};
            id << std::hex << hash_value;
            return id.str();
        }

        static void ensure_dir(const fs::path& path) {
            std::error_code ec{};
            fs::create_directories(path, ec);
            if (ec) {
                throw std::runtime_error("failed to create directory: {}"_format(path.string()));
            }
        }

        static int open_write_file(const fs::path& path) {
            auto fd = ::open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd < 0) {
                throw std::runtime_error("failed to open file for write: {}"_format(path.string()));
            }
            return fd;
        }

        static int run_process(
                const std::vector<std::string>& args, const fs::path& stdout_path, const fs::path& stderr_path) {
            auto stdout_fd = open_write_file(stdout_path);
            auto stderr_fd = open_write_file(stderr_path);

            auto pid = ::fork();
            if (pid < 0) {
                ::close(stdout_fd);
                ::close(stderr_fd);
                throw std::runtime_error("fork failed");
            }

            if (pid == 0) {
                if (::dup2(stdout_fd, STDOUT_FILENO) < 0) {
                    _exit(127);
                }
                if (::dup2(stderr_fd, STDERR_FILENO) < 0) {
                    _exit(127);
                }

                ::close(stdout_fd);
                ::close(stderr_fd);

                std::vector<char*> argv{};
                argv.reserve(args.size() + 1U);
                for (const auto& arg : args) {
                    argv.push_back(const_cast<char*>(arg.c_str()));
                }
                argv.push_back(nullptr);

                ::execvp(argv[0], argv.data());
                _exit(127);
            }

            ::close(stdout_fd);
            ::close(stderr_fd);

            int status = 0;
            if (::waitpid(pid, &status, 0) < 0) {
                throw std::runtime_error("waitpid failed");
            }

            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 1;
        }

        namespace arg_tokens {
            static constexpr auto std_prefix = "-std="sv;
            static constexpr auto opt_prefix = "-"sv;
            static constexpr auto target_prefix = "--target="sv;
            static constexpr auto cpu_prefix = "-mcpu="sv;
            static constexpr auto mtriple_prefix = "-mtriple="sv;
            static constexpr auto llvm_mca_version_prefix = "llvm-mca-"sv;
            static constexpr auto llvm_objdump_version_prefix = "llvm-objdump-"sv;

            static constexpr auto compile_to_text = "-S"sv;
            static constexpr auto compile_to_object = "-c"sv;
            static constexpr auto verbose_asm = "-fverbose-asm"sv;
            static constexpr auto intel_syntax = "-masm=intel"sv;
            static constexpr auto output_path = "-o"sv;
            static constexpr auto emit_llvm = "-emit-llvm"sv;
            static constexpr auto syntax_only = "-fsyntax-only"sv;
            static constexpr auto warn_all = "-Wall"sv;
            static constexpr auto warn_extra = "-Wextra"sv;
            static constexpr auto no_warn_error = "-Wno-error"sv;
            static constexpr auto no_unused_variable = "-Wno-unused-variable"sv;
            static constexpr auto no_unused_parameter = "-Wno-unused-parameter"sv;
            static constexpr auto no_unused_function = "-Wno-unused-function"sv;
            static constexpr auto version = "--version"sv;
            static constexpr auto clang_verbose = "-v"sv;
            static constexpr auto show_encoding = "--show-encoding"sv;
            static constexpr auto register_file_stats = "--register-file-stats"sv;
            static constexpr auto all_views = "--all-views"sv;

            static constexpr auto objdump_disassemble = "--disassemble"sv;
            static constexpr auto objdump_demangle = "--demangle"sv;
            static constexpr auto objdump_x86_intel_syntax = "--x86-asm-syntax=intel"sv;
            static constexpr auto objdump_x86_att_syntax = "--x86-asm-syntax=att"sv;
            static constexpr auto objdump_symbolize_operands = "--symbolize-operands"sv;
            static constexpr auto objdump_show_all_symbols = "--show-all-symbols"sv;
            static constexpr auto objdump_disassemble_symbols_prefix = "--disassemble-symbols="sv;
            static constexpr auto objdump_line_numbers = "--line-numbers"sv;
            static constexpr auto objdump_source = "--source"sv;

            static constexpr auto dot_output_format_prefix = "-T"sv;
        }  // namespace arg_tokens

        template <typename T>
            requires std::is_scoped_enum_v<T>
        static void append_prefixed_arg(std::vector<std::string>& args, std::string_view prefix, T value) {
            args.emplace_back("{}{}"_format(prefix, value));
        }

        static void append_prefixed_arg(
                std::vector<std::string>& args, std::string_view prefix, std::string_view value) {
            args.emplace_back("{}{}"_format(prefix, value));
        }

        static void append_optional_prefixed_arg(
                std::vector<std::string>& args, std::string_view prefix, const std::optional<std::string>& value) {
            if (value) {
                args.emplace_back("{}{}"_format(prefix, *value));
            }
        }

        static std::vector<std::string> base_clang_args(const analysis_request& request) {
            std::vector<std::string> base_args{};
            base_args.reserve(9U);
            base_args.push_back(request.clang_path.string());
            append_prefixed_arg(base_args, arg_tokens::std_prefix, request.language_standard);
            append_prefixed_arg(base_args, arg_tokens::opt_prefix, request.opt_level);
            append_optional_prefixed_arg(base_args, arg_tokens::target_prefix, request.target_triple);
            append_optional_prefixed_arg(base_args, arg_tokens::cpu_prefix, request.cpu);
            base_args.emplace_back(arg_tokens::no_warn_error);
            base_args.emplace_back(arg_tokens::no_unused_variable);
            base_args.emplace_back(arg_tokens::no_unused_parameter);
            base_args.emplace_back(arg_tokens::no_unused_function);
            if (request.verbose) {
                base_args.emplace_back(arg_tokens::clang_verbose);
            }
            return base_args;
        }

        static std::vector<std::string> build_command(
                const analysis_request& request,
                analysis_kind kind,
                const fs::path& source_path,
                const fs::path& artifact_path) {
            auto base_args = base_clang_args(request);
            switch (kind) {
                case analysis_kind::asm_text:
                    base_args.emplace_back(arg_tokens::compile_to_text);
                    base_args.emplace_back(arg_tokens::verbose_asm);
                    if (request.asm_syntax == "intel") {
                        base_args.emplace_back(arg_tokens::intel_syntax);
                    }
                    base_args.push_back(source_path.string());
                    base_args.emplace_back(arg_tokens::output_path);
                    base_args.push_back(artifact_path.string());
                    break;
                case analysis_kind::ir:
                    base_args.emplace_back(arg_tokens::compile_to_text);
                    base_args.emplace_back(arg_tokens::emit_llvm);
                    base_args.push_back(source_path.string());
                    base_args.emplace_back(arg_tokens::output_path);
                    base_args.push_back(artifact_path.string());
                    break;
                case analysis_kind::diag:
                    base_args.emplace_back(arg_tokens::syntax_only);
                    base_args.emplace_back(arg_tokens::warn_all);
                    base_args.emplace_back(arg_tokens::warn_extra);
                    base_args.push_back(source_path.string());
                    break;
                case analysis_kind::mca:
                    break;
                case analysis_kind::dump:
                    base_args.emplace_back(arg_tokens::compile_to_object);
                    base_args.push_back(source_path.string());
                    base_args.emplace_back(arg_tokens::output_path);
                    base_args.push_back(artifact_path.string());
                    break;
                case analysis_kind::inspect_asm_map:
                case analysis_kind::inspect_mca_summary:
                case analysis_kind::inspect_mca_heatmap:
                case analysis_kind::graph_cfg:
                case analysis_kind::graph_call:
                case analysis_kind::graph_defuse:
                    break;
            }
            return base_args;
        }

        static std::vector<std::string> build_mca_command(
                const analysis_request& request, const fs::path& asm_path, std::string_view mca_executable) {
            std::vector<std::string> base_args{};
            base_args.emplace_back(mca_executable);

            append_optional_prefixed_arg(base_args, arg_tokens::mtriple_prefix, request.target_triple);

            if (request.mca_cpu) {
                append_prefixed_arg(base_args, arg_tokens::cpu_prefix, *request.mca_cpu);
            }
            else if (request.cpu) {
                append_prefixed_arg(base_args, arg_tokens::cpu_prefix, *request.cpu);
            }

            base_args.emplace_back(arg_tokens::show_encoding);
            base_args.emplace_back(arg_tokens::register_file_stats);
            if (request.verbose) {
                base_args.emplace_back(arg_tokens::all_views);
            }
            base_args.push_back(asm_path.string());
            return base_args;
        }

        static std::vector<std::string> build_objdump_command(
                const analysis_request& request,
                const fs::path& object_path,
                std::string_view objdump_executable,
                const std::optional<std::string>& symbol) {
            std::vector<std::string> base_args{};
            base_args.emplace_back(objdump_executable);
            base_args.emplace_back(arg_tokens::objdump_disassemble);
            base_args.emplace_back(arg_tokens::objdump_demangle);
            if (request.asm_syntax == "intel"sv) {
                base_args.emplace_back(arg_tokens::objdump_x86_intel_syntax);
            }
            else {
                base_args.emplace_back(arg_tokens::objdump_x86_att_syntax);
            }
            base_args.emplace_back(arg_tokens::objdump_symbolize_operands);

            if (symbol) {
                append_prefixed_arg(base_args, arg_tokens::objdump_disassemble_symbols_prefix, *symbol);
            }
            else {
                base_args.emplace_back(arg_tokens::objdump_show_all_symbols);
            }

            if (request.verbose) {
                base_args.emplace_back(arg_tokens::objdump_line_numbers);
                base_args.emplace_back(arg_tokens::objdump_source);
            }

            base_args.push_back(object_path.string());
            return base_args;
        }

        static void append_unique(std::vector<std::string>& values, std::string value) {
            if (value.empty()) {
                return;
            }
            if (std::find(values.begin(), values.end(), value) == values.end()) {
                values.push_back(std::move(value));
            }
        }

        static std::string join_text(std::string_view lhs, std::string_view rhs) {
            if (rhs.empty()) {
                return std::string{lhs};
            }
            if (lhs.empty()) {
                return std::string{rhs};
            }
            if (lhs.ends_with('\n')) {
                return "{}{}"_format(lhs, rhs);
            }
            return "{}\n{}"_format(lhs, rhs);
        }

        static std::string join_with_separator(const std::vector<std::string>& values, std::string_view separator) {
            if (values.empty()) {
                return {};
            }

            std::string joined{values.front()};
            for (size_t i = 1U; i < values.size(); ++i) {
                joined = "{}{}{}"_format(joined, separator, values[i]);
            }
            return joined;
        }

        static std::optional<std::string> parse_clang_name_suffix(std::string_view clang_name) {
            constexpr auto clang_xx_prefix = "clang++-"sv;
            constexpr auto clang_prefix = "clang-"sv;

            if (clang_name.rfind(clang_xx_prefix, 0U) == 0U && clang_name.size() > clang_xx_prefix.size()) {
                return std::string{clang_name.substr(clang_xx_prefix.size())};
            }
            if (clang_name.rfind(clang_prefix, 0U) == 0U && clang_name.size() > clang_prefix.size()) {
                return std::string{clang_name.substr(clang_prefix.size())};
            }
            return std::nullopt;
        }

        static std::optional<std::string> parse_clang_version_token(std::string_view clang_version_text) {
            auto marker = clang_version_text.find("version "sv);
            if (marker == std::string_view::npos) {
                return std::nullopt;
            }
            auto pos = marker + std::string_view{"version "sv}.size();
            while (pos < clang_version_text.size() &&
                   std::isspace(static_cast<unsigned char>(clang_version_text[pos]))) {
                ++pos;
            }
            if (pos >= clang_version_text.size()) {
                return std::nullopt;
            }

            std::string token{};
            bool seen_digit = false;
            while (pos < clang_version_text.size()) {
                auto c = clang_version_text[pos];
                if (std::isdigit(static_cast<unsigned char>(c))) {
                    seen_digit = true;
                    token.push_back(c);
                    ++pos;
                    continue;
                }
                if (c == '.' && seen_digit) {
                    token.push_back(c);
                    ++pos;
                    continue;
                }
                break;
            }

            while (token.ends_with('.')) {
                token.pop_back();
            }
            if (token.empty()) {
                return std::nullopt;
            }
            return token;
        }

        static std::optional<std::string> parse_major_version(std::string_view version_token) {
            auto dot = version_token.find('.');
            auto major = dot == std::string_view::npos ? version_token : version_token.substr(0U, dot);
            if (major.empty()) {
                return std::nullopt;
            }
            return std::string{major};
        }

        static std::optional<std::string> query_clang_version_token(
                const analysis_request& request, const fs::path& temp_dir, std::string_view artifact_id) {
            auto stdout_path = temp_dir / std::string{artifact_id} / "clang_version.stdout.txt";
            auto stderr_path = temp_dir / std::string{artifact_id} / "clang_version.stderr.txt";
            ensure_dir(stdout_path.parent_path());

            std::vector<std::string> version_command{request.clang_path.string(), std::string{arg_tokens::version}};
            auto exit_code = run_process(version_command, stdout_path, stderr_path);
            if (exit_code != 0) {
                return std::nullopt;
            }

            auto version_text = read_text_file(stdout_path);
            return parse_clang_version_token(version_text);
        }

        static std::vector<std::string> build_tool_executable_candidates(
                const analysis_request& request,
                const fs::path& configured_tool_path,
                std::string_view versioned_prefix,
                const fs::path& temp_dir,
                std::string_view artifact_id) {
            std::vector<std::string> candidates{};
            append_unique(candidates, configured_tool_path.string());
            if (configured_tool_path.has_parent_path()) {
                return candidates;
            }

            std::vector<std::string> suffixes{};
            if (auto from_name = parse_clang_name_suffix(request.clang_path.filename().string())) {
                append_unique(suffixes, *from_name);
            }
            if (auto from_version = query_clang_version_token(request, temp_dir, artifact_id)) {
                append_unique(suffixes, *from_version);
            }

            std::vector<std::string> suffixes_with_major{};
            for (const auto& suffix : suffixes) {
                append_unique(suffixes_with_major, suffix);
                if (auto major = parse_major_version(suffix)) {
                    append_unique(suffixes_with_major, *major);
                }
            }

            auto clang_dir = request.clang_path.parent_path();
            auto configured_dir = configured_tool_path.parent_path();
            for (const auto& suffix : suffixes_with_major) {
                std::string tool_name{versioned_prefix};
                tool_name.append(suffix);
                append_unique(candidates, tool_name);
                if (!clang_dir.empty()) {
                    append_unique(candidates, (clang_dir / tool_name).string());
                }
                if (!configured_dir.empty()) {
                    append_unique(candidates, (configured_dir / tool_name).string());
                }
            }

            return candidates;
        }

        static std::vector<std::string> build_mca_executable_candidates(
                const analysis_request& request, const fs::path& temp_dir, std::string_view artifact_id) {
            return build_tool_executable_candidates(
                    request, request.mca_path, arg_tokens::llvm_mca_version_prefix, temp_dir, artifact_id);
        }

        static std::vector<std::string> build_objdump_executable_candidates(
                const analysis_request& request, const fs::path& temp_dir, std::string_view artifact_id) {
            return build_tool_executable_candidates(
                    request, request.objdump_path, arg_tokens::llvm_objdump_version_prefix, temp_dir, artifact_id);
        }

        static bool starts_with(std::string_view value, std::string_view prefix) {
            return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
        }

        static std::vector<std::string> split_lines(const std::string& text) {
            std::vector<std::string> lines{};
            std::istringstream in{text};
            std::string line{};
            while (std::getline(in, line)) {
                lines.push_back(line);
            }
            return lines;
        }

        static bool contains_token(std::string_view haystack, std::string_view needle) {
            return haystack.find(needle) != std::string_view::npos;
        }

        static std::string_view trim_ascii(std::string_view value) {
            auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return {};
            }
            auto last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, (last - first) + 1U);
        }

        static std::string demangle_symbol_name(std::string_view mangled) {
            int status = 0;
            auto* demangled_ptr = abi::__cxa_demangle(std::string{mangled}.c_str(), nullptr, nullptr, &status);
            if (demangled_ptr == nullptr || status != 0) {
                return std::string{mangled};
            }

            std::string demangled{demangled_ptr};
            std::free(demangled_ptr);
            return demangled;
        }

        static std::optional<analysis_symbol> parse_nm_symbol_line(std::string_view line) {
            auto trimmed = trim_ascii(line);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            auto name_start = trimmed.find_last_of(" \t");
            if (name_start == std::string_view::npos || name_start + 1U >= trimmed.size()) {
                return std::nullopt;
            }
            auto mangled = trim_ascii(trimmed.substr(name_start + 1U));
            if (mangled.empty()) {
                return std::nullopt;
            }

            auto prefix = trim_ascii(trimmed.substr(0U, name_start));
            if (prefix.empty()) {
                return std::nullopt;
            }

            auto kind_start = prefix.find_last_of(" \t");
            auto kind_token =
                    kind_start == std::string_view::npos ? prefix : trim_ascii(prefix.substr(kind_start + 1U));
            if (kind_token.size() != 1U) {
                return std::nullopt;
            }

            return analysis_symbol{
                    .kind = kind_token.front(),
                    .mangled = std::string{mangled},
                    .demangled = demangle_symbol_name(mangled)};
        }

        static std::vector<analysis_symbol> parse_nm_symbols(std::string_view nm_output) {
            std::vector<analysis_symbol> symbols{};
            std::istringstream in{std::string{nm_output}};
            std::string line{};

            while (std::getline(in, line)) {
                auto parsed = parse_nm_symbol_line(line);
                if (!parsed) {
                    continue;
                }
                symbols.push_back(std::move(*parsed));
            }

            std::sort(symbols.begin(), symbols.end(), [](const analysis_symbol& lhs, const analysis_symbol& rhs) {
                if (lhs.demangled != rhs.demangled) {
                    return lhs.demangled < rhs.demangled;
                }
                if (lhs.mangled != rhs.mangled) {
                    return lhs.mangled < rhs.mangled;
                }
                return lhs.kind < rhs.kind;
            });

            symbols.erase(
                    std::unique(
                            symbols.begin(),
                            symbols.end(),
                            [](const analysis_symbol& lhs, const analysis_symbol& rhs) {
                                return lhs.kind == rhs.kind && lhs.mangled == rhs.mangled;
                            }),
                    symbols.end());

            return symbols;
        }

        static std::optional<std::vector<analysis_symbol>> try_collect_defined_symbols(
                const analysis_request& request) {
            auto inputs_dir = request.session_dir / "artifacts" / "inputs";
            auto source_path = inputs_dir / "symbol_index.cpp";
            auto object_path = inputs_dir / "symbol_index.o";
            auto clang_stdout_path = inputs_dir / "symbol_index.clang.stdout.txt";
            auto clang_stderr_path = inputs_dir / "symbol_index.clang.stderr.txt";
            auto nm_stdout_path = inputs_dir / "symbol_index.nm.stdout.txt";
            auto nm_stderr_path = inputs_dir / "symbol_index.nm.stderr.txt";

            ensure_dir(inputs_dir);
            write_text_file(source_path, render_source(request.decl_cells, request.exec_cells));

            auto compile_args = base_clang_args(request);
            compile_args.emplace_back("-c");
            compile_args.push_back(source_path.string());
            compile_args.emplace_back("-o");
            compile_args.push_back(object_path.string());

            auto compile_exit = run_process(compile_args, clang_stdout_path, clang_stderr_path);
            if (compile_exit != 0) {
                return std::nullopt;
            }

            std::vector<std::string> nm_args{"nm", "--defined-only", object_path.string()};
            auto nm_exit = run_process(nm_args, nm_stdout_path, nm_stderr_path);
            if (nm_exit != 0) {
                return std::nullopt;
            }

            auto nm_output = read_text_file(nm_stdout_path);
            return parse_nm_symbols(nm_output);
        }

        static std::optional<size_t> parse_header_line_number(std::string_view line, const std::string& source_path) {
            if (!starts_with(line, source_path)) {
                return std::nullopt;
            }
            auto first_colon = line.find(':', source_path.size());
            if (first_colon == std::string_view::npos) {
                return std::nullopt;
            }
            auto second_colon = line.find(':', first_colon + 1U);
            if (second_colon == std::string_view::npos) {
                return std::nullopt;
            }
            auto line_number_text = line.substr(first_colon + 1U, second_colon - (first_colon + 1U));
            if (line_number_text.empty()) {
                return std::nullopt;
            }
            size_t line_number = 0U;
            for (auto c : line_number_text) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    return std::nullopt;
                }
                line_number = (line_number * 10U) + static_cast<size_t>(c - '0');
            }
            return line_number;
        }

        static std::string filter_diag_by_symbol(
                const std::string& diagnostics_text,
                const std::string& source_text,
                const std::string& source_path,
                std::string_view symbol) {
            if (diagnostics_text.empty()) {
                return {};
            }

            auto source_lines = split_lines(source_text);

            std::vector<std::pair<size_t, size_t>> symbol_ranges{};
            for (size_t i = 0U; i < source_lines.size(); ++i) {
                if (!contains_token(source_lines[i], symbol) || !contains_token(source_lines[i], "("sv)) {
                    continue;
                }

                size_t j = i;
                bool found_open = false;
                int depth = 0;
                for (; j < source_lines.size(); ++j) {
                    for (auto c : source_lines[j]) {
                        if (c == '{') {
                            found_open = true;
                            ++depth;
                        }
                        else if (c == '}') {
                            --depth;
                        }
                    }
                    if (found_open && depth <= 0) {
                        symbol_ranges.push_back({i + 1U, j + 1U});
                        i = j;
                        break;
                    }
                }
            }
            auto diag_lines = split_lines(diagnostics_text);
            std::ostringstream filtered{};

            for (size_t i = 0U; i < diag_lines.size();) {
                auto header_line_number = parse_header_line_number(diag_lines[i], source_path);
                if (!header_line_number) {
                    ++i;
                    continue;
                }

                auto block_start = i;
                auto block_end = i + 1U;
                while (block_end < diag_lines.size()) {
                    if (parse_header_line_number(diag_lines[block_end], source_path)) {
                        break;
                    }
                    ++block_end;
                }

                bool keep = contains_token(diag_lines[block_start], symbol);
                if (!keep && *header_line_number > 0U && *header_line_number <= source_lines.size()) {
                    keep = contains_token(source_lines[*header_line_number - 1U], symbol);
                }
                if (!keep) {
                    for (const auto& range : symbol_ranges) {
                        if (*header_line_number >= range.first && *header_line_number <= range.second) {
                            keep = true;
                            break;
                        }
                    }
                }

                if (keep) {
                    for (auto line_index = block_start; line_index < block_end; ++line_index) {
                        filtered << diag_lines[line_index] << '\n';
                    }
                }

                i = block_end;
            }

            auto filtered_text = filtered.str();
            if (!filtered_text.empty()) {
                return filtered_text;
            }

            return "no diagnostics matched symbol '{}'\n"_format(symbol);
        }

        static std::optional<std::string> resolve_symbol_name(
                const std::vector<analysis_symbol>& symbols, std::string_view symbol) {
            for (const auto& candidate : symbols) {
                if (candidate.mangled == symbol || contains_token(candidate.mangled, symbol) ||
                    contains_token(candidate.demangled, symbol)) {
                    return candidate.mangled;
                }
            }

            return std::nullopt;
        }

        static std::optional<std::string> resolve_symbol_name(
                const analysis_request& request, std::string_view symbol) {
            auto symbols = try_collect_defined_symbols(request);
            if (!symbols) {
                return std::nullopt;
            }
            return resolve_symbol_name(*symbols, symbol);
        }

        static std::string extract_ir_for_symbol(const std::string& ir_text, std::string_view mangled_symbol) {
            auto lines = split_lines(ir_text);
            std::ostringstream extracted{};
            bool in_function = false;
            int brace_depth = 0;
            auto symbol_tag = "@{}("_format(mangled_symbol);

            for (const auto& line : lines) {
                if (!in_function) {
                    if (contains_token(line, "define"sv) && contains_token(line, symbol_tag)) {
                        in_function = true;
                    }
                    else {
                        continue;
                    }
                }

                extracted << line << '\n';
                for (auto c : line) {
                    if (c == '{') {
                        ++brace_depth;
                    }
                    else if (c == '}') {
                        --brace_depth;
                    }
                }
                if (in_function && brace_depth <= 0 && contains_token(line, "}"sv)) {
                    break;
                }
            }

            return extracted.str();
        }

        static std::string extract_asm_for_symbol(const std::string& asm_text, std::string_view mangled_symbol) {
            auto lines = split_lines(asm_text);
            std::ostringstream extracted{};
            bool in_function = false;
            auto begin_tag = "# -- Begin function {}"_format(mangled_symbol);
            auto label_tag = "{}:"_format(mangled_symbol);
            auto size_tag = ".size\t{}"_format(mangled_symbol);
            auto size_tag_space = ".size {}"_format(mangled_symbol);

            for (const auto& line : lines) {
                if (!in_function) {
                    if (contains_token(line, begin_tag) || starts_with(line, label_tag)) {
                        in_function = true;
                    }
                    else {
                        continue;
                    }
                }

                extracted << line << '\n';
                if (contains_token(line, "# -- End function"sv) || contains_token(line, size_tag) ||
                    contains_token(line, size_tag_space)) {
                    break;
                }
            }

            return extracted.str();
        }

        static std::string prepare_mca_symbol_input(std::string_view extracted_asm, std::string_view asm_syntax) {
            std::string prepared{};
            prepared.reserve(extracted_asm.size() + 64U);
            prepared.append(".text\n");
            if (asm_syntax == "intel"sv) {
                prepared.append(".intel_syntax noprefix\n");
            }
            auto lines = split_lines(std::string{extracted_asm});
            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (trimmed.starts_with(".cfi_"sv)) {
                    continue;
                }
                prepared.append(line);
                prepared.push_back('\n');
            }
            return prepared;
        }

        static std::string to_lower_ascii(std::string_view value) {
            std::string lower{};
            lower.reserve(value.size());
            for (auto c : value) {
                lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
            return lower;
        }

        static std::string normalize_graph_format(std::string_view format) {
            auto normalized = to_lower_ascii(trim_ascii(format));
            if (normalized == "dot"sv || normalized == "svg"sv || normalized == "png"sv) {
                return normalized;
            }
            return "png";
        }

        template <typename T>
        static std::string serialize_json_payload(const T& payload) {
            std::string json{};
            auto ec = glz::write_json(payload, json);
            if (ec) {
                throw std::runtime_error("failed to serialize json payload");
            }
            return json;
        }

        static graph::symbol_display_map make_symbol_display_map(
                const std::optional<std::vector<analysis_symbol>>& defined_symbols) {
            graph::symbol_display_map display_names{};
            if (!defined_symbols) {
                return display_names;
            }
            for (const auto& symbol : *defined_symbols) {
                display_names.emplace(symbol.mangled, symbol.demangled);
            }
            return display_names;
        }

        static std::string resolve_symbol_display_name(
                std::string_view mangled, const graph::symbol_display_map& display_names) {
            if (auto it = display_names.find(std::string{mangled}); it != display_names.end()) {
                return it->second;
            }
            return demangle_symbol_name(mangled);
        }

        static std::vector<inspect_line_record> make_line_records(std::string_view text) {
            auto lines = split_lines(std::string{text});
            std::vector<inspect_line_record> records{};
            records.reserve(lines.size());
            for (size_t i = 0U; i < lines.size(); ++i) {
                records.push_back(inspect_line_record{.line = i + 1U, .text = lines[i]});
            }
            return records;
        }

        static std::optional<double> parse_number_after_colon(std::string_view line) {
            auto colon = line.find(':');
            if (colon == std::string_view::npos || colon + 1U >= line.size()) {
                return std::nullopt;
            }
            auto value = std::string{trim_ascii(line.substr(colon + 1U))};
            if (value.empty()) {
                return std::nullopt;
            }
            char* end = nullptr;
            auto parsed = std::strtod(value.c_str(), &end);
            if (end == value.c_str()) {
                return std::nullopt;
            }
            return parsed;
        }

        static std::optional<double> parse_numeric_token(std::string_view token) {
            auto value = std::string{trim_ascii(token)};
            if (value.empty()) {
                return std::nullopt;
            }
            char* end = nullptr;
            auto parsed = std::strtod(value.c_str(), &end);
            if (end == value.c_str()) {
                return std::nullopt;
            }
            return parsed;
        }

        static void parse_mca_summary(std::string_view mca_text, inspect_mca_summary_payload& payload) {
            auto lines = split_lines(std::string{mca_text});
            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (trimmed.empty()) {
                    continue;
                }
                if (trimmed.starts_with("Iterations:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.iterations = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Instructions:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.instructions = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Total Cycles:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.total_cycles = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Total uOps:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.total_uops = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Dispatch Width:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.dispatch_width = *value;
                    }
                    continue;
                }
                if (trimmed.starts_with("uOps Per Cycle:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.uops_per_cycle = *value;
                    }
                    continue;
                }
                if (trimmed.starts_with("IPC:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.ipc = *value;
                    }
                    continue;
                }
                if (trimmed.starts_with("Block RThroughput:"sv)) {
                    if (auto value = parse_number_after_colon(trimmed)) {
                        payload.block_rthroughput = *value;
                    }
                }
            }
        }

        static std::vector<std::string_view> split_whitespace_tokens(std::string_view line) {
            std::vector<std::string_view> tokens{};
            size_t i = 0U;
            while (i < line.size()) {
                while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) {
                    ++i;
                }
                if (i >= line.size()) {
                    break;
                }
                auto start = i;
                while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i]))) {
                    ++i;
                }
                tokens.push_back(line.substr(start, i - start));
            }
            return tokens;
        }

        static std::vector<inspect_mca_heatmap_row> parse_mca_heatmap_rows(std::string_view mca_text) {
            auto lines = split_lines(std::string{mca_text});
            std::vector<std::string> resources{};

            bool in_resources = false;
            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (trimmed.empty()) {
                    if (in_resources) {
                        break;
                    }
                    continue;
                }
                if (trimmed == "Resources:"sv) {
                    in_resources = true;
                    continue;
                }
                if (!in_resources) {
                    continue;
                }
                auto dash = trimmed.find("- "sv);
                if (dash == std::string_view::npos || dash + 2U >= trimmed.size()) {
                    continue;
                }
                resources.emplace_back(trimmed.substr(dash + 2U));
            }

            std::vector<double> pressure{};
            for (size_t i = 0U; i < lines.size(); ++i) {
                auto trimmed = trim_ascii(lines[i]);
                if (trimmed != "Resource pressure per iteration:"sv) {
                    continue;
                }
                if (i + 2U >= lines.size()) {
                    break;
                }
                auto values_line = trim_ascii(lines[i + 2U]);
                auto tokens = split_whitespace_tokens(values_line);
                for (const auto token : tokens) {
                    if (token == "-"sv) {
                        pressure.push_back(0.0);
                        continue;
                    }
                    auto parsed = parse_numeric_token(token);
                    if (parsed) {
                        pressure.push_back(*parsed);
                    }
                    else {
                        pressure.push_back(0.0);
                    }
                }
                break;
            }

            std::vector<inspect_mca_heatmap_row> rows{};
            auto count = std::min(resources.size(), pressure.size());
            rows.reserve(count);
            for (size_t i = 0U; i < count; ++i) {
                auto scaled = static_cast<int>(pressure[i] * 10.0);
                if (scaled < 0) {
                    scaled = 0;
                }
                std::string bar{};
                bar.assign(static_cast<size_t>(scaled), '#');
                rows.push_back(
                        inspect_mca_heatmap_row{.label = resources[i], .value = pressure[i], .bar = std::move(bar)});
            }
            return rows;
        }

        static std::vector<std::string> build_dot_executable_candidates(const analysis_request& request) {
            std::vector<std::string> candidates{};
            if (request.dot_path) {
                append_unique(candidates, request.dot_path->string());
            }
            append_unique(candidates, "dot");
            return candidates;
        }

        static std::vector<std::string> build_dot_render_command(
                std::string_view dot_executable,
                std::string_view output_format,
                const fs::path& dot_path,
                const fs::path& output_path) {
            std::vector<std::string> args{};
            args.emplace_back(dot_executable);
            append_prefixed_arg(args, arg_tokens::dot_output_format_prefix, output_format);
            args.push_back(dot_path.string());
            args.emplace_back(arg_tokens::output_path);
            args.push_back(output_path.string());
            return args;
        }

    }  // namespace detail

    analysis_result run_analysis(const analysis_request& request, analysis_kind kind) {
        if (request.decl_cells.empty() && request.exec_cells.empty()) {
            throw std::runtime_error("analysis requires at least one stored cell");
        }

        auto artifacts_root = request.session_dir / "artifacts";
        auto inputs_dir = artifacts_root / "inputs";
        fs::path kind_dir{};
        switch (kind) {
            case analysis_kind::graph_cfg:
                kind_dir = artifacts_root / "graphs" / "cfg";
                break;
            case analysis_kind::graph_call:
                kind_dir = artifacts_root / "graphs" / "call";
                break;
            case analysis_kind::graph_defuse:
                kind_dir = artifacts_root / "graphs" / "defuse";
                break;
            case analysis_kind::inspect_asm_map:
                kind_dir = artifacts_root / "inspect" / "asm";
                break;
            case analysis_kind::inspect_mca_summary:
            case analysis_kind::inspect_mca_heatmap:
                kind_dir = artifacts_root / "inspect" / "mca";
                break;
            default:
                kind_dir = artifacts_root / "{}"_format(kind);
                break;
        }

        detail::ensure_dir(inputs_dir);
        detail::ensure_dir(kind_dir);

        auto id = detail::make_artifact_id(request, kind);
        auto source_path = inputs_dir / (id + ".cpp");

        std::string extension{};
        switch (kind) {
            case analysis_kind::asm_text:
                extension = ".s";
                break;
            case analysis_kind::ir:
                extension = ".ll";
                break;
            case analysis_kind::diag:
            case analysis_kind::mca:
            case analysis_kind::dump:
                extension = ".txt";
                break;
            case analysis_kind::inspect_asm_map:
            case analysis_kind::inspect_mca_summary:
            case analysis_kind::inspect_mca_heatmap:
                extension = ".json";
                break;
            case analysis_kind::graph_cfg:
            case analysis_kind::graph_call:
            case analysis_kind::graph_defuse:
                extension = ".dot";
                break;
        }

        auto artifact_path = kind_dir / (id + extension);
        auto stdout_path = kind_dir / (id + ".stdout.txt");
        auto stderr_path = kind_dir / (id + ".stderr.txt");

        {
            std::ofstream out{source_path};
            if (!out) {
                throw std::runtime_error("failed to write source file: {}"_format(source_path.string()));
            }
            out << detail::render_source(request.decl_cells, request.exec_cells);
            if (!out) {
                throw std::runtime_error("failed to write source file: {}"_format(source_path.string()));
            }
        }

        analysis_result result{};
        result.kind = kind;
        result.source_path = source_path;
        result.artifact_path = artifact_path;
        result.stdout_path = stdout_path;
        result.stderr_path = stderr_path;

        if (kind == analysis_kind::graph_cfg || kind == analysis_kind::graph_call ||
            kind == analysis_kind::graph_defuse) {
            auto ir_path = kind_dir / (id + ".graph.ll");
            auto compile_command = detail::build_command(request, analysis_kind::ir, source_path, ir_path);
            auto compile_exit = detail::run_process(compile_command, stdout_path, stderr_path);
            auto compile_stdout = detail::read_text_file(stdout_path);
            auto compile_stderr = detail::read_text_file(stderr_path);

            if (compile_exit != 0) {
                detail::write_text_file(artifact_path, compile_stdout);

                result.exit_code = compile_exit;
                result.success = false;
                result.command = std::move(compile_command);
                result.artifact_text = std::move(compile_stdout);
                result.diagnostics_text = std::move(compile_stderr);
                return result;
            }

            auto ir_text = detail::read_text_file(ir_path);
            auto defined_symbols = detail::try_collect_defined_symbols(request);

            std::optional<std::string> resolved_symbol{};
            if (request.symbol) {
                if (defined_symbols) {
                    resolved_symbol = detail::resolve_symbol_name(*defined_symbols, *request.symbol);
                }
                if (!resolved_symbol) {
                    resolved_symbol = detail::resolve_symbol_name(request, *request.symbol);
                }
                if (!resolved_symbol) {
                    throw std::runtime_error("unable to resolve symbol: {}"_format(*request.symbol));
                }
            }
            else if (kind == analysis_kind::graph_call) {
                resolved_symbol = std::nullopt;
            }
            else {
                if (defined_symbols) {
                    resolved_symbol = detail::resolve_symbol_name(*defined_symbols, "__sontag_main");
                }
                if (!resolved_symbol) {
                    resolved_symbol = detail::resolve_symbol_name(request, "__sontag_main");
                }
                if (!resolved_symbol) {
                    resolved_symbol = graph::find_first_ir_function_name(ir_text);
                }
            }
            if (kind != analysis_kind::graph_call && !resolved_symbol) {
                throw std::runtime_error("unable to resolve graph root function");
            }

            std::string artifact_summary{};
            std::string dot_text{};
            if (kind == analysis_kind::graph_cfg) {
                auto cfg_artifact = graph::build_cfg_graph_artifact(ir_text, *resolved_symbol);
                if (!cfg_artifact && !request.symbol) {
                    if (auto fallback = graph::find_first_ir_function_name(ir_text)) {
                        resolved_symbol = fallback;
                        cfg_artifact = graph::build_cfg_graph_artifact(ir_text, *resolved_symbol);
                    }
                }
                if (!cfg_artifact) {
                    throw std::runtime_error("unable to build cfg graph for function: {}"_format(*resolved_symbol));
                }

                dot_text = cfg_artifact->dot_text;
                artifact_summary = "function: {}\nblocks: {}\nedges: {}\ndot: {}\n"_format(
                        cfg_artifact->function_name,
                        cfg_artifact->block_count,
                        cfg_artifact->edge_count,
                        artifact_path.string());
            }
            else if (kind == analysis_kind::graph_call) {
                auto symbol_display_names = detail::make_symbol_display_map(defined_symbols);

                auto call_artifact = graph::build_call_graph_artifact(
                        ir_text,
                        resolved_symbol ? *resolved_symbol : std::string_view{},
                        symbol_display_names.empty() ? nullptr : &symbol_display_names,
                        request.verbose);
                if (!call_artifact) {
                    throw std::runtime_error("unable to build call graph");
                }

                dot_text = call_artifact->dot_text;
                artifact_summary = "root: {}\nnodes: {}\nedges: {}\ndot: {}\n"_format(
                        call_artifact->root_display_name,
                        call_artifact->node_count,
                        call_artifact->edge_count,
                        artifact_path.string());
            }
            else {
                auto symbol_display_names = detail::make_symbol_display_map(defined_symbols);
                auto defuse_artifact = graph::build_defuse_graph_artifact(
                        ir_text, *resolved_symbol, symbol_display_names.empty() ? nullptr : &symbol_display_names);
                if (!defuse_artifact) {
                    throw std::runtime_error("unable to build defuse graph for function: {}"_format(*resolved_symbol));
                }

                dot_text = defuse_artifact->dot_text;
                artifact_summary = "function: {}\nnodes: {}\nedges: {}\ndot: {}\n"_format(
                        defuse_artifact->function_display_name,
                        defuse_artifact->node_count,
                        defuse_artifact->edge_count,
                        artifact_path.string());
            }
            detail::write_text_file(artifact_path, dot_text);

            auto diagnostics_text = compile_stderr;
            auto graph_format = detail::normalize_graph_format(request.graph_format);
            std::optional<fs::path> rendered_path{};

            auto render_exit = 0;
            std::vector<std::string> render_command{};
            if (graph_format != "dot") {
                rendered_path = kind_dir / (id + "." + graph_format);
                auto render_stdout_path = kind_dir / (id + ".render.stdout.txt");
                auto render_stderr_path = kind_dir / (id + ".render.stderr.txt");
                std::vector<std::string> attempted{};
                std::string render_stdout{};
                std::string render_stderr{};
                auto dot_candidates = detail::build_dot_executable_candidates(request);

                for (const auto& candidate : dot_candidates) {
                    render_command =
                            detail::build_dot_render_command(candidate, graph_format, artifact_path, *rendered_path);
                    render_exit = detail::run_process(render_command, render_stdout_path, render_stderr_path);
                    render_stdout = detail::read_text_file(render_stdout_path);
                    render_stderr = detail::read_text_file(render_stderr_path);
                    attempted.push_back(candidate);

                    auto tool_missing = render_exit == 127 && render_stdout.empty() && render_stderr.empty();
                    if (!tool_missing) {
                        break;
                    }
                }

                auto tool_missing = render_exit == 127 && render_stdout.empty() && render_stderr.empty();
                if (tool_missing) {
                    rendered_path.reset();
                    std::string missing_tool_message{"graphviz dot executable not found; render skipped"};
                    if (!attempted.empty()) {
                        missing_tool_message.append("\ntried: ");
                        missing_tool_message.append(detail::join_with_separator(attempted, ", "sv));
                    }
                    missing_tool_message.push_back('\n');
                    diagnostics_text = detail::join_text(diagnostics_text, missing_tool_message);
                }
                else {
                    diagnostics_text = detail::join_text(diagnostics_text, render_stderr);
                    if (render_exit != 0) {
                        detail::write_text_file(stderr_path, diagnostics_text);
                        result.exit_code = render_exit;
                        result.success = false;
                        result.command = std::move(render_command);
                        result.artifact_text = artifact_summary;
                        result.diagnostics_text = std::move(diagnostics_text);
                        return result;
                    }
                }
            }

            detail::write_text_file(stderr_path, diagnostics_text);

            auto artifact_text = artifact_summary;
            if (rendered_path) {
                artifact_text.append("rendered: {}\n"_format(rendered_path->string()));
            }
            else {
                artifact_text.append("rendered: <none>\n");
            }

            result.exit_code = 0;
            result.success = true;
            result.command = std::move(compile_command);
            result.artifact_text = std::move(artifact_text);
            result.diagnostics_text = std::move(diagnostics_text);
            return result;
        }

        if (kind == analysis_kind::inspect_asm_map) {
            auto asm_path = kind_dir / (id + ".viz.s");
            auto ir_path = kind_dir / (id + ".viz.ll");

            auto asm_stdout_path = kind_dir / (id + ".asm.stdout.txt");
            auto asm_stderr_path = kind_dir / (id + ".asm.stderr.txt");
            auto ir_stdout_path = kind_dir / (id + ".ir.stdout.txt");
            auto ir_stderr_path = kind_dir / (id + ".ir.stderr.txt");

            auto asm_command = detail::build_command(request, analysis_kind::asm_text, source_path, asm_path);
            auto asm_exit = detail::run_process(asm_command, asm_stdout_path, asm_stderr_path);
            if (asm_exit != 0) {
                result.exit_code = asm_exit;
                result.success = false;
                result.command = std::move(asm_command);
                result.artifact_text = detail::read_text_file(asm_stdout_path);
                result.diagnostics_text = detail::read_text_file(asm_stderr_path);
                detail::write_text_file(artifact_path, result.artifact_text);
                return result;
            }

            auto ir_command = detail::build_command(request, analysis_kind::ir, source_path, ir_path);
            auto ir_exit = detail::run_process(ir_command, ir_stdout_path, ir_stderr_path);
            if (ir_exit != 0) {
                result.exit_code = ir_exit;
                result.success = false;
                result.command = std::move(ir_command);
                result.artifact_text = detail::read_text_file(ir_stdout_path);
                result.diagnostics_text = detail::read_text_file(ir_stderr_path);
                detail::write_text_file(artifact_path, result.artifact_text);
                return result;
            }

            auto asm_text = detail::read_text_file(asm_path);
            auto ir_text = detail::read_text_file(ir_path);
            auto source_text = detail::read_text_file(source_path);

            auto defined_symbols = detail::try_collect_defined_symbols(request);
            auto symbol_display_names = detail::make_symbol_display_map(defined_symbols);

            std::optional<std::string> resolved_symbol{};
            if (request.symbol) {
                if (defined_symbols) {
                    resolved_symbol = detail::resolve_symbol_name(*defined_symbols, *request.symbol);
                }
                if (!resolved_symbol) {
                    resolved_symbol = detail::resolve_symbol_name(request, *request.symbol);
                }
                if (!resolved_symbol) {
                    throw std::runtime_error("unable to resolve symbol: {}"_format(*request.symbol));
                }
            }
            else {
                if (defined_symbols) {
                    resolved_symbol = detail::resolve_symbol_name(*defined_symbols, "__sontag_main");
                }
                if (!resolved_symbol) {
                    resolved_symbol = detail::resolve_symbol_name(request, "__sontag_main");
                }
            }

            if (resolved_symbol) {
                auto extracted_asm = detail::extract_asm_for_symbol(asm_text, *resolved_symbol);
                if (!extracted_asm.empty()) {
                    asm_text = std::move(extracted_asm);
                }
                auto extracted_ir = detail::extract_ir_for_symbol(ir_text, *resolved_symbol);
                if (!extracted_ir.empty()) {
                    ir_text = std::move(extracted_ir);
                }
            }

            auto symbol_name = resolved_symbol ? *resolved_symbol : std::string{"<all>"};
            auto symbol_display = detail::resolve_symbol_display_name(symbol_name, symbol_display_names);

            auto payload = detail::inspect_asm_map_payload{
                    .symbol = symbol_name,
                    .symbol_display = symbol_display,
                    .source = detail::make_line_records(source_text),
                    .ir = detail::make_line_records(ir_text),
                    .asm_lines = detail::make_line_records(asm_text)};
            auto payload_json = detail::serialize_json_payload(payload);
            detail::write_text_file(artifact_path, payload_json);

            auto diagnostics_text =
                    detail::join_text(detail::read_text_file(asm_stderr_path), detail::read_text_file(ir_stderr_path));
            detail::write_text_file(stderr_path, diagnostics_text);

            result.exit_code = 0;
            result.success = true;
            result.command = std::move(ir_command);
            result.artifact_text = "symbol: {}\nsource_lines: {}\nir_lines: {}\nasm_lines: {}\njson: {}\n"_format(
                    payload.symbol_display,
                    payload.source.size(),
                    payload.ir.size(),
                    payload.asm_lines.size(),
                    artifact_path.string());
            result.diagnostics_text = std::move(diagnostics_text);
            return result;
        }

        if (kind == analysis_kind::inspect_mca_summary || kind == analysis_kind::inspect_mca_heatmap) {
            auto mca_result = run_analysis(request, analysis_kind::mca);
            if (!mca_result.success) {
                result.exit_code = mca_result.exit_code;
                result.success = false;
                result.command = mca_result.command;
                result.artifact_text = mca_result.artifact_text;
                result.diagnostics_text = mca_result.diagnostics_text;
                detail::write_text_file(artifact_path, mca_result.artifact_text);
                return result;
            }

            auto defined_symbols = detail::try_collect_defined_symbols(request);
            auto symbol_display_names = detail::make_symbol_display_map(defined_symbols);
            std::string symbol_name{};
            if (request.symbol) {
                if (defined_symbols) {
                    if (auto resolved = detail::resolve_symbol_name(*defined_symbols, *request.symbol)) {
                        symbol_name = *resolved;
                    }
                }
                if (symbol_name.empty()) {
                    symbol_name = *request.symbol;
                }
            }
            else {
                symbol_name = "__sontag_main";
            }

            auto symbol_display = detail::resolve_symbol_display_name(symbol_name, symbol_display_names);

            std::string payload_json{};
            std::string artifact_summary{};
            if (kind == analysis_kind::inspect_mca_summary) {
                auto payload = detail::inspect_mca_summary_payload{
                        .symbol = symbol_name,
                        .symbol_display = symbol_display,
                        .source_path = mca_result.source_path.string()};
                detail::parse_mca_summary(mca_result.artifact_text, payload);
                payload.warnings = detail::split_lines(mca_result.diagnostics_text);
                payload_json = detail::serialize_json_payload(payload);
                auto rows = detail::parse_mca_heatmap_rows(mca_result.artifact_text);

                std::ostringstream summary{};
                summary << "symbol: " << payload.symbol_display << '\n';
                summary << "iterations: " << payload.iterations << '\n';
                summary << "instructions: " << payload.instructions << '\n';
                summary << "cycles: " << payload.total_cycles << '\n';
                summary << "ipc: " << payload.ipc << '\n';
                summary << "block_rthroughput: " << payload.block_rthroughput << '\n';
                if (!rows.empty()) {
                    summary << "resource pressure (top " << std::min<size_t>(8U, rows.size()) << "):\n";
                    for (size_t i = 0U; i < rows.size() && i < 8U; ++i) {
                        summary << "  " << rows[i].label << " " << rows[i].bar << " (" << rows[i].value << ")\n";
                    }
                }
                summary << "json: " << artifact_path.string() << '\n';
                artifact_summary = summary.str();
            }
            else {
                auto payload = detail::inspect_mca_heatmap_payload{
                        .symbol = symbol_name,
                        .symbol_display = symbol_display,
                        .rows = detail::parse_mca_heatmap_rows(mca_result.artifact_text)};
                payload_json = detail::serialize_json_payload(payload);

                std::ostringstream summary{};
                summary << "symbol: " << payload.symbol_display << '\n';
                summary << "heatmap rows: " << payload.rows.size() << '\n';
                for (const auto& row : payload.rows) {
                    summary << "  " << row.label << " " << row.bar << " (" << row.value << ")\n";
                }
                summary << "json: " << artifact_path.string() << '\n';
                artifact_summary = summary.str();
            }

            detail::write_text_file(artifact_path, payload_json);
            detail::write_text_file(stderr_path, mca_result.diagnostics_text);

            result.exit_code = 0;
            result.success = true;
            result.command = std::move(mca_result.command);
            result.artifact_text = std::move(artifact_summary);
            result.diagnostics_text = std::move(mca_result.diagnostics_text);
            return result;
        }

        if (kind == analysis_kind::mca) {
            auto asm_path = kind_dir / (id + ".input.s");
            auto compile_stdout_path = kind_dir / (id + ".compile.stdout.txt");
            auto compile_stderr_path = kind_dir / (id + ".compile.stderr.txt");

            auto compile_command = detail::build_command(request, analysis_kind::asm_text, source_path, asm_path);
            auto compile_exit = detail::run_process(compile_command, compile_stdout_path, compile_stderr_path);
            if (compile_exit != 0) {
                auto compile_stdout = detail::read_text_file(compile_stdout_path);
                auto compile_stderr = detail::read_text_file(compile_stderr_path);

                detail::write_text_file(stdout_path, compile_stdout);
                detail::write_text_file(stderr_path, compile_stderr);

                detail::write_text_file(artifact_path, compile_stdout);

                result.exit_code = compile_exit;
                result.success = false;
                result.command = std::move(compile_command);
                result.artifact_text = std::move(compile_stdout);
                result.diagnostics_text = std::move(compile_stderr);
                return result;
            }

            if (request.symbol) {
                auto resolved = detail::resolve_symbol_name(request, *request.symbol);
                if (!resolved) {
                    throw std::runtime_error("unable to resolve symbol: {}"_format(*request.symbol));
                }

                auto asm_text = detail::read_text_file(asm_path);
                auto extracted = detail::extract_asm_for_symbol(asm_text, *resolved);
                if (extracted.empty()) {
                    throw std::runtime_error("symbol not found in artifact: {}"_format(*resolved));
                }
                auto prepared_input = detail::prepare_mca_symbol_input(extracted, request.asm_syntax);
                detail::write_text_file(asm_path, prepared_input);
            }

            auto mca_exit = 127;
            std::string stdout_text{};
            std::string stderr_text{};
            std::vector<std::string> mca_command{};
            std::vector<std::string> attempted{};
            auto mca_candidates = detail::build_mca_executable_candidates(request, kind_dir, id);

            for (const auto& candidate : mca_candidates) {
                mca_command = detail::build_mca_command(request, asm_path, candidate);
                mca_exit = detail::run_process(mca_command, stdout_path, stderr_path);
                stdout_text = detail::read_text_file(stdout_path);
                stderr_text = detail::read_text_file(stderr_path);
                attempted.push_back(candidate);
                auto tool_missing = mca_exit == 127 && stdout_text.empty() && stderr_text.empty();
                if (!tool_missing) {
                    break;
                }
            }

            if (mca_exit == 127 && stdout_text.empty() && stderr_text.empty()) {
                if (attempted.empty()) {
                    stderr_text = "failed to execute llvm-mca tool: {}\n"_format(request.mca_path.string());
                }
                else {
                    stderr_text = "failed to execute llvm-mca tool: {}\ntried: {}\n"_format(
                            request.mca_path.string(), detail::join_with_separator(attempted, ", "sv));
                }
                detail::write_text_file(stderr_path, stderr_text);
            }

            detail::write_text_file(artifact_path, stdout_text);

            result.exit_code = mca_exit;
            result.success = (mca_exit == 0);
            result.command = std::move(mca_command);
            result.artifact_text = std::move(stdout_text);
            result.diagnostics_text = std::move(stderr_text);
            return result;
        }

        if (kind == analysis_kind::dump) {
            auto object_path = kind_dir / (id + ".input.o");
            auto compile_stdout_path = kind_dir / (id + ".compile.stdout.txt");
            auto compile_stderr_path = kind_dir / (id + ".compile.stderr.txt");

            auto compile_command = detail::build_command(request, analysis_kind::dump, source_path, object_path);
            auto compile_exit = detail::run_process(compile_command, compile_stdout_path, compile_stderr_path);
            if (compile_exit != 0) {
                auto compile_stdout = detail::read_text_file(compile_stdout_path);
                auto compile_stderr = detail::read_text_file(compile_stderr_path);

                detail::write_text_file(stdout_path, compile_stdout);
                detail::write_text_file(stderr_path, compile_stderr);
                detail::write_text_file(artifact_path, compile_stdout);

                result.exit_code = compile_exit;
                result.success = false;
                result.command = std::move(compile_command);
                result.artifact_text = std::move(compile_stdout);
                result.diagnostics_text = std::move(compile_stderr);
                return result;
            }

            std::optional<std::string> resolved_symbol{};
            if (request.symbol) {
                resolved_symbol = detail::resolve_symbol_name(request, *request.symbol);
                if (!resolved_symbol) {
                    throw std::runtime_error("unable to resolve symbol: {}"_format(*request.symbol));
                }
            }

            auto objdump_exit = 127;
            std::string stdout_text{};
            std::string stderr_text{};
            std::vector<std::string> objdump_command{};
            std::vector<std::string> attempted{};
            auto objdump_candidates = detail::build_objdump_executable_candidates(request, kind_dir, id);

            for (const auto& candidate : objdump_candidates) {
                objdump_command = detail::build_objdump_command(request, object_path, candidate, resolved_symbol);
                objdump_exit = detail::run_process(objdump_command, stdout_path, stderr_path);
                stdout_text = detail::read_text_file(stdout_path);
                stderr_text = detail::read_text_file(stderr_path);
                attempted.push_back(candidate);
                auto tool_missing = objdump_exit == 127 && stdout_text.empty() && stderr_text.empty();
                if (!tool_missing) {
                    break;
                }
            }

            if (objdump_exit == 127 && stdout_text.empty() && stderr_text.empty()) {
                if (attempted.empty()) {
                    stderr_text = "failed to execute llvm-objdump tool: {}\n"_format(request.objdump_path.string());
                }
                else {
                    stderr_text = "failed to execute llvm-objdump tool: {}\ntried: {}\n"_format(
                            request.objdump_path.string(), detail::join_with_separator(attempted, ", "sv));
                }
                detail::write_text_file(stderr_path, stderr_text);
            }

            detail::write_text_file(artifact_path, stdout_text);

            result.exit_code = objdump_exit;
            result.success = (objdump_exit == 0);
            result.command = std::move(objdump_command);
            result.artifact_text = std::move(stdout_text);
            result.diagnostics_text = std::move(stderr_text);
            return result;
        }

        if (kind == analysis_kind::diag) {
            std::ofstream artifact{artifact_path};
            if (!artifact) {
                throw std::runtime_error("failed to open diagnostic artifact: {}"_format(artifact_path.string()));
            }
        }

        auto command = detail::build_command(request, kind, source_path, artifact_path);
        auto exit_code = detail::run_process(command, stdout_path, stderr_path);

        result.exit_code = exit_code;
        result.success = (exit_code == 0);
        result.command = command;

        if (kind == analysis_kind::diag) {
            auto stdout_text = detail::read_text_file(stdout_path);
            auto stderr_text = detail::read_text_file(stderr_path);
            {
                std::ofstream artifact_out{artifact_path};
                if (!artifact_out) {
                    throw std::runtime_error("failed to open diagnostic artifact: {}"_format(artifact_path.string()));
                }
                artifact_out << stderr_text;
                if (!stdout_text.empty()) {
                    if (!stderr_text.empty()) {
                        artifact_out << '\n';
                    }
                    artifact_out << stdout_text;
                }
            }
            result.diagnostics_text = detail::read_text_file(artifact_path);
            result.artifact_text = result.diagnostics_text;
            if (request.symbol) {
                auto source_text = detail::read_text_file(source_path);
                auto filtered = detail::filter_diag_by_symbol(
                        result.artifact_text, source_text, source_path.string(), *request.symbol);
                {
                    std::ofstream artifact_out{artifact_path};
                    if (!artifact_out) {
                        throw std::runtime_error(
                                "failed to open diagnostic artifact: {}"_format(artifact_path.string()));
                    }
                    artifact_out << filtered;
                }
                result.diagnostics_text = filtered;
                result.artifact_text = filtered;
            }
        }
        else {
            result.artifact_text = detail::read_text_file(artifact_path);
            result.diagnostics_text = detail::read_text_file(stderr_path);
            if (request.symbol) {
                auto resolved = detail::resolve_symbol_name(request, *request.symbol);
                if (!resolved) {
                    throw std::runtime_error("unable to resolve symbol: {}"_format(*request.symbol));
                }

                std::string extracted{};
                if (kind == analysis_kind::asm_text) {
                    extracted = detail::extract_asm_for_symbol(result.artifact_text, *resolved);
                }
                else if (kind == analysis_kind::ir) {
                    extracted = detail::extract_ir_for_symbol(result.artifact_text, *resolved);
                }

                if (extracted.empty()) {
                    throw std::runtime_error("symbol not found in artifact: {}"_format(*resolved));
                }

                {
                    std::ofstream artifact_out{artifact_path};
                    if (!artifact_out) {
                        throw std::runtime_error(
                                "failed to open artifact for symbol extraction: {}"_format(artifact_path.string()));
                    }
                    artifact_out << extracted;
                }
                result.artifact_text = extracted;
            }
        }

        return result;
    }

    std::vector<analysis_symbol> list_symbols(const analysis_request& request) {
        if (request.decl_cells.empty() && request.exec_cells.empty()) {
            throw std::runtime_error("symbol listing requires at least one stored cell");
        }

        auto symbols = detail::try_collect_defined_symbols(request);
        if (!symbols) {
            throw std::runtime_error("failed to collect symbols from current snapshot");
        }
        return *symbols;
    }

    std::string synthesize_source(const analysis_request& request) {
        return detail::render_source(request.decl_cells, request.exec_cells);
    }

}  // namespace sontag
