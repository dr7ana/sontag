#include "sontag/analysis.hpp"

#include "sontag/config.hpp"
#include "sontag/graph.hpp"
#include "sontag/utils.hpp"

#include "internal/delta.hpp"
#include "internal/mem.hpp"
#include "internal/metrics.hpp"
#include "internal/opcode.hpp"
#include "internal/platform.hpp"
#include "internal/symbols.hpp"

#include <glaze/glaze.hpp>

#include <cxxabi.h>
extern "C" {
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
}

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ranges>
#include <span>
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
        std::string symbol_canonical{};
        std::optional<std::string> symbol_addendum{};
        std::string symbol_status{};
        std::string symbol_confidence{};
        std::string symbol_source{};
        std::vector<inspect_line_record> source{};
        std::vector<inspect_line_record> ir{};
        std::vector<inspect_line_record> asm_lines{};
        std::vector<analysis_opcode_entry> opcode_table{};
        std::vector<analysis_operation_entry> operations{};
    };

    struct inspect_mca_summary_payload {
        int schema_version{1};
        std::string symbol{};
        std::string symbol_display{};
        std::string symbol_canonical{};
        std::optional<std::string> symbol_addendum{};
        std::string symbol_status{};
        std::string symbol_confidence{};
        std::string symbol_source{};
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
        std::vector<analysis_opcode_entry> opcode_table{};
        std::vector<analysis_operation_entry> operations{};
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
        std::string symbol_canonical{};
        std::optional<std::string> symbol_addendum{};
        std::string symbol_status{};
        std::string symbol_confidence{};
        std::string symbol_source{};
        std::vector<inspect_mca_heatmap_row> rows{};
        std::vector<analysis_opcode_entry> opcode_table{};
        std::vector<analysis_operation_entry> operations{};
    };

}  // namespace sontag::detail

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
                       "symbol_canonical",
                       &T::symbol_canonical,
                       "symbol_addendum",
                       &T::symbol_addendum,
                       "symbol_status",
                       &T::symbol_status,
                       "symbol_confidence",
                       &T::symbol_confidence,
                       "symbol_source",
                       &T::symbol_source,
                       "source",
                       &T::source,
                       "ir",
                       &T::ir,
                       "asm",
                       &T::asm_lines,
                       "opcode_table",
                       &T::opcode_table,
                       "operations",
                       &T::operations);
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
                       "symbol_canonical",
                       &T::symbol_canonical,
                       "symbol_addendum",
                       &T::symbol_addendum,
                       "symbol_status",
                       &T::symbol_status,
                       "symbol_confidence",
                       &T::symbol_confidence,
                       "symbol_source",
                       &T::symbol_source,
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
                       &T::warnings,
                       "opcode_table",
                       &T::opcode_table,
                       "operations",
                       &T::operations);
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
                       "symbol_canonical",
                       &T::symbol_canonical,
                       "symbol_addendum",
                       &T::symbol_addendum,
                       "symbol_status",
                       &T::symbol_status,
                       "symbol_confidence",
                       &T::symbol_confidence,
                       "symbol_source",
                       &T::symbol_source,
                       "rows",
                       &T::rows,
                       "opcode_table",
                       &T::opcode_table,
                       "operations",
                       &T::operations);
    };

}  // namespace glz

namespace sontag {
    namespace detail {

        using namespace std::string_view_literals;

        static constexpr std::string_view trim_ascii(std::string_view value) {
            auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return {};
            }
            auto last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, (last - first) + 1U);
        }

        static constexpr bool is_identifier_char(char c) noexcept {
            auto lower = static_cast<char>(c | 0x20);
            return (c >= '0' && c <= '9') || (lower >= 'a' && lower <= 'z') || c == '_';
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

        static bool has_effective_code(std::string_view text) {
            auto sanitized = strip_comments_and_string_literals(text);
            return !trim_ascii(sanitized).empty();
        }

        struct trailing_return_statement {
            size_t token_start{};
            size_t expression_start{};
            size_t semicolon_offset{};
        };

        static std::optional<trailing_return_statement> parse_trailing_return_statement(std::string_view text) {
            auto sanitized = strip_comments_and_string_literals(text);
            auto sanitized_view = std::string_view{sanitized};
            auto semicolon_offset = sanitized_view.find_last_not_of(" \t\r\n");
            if (semicolon_offset == std::string_view::npos || sanitized_view[semicolon_offset] != ';') {
                return std::nullopt;
            }

            auto prefix = sanitized_view.substr(0U, semicolon_offset);
            auto statement_separator = prefix.find_last_of(";{}");
            auto statement_start = statement_separator == std::string_view::npos ? 0U : statement_separator + 1U;
            auto token_start = prefix.find_first_not_of(" \t\r\n", statement_start);
            if (token_start == std::string_view::npos) {
                return std::nullopt;
            }

            auto statement = trim_ascii(prefix.substr(token_start));
            constexpr auto return_keyword = "return"sv;
            if (!statement.starts_with(return_keyword)) {
                return std::nullopt;
            }
            if (statement.size() > return_keyword.size() && is_identifier_char(statement[return_keyword.size()])) {
                return std::nullopt;
            }

            auto expression_start = token_start + return_keyword.size();
            while (expression_start < semicolon_offset &&
                   std::isspace(static_cast<unsigned char>(sanitized_view[expression_start])) != 0) {
                ++expression_start;
            }

            return trailing_return_statement{
                    .token_start = token_start,
                    .expression_start = expression_start,
                    .semicolon_offset = semicolon_offset};
        }

        static constexpr std::string_view trailing_return_expression(
                std::string_view text, const trailing_return_statement& trailing_return) noexcept {
            return trim_ascii(text.substr(
                    trailing_return.expression_start,
                    trailing_return.semicolon_offset - trailing_return.expression_start));
        }

        static constexpr bool trailing_return_has_expression(
                std::string_view text, const trailing_return_statement& trailing_return) noexcept {
            return !trailing_return_expression(text, trailing_return).empty();
        }

        static bool has_terminal_return_expression(std::string_view cell) {
            auto trailing_return = parse_trailing_return_statement(cell);
            return trailing_return.has_value() && trailing_return_has_expression(cell, *trailing_return);
        }

        static constexpr std::string_view trim_trailing_ascii(std::string_view value) {
            while (!value.empty()) {
                auto c = value.back();
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                    break;
                }
                value.remove_suffix(1U);
            }
            return value;
        }

        static std::vector<std::string> prepare_exec_cells_for_render(const std::vector<std::string>& exec_cells) {
            std::vector<std::string> render_cells{};
            render_cells.reserve(exec_cells.size());
            for (const auto& cell : exec_cells) {
                auto render_cell = std::string{cell};
                if (has_effective_code(render_cell)) {
                    // Strip only terminal bare `return;`. Keep `return <expr>;` so caller-selected exit values survive.
                    if (auto trailing_return = parse_trailing_return_statement(render_cell)) {
                        if (!trailing_return_has_expression(render_cell, *trailing_return)) {
                            render_cell.erase(trailing_return->token_start);
                        }
                    }
                }
                render_cells.emplace_back(trim_trailing_ascii(render_cell));
            }

            return render_cells;
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

        static bool write_text_file(const fs::path& path, std::string_view text) {
            if (text.empty()) {
                return false;
            }
            std::ofstream out{path};
            if (!out) {
                throw std::runtime_error("failed to open file for write: {}"_format(path.string()));
            }
            out << text;
            if (!out) {
                throw std::runtime_error("failed to write file: {}"_format(path.string()));
            }
            return true;
        }

        static std::string render_source(
                const std::vector<std::string>& decl_cells, const std::vector<std::string>& exec_cells) {
            std::ostringstream source{};
            auto render_exec_cells = prepare_exec_cells_for_render(exec_cells);
            auto append_canonical_return = true;
            for (auto it = render_exec_cells.rbegin(); it != render_exec_cells.rend(); ++it) {
                if (!has_effective_code(*it)) {
                    continue;
                }
                append_canonical_return = !has_terminal_return_expression(*it);
                break;
            }

            source << "// generated by sontag m1\n";
            for (size_t i = 0U; i < decl_cells.size(); ++i) {
                source << "// decl cell " << (i + 1U) << '\n';
                source << decl_cells[i] << "\n\n";
            }

            source << "int main() {\n";
            for (size_t i = 0U; i < render_exec_cells.size(); ++i) {
                source << "    // exec cell " << (i + 1U) << '\n';
                write_exec_cell(source, render_exec_cells[i]);
                if (i + 1U < render_exec_cells.size()) {
                    source << '\n';
                }
            }
            if (!render_exec_cells.empty() && append_canonical_return) {
                source << '\n';
            }
            if (append_canonical_return) {
                source << "    return 0;\n";
            }
            source << "}\n";
            return source.str();
        }

        static void ensure_dir(const fs::path& path);
        static void attach_opcode_mapping(
                analysis_result& result, std::span<const opcode::operation_stream_input> streams);

        static std::string hash_fnv1a_64_hex(std::string_view text) {
            auto hash = uint64_t{14695981039346656037ULL};
            constexpr auto prime = uint64_t{1099511628211ULL};
            for (unsigned char c : text) {
                hash ^= static_cast<uint64_t>(c);
                hash *= prime;
            }
            std::ostringstream out{};
            out << std::hex << hash;
            return out.str();
        }

        static std::string format_optional_value(const std::optional<std::string>& value) {
            if (!value) {
                return "<none>";
            }
            return *value;
        }

        static std::string normalize_requested_symbol_for_cache(const analysis_request& request) {
            if (request.symbol) {
                return *request.symbol;
            }
            return "<default>";
        }

        static std::string render_build_unit_payload(const analysis_request& request, std::string_view source_text) {
            std::ostringstream payload{};
            payload << "clang_path=" << request.clang_path.string() << '\n';
            payload << "language_standard=" << "{}"_format(request.language_standard) << '\n';
            payload << "opt_level=" << "{}"_format(request.opt_level) << '\n';
            payload << "target_triple=" << format_optional_value(request.target_triple) << '\n';
            payload << "cpu=" << format_optional_value(request.cpu) << '\n';
            payload << "mca_cpu=" << format_optional_value(request.mca_cpu) << '\n';
            payload << "objdump_path=" << request.objdump_path.string() << '\n';
            payload << "nm_path=" << request.nm_path.string() << '\n';
            payload << "mca_path=" << request.mca_path.string() << '\n';
            payload << "asm_syntax=" << request.asm_syntax << '\n';
            payload << "static_link=" << (request.static_link ? "true" : "false") << '\n';
            payload << "no_link=" << (request.no_link ? "true" : "false") << '\n';
            payload << "graph_format=" << request.graph_format << '\n';
            payload << "source_digest=" << hash_fnv1a_64_hex(source_text) << '\n';
            payload << "source_bytes=" << source_text.size() << '\n';

            for (size_t i = 0U; i < request.library_dirs.size(); ++i) {
                payload << "library_dir[" << i << "]=" << request.library_dirs[i].string() << '\n';
            }
            for (size_t i = 0U; i < request.libraries.size(); ++i) {
                payload << "library[" << i << "]=" << request.libraries[i] << '\n';
            }
            for (size_t i = 0U; i < request.linker_args.size(); ++i) {
                payload << "linker_arg[" << i << "]=" << request.linker_args[i] << '\n';
            }

            return payload.str();
        }

        static std::string render_symbol_view_payload(
                std::string_view build_unit_hash, const analysis_request& request, analysis_kind kind) {
            std::ostringstream payload{};
            payload << "build_unit_hash=" << build_unit_hash << '\n';
            payload << "analysis_kind=" << to_string(kind) << '\n';
            payload << "requested_symbol=" << normalize_requested_symbol_for_cache(request) << '\n';
            payload << "asm_syntax=" << request.asm_syntax << '\n';
            payload << "graph_format=" << request.graph_format << '\n';
            return payload.str();
        }

        static std::string render_trace_payload(std::string_view build_unit_hash, const analysis_request& request) {
            std::ostringstream payload{};
            payload << "build_unit_hash=" << build_unit_hash << '\n';
            payload << "analysis_kind=mem_trace\n";
            payload << "requested_symbol=" << normalize_requested_symbol_for_cache(request) << '\n';
            payload << "trace_mode=runtime_instrumented\n";
            return payload.str();
        }

        static std::string make_merkle_node_hash(
                std::string_view node_kind, std::string_view payload_hash, std::span<const std::string> child_hashes) {
            std::ostringstream key{};
            key << "node_kind=" << node_kind << '\n';
            key << "payload_hash=" << payload_hash << '\n';
            for (size_t i = 0U; i < child_hashes.size(); ++i) {
                key << "child[" << i << "]=" << child_hashes[i] << '\n';
            }
            return hash_fnv1a_64_hex(key.str());
        }

        static std::string make_build_unit_hash(const analysis_request& request, std::string_view source_text) {
            auto build_payload = render_build_unit_payload(request, source_text);
            auto build_payload_hash = hash_fnv1a_64_hex(build_payload);
            auto empty_children = std::array<std::string, 0U>{};
            return make_merkle_node_hash("build_unit", build_payload_hash, empty_children);
        }

        static std::string make_symbol_view_hash(
                std::string_view build_unit_hash, const analysis_request& request, analysis_kind kind) {
            auto symbol_payload = render_symbol_view_payload(build_unit_hash, request, kind);
            auto symbol_payload_hash = hash_fnv1a_64_hex(symbol_payload);
            auto symbol_children = std::array<std::string, 1U>{std::string{build_unit_hash}};
            return make_merkle_node_hash("symbol_view", symbol_payload_hash, symbol_children);
        }

        static std::string make_trace_hash(std::string_view build_unit_hash, const analysis_request& request) {
            auto trace_payload = render_trace_payload(build_unit_hash, request);
            auto trace_payload_hash = hash_fnv1a_64_hex(trace_payload);
            auto trace_children = std::array<std::string, 1U>{std::string{build_unit_hash}};
            return make_merkle_node_hash("trace", trace_payload_hash, trace_children);
        }

        static std::string make_artifact_id(
                std::string_view build_unit_hash, const analysis_request& request, analysis_kind kind) {
            if (kind == analysis_kind::mem_trace) {
                return make_trace_hash(build_unit_hash, request);
            }
            return make_symbol_view_hash(build_unit_hash, request, kind);
        }

        static void persist_merkle_node(
                const fs::path& root_dir,
                std::string_view node_kind,
                std::string_view payload,
                std::span<const std::string> child_hashes,
                std::span<const fs::path> artifacts) {
            auto payload_hash = hash_fnv1a_64_hex(payload);
            auto node_hash = make_merkle_node_hash(node_kind, payload_hash, child_hashes);
            auto node_dir = root_dir / node_hash;
            ensure_dir(node_dir);

            auto payload_path = node_dir / "payload.txt";
            auto manifest_path = node_dir / "manifest.txt";
            (void)write_text_file(payload_path, payload);

            std::ostringstream manifest{};
            manifest << "node_kind=" << node_kind << '\n';
            manifest << "node_hash=" << node_hash << '\n';
            manifest << "payload_hash=" << payload_hash << '\n';
            manifest << "payload_file=payload.txt\n";
            for (size_t i = 0U; i < child_hashes.size(); ++i) {
                manifest << "child[" << i << "]=" << child_hashes[i] << '\n';
            }
            for (size_t i = 0U; i < artifacts.size(); ++i) {
                manifest << "artifact[" << i << "]=" << artifacts[i].string() << '\n';
            }
            (void)write_text_file(manifest_path, manifest.str());
        }

        static void persist_merkle_cache_manifests(
                const analysis_request& request,
                analysis_kind kind,
                std::string_view source_text,
                std::string_view build_unit_hash,
                const fs::path& source_path,
                const fs::path& artifact_path) {
            try {
                auto cache_root = request.session_dir / "artifacts" / "cache";
                auto units_root = cache_root / "units";
                auto symbols_root = cache_root / "symbols";
                auto traces_root = cache_root / "traces";
                ensure_dir(units_root);
                ensure_dir(symbols_root);
                ensure_dir(traces_root);

                auto build_payload = render_build_unit_payload(request, source_text);
                auto empty_children = std::array<std::string, 0U>{};
                auto build_artifacts = std::array<fs::path, 1U>{source_path};
                persist_merkle_node(units_root, "build_unit", build_payload, empty_children, build_artifacts);

                auto symbol_payload = render_symbol_view_payload(build_unit_hash, request, kind);
                auto symbol_children = std::array<std::string, 1U>{std::string{build_unit_hash}};
                auto symbol_artifacts = std::array<fs::path, 1U>{artifact_path};
                persist_merkle_node(symbols_root, "symbol_view", symbol_payload, symbol_children, symbol_artifacts);

                if (kind == analysis_kind::mem_trace) {
                    auto trace_payload = render_trace_payload(build_unit_hash, request);
                    auto trace_children = std::array<std::string, 1U>{std::string{build_unit_hash}};
                    auto trace_artifacts = std::array<fs::path, 1U>{artifact_path};
                    persist_merkle_node(traces_root, "trace", trace_payload, trace_children, trace_artifacts);
                }
            } catch (...) {
                // Cache-manifest writes are best-effort and must not affect analysis behavior.
            }
        }

        static bool looks_like_mem_trace_payload(std::string_view text) {
            return text.find("symbol="sv) != std::string_view::npos &&
                   text.find("tracee_exit_code="sv) != std::string_view::npos &&
                   text.find("--events--"sv) != std::string_view::npos;
        }

        static std::optional<int> parse_mem_trace_exit_code(std::string_view text) {
            constexpr auto prefix = "tracee_exit_code="sv;
            size_t begin = 0U;
            while (begin <= text.size()) {
                auto end = text.find('\n', begin);
                if (end == std::string_view::npos) {
                    end = text.size();
                }

                auto line = text.substr(begin, end - begin);
                if (line.starts_with(prefix)) {
                    auto value_text = line.substr(prefix.size());
                    int value = 0;
                    auto* value_begin = value_text.data();
                    auto* value_end = value_begin + value_text.size();
                    auto parsed = std::from_chars(value_begin, value_end, value);
                    if (parsed.ec == std::errc{} && parsed.ptr == value_end) {
                        return value;
                    }
                    return std::nullopt;
                }

                if (end == text.size()) {
                    break;
                }
                begin = end + 1U;
            }
            return std::nullopt;
        }

        static std::optional<analysis_result> try_load_cached_mem_trace_result(
                const fs::path& source_path,
                const fs::path& artifact_path,
                const fs::path& stdout_path,
                const fs::path& stderr_path) {
            auto cached = read_text_file(artifact_path);
            if (cached.empty() || !looks_like_mem_trace_payload(cached)) {
                return std::nullopt;
            }

            auto cached_result = analysis_result{
                    .kind = analysis_kind::mem_trace,
                    .success = true,
                    .exit_code = parse_mem_trace_exit_code(cached).value_or(0),
                    .source_path = source_path,
                    .artifact_path = artifact_path,
                    .stdout_path = stdout_path,
                    .stderr_path = stderr_path,
                    .artifact_text = std::move(cached)};
            return cached_result;
        }

        static bool supports_text_cache_hit(analysis_kind kind) {
            return kind == analysis_kind::asm_text || kind == analysis_kind::ir || kind == analysis_kind::dump;
        }

        static bool supports_summary_cache_hit(analysis_kind kind) {
            return kind == analysis_kind::graph_cfg || kind == analysis_kind::graph_call ||
                   kind == analysis_kind::graph_defuse || kind == analysis_kind::inspect_asm_map ||
                   kind == analysis_kind::inspect_mca_summary || kind == analysis_kind::inspect_mca_heatmap;
        }

        static fs::path summary_sidecar_path_for_artifact(const fs::path& artifact_path) {
            return fs::path{artifact_path.string() + ".summary.txt"};
        }

        static void write_summary_sidecar(const fs::path& artifact_path, std::string_view summary_text) {
            (void)write_text_file(summary_sidecar_path_for_artifact(artifact_path), summary_text);
        }

        static std::optional<analysis_result> try_load_cached_text_artifact_result(
                analysis_kind kind,
                const fs::path& source_path,
                const fs::path& artifact_path,
                const fs::path& stdout_path,
                const fs::path& stderr_path) {
            if (!supports_text_cache_hit(kind)) {
                return std::nullopt;
            }

            auto cached = read_text_file(artifact_path);
            if (trim_ascii(cached).empty()) {
                return std::nullopt;
            }

            auto cached_result = analysis_result{
                    .kind = kind,
                    .success = true,
                    .exit_code = 0,
                    .source_path = source_path,
                    .artifact_path = artifact_path,
                    .stdout_path = stdout_path,
                    .stderr_path = stderr_path,
                    .artifact_text = std::move(cached),
                    .diagnostics_text = read_text_file(stderr_path)};
            if (kind == analysis_kind::dump) {
                auto dump_streams = std::array{
                        opcode::operation_stream_input{.name = "asm", .disassembly = cached_result.artifact_text}};
                attach_opcode_mapping(cached_result, dump_streams);
            }
            return cached_result;
        }

        static std::optional<analysis_result> try_load_cached_summary_result(
                analysis_kind kind,
                const fs::path& source_path,
                const fs::path& artifact_path,
                const fs::path& stdout_path,
                const fs::path& stderr_path) {
            if (!supports_summary_cache_hit(kind)) {
                return std::nullopt;
            }

            auto summary_text = read_text_file(summary_sidecar_path_for_artifact(artifact_path));
            auto artifact_payload = read_text_file(artifact_path);
            if (trim_ascii(summary_text).empty() || trim_ascii(artifact_payload).empty()) {
                return std::nullopt;
            }

            auto cached_result = analysis_result{
                    .kind = kind,
                    .success = true,
                    .exit_code = 0,
                    .source_path = source_path,
                    .artifact_path = artifact_path,
                    .stdout_path = stdout_path,
                    .stderr_path = stderr_path,
                    .artifact_text = std::move(summary_text),
                    .diagnostics_text = read_text_file(stderr_path)};
            return cached_result;
        }

        template <typename T, typename TryLoadFn, typename BuildFn>
        static T get_or_create(TryLoadFn&& try_load, BuildFn&& build) {
            if (auto loaded = std::invoke(std::forward<TryLoadFn>(try_load)); loaded.has_value()) {
                return std::move(*loaded);
            }
            return std::invoke(std::forward<BuildFn>(build));
        }

        static void ensure_dir(const fs::path& path) {
            std::error_code ec{};
            fs::create_directories(path, ec);
            if (ec) {
                throw std::runtime_error("failed to create directory: {}"_format(path.string()));
            }
        }

        static void remove_if_empty(const fs::path& path) {
            std::error_code ec{};
            if (fs::exists(path, ec) && fs::file_size(path, ec) == 0U) {
                fs::remove(path, ec);
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

            remove_if_empty(stdout_path);
            remove_if_empty(stderr_path);

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
            static constexpr auto stdlib_libcpp = "-stdlib=libc++"sv;
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
            static constexpr auto objdump_disassembler_options_prefix = "--disassembler-options="sv;
            static constexpr auto objdump_no_aliases = "no-aliases"sv;
            static constexpr auto objdump_symbolize_operands = "--symbolize-operands"sv;
            static constexpr auto objdump_show_all_symbols = "--show-all-symbols"sv;
            static constexpr auto objdump_disassemble_symbols_prefix = "--disassemble-symbols="sv;
            static constexpr auto objdump_line_numbers = "--line-numbers"sv;
            static constexpr auto objdump_source = "--source"sv;
            static constexpr auto nm_defined_only = "--defined-only"sv;
            static constexpr auto nm_posix_format = "-P"sv;

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

        static void append_host_objdump_arch_args(std::vector<std::string>& args, const analysis_request& request) {
#if SONTAG_ARCH_X86_64
            if (request.asm_syntax == "intel"sv) {
                args.emplace_back(arg_tokens::objdump_x86_intel_syntax);
            }
            else {
                args.emplace_back(arg_tokens::objdump_x86_att_syntax);
            }
#elif SONTAG_ARCH_ARM64
            append_prefixed_arg(args, arg_tokens::objdump_disassembler_options_prefix, arg_tokens::objdump_no_aliases);
#else
            static_cast<void>(args);
            static_cast<void>(request);
#endif
        }

        static std::vector<std::string> base_clang_args(const analysis_request& request) {
            std::vector<std::string> base_args{};
            base_args.reserve(10U);
            base_args.push_back(request.clang_path.string());
            base_args.emplace_back(arg_tokens::stdlib_libcpp);
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
#if SONTAG_ARCH_X86_64
                    if (request.asm_syntax == "intel") {
                        base_args.emplace_back(arg_tokens::intel_syntax);
                    }
#endif
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
                case analysis_kind::mem_trace:
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
            append_host_objdump_arch_args(base_args, request);
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
            if (std::ranges::find(values, value) == values.end()) {
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
            return utils::join_with_separator(values, separator);
        }

        static void append_link_flags(std::vector<std::string>& args, const analysis_request& request) {
            args.push_back("-fuse-ld=" + std::string{internal::platform::tool::lld_path});
            args.emplace_back("-fPIC");
            args.emplace_back("-flto=thin");
            args.emplace_back("-nostdlib++");
            args.emplace_back("-Wl,--push-state,-Bstatic");
            args.emplace_back("-lc++");
            args.emplace_back("-lc");
            args.emplace_back("-Wl,--pop-state");

            args.emplace_back("-lc++abi");
            if (request.static_link) {
                args.emplace_back("-static");
                args.emplace_back("-static-libgcc");
            }
            else {
                args.emplace_back("-ldl");
            }
            for (const auto& dir : request.library_dirs) {
                args.push_back("-L" + dir.string());
            }
            for (const auto& lib : request.libraries) {
                args.push_back("-l" + lib);
            }
            for (const auto& arg : request.linker_args) {
                args.push_back(arg);
            }
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

        static constexpr bool starts_with(std::string_view value, std::string_view prefix) {
            return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
        }

        static std::vector<std::string> split_lines(std::string_view text) {
            std::vector<std::string> lines{};
            size_t begin = 0U;
            while (begin <= text.size()) {
                auto end = text.find('\n', begin);
                if (end == std::string_view::npos) {
                    end = text.size();
                }

                auto line = text.substr(begin, end - begin);
                if (!line.empty() && line.back() == '\r') {
                    line.remove_suffix(1U);
                }
                lines.emplace_back(line);

                if (end == text.size()) {
                    break;
                }
                begin = end + 1U;
            }
            return lines;
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

        static constexpr bool contains_token(std::string_view haystack, std::string_view needle) {
            return haystack.find(needle) != std::string_view::npos;
        }

        static constexpr std::string_view strip_one_leading_underscore(std::string_view symbol) noexcept {
            return internal::symbols::strip_one_leading_underscore(symbol);
        }

        static constexpr std::string_view strip_symbol_addendum(std::string_view symbol) noexcept {
            return internal::symbols::strip_symbol_addendum(symbol);
        }

        static constexpr std::string_view canonical_symbol_for_match(std::string_view symbol) noexcept {
            return internal::symbols::canonical_symbol_for_match(symbol);
        }

        static constexpr bool symbol_names_equivalent(std::string_view lhs, std::string_view rhs) noexcept {
            return internal::symbols::symbol_names_equivalent(lhs, rhs);
        }

        static constexpr bool ascii_is_digit(char c) noexcept {
            return c >= '0' && c <= '9';
        }

        static std::optional<std::string> try_demangle_symbol_name(std::string_view input) {
            int status = 0;
            auto* demangled_ptr = abi::__cxa_demangle(std::string{input}.c_str(), nullptr, nullptr, &status);
            if (demangled_ptr == nullptr || status != 0) {
                return std::nullopt;
            }

            std::string demangled{demangled_ptr};
            std::free(demangled_ptr);
            return demangled;
        }

        static std::string demangle_symbol_name(std::string_view mangled) {
            if (auto demangled = try_demangle_symbol_name(mangled)) {
                return *demangled;
            }
            if (auto stripped = strip_one_leading_underscore(mangled); stripped != mangled) {
                if (auto demangled = try_demangle_symbol_name(stripped)) {
                    return *demangled;
                }
            }
            return std::string{mangled};
        }

        static std::optional<analysis_symbol> parse_nm_symbol_line(std::string_view line) {
            auto trimmed = trim_ascii(line);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            auto tokens = split_whitespace_tokens(trimmed);
            if (tokens.size() < 2U) {
                return std::nullopt;
            }

            auto kind_token = trim_ascii(tokens[1]);
            if (kind_token.size() != 1U) {
                return std::nullopt;
            }
            auto kind = kind_token.front();

            // POSIX nm format (-P): <name> <type> <value> <size>
            if (tokens.size() >= 4U) {
                auto mangled = trim_ascii(tokens[0]);
                if (mangled.empty()) {
                    return std::nullopt;
                }
                return analysis_symbol{
                        .kind = kind, .mangled = std::string{mangled}, .demangled = demangle_symbol_name(mangled)};
            }

            // Legacy/default nm format: <value> <type> <name>
            if (tokens.size() >= 3U) {
                auto mangled = trim_ascii(tokens[2]);
                if (mangled.empty()) {
                    return std::nullopt;
                }
                return analysis_symbol{
                        .kind = kind, .mangled = std::string{mangled}, .demangled = demangle_symbol_name(mangled)};
            }

            auto mangled = trim_ascii(tokens[0]);
            if (mangled.empty()) {
                return std::nullopt;
            }

            return analysis_symbol{
                    .kind = kind, .mangled = std::string{mangled}, .demangled = demangle_symbol_name(mangled)};
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

            std::ranges::sort(symbols, [](const analysis_symbol& lhs, const analysis_symbol& rhs) {
                if (lhs.demangled != rhs.demangled) {
                    return lhs.demangled < rhs.demangled;
                }
                if (lhs.mangled != rhs.mangled) {
                    return lhs.mangled < rhs.mangled;
                }
                return lhs.kind < rhs.kind;
            });

            auto deduplicated_end =
                    std::ranges::unique(symbols, [](const analysis_symbol& lhs, const analysis_symbol& rhs) {
                        return lhs.kind == rhs.kind && lhs.mangled == rhs.mangled;
                    });
            symbols.erase(deduplicated_end.begin(), deduplicated_end.end());

            return symbols;
        }

        static std::optional<std::vector<analysis_symbol>> try_collect_defined_symbols(
                const analysis_request& request) {
            auto source_text = render_source(request.decl_cells, request.exec_cells);
            auto build_unit_hash = make_build_unit_hash(request, source_text);
            auto inputs_dir = request.session_dir / "artifacts" / "inputs" / build_unit_hash;
            auto source_path = inputs_dir / "source.cpp";
            auto object_path = inputs_dir / "symbol_index.o";
            auto clang_stdout_path = inputs_dir / "symbol_index.clang.stdout.txt";
            auto clang_stderr_path = inputs_dir / "symbol_index.clang.stderr.txt";
            auto nm_stdout_path = inputs_dir / "symbol_index.nm.stdout.txt";
            auto nm_stderr_path = inputs_dir / "symbol_index.nm.stderr.txt";

            ensure_dir(inputs_dir);
            write_text_file(source_path, source_text);

            auto collect_symbols_from_target = [&](const fs::path& target_path,
                                                   bool from_object) -> std::optional<std::vector<analysis_symbol>> {
                std::vector<std::string> nm_args{};
                nm_args.push_back(request.nm_path.string());
                nm_args.emplace_back(arg_tokens::nm_defined_only);
                nm_args.emplace_back(arg_tokens::nm_posix_format);
                nm_args.push_back(target_path.string());
                auto nm_exit = run_process(nm_args, nm_stdout_path, nm_stderr_path);
                if (nm_exit != 0) {
                    return std::nullopt;
                }
                auto nm_output = read_text_file(nm_stdout_path);
                auto symbols = parse_nm_symbols(nm_output);
                for (auto& symbol : symbols) {
                    symbol.present_in_object = from_object;
                    symbol.present_in_binary = !from_object;
                }
                return symbols;
            };

            auto compile_args = base_clang_args(request);
            compile_args.emplace_back("-c");
            compile_args.push_back(source_path.string());
            compile_args.emplace_back("-o");
            compile_args.push_back(object_path.string());
            auto compile_exit = run_process(compile_args, clang_stdout_path, clang_stderr_path);
            if (compile_exit != 0) {
                return std::nullopt;
            }

            auto merged_symbols = std::vector<analysis_symbol>{};
            if (auto object_symbols = collect_symbols_from_target(object_path, true); object_symbols.has_value()) {
                merged_symbols = std::move(*object_symbols);
            }
            else {
                return std::nullopt;
            }

            auto binary_path = inputs_dir / "symbol_index.bin";
            bool linked = false;

            if (!request.no_link) {
                auto link_args = base_clang_args(request);
                link_args.push_back(source_path.string());
                link_args.emplace_back("-o");
                link_args.push_back(binary_path.string());
                append_link_flags(link_args, request);
                auto link_exit = run_process(link_args, clang_stdout_path, clang_stderr_path);
                linked = (link_exit == 0);
                if (!linked && request.verbose) {
                    auto link_stderr = read_text_file(clang_stderr_path);
                    if (!link_stderr.empty()) {
                        debug_log("symbol index link failed (exit {}): {}", link_exit, link_stderr);
                    }
                }
            }

            if (linked) {
                if (auto linked_symbols = collect_symbols_from_target(binary_path, false); linked_symbols.has_value()) {
                    merged_symbols.insert(
                            merged_symbols.end(),
                            std::make_move_iterator(linked_symbols->begin()),
                            std::make_move_iterator(linked_symbols->end()));
                }
                else if (request.verbose) {
                    auto link_nm_stderr = read_text_file(nm_stderr_path);
                    if (!link_nm_stderr.empty()) {
                        debug_log("symbol index nm failed for linked binary: {}", link_nm_stderr);
                    }
                }

                std::error_code ec{};
                fs::remove(binary_path, ec);
            }

            auto merged_by_mangled = std::unordered_map<std::string, analysis_symbol>{};
            merged_by_mangled.reserve(merged_symbols.size());
            auto prefer_kind = [](char current, char incoming) {
                auto current_upper = std::isupper(static_cast<unsigned char>(current)) != 0;
                auto incoming_upper = std::isupper(static_cast<unsigned char>(incoming)) != 0;
                if (incoming_upper && !current_upper) {
                    return incoming;
                }
                return current;
            };
            for (const auto& symbol : merged_symbols) {
                auto [it, inserted] = merged_by_mangled.try_emplace(symbol.mangled, symbol);
                if (inserted) {
                    continue;
                }
                auto& existing = it->second;
                existing.kind = prefer_kind(existing.kind, symbol.kind);
                if (existing.demangled == existing.mangled && symbol.demangled != symbol.mangled) {
                    existing.demangled = symbol.demangled;
                }
                existing.present_in_object = existing.present_in_object || symbol.present_in_object;
                existing.present_in_binary = existing.present_in_binary || symbol.present_in_binary;
            }

            auto out_symbols = std::vector<analysis_symbol>{};
            out_symbols.reserve(merged_by_mangled.size());
            for (auto& [_, symbol] : merged_by_mangled) {
                out_symbols.push_back(std::move(symbol));
            }
            std::ranges::sort(out_symbols, [](const analysis_symbol& lhs, const analysis_symbol& rhs) {
                if (lhs.demangled != rhs.demangled) {
                    return lhs.demangled < rhs.demangled;
                }
                if (lhs.mangled != rhs.mangled) {
                    return lhs.mangled < rhs.mangled;
                }
                return lhs.kind < rhs.kind;
            });
            return out_symbols;
        }

        static constexpr std::optional<size_t> parse_header_line_number(
                std::string_view line, std::string_view source_path) {
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
                if (!ascii_is_digit(c)) {
                    return std::nullopt;
                }
                line_number = (line_number * 10U) + static_cast<size_t>(c - '0');
            }
            return line_number;
        }

        static std::string filter_diag_by_symbol(
                std::string_view diagnostics_text,
                std::string_view source_text,
                std::string_view source_path,
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

        struct resolved_symbol_match {
            std::string mangled{};
            symbol_resolution_info info{};
        };

        static symbol_resolution_status adjust_status_from_symbol_addendum(
                symbol_resolution_status base_status, std::optional<std::string_view> addendum) {
            if (!addendum.has_value()) {
                return base_status;
            }
            if (internal::symbols::addendum_implies_stub(*addendum)) {
                return symbol_resolution_status::resolved_stub;
            }
            if (internal::symbols::addendum_implies_indirect(*addendum)) {
                return symbol_resolution_status::unresolved_indirect;
            }
            return base_status;
        }

        static symbol_resolution_info make_symbol_resolution_info(
                std::string_view requested,
                const analysis_symbol& candidate,
                symbol_resolution_confidence confidence,
                std::string_view source_hint = {}) {
            auto info = symbol_resolution_info{};
            info.raw_name = std::string{requested};
            info.canonical_name = std::string{canonical_symbol_for_match(candidate.mangled)};
            info.display_name =
                    candidate.demangled.empty() ? demangle_symbol_name(candidate.mangled) : candidate.demangled;
            auto requested_addendum = internal::symbols::extract_symbol_addendum(requested);
            auto mangled_addendum = internal::symbols::extract_symbol_addendum(candidate.mangled);
            auto selected_addendum = mangled_addendum.has_value() ? mangled_addendum : requested_addendum;
            if (selected_addendum.has_value()) {
                info.addendum = std::string{*selected_addendum};
            }

            if (candidate.present_in_binary) {
                info.status = symbol_resolution_status::resolved_final;
                info.source = source_hint.empty() ? "symtab_bin" : std::string{source_hint};
            }
            else if (candidate.present_in_object) {
                info.status = symbol_resolution_status::resolved_object_only;
                info.source = source_hint.empty() ? "symtab_obj" : std::string{source_hint};
            }
            else {
                info.status = symbol_resolution_status::missing;
                info.source = source_hint.empty() ? "symtab_unknown" : std::string{source_hint};
            }
            info.status = adjust_status_from_symbol_addendum(info.status, selected_addendum);
            if (info.status == symbol_resolution_status::resolved_stub) {
                info.source = "{}_stub"_format(info.source);
            }
            else if (info.status == symbol_resolution_status::unresolved_indirect) {
                info.source = "{}_indirect"_format(info.source);
            }
            info.confidence = confidence;
            return info;
        }

        static symbol_resolution_info make_missing_symbol_resolution_info(std::string_view requested) {
            auto info = symbol_resolution_info{};
            info.raw_name = std::string{requested};
            info.canonical_name = std::string{canonical_symbol_for_match(requested)};
            info.display_name = std::string{trim_ascii(requested)};
            if (auto addendum = internal::symbols::extract_symbol_addendum(requested); addendum.has_value()) {
                info.addendum = std::string{*addendum};
                if (internal::symbols::addendum_implies_stub(*addendum) ||
                    internal::symbols::addendum_implies_indirect(*addendum)) {
                    info.status = symbol_resolution_status::unresolved_indirect;
                    info.source = "unresolved_indirect";
                }
            }
            info.confidence = symbol_resolution_confidence::heuristic_match;
            if (info.source.empty()) {
                info.source = "unresolved";
            }
            return info;
        }

        static std::optional<resolved_symbol_match> resolve_symbol_match(
                const std::vector<analysis_symbol>& symbols, std::string_view symbol) {
            auto requested = trim_ascii(symbol);
            auto requested_canonical = canonical_symbol_for_match(requested);
            auto requested_addendum = internal::symbols::extract_symbol_addendum(requested);
            auto is_symbol_char = [](char c) {
                auto u = static_cast<unsigned char>(c);
                auto lower = static_cast<char>(u | 0x20);
                return (u >= '0' && u <= '9') || (lower >= 'a' && lower <= 'z') || c == '_' || c == '$' || c == ':';
            };
            auto starts_with_symbol_token = [&](std::string_view haystack, std::string_view needle) {
                if (needle.empty() || haystack.size() < needle.size()) {
                    return false;
                }
                if (!haystack.starts_with(needle)) {
                    return false;
                }
                if (haystack.size() == needle.size()) {
                    return true;
                }
                auto next = haystack[needle.size()];
                return !is_symbol_char(next) || next == '(' || next == '<';
            };

            enum class match_kind : uint8_t { exact, canonical_exact, token_prefix };
            struct ranked_match {
                const analysis_symbol* candidate{nullptr};
                match_kind kind{match_kind::token_prefix};
                symbol_resolution_confidence confidence{symbol_resolution_confidence::heuristic_match};
                std::string_view source{"symtab_token_prefix"};
                int presence_rank{2};
                int addendum_rank{0};
                size_t canonical_length_delta{};
            };

            auto compute_addendum_rank = [&](const analysis_symbol& candidate) {
                if (!requested_addendum.has_value()) {
                    return 0;
                }
                auto candidate_addendum = internal::symbols::extract_symbol_addendum(candidate.mangled);
                if (!candidate_addendum.has_value()) {
                    return 1;
                }
                return internal::symbols::ascii_iequals(*candidate_addendum, *requested_addendum) ? 0 : 2;
            };

            auto compute_presence_rank = [](const analysis_symbol& candidate, match_kind kind) {
                // For exact/canonical matches, final binary remains authoritative.
                if (kind == match_kind::exact || kind == match_kind::canonical_exact) {
                    if (candidate.present_in_binary) {
                        return 0;
                    }
                    if (candidate.present_in_object) {
                        return 1;
                    }
                    return 2;
                }

                // For token-prefix matches (heuristic), prefer snapshot-owned/object symbols first.
                // This avoids short-token ambiguity against large static runtime symbol sets.
                if (candidate.present_in_object) {
                    return 0;
                }
                if (candidate.present_in_binary) {
                    return 1;
                }
                return 2;
            };

            auto apply_relocation_alias_metadata = [&](ranked_match& match) {
                if (!requested_addendum.has_value() || match.addendum_rank == 0) {
                    return;
                }
                match.confidence = symbol_resolution_confidence::exact_relocation;
                switch (match.kind) {
                    case match_kind::exact:
                        match.source = "symtab_relocation_alias";
                        break;
                    case match_kind::canonical_exact:
                        match.source = "symtab_canonical_relocation_alias";
                        break;
                    case match_kind::token_prefix:
                        match.source = "symtab_token_prefix_relocation_alias";
                        break;
                }
            };

            auto is_short_query = requested_canonical.size() <= 4U;
            auto has_addendum_query = requested_addendum.has_value();
            auto should_prioritize_snapshot_before_kind = [&](const ranked_match& lhs,
                                                              const ranked_match& rhs) constexpr {
                if (has_addendum_query) {
                    // For addendum aliases (e.g. @PLT) without exact addendum matches, avoid static-runtime
                    // exact/canonical collisions and prefer snapshot/object-owned candidates first.
                    return lhs.addendum_rank > 0 && rhs.addendum_rank > 0;
                }
                // For short tokens, exact static-runtime names can dominate; prefer snapshot ownership first.
                return is_short_query;
            };

            auto is_better = [&](const ranked_match& lhs, const ranked_match& rhs) {
                if (lhs.addendum_rank != rhs.addendum_rank) {
                    return lhs.addendum_rank < rhs.addendum_rank;
                }
                if (should_prioritize_snapshot_before_kind(lhs, rhs)) {
                    if (lhs.presence_rank != rhs.presence_rank) {
                        return lhs.presence_rank < rhs.presence_rank;
                    }
                    if (lhs.candidate->present_in_object != rhs.candidate->present_in_object) {
                        return lhs.candidate->present_in_object;
                    }
                }
                if (lhs.kind != rhs.kind) {
                    return lhs.kind < rhs.kind;
                }
                if (lhs.presence_rank != rhs.presence_rank) {
                    return lhs.presence_rank < rhs.presence_rank;
                }
                if (lhs.canonical_length_delta != rhs.canonical_length_delta) {
                    return lhs.canonical_length_delta < rhs.canonical_length_delta;
                }
                if (lhs.candidate->mangled.size() != rhs.candidate->mangled.size()) {
                    return lhs.candidate->mangled.size() < rhs.candidate->mangled.size();
                }
                return lhs.candidate->mangled < rhs.candidate->mangled;
            };

            std::optional<ranked_match> best{};
            for (const auto& candidate : symbols) {
                auto mangled = std::string_view{candidate.mangled};
                auto demangled = std::string_view{candidate.demangled};
                auto mangled_canonical = canonical_symbol_for_match(mangled);
                auto demangled_canonical = canonical_symbol_for_match(demangled);

                auto exact_match =
                        symbol_names_equivalent(mangled, requested) || symbol_names_equivalent(demangled, requested);
                if (exact_match) {
                    auto match = ranked_match{
                            .candidate = &candidate,
                            .kind = match_kind::exact,
                            .confidence = symbol_resolution_confidence::exact_symtab,
                            .source = "symtab_exact",
                            .presence_rank = compute_presence_rank(candidate, match_kind::exact),
                            .addendum_rank = compute_addendum_rank(candidate),
                            .canonical_length_delta = 0U};
                    apply_relocation_alias_metadata(match);
                    if (!best.has_value() || is_better(match, *best)) {
                        best = match;
                    }
                    continue;
                }

                auto canonical_exact_match =
                        !requested_canonical.empty() &&
                        (mangled_canonical == requested_canonical || demangled_canonical == requested_canonical);
                if (canonical_exact_match) {
                    auto match = ranked_match{
                            .candidate = &candidate,
                            .kind = match_kind::canonical_exact,
                            .confidence = symbol_resolution_confidence::exact_label_match,
                            .source = "symtab_canonical_exact",
                            .presence_rank = compute_presence_rank(candidate, match_kind::canonical_exact),
                            .addendum_rank = compute_addendum_rank(candidate),
                            .canonical_length_delta = 0U};
                    apply_relocation_alias_metadata(match);
                    if (!best.has_value() || is_better(match, *best)) {
                        best = match;
                    }
                    continue;
                }

                auto mangled_prefix_match = !requested_canonical.empty() &&
                                            starts_with_symbol_token(mangled_canonical, requested_canonical);
                auto demangled_prefix_match = !requested_canonical.empty() &&
                                              starts_with_symbol_token(demangled_canonical, requested_canonical);
                auto token_prefix_match = mangled_prefix_match || demangled_prefix_match;
                if (token_prefix_match) {
                    auto canonical_delta = std::string_view::npos;
                    if (mangled_prefix_match && mangled_canonical.size() >= requested_canonical.size()) {
                        canonical_delta = mangled_canonical.size() - requested_canonical.size();
                    }
                    if (demangled_prefix_match && demangled_canonical.size() >= requested_canonical.size()) {
                        auto demangled_delta = demangled_canonical.size() - requested_canonical.size();
                        canonical_delta = std::min(canonical_delta, demangled_delta);
                    }
                    if (canonical_delta == std::string_view::npos) {
                        canonical_delta = 0U;
                    }
                    auto match = ranked_match{
                            .candidate = &candidate,
                            .kind = match_kind::token_prefix,
                            .confidence = symbol_resolution_confidence::heuristic_match,
                            .source = "symtab_token_prefix",
                            .presence_rank = compute_presence_rank(candidate, match_kind::token_prefix),
                            .addendum_rank = compute_addendum_rank(candidate),
                            .canonical_length_delta = canonical_delta};
                    apply_relocation_alias_metadata(match);
                    if (!best.has_value() || is_better(match, *best)) {
                        best = match;
                    }
                }
            }
            if (best.has_value() && best->candidate != nullptr) {
                return resolved_symbol_match{
                        .mangled = best->candidate->mangled,
                        .info = make_symbol_resolution_info(
                                requested, *best->candidate, best->confidence, best->source)};
            }
            return std::nullopt;
        }

        static std::optional<std::string> resolve_symbol_name(
                const std::vector<analysis_symbol>& symbols, std::string_view symbol) {
            if (auto match = resolve_symbol_match(symbols, symbol)) {
                return match->mangled;
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

        static std::optional<resolved_symbol_match> resolve_symbol_match(
                const analysis_request& request, std::string_view symbol) {
            auto symbols = try_collect_defined_symbols(request);
            if (!symbols) {
                return std::nullopt;
            }
            return resolve_symbol_match(*symbols, symbol);
        }

        static std::optional<std::string_view> parse_ir_function_name_from_define_line(std::string_view line) {
            auto trimmed = trim_ascii(line);
            if (!trimmed.starts_with("define "sv)) {
                return std::nullopt;
            }

            auto at = trimmed.find('@');
            if (at == std::string_view::npos || at + 1U >= trimmed.size()) {
                return std::nullopt;
            }

            auto symbol = trimmed.substr(at + 1U);
            auto end = symbol.find('(');
            if (end == std::string_view::npos || end == 0U) {
                return std::nullopt;
            }
            symbol = symbol.substr(0U, end);
            symbol = trim_ascii(symbol);
            if (symbol.empty()) {
                return std::nullopt;
            }
            return symbol;
        }

        static std::string extract_ir_for_symbol(std::string_view ir_text, std::string_view mangled_symbol) {
            auto lines = split_lines(ir_text);
            std::ostringstream extracted{};
            bool in_function = false;
            int brace_depth = 0;

            for (const auto& line : lines) {
                if (!in_function) {
                    auto function_symbol = parse_ir_function_name_from_define_line(line);
                    if (function_symbol && symbol_names_equivalent(*function_symbol, mangled_symbol)) {
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

        struct mem_trace_map_entry {
            uint64_t trace_id{};
            size_t ir_line{};
            internal::mem::access_kind access{internal::mem::access_kind::none};
            std::string pointer_expr{};
        };

        struct mem_trace_event_entry {
            uint64_t sequence{};
            uint64_t trace_id{};
            internal::mem::access_kind access{internal::mem::access_kind::none};
            uint64_t address{};
            uint64_t width_bytes{};
            uint64_t value{};
        };

        struct mem_trace_payload {
            std::string symbol{};
            int tracee_exit_code{0};
            bool truncated{false};
            size_t dropped_events{};
            std::vector<mem_trace_map_entry> map_entries{};
            std::vector<mem_trace_event_entry> events{};
        };

        static constexpr std::string_view mem_trace_tag(internal::mem::access_kind access) noexcept {
            switch (access) {
                case internal::mem::access_kind::load:
                    return "load"sv;
                case internal::mem::access_kind::store:
                    return "store"sv;
                case internal::mem::access_kind::rmw:
                    return "rmw"sv;
                case internal::mem::access_kind::none:
                    return "none"sv;
            }
            return "none"sv;
        }

        static constexpr std::optional<internal::mem::access_kind> parse_mem_trace_tag(std::string_view tag) noexcept {
            if (tag == "load"sv) {
                return internal::mem::access_kind::load;
            }
            if (tag == "store"sv) {
                return internal::mem::access_kind::store;
            }
            if (tag == "rmw"sv) {
                return internal::mem::access_kind::rmw;
            }
            return std::nullopt;
        }

        static constexpr size_t find_top_level_comma(std::string_view text, size_t start) noexcept {
            auto paren_depth = int{0};
            auto bracket_depth = int{0};
            auto brace_depth = int{0};
            for (auto i = start; i < text.size(); ++i) {
                auto c = text[i];
                if (c == '(') {
                    ++paren_depth;
                    continue;
                }
                if (c == ')') {
                    paren_depth = std::max(0, paren_depth - 1);
                    continue;
                }
                if (c == '[') {
                    ++bracket_depth;
                    continue;
                }
                if (c == ']') {
                    bracket_depth = std::max(0, bracket_depth - 1);
                    continue;
                }
                if (c == '{') {
                    ++brace_depth;
                    continue;
                }
                if (c == '}') {
                    brace_depth = std::max(0, brace_depth - 1);
                    continue;
                }
                if (c == ',' && paren_depth == 0 && bracket_depth == 0 && brace_depth == 0) {
                    return i;
                }
            }
            return std::string_view::npos;
        }

        static std::optional<std::string_view> extract_ptr_operand(std::string_view text, size_t start) {
            if (start >= text.size()) {
                return std::nullopt;
            }
            auto end = find_top_level_comma(text, start);
            if (end == std::string_view::npos) {
                end = text.size();
            }
            auto operand = trim_ascii(text.substr(start, end - start));
            if (operand.empty()) {
                return std::nullopt;
            }
            return operand;
        }

        static std::optional<size_t> parse_llvm_type_width_bytes(std::string_view llvm_type) {
            llvm_type = trim_ascii(llvm_type);
            if (llvm_type.empty()) {
                return std::nullopt;
            }
            if (llvm_type == "half"sv) {
                return 2U;
            }
            if (llvm_type == "float"sv) {
                return 4U;
            }
            if (llvm_type == "double"sv) {
                return 8U;
            }
            if (llvm_type == "ptr"sv || llvm_type.ends_with('*')) {
                return 8U;
            }
            if (llvm_type[0] == 'i') {
                auto bits_text = llvm_type.substr(1U);
                if (bits_text.empty()) {
                    return std::nullopt;
                }
                size_t bits = 0U;
                for (auto c : bits_text) {
                    if (!ascii_is_digit(c)) {
                        return std::nullopt;
                    }
                    bits = (bits * 10U) + static_cast<size_t>(c - '0');
                }
                if (bits == 0U) {
                    return std::nullopt;
                }
                return (bits + 7U) / 8U;
            }
            return std::nullopt;
        }

        static std::optional<std::pair<std::string_view, size_t>> parse_llvm_type_token(std::string_view text) {
            auto cursor = size_t{0U};
            while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor])) != 0) {
                ++cursor;
            }
            if (cursor >= text.size()) {
                return std::nullopt;
            }
            auto start = cursor;
            auto angle_depth = int{0};
            auto paren_depth = int{0};
            auto bracket_depth = int{0};
            auto brace_depth = int{0};
            for (; cursor < text.size(); ++cursor) {
                auto c = text[cursor];
                if (c == '<') {
                    ++angle_depth;
                    continue;
                }
                if (c == '>') {
                    angle_depth = std::max(0, angle_depth - 1);
                    continue;
                }
                if (c == '(') {
                    ++paren_depth;
                    continue;
                }
                if (c == ')') {
                    paren_depth = std::max(0, paren_depth - 1);
                    continue;
                }
                if (c == '[') {
                    ++bracket_depth;
                    continue;
                }
                if (c == ']') {
                    bracket_depth = std::max(0, bracket_depth - 1);
                    continue;
                }
                if (c == '{') {
                    ++brace_depth;
                    continue;
                }
                if (c == '}') {
                    brace_depth = std::max(0, brace_depth - 1);
                    continue;
                }
                if (std::isspace(static_cast<unsigned char>(c)) != 0 && angle_depth == 0 && paren_depth == 0 &&
                    bracket_depth == 0 && brace_depth == 0) {
                    break;
                }
            }
            auto token = trim_ascii(text.substr(start, cursor - start));
            if (token.empty()) {
                return std::nullopt;
            }
            return std::pair{token, cursor};
        }

        struct ir_mem_trace_instruction {
            internal::mem::access_kind access{internal::mem::access_kind::none};
            size_t width_bytes{};
            std::string pointer_operand{};
        };

        static std::optional<ir_mem_trace_instruction> parse_ir_mem_trace_instruction(std::string_view line) {
            auto trimmed = trim_ascii(line);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            auto parse_load = [&](std::string_view payload) -> std::optional<ir_mem_trace_instruction> {
                payload = trim_ascii(payload);
                if (payload.starts_with("atomic "sv)) {
                    payload.remove_prefix("atomic "sv.size());
                    payload = trim_ascii(payload);
                }
                if (payload.starts_with("volatile "sv)) {
                    payload.remove_prefix("volatile "sv.size());
                    payload = trim_ascii(payload);
                }
                auto comma = find_top_level_comma(payload, 0U);
                if (comma == std::string_view::npos) {
                    return std::nullopt;
                }
                auto type_token = trim_ascii(payload.substr(0U, comma));
                auto width = parse_llvm_type_width_bytes(type_token).value_or(0U);
                auto ptr_prefix = payload.find(", ptr ", comma);
                auto prefix_size = ", ptr "sv.size();
                if (ptr_prefix == std::string_view::npos) {
                    ptr_prefix = payload.find(", ptr", comma);
                    prefix_size = ", ptr"sv.size();
                    if (ptr_prefix == std::string_view::npos) {
                        return std::nullopt;
                    }
                }
                auto pointer_operand = extract_ptr_operand(payload, ptr_prefix + prefix_size);
                if (!pointer_operand.has_value()) {
                    return std::nullopt;
                }
                return ir_mem_trace_instruction{
                        .access = internal::mem::access_kind::load,
                        .width_bytes = width,
                        .pointer_operand = std::string{trim_ascii(*pointer_operand)}};
            };

            auto parse_store = [&](std::string_view payload) -> std::optional<ir_mem_trace_instruction> {
                payload = trim_ascii(payload);
                if (payload.starts_with("atomic "sv)) {
                    payload.remove_prefix("atomic "sv.size());
                    payload = trim_ascii(payload);
                }
                if (payload.starts_with("volatile "sv)) {
                    payload.remove_prefix("volatile "sv.size());
                    payload = trim_ascii(payload);
                }

                auto type_and_cursor = parse_llvm_type_token(payload);
                if (!type_and_cursor.has_value()) {
                    return std::nullopt;
                }
                auto width = parse_llvm_type_width_bytes(type_and_cursor->first).value_or(0U);
                auto ptr_prefix = payload.find(", ptr ", type_and_cursor->second);
                auto prefix_size = ", ptr "sv.size();
                if (ptr_prefix == std::string_view::npos) {
                    ptr_prefix = payload.find(", ptr", type_and_cursor->second);
                    prefix_size = ", ptr"sv.size();
                    if (ptr_prefix == std::string_view::npos) {
                        return std::nullopt;
                    }
                }
                auto pointer_operand = extract_ptr_operand(payload, ptr_prefix + prefix_size);
                if (!pointer_operand.has_value()) {
                    return std::nullopt;
                }
                return ir_mem_trace_instruction{
                        .access = internal::mem::access_kind::store,
                        .width_bytes = width,
                        .pointer_operand = std::string{trim_ascii(*pointer_operand)}};
            };

            auto parse_atomicrmw = [&](std::string_view payload) -> std::optional<ir_mem_trace_instruction> {
                // atomicrmw <op> ptr %addr, <type> %val <ordering>
                payload = trim_ascii(payload);
                // skip the operation keyword (add, sub, xchg, etc.)
                auto space = payload.find(' ');
                if (space == std::string_view::npos) {
                    return std::nullopt;
                }
                payload = trim_ascii(payload.substr(space + 1U));
                if (payload.starts_with("volatile "sv)) {
                    payload.remove_prefix("volatile "sv.size());
                    payload = trim_ascii(payload);
                }
                // expect "ptr %addr, <type> %val"
                if (!payload.starts_with("ptr "sv) && !payload.starts_with("ptr,"sv)) {
                    return std::nullopt;
                }
                payload.remove_prefix("ptr"sv.size());
                payload = trim_ascii(payload);
                auto pointer_operand = extract_ptr_operand(payload, 0U);
                if (!pointer_operand.has_value()) {
                    return std::nullopt;
                }
                // type is after the comma following the pointer
                auto comma = find_top_level_comma(payload, 0U);
                size_t width = 0U;
                if (comma != std::string_view::npos) {
                    auto after_comma = trim_ascii(payload.substr(comma + 1U));
                    auto type_and_cursor = parse_llvm_type_token(after_comma);
                    if (type_and_cursor.has_value()) {
                        width = parse_llvm_type_width_bytes(type_and_cursor->first).value_or(0U);
                    }
                }
                return ir_mem_trace_instruction{
                        .access = internal::mem::access_kind::rmw,
                        .width_bytes = width,
                        .pointer_operand = std::string{trim_ascii(*pointer_operand)}};
            };

            auto parse_cmpxchg = [&](std::string_view payload) -> std::optional<ir_mem_trace_instruction> {
                // cmpxchg [weak] [volatile] ptr %addr, <type> %expected, <type> %new <ord> <ord>
                payload = trim_ascii(payload);
                if (payload.starts_with("weak "sv)) {
                    payload.remove_prefix("weak "sv.size());
                    payload = trim_ascii(payload);
                }
                if (payload.starts_with("volatile "sv)) {
                    payload.remove_prefix("volatile "sv.size());
                    payload = trim_ascii(payload);
                }
                if (!payload.starts_with("ptr "sv) && !payload.starts_with("ptr,"sv)) {
                    return std::nullopt;
                }
                payload.remove_prefix("ptr"sv.size());
                payload = trim_ascii(payload);
                auto pointer_operand = extract_ptr_operand(payload, 0U);
                if (!pointer_operand.has_value()) {
                    return std::nullopt;
                }
                auto comma = find_top_level_comma(payload, 0U);
                size_t width = 0U;
                if (comma != std::string_view::npos) {
                    auto after_comma = trim_ascii(payload.substr(comma + 1U));
                    auto type_and_cursor = parse_llvm_type_token(after_comma);
                    if (type_and_cursor.has_value()) {
                        width = parse_llvm_type_width_bytes(type_and_cursor->first).value_or(0U);
                    }
                }
                return ir_mem_trace_instruction{
                        .access = internal::mem::access_kind::rmw,
                        .width_bytes = width,
                        .pointer_operand = std::string{trim_ascii(*pointer_operand)}};
            };

            if (auto eq = trimmed.find('='); eq != std::string_view::npos) {
                auto rhs = trim_ascii(trimmed.substr(eq + 1U));
                if (rhs.starts_with("load "sv)) {
                    return parse_load(rhs.substr("load "sv.size()));
                }
                if (rhs.starts_with("atomicrmw "sv)) {
                    return parse_atomicrmw(rhs.substr("atomicrmw "sv.size()));
                }
                if (rhs.starts_with("cmpxchg "sv)) {
                    return parse_cmpxchg(rhs.substr("cmpxchg "sv.size()));
                }
            }
            if (trimmed.starts_with("store "sv)) {
                return parse_store(trimmed.substr("store "sv.size()));
            }
            return std::nullopt;
        }

        static std::string build_instrumented_mem_trace_ir(
                std::string_view ir_text,
                std::string_view target_symbol,
                std::vector<mem_trace_map_entry>& out_map_entries) {
            auto lines = split_lines(ir_text);
            auto out = std::ostringstream{};

            auto declaration_missing = ir_text.find("__sontag_mem_trace_load"sv) == std::string_view::npos;
            auto declarations_inserted = !declaration_missing;

            auto in_target = false;
            auto brace_depth = 0;
            auto function_line = size_t{0U};
            auto next_trace_id = uint64_t{1U};
            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (!declarations_inserted && trimmed.starts_with("define "sv)) {
                    out << "declare void @__sontag_mem_trace_load(i64, ptr, i64)\n";
                    out << "declare void @__sontag_mem_trace_store(i64, ptr, i64)\n\n";
                    declarations_inserted = true;
                }

                auto entered_target = false;
                if (!in_target) {
                    auto function_symbol = parse_ir_function_name_from_define_line(trimmed);
                    if (function_symbol && symbol_names_equivalent(*function_symbol, target_symbol)) {
                        in_target = true;
                        entered_target = true;
                        function_line = 1U;
                    }
                }

                if (in_target) {
                    if (auto parsed = parse_ir_mem_trace_instruction(trimmed); parsed.has_value()) {
                        auto width = parsed->width_bytes == 0U ? 1U : parsed->width_bytes;
                        auto trace_id = next_trace_id++;
                        out_map_entries.push_back(
                                mem_trace_map_entry{
                                        .trace_id = trace_id,
                                        .ir_line = function_line,
                                        .access = parsed->access,
                                        .pointer_expr = parsed->pointer_operand});

                        auto indent_length = line.find_first_not_of(" \t");
                        auto indent = indent_length == std::string::npos
                                            ? std::string_view{}
                                            : std::string_view{line}.substr(0U, indent_length);
                        if (parsed->access == internal::mem::access_kind::load) {
                            out << line << '\n';
                            out << indent << "  call void @__sontag_mem_trace_load(i64 " << trace_id << ", ptr "
                                << parsed->pointer_operand << ", i64 " << width << ")\n";
                        }
                        else if (parsed->access == internal::mem::access_kind::store) {
                            out << line << '\n';
                            out << indent << "  call void @__sontag_mem_trace_store(i64 " << trace_id << ", ptr "
                                << parsed->pointer_operand << ", i64 " << width << ")\n";
                        }
                        else if (parsed->access == internal::mem::access_kind::rmw) {
                            // emit load hook BEFORE the instruction (captures before-value)
                            out << indent << "  call void @__sontag_mem_trace_load(i64 " << trace_id << ", ptr "
                                << parsed->pointer_operand << ", i64 " << width << ")\n";
                            out << line << '\n';
                            // emit store hook AFTER the instruction (captures after-value)
                            out << indent << "  call void @__sontag_mem_trace_store(i64 " << trace_id << ", ptr "
                                << parsed->pointer_operand << ", i64 " << width << ")\n";
                        }
                    }
                    else {
                        out << line << '\n';
                    }
                }
                else {
                    out << line << '\n';
                }

                if (in_target) {
                    for (auto c : line) {
                        if (c == '{') {
                            ++brace_depth;
                        }
                        else if (c == '}') {
                            --brace_depth;
                        }
                    }
                    ++function_line;
                    if (brace_depth <= 0 && trimmed == "}"sv) {
                        in_target = false;
                        brace_depth = 0;
                        function_line = 0U;
                    }
                }
            }

            if (!declarations_inserted) {
                out << "\ndeclare void @__sontag_mem_trace_load(i64, ptr, i64)\n";
                out << "declare void @__sontag_mem_trace_store(i64, ptr, i64)\n";
            }

            return out.str();
        }

        static std::string escape_c_string_literal(std::string_view value) {
            auto out = std::string{};
            out.reserve(value.size());
            for (auto c : value) {
                if (c == '\\' || c == '"') {
                    out.push_back('\\');
                }
                out.push_back(c);
            }
            return out;
        }

        static std::string build_mem_trace_runtime_source(
                std::string_view trace_events_path, std::string_view trace_stats_path) {
            auto escaped_events_path = escape_c_string_literal(trace_events_path);
            auto escaped_stats_path = escape_c_string_literal(trace_stats_path);
            return R"cpp(#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

                         namespace {
                             constexpr const char* kTraceEventsPath = ")cpp" +
                   escaped_events_path +
                   R"cpp(";
                                 constexpr const char* kTraceStatsPath = ")cpp" +
                   escaped_stats_path +
                   R"cpp(";

                                 constexpr uint64_t kMaxTraceEvents = 50000;
                         std::FILE* g_trace_file = nullptr;
                         std::FILE* g_stats_file = nullptr;
                         uint64_t g_sequence = 0;
                         uint64_t g_written_events = 0;
                         uint64_t g_dropped_events = 0;

                         void init_trace_files() {
                             if (kTraceEventsPath != nullptr && kTraceEventsPath[0] != '\0') {
                                 g_trace_file = std::fopen(kTraceEventsPath, "w");
                             }
                             if (kTraceStatsPath != nullptr && kTraceStatsPath[0] != '\0') {
                                 g_stats_file = std::fopen(kTraceStatsPath, "w");
                             }
                         }

                         void flush_trace_stats() {
                             if (g_stats_file == nullptr) {
                                 return;
                             }
                             std::fprintf(g_stats_file, "truncated=%s\n", g_dropped_events > 0 ? "true" : "false");
                             std::fprintf(g_stats_file, "dropped_events=%" PRIu64 "\n", g_dropped_events);
                             std::fprintf(g_stats_file, "written_events=%" PRIu64 "\n", g_written_events);
                             std::fprintf(g_stats_file, "max_events=%" PRIu64 "\n", kMaxTraceEvents);
                         }

                         uint64_t read_value(const void* address, uint64_t width) {
                             if (address == nullptr) {
                                 return 0;
                             }
                             if (width == 0) {
                                 width = 1;
                             }
                             if (width > 8) {
                                 width = 8;
                             }
                             uint64_t value = 0;
                             std::memcpy(&value, address, static_cast<size_t>(width));
                             return value;
                         }

                         void write_trace(uint64_t id, char access, const void* address, uint64_t width) {
                             if (g_trace_file == nullptr) {
                                 return;
                             }
                             ++g_sequence;
                             if (g_written_events >= kMaxTraceEvents) {
                                 ++g_dropped_events;
                                 return;
                             }
                             auto addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(address));
                             auto value = read_value(address, width);
                             std::fprintf(
                                     g_trace_file,
                                     "%" PRIu64 "|%" PRIu64 "|%c|0x%016" PRIx64 "|%" PRIu64 "|0x%016" PRIx64 "\n",
                                     g_sequence,
                                     id,
                                     access,
                                     addr,
                                     width,
                                     value);
                             ++g_written_events;
                         }

                         __attribute__((constructor)) void init_trace_runtime() {
                             init_trace_files();
                         }

                         __attribute__((destructor)) void shutdown_trace_runtime() {
                             if (g_trace_file != nullptr) {
                                 std::fclose(g_trace_file);
                                 g_trace_file = nullptr;
                             }
                             if (g_stats_file != nullptr) {
                                 flush_trace_stats();
                                 std::fclose(g_stats_file);
                                 g_stats_file = nullptr;
                             }
                         }

                         }  // namespace

                         extern "C" void __sontag_mem_trace_load(uint64_t id, const void* address, uint64_t width) {
                             write_trace(id, 'L', address, width);
                         }

                         extern "C" void __sontag_mem_trace_store(uint64_t id, const void* address, uint64_t width) {
                             write_trace(id, 'S', address, width);
                         }
                   )cpp";
        }

        struct mem_trace_runtime_stats {
            bool truncated{false};
            size_t dropped_events{};
            std::optional<size_t> max_events{};
        };

        static bool parse_unsigned_decimal(std::string_view text, uint64_t& out) {
            text = trim_ascii(text);
            if (text.empty()) {
                return false;
            }
            auto value = uint64_t{0};
            auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, 10);
            if (ec != std::errc{} || ptr != (text.data() + text.size())) {
                return false;
            }
            out = value;
            return true;
        }

        static mem_trace_runtime_stats parse_mem_trace_runtime_stats(std::string_view text) {
            auto stats = mem_trace_runtime_stats{};
            auto lines = split_lines(text);
            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (trimmed.empty()) {
                    continue;
                }
                auto split = trimmed.find('=');
                if (split == std::string_view::npos) {
                    continue;
                }
                auto key = trim_ascii(trimmed.substr(0U, split));
                auto value = trim_ascii(trimmed.substr(split + 1U));
                if (key == "truncated"sv) {
                    stats.truncated = (value == "true"sv);
                    continue;
                }
                auto parsed = uint64_t{0U};
                if (!parse_unsigned_decimal(value, parsed)) {
                    continue;
                }
                if (key == "dropped_events"sv) {
                    stats.dropped_events = static_cast<size_t>(parsed);
                }
                else if (key == "max_events"sv) {
                    stats.max_events = static_cast<size_t>(parsed);
                }
            }
            return stats;
        }

        static bool parse_unsigned_hex(std::string_view text, uint64_t& out) {
            text = trim_ascii(text);
            if (text.size() >= 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
                text.remove_prefix(2U);
            }
            if (text.empty()) {
                return false;
            }
            auto value = uint64_t{0};
            auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
            if (ec != std::errc{} || ptr != (text.data() + text.size())) {
                return false;
            }
            out = value;
            return true;
        }

        static std::vector<std::string_view> split_pipe_fields(std::string_view line) {
            auto out = std::vector<std::string_view>{};
            auto begin = size_t{0U};
            while (begin <= line.size()) {
                auto end = line.find('|', begin);
                if (end == std::string_view::npos) {
                    end = line.size();
                }
                out.push_back(line.substr(begin, end - begin));
                if (end == line.size()) {
                    break;
                }
                begin = end + 1U;
            }
            return out;
        }

        static std::optional<mem_trace_event_entry> parse_mem_trace_event_line(std::string_view line) {
            auto fields = split_pipe_fields(trim_ascii(line));
            if (fields.size() != 6U) {
                return std::nullopt;
            }

            auto access = internal::mem::access_kind::none;
            auto access_token = trim_ascii(fields[2]);
            if (access_token == "L"sv) {
                access = internal::mem::access_kind::load;
            }
            else if (access_token == "S"sv) {
                access = internal::mem::access_kind::store;
            }
            else if (access_token == "R"sv) {
                access = internal::mem::access_kind::rmw;
            }
            else {
                return std::nullopt;
            }

            auto sequence = uint64_t{0};
            auto trace_id = uint64_t{0};
            auto address = uint64_t{0};
            auto width = uint64_t{0};
            auto value = uint64_t{0};
            if (!parse_unsigned_decimal(fields[0], sequence) || !parse_unsigned_decimal(fields[1], trace_id) ||
                !parse_unsigned_hex(fields[3], address) || !parse_unsigned_decimal(fields[4], width) ||
                !parse_unsigned_hex(fields[5], value)) {
                return std::nullopt;
            }

            return mem_trace_event_entry{
                    .sequence = sequence,
                    .trace_id = trace_id,
                    .access = access,
                    .address = address,
                    .width_bytes = width,
                    .value = value};
        }

        static std::string render_mem_trace_payload(const mem_trace_payload& payload) {
            auto out = std::ostringstream{};
            out << "symbol=" << payload.symbol << '\n';
            out << "tracee_exit_code=" << payload.tracee_exit_code << '\n';
            out << "truncated=" << (payload.truncated ? "true" : "false") << '\n';
            out << "dropped_events=" << payload.dropped_events << '\n';
            out << "map_count=" << payload.map_entries.size() << '\n';
            out << "event_count=" << payload.events.size() << '\n';
            out << "--map--\n";
            for (const auto& entry : payload.map_entries) {
                out << entry.trace_id << '|' << entry.ir_line << '|' << mem_trace_tag(entry.access) << '|'
                    << entry.pointer_expr << '\n';
            }
            out << "--events--\n";
            for (const auto& event : payload.events) {
                out << event.sequence << '|' << event.trace_id << '|';
                switch (event.access) {
                    case internal::mem::access_kind::load:
                        out << 'L';
                        break;
                    case internal::mem::access_kind::store:
                        out << 'S';
                        break;
                    case internal::mem::access_kind::rmw:
                        out << 'R';
                        break;
                    case internal::mem::access_kind::none:
                        out << '?';
                        break;
                }
                out << "|0x" << std::hex << std::setw(16) << std::setfill('0') << event.address << std::dec << "|"
                    << event.width_bytes << "|0x" << std::hex << std::setw(16) << std::setfill('0') << event.value
                    << std::dec << '\n';
            }
            return out.str();
        }

        static constexpr std::optional<std::string_view> parse_asm_begin_symbol(std::string_view line) {
            static constexpr auto marker = "Begin function "sv;
            auto pos = line.find(marker);
            if (pos == std::string_view::npos) {
                return std::nullopt;
            }
            auto symbol = line.substr(pos + marker.size());
            symbol = trim_ascii(symbol);
            auto end = symbol.find_first_of(" \t\r\n");
            if (end != std::string_view::npos) {
                symbol = symbol.substr(0U, end);
            }
            if (symbol.empty()) {
                return std::nullopt;
            }
            return symbol;
        }

        static constexpr std::optional<std::string_view> parse_asm_label_symbol(std::string_view line) {
            auto trimmed = trim_ascii(line);
            auto colon = trimmed.find(':');
            if (colon == std::string_view::npos || colon == 0U) {
                return std::nullopt;
            }
            auto symbol = trim_ascii(trimmed.substr(0U, colon));
            if (symbol.empty()) {
                return std::nullopt;
            }
            return symbol;
        }

        static constexpr std::optional<std::string_view> parse_asm_size_symbol(std::string_view line) {
            static constexpr auto prefix = ".size"sv;
            auto trimmed = trim_ascii(line);
            if (!trimmed.starts_with(prefix)) {
                return std::nullopt;
            }
            trimmed.remove_prefix(prefix.size());
            trimmed = trim_ascii(trimmed);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            auto end = trimmed.find_first_of(", \t");
            auto symbol = end == std::string_view::npos ? trimmed : trimmed.substr(0U, end);
            symbol = trim_ascii(symbol);
            if (symbol.empty()) {
                return std::nullopt;
            }
            return symbol;
        }

        static constexpr bool ascii_is_alnum(char c) noexcept {
            auto lower = static_cast<char>(c | 0x20);
            return (c >= '0' && c <= '9') || (lower >= 'a' && lower <= 'z');
        }

        static std::string extract_asm_for_symbol(std::string_view asm_text, std::string_view mangled_symbol) {
            auto lines = split_lines(asm_text);
            std::ostringstream extracted{};
            bool in_function = false;

            for (const auto& line : lines) {
                if (!in_function) {
                    auto begin_symbol = parse_asm_begin_symbol(line);
                    auto label_symbol = parse_asm_label_symbol(line);
                    if ((begin_symbol && symbol_names_equivalent(*begin_symbol, mangled_symbol)) ||
                        (label_symbol && symbol_names_equivalent(*label_symbol, mangled_symbol))) {
                        in_function = true;
                    }
                    else {
                        continue;
                    }
                }

                extracted << line << '\n';
                if (contains_token(line, "End function"sv)) {
                    break;
                }
                if (auto size_symbol = parse_asm_size_symbol(line);
                    size_symbol && symbol_names_equivalent(*size_symbol, mangled_symbol)) {
                    break;
                }
            }

            auto extracted_text = extracted.str();
            return extracted_text;
        }

        static std::optional<std::string_view> parse_objdump_symbol_header_name(std::string_view line) {
            auto trimmed = trim_ascii(line);
            if (!trimmed.ends_with(">:")) {
                return std::nullopt;
            }
            auto left = trimmed.find('<');
            if (left == std::string_view::npos || left + 1U >= trimmed.size()) {
                return std::nullopt;
            }
            auto right = trimmed.rfind(">:");
            if (right == std::string_view::npos || right <= left + 1U) {
                return std::nullopt;
            }
            return trimmed.substr(left + 1U, (right - left) - 1U);
        }

        static constexpr bool starts_with_case_insensitive(std::string_view value, std::string_view prefix) noexcept {
            if (value.size() < prefix.size()) {
                return false;
            }
            for (size_t i = 0U; i < prefix.size(); ++i) {
                if (utils::char_tolower(value[i]) != utils::char_tolower(prefix[i])) {
                    return false;
                }
            }
            return true;
        }

        static constexpr bool is_objdump_local_label(std::string_view label) noexcept {
            label = trim_ascii(label);
            if (label.empty()) {
                return false;
            }

            if (label.starts_with(".L"sv) || starts_with_case_insensitive(label, "ltmp"sv) ||
                starts_with_case_insensitive(label, "lbb"sv)) {
                return true;
            }

            if ((label.front() == 'L' || label.front() == 'l') && label.size() > 1U) {
                auto second = label[1];
                if (second >= '0' && second <= '9') {
                    return true;
                }
            }

            if (label.find('(') != std::string_view::npos || label.find("::"sv) != std::string_view::npos) {
                return false;
            }

            if ((label.front() == 'L' || label.front() == 'l') &&
                std::ranges::all_of(label, [](char c) { return ascii_is_alnum(c) || c == '_' || c == '.'; })) {
                return true;
            }

            return false;
        }

        static std::string extract_objdump_for_symbol(
                std::string_view dump_text, std::string_view mangled_symbol, std::string_view display_symbol) {
            auto lines = split_lines(dump_text);
            std::ostringstream extracted{};
            bool in_symbol = false;

            for (const auto& line : lines) {
                auto header_name = parse_objdump_symbol_header_name(line);
                if (header_name) {
                    auto demangled_header = demangle_symbol_name(*header_name);
                    auto local_header =
                            is_objdump_local_label(*header_name) || is_objdump_local_label(demangled_header);
                    if (in_symbol) {
                        if (local_header) {
                            extracted << line << '\n';
                            continue;
                        }
                        break;
                    }
                    if (symbol_names_equivalent(*header_name, mangled_symbol) ||
                        symbol_names_equivalent(*header_name, display_symbol) ||
                        symbol_names_equivalent(demangled_header, display_symbol)) {
                        in_symbol = true;
                        extracted << line << '\n';
                        continue;
                    }
                }

                if (!in_symbol) {
                    continue;
                }
                extracted << line << '\n';
            }

            return extracted.str();
        }

        static constexpr bool should_strip_mca_line(std::string_view trimmed_line) noexcept {
#if SONTAG_PLATFORM_MACOS && SONTAG_ARCH_ARM64
            return trimmed_line == ".subsections_via_symbols"sv;
#else
            static_cast<void>(trimmed_line);
            return false;
#endif
        }

        static std::string sanitize_mca_input(std::string_view asm_text, bool strip_cfi_directives) {
            auto lines = split_lines(asm_text);
            std::string sanitized{};
            sanitized.reserve(asm_text.size());
            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (strip_cfi_directives && trimmed.starts_with(".cfi_"sv)) {
                    continue;
                }
                if (should_strip_mca_line(trimmed)) {
                    continue;
                }
                sanitized.append(line);
                sanitized.push_back('\n');
            }
            return sanitized;
        }

        static std::string prepare_mca_symbol_input(
                std::string_view extracted_asm, [[maybe_unused]] std::string_view asm_syntax) {
            auto sanitized_input = sanitize_mca_input(extracted_asm, true);
            std::string prepared{};
            prepared.reserve(sanitized_input.size() + 64U);
            prepared.append(".text\n");
#if SONTAG_ARCH_X86_64
            if (asm_syntax == "intel"sv) {
                prepared.append(".intel_syntax noprefix\n");
            }
#endif
            prepared.append(sanitized_input);
            return prepared;
        }

        static std::string prepare_mca_from_objdump(
                std::string_view objdump_text, [[maybe_unused]] std::string_view asm_syntax) {
            auto lines = split_lines(objdump_text);
            std::string instructions{};
            instructions.reserve(objdump_text.size());

            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (trimmed.empty()) {
                    continue;
                }

                auto colon = trimmed.find(':');
                if (colon == std::string_view::npos) {
                    continue;
                }

                auto tail = trimmed.substr(colon + 1U);
                size_t cursor = 0U;
                bool found_hex = false;
                std::optional<size_t> instruction_start{};

                while (cursor < tail.size()) {
                    while (cursor < tail.size() && (tail[cursor] == ' ' || tail[cursor] == '\t')) {
                        ++cursor;
                    }
                    if (cursor >= tail.size())
                        break;

                    auto token_end = cursor;
                    while (token_end < tail.size() && tail[token_end] != ' ' && tail[token_end] != '\t') {
                        ++token_end;
                    }

                    auto token = tail.substr(cursor, token_end - cursor);
                    if (opcode::is_hex_blob_token(token)) {
                        found_hex = true;
                        cursor = token_end;
                        continue;
                    }

                    instruction_start = cursor;
                    break;
                }

                if (!found_hex || !instruction_start.has_value()) {
                    continue;
                }

                auto instruction = trim_ascii(tail.substr(*instruction_start));
                if (!instruction.empty()) {
                    instructions.append(instruction);
                    instructions.push_back('\n');
                }
            }

            std::string prepared{};
            prepared.reserve(instructions.size() + 64U);
            prepared.append(".text\n");
#if SONTAG_ARCH_X86_64
            if (asm_syntax == "intel"sv) {
                prepared.append(".intel_syntax noprefix\n");
            }
#endif
            prepared.append(instructions);
            return prepared;
        }

        static std::string to_lower_ascii(std::string_view value) {
            std::string lower{};
            lower.reserve(value.size());
            for (auto c : value) {
                lower.push_back(utils::char_tolower(c));
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
                auto mangled_sv = std::string_view{symbol.mangled};
                if (auto stripped = strip_one_leading_underscore(mangled_sv); stripped != mangled_sv) {
                    display_names.try_emplace(std::string{stripped}, symbol.demangled);
                }
            }
            return display_names;
        }

        static std::string resolve_symbol_display_name(
                std::string_view mangled, const graph::symbol_display_map& display_names) {
            if (auto it = display_names.find(std::string{mangled}); it != display_names.end()) {
                return it->second;
            }
            if (auto stripped = strip_one_leading_underscore(mangled); stripped != mangled) {
                if (auto it = display_names.find(std::string{stripped}); it != display_names.end()) {
                    return it->second;
                }
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

        static std::optional<double> parse_numeric_token(std::string_view token) {
            std::string value{trim_ascii(token)};
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
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.iterations = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Instructions:"sv)) {
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.instructions = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Total Cycles:"sv)) {
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.total_cycles = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Total uOps:"sv)) {
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.total_uops = static_cast<int>(*value);
                    }
                    continue;
                }
                if (trimmed.starts_with("Dispatch Width:"sv)) {
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.dispatch_width = *value;
                    }
                    continue;
                }
                if (trimmed.starts_with("uOps Per Cycle:"sv)) {
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.uops_per_cycle = *value;
                    }
                    continue;
                }
                if (trimmed.starts_with("IPC:"sv)) {
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.ipc = *value;
                    }
                    continue;
                }
                if (trimmed.starts_with("Block RThroughput:"sv)) {
                    if (auto value = metrics::parse_number_after_colon(trimmed)) {
                        payload.block_rthroughput = *value;
                    }
                }
            }
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

        static std::vector<analysis_opcode_entry> to_analysis_opcode_entries(
                const std::vector<opcode::opcode_entry>& entries) {
            std::vector<analysis_opcode_entry> opcode_table{};
            opcode_table.reserve(entries.size());
            for (const auto& entry : entries) {
                opcode_table.push_back(analysis_opcode_entry{.opcode_uid = entry.uid, .opcode = entry.mnemonic});
            }
            return opcode_table;
        }

        static std::vector<analysis_operation_entry> to_analysis_operation_entries(
                const std::vector<opcode::mapped_operation_stream>& streams) {
            std::vector<analysis_operation_entry> operations{};
            size_t total_size = 0U;
            for (const auto& stream : streams) {
                total_size += stream.operations.size();
            }
            operations.reserve(total_size);

            for (const auto& stream : streams) {
                for (const auto& op : stream.operations) {
                    operations.push_back(
                            analysis_operation_entry{
                                    .ordinal = static_cast<uint64_t>(op.ordinal),
                                    .opcode_uid = op.opcode,
                                    .opcode = op.mnemonic,
                                    .stream = stream.name});
                }
            }
            return operations;
        }

        static std::vector<delta_operation> to_delta_operations(const std::vector<opcode::operation_node>& operations) {
            std::vector<delta_operation> normalized{};
            normalized.reserve(operations.size());
            for (const auto& operation : operations) {
                normalized.push_back(
                        delta_operation{
                                .ordinal = operation.ordinal,
                                .opcode_uid = operation.opcode,
                                .opcode = operation.mnemonic,
                                .triplet = operation.signature.empty() ? operation.mnemonic : operation.signature});
            }
            return normalized;
        }

        static opcode::mapped_operation_set build_opcode_mapping(
                std::span<const opcode::operation_stream_input> streams) {
            return opcode::map_operation_streams(streams);
        }

        static void attach_opcode_mapping(
                analysis_result& result, std::span<const opcode::operation_stream_input> streams) {
            auto mapped = build_opcode_mapping(streams);
            result.opcode_table = to_analysis_opcode_entries(mapped.opcode_table);
            result.operations = to_analysis_operation_entries(mapped.streams);
        }

        struct delta_symbol_resolution {
            std::optional<std::string> mangled{};
            std::string display{};
            bool resolved{false};
            symbol_resolution_info info{};
            std::string diagnostics_text{};
        };

        static std::vector<optimization_level> make_delta_pair_levels(optimization_level target) {
            if (target == optimization_level::o0) {
                return {optimization_level::o0, optimization_level::o2};
            }
            return {optimization_level::o0, target};
        }

        static std::vector<optimization_level> make_delta_spectrum_levels(optimization_level upper_bound) {
            std::vector<optimization_level> levels{optimization_level::o0};
            switch (upper_bound) {
                case optimization_level::o0:
                    levels.push_back(optimization_level::o1);
                    levels.push_back(optimization_level::o2);
                    return levels;
                case optimization_level::o1:
                    levels.push_back(optimization_level::o1);
                    return levels;
                case optimization_level::o2:
                    levels.push_back(optimization_level::o1);
                    levels.push_back(optimization_level::o2);
                    return levels;
                case optimization_level::o3:
                    levels.push_back(optimization_level::o1);
                    levels.push_back(optimization_level::o2);
                    levels.push_back(optimization_level::o3);
                    return levels;
                case optimization_level::ofast:
                    levels.push_back(optimization_level::o1);
                    levels.push_back(optimization_level::o2);
                    levels.push_back(optimization_level::o3);
                    levels.push_back(optimization_level::ofast);
                    return levels;
                case optimization_level::oz:
                    levels.push_back(optimization_level::o1);
                    levels.push_back(optimization_level::o2);
                    levels.push_back(optimization_level::oz);
                    return levels;
            }
            return levels;
        }

        static std::vector<optimization_level> make_delta_levels(const delta_request& delta) {
            switch (delta.mode) {
                case delta_mode::pairwise:
                    return make_delta_pair_levels(delta.target);
                case delta_mode::spectrum:
                    return make_delta_spectrum_levels(delta.target);
            }
            return make_delta_pair_levels(delta.target);
        }

        static delta_metric_entry make_ok_metric(std::string_view name, double value, std::string_view unit) {
            return delta_metric_entry{
                    .name = std::string{name}, .value = value, .unit = std::string{unit}, .status = metric_status::ok};
        }

        static delta_metric_entry make_na_metric(std::string_view name, std::string_view unit) {
            return delta_metric_entry{
                    .name = std::string{name}, .value = 0.0, .unit = std::string{unit}, .status = metric_status::na};
        }

        static delta_metric_entry make_error_metric(std::string_view name, std::string_view unit) {
            return delta_metric_entry{
                    .name = std::string{name}, .value = 0.0, .unit = std::string{unit}, .status = metric_status::error};
        }

        static std::vector<delta_metric_entry> collect_level_metrics(
                analysis_request level_request,
                const delta_symbol_resolution& symbol_resolution,
                const delta_level_record& level_record,
                std::string_view symbol_disassembly,
                double compile_time_ms) {
            std::vector<delta_metric_entry> metrics{};
            metrics.reserve(internal::platform::mca_supported ? 14U : 9U);

            auto has_disassembly = !symbol_disassembly.empty();

            if (!has_disassembly) {
                metrics.push_back(make_na_metric("size.symbol_text_bytes"sv, "bytes"sv));
            }
            else if (auto span = ::sontag::metrics::parse_objdump_symbol_span(symbol_disassembly)) {
                metrics.push_back(make_ok_metric(
                        "size.symbol_text_bytes"sv, static_cast<double>(span->end - span->start), "bytes"sv));
            }
            else {
                metrics.push_back(make_na_metric("size.symbol_text_bytes"sv, "bytes"sv));
            }

            auto profile = ::sontag::metrics::build_asm_operation_profile(level_record.operations, symbol_disassembly);
            auto instruction_count = static_cast<double>(profile.instruction_count);
            if (profile.instruction_count == 0U) {
                metrics.push_back(make_na_metric("asm.insn_total"sv, "count"sv));
                metrics.push_back(make_na_metric("asm.mem_ops_ratio"sv, "ratio"sv));
                metrics.push_back(make_na_metric("asm.call_count"sv, "count"sv));
                metrics.push_back(make_na_metric("asm.branch_density"sv, "ratio"sv));
            }
            else {
                auto memory_ops = static_cast<double>(profile.load_count + profile.store_count);
                metrics.push_back(make_ok_metric("asm.insn_total"sv, instruction_count, "count"sv));
                metrics.push_back(make_ok_metric("asm.mem_ops_ratio"sv, memory_ops / instruction_count, "ratio"sv));
                metrics.push_back(
                        make_ok_metric("asm.call_count"sv, static_cast<double>(profile.call_count), "count"sv));
                metrics.push_back(make_ok_metric(
                        "asm.branch_density"sv,
                        static_cast<double>(profile.branch_count) / instruction_count,
                        "ratio"sv));
            }
            metrics.push_back(
                    make_ok_metric("asm.bb_count"sv, static_cast<double>(profile.basic_block_count), "count"sv));
            metrics.push_back(make_ok_metric(
                    "asm.stack_frame_bytes"sv, static_cast<double>(profile.stack_frame_bytes), "bytes"sv));
            metrics.push_back(
                    make_ok_metric("asm.spill_fill_count"sv, static_cast<double>(profile.spill_fill_count), "count"sv));

            if (compile_time_ms >= 0.0) {
                metrics.push_back(make_ok_metric("build.compile_time_ms"sv, compile_time_ms, "ms"sv));
            }
            else {
                metrics.push_back(make_na_metric("build.compile_time_ms"sv, "ms"sv));
            }

            if constexpr (!internal::platform::mca_supported) {
                return metrics;
            }

            auto missing_symbol = !symbol_resolution.mangled.has_value();
            auto unresolved_for_mca = missing_symbol || !level_record.success ||
                                      level_record.symbol_status == symbol_resolution_status::optimized_out;
            if (unresolved_for_mca) {
                metrics.push_back(make_na_metric("mca.block_rthroughput"sv, "cycles_per_iteration"sv));
                metrics.push_back(make_na_metric("mca.ipc"sv, "inst_per_cycle"sv));
                metrics.push_back(make_na_metric("mca.total_uops"sv, "count"sv));
                metrics.push_back(make_na_metric("mca.rf_integer_max_mappings"sv, "count"sv));
                metrics.push_back(make_na_metric("mca.rf_fp_max_mappings"sv, "count"sv));
                return metrics;
            }

            level_request.symbol = *symbol_resolution.mangled;
            auto mca_result = run_analysis(level_request, analysis_kind::mca);
            if (!mca_result.success) {
                metrics.push_back(make_error_metric("mca.block_rthroughput"sv, "cycles_per_iteration"sv));
                metrics.push_back(make_error_metric("mca.ipc"sv, "inst_per_cycle"sv));
                metrics.push_back(make_error_metric("mca.total_uops"sv, "count"sv));
                metrics.push_back(make_error_metric("mca.rf_integer_max_mappings"sv, "count"sv));
                metrics.push_back(make_error_metric("mca.rf_fp_max_mappings"sv, "count"sv));
                return metrics;
            }

            auto summary = inspect_mca_summary_payload{};
            parse_mca_summary(mca_result.artifact_text, summary);
            auto register_file_metrics = ::sontag::metrics::parse_mca_register_file_metrics(mca_result.artifact_text);

            metrics.push_back(
                    make_ok_metric("mca.block_rthroughput"sv, summary.block_rthroughput, "cycles_per_iteration"sv));
            metrics.push_back(make_ok_metric("mca.ipc"sv, summary.ipc, "inst_per_cycle"sv));
            metrics.push_back(make_ok_metric("mca.total_uops"sv, static_cast<double>(summary.total_uops), "count"sv));

            if (register_file_metrics.integer_max_mappings.has_value()) {
                metrics.push_back(make_ok_metric(
                        "mca.rf_integer_max_mappings"sv, *register_file_metrics.integer_max_mappings, "count"sv));
            }
            else {
                metrics.push_back(make_na_metric("mca.rf_integer_max_mappings"sv, "count"sv));
            }

            if (register_file_metrics.fp_max_mappings.has_value()) {
                metrics.push_back(
                        make_ok_metric("mca.rf_fp_max_mappings"sv, *register_file_metrics.fp_max_mappings, "count"sv));
            }
            else {
                metrics.push_back(make_na_metric("mca.rf_fp_max_mappings"sv, "count"sv));
            }

            return metrics;
        }

        static constexpr bool is_function_symbol_kind(char kind) noexcept {
            auto lower = static_cast<char>(kind | 0x20);
            return lower == 't' || lower == 'w';
        }

        static delta_symbol_resolution resolve_delta_symbol(
                const analysis_request& request, const std::optional<std::string>& symbol) {
            auto resolution = delta_symbol_resolution{};
            auto requested_symbol = symbol.value_or("main");
            resolution.display = requested_symbol;
            resolution.info = make_missing_symbol_resolution_info(requested_symbol);

            auto symbols = try_collect_defined_symbols(request);
            if (!symbols) {
                resolution.diagnostics_text = "unable to resolve symbol: failed to collect defined symbols";
                return resolution;
            }

            auto assign_from_match = [&](const resolved_symbol_match& match) {
                resolution.mangled = match.mangled;
                resolution.display =
                        match.info.display_name.empty() ? demangle_symbol_name(match.mangled) : match.info.display_name;
                resolution.info = match.info;
            };

            if (auto match = resolve_symbol_match(*symbols, requested_symbol)) {
                assign_from_match(*match);
                resolution.resolved = true;
                return resolution;
            }

            if (!symbol) {
                if (auto match = resolve_symbol_match(*symbols, "main"sv)) {
                    assign_from_match(*match);
                    resolution.resolved = true;
                    return resolution;
                }
                for (const auto& candidate : *symbols) {
                    if (!is_function_symbol_kind(candidate.kind)) {
                        continue;
                    }
                    assign_from_match(
                            resolved_symbol_match{
                                    .mangled = candidate.mangled,
                                    .info = make_symbol_resolution_info(
                                            requested_symbol,
                                            candidate,
                                            symbol_resolution_confidence::exact_symtab,
                                            candidate.present_in_binary ? "symtab_bin_fallback"
                                                                        : "symtab_obj_fallback")});
                    resolution.resolved = true;
                    return resolution;
                }
            }

            resolution.diagnostics_text = "unable to resolve symbol: {}"_format(requested_symbol);
            return resolution;
        }

        static const delta_level_record* find_level(
                const std::vector<delta_level_record>& levels, optimization_level wanted_level) {
            for (const auto& level : levels) {
                if (level.level == wanted_level) {
                    return &level;
                }
            }
            return nullptr;
        }

        static bool level_success(const std::vector<delta_level_record>& levels, optimization_level wanted_level) {
            for (const auto& level : levels) {
                if (level.level == wanted_level) {
                    return level.success;
                }
            }
            return false;
        }

        static bool all_levels_success(
                const std::vector<delta_level_record>& levels, std::span<const optimization_level> wanted_levels) {
            for (auto level : wanted_levels) {
                if (!level_success(levels, level)) {
                    return false;
                }
            }
            return true;
        }

        static delta_change_counters compute_pairwise_counters(
                const std::vector<delta_level_record>& levels, optimization_level baseline, optimization_level target) {
            auto counters = delta_change_counters{};

            auto* baseline_level = find_level(levels, baseline);
            auto* target_level = find_level(levels, target);
            if (baseline_level == nullptr || target_level == nullptr) {
                return counters;
            }
            if (!baseline_level->success || !target_level->success) {
                return counters;
            }

            auto overlap = std::min(baseline_level->operations.size(), target_level->operations.size());
            for (size_t i = 0U; i < overlap; ++i) {
                if (baseline_level->operations[i].opcode_uid == target_level->operations[i].opcode_uid) {
                    ++counters.unchanged_count;
                }
                else {
                    ++counters.modified_count;
                }
            }

            if (baseline_level->operations.size() > overlap) {
                counters.removed_count = baseline_level->operations.size() - overlap;
            }
            if (target_level->operations.size() > overlap) {
                counters.inserted_count = target_level->operations.size() - overlap;
            }
            return counters;
        }

    }  // namespace detail

    analysis_result run_analysis(const analysis_request& request, analysis_kind kind) {
        if (request.decl_cells.empty() && request.exec_cells.empty()) {
            throw std::runtime_error("analysis requires at least one stored cell");
        }

        auto source_text = detail::render_source(request.decl_cells, request.exec_cells);
        auto build_unit_hash = detail::make_build_unit_hash(request, source_text);

        auto artifacts_root = request.session_dir / "artifacts";
        auto inputs_dir = artifacts_root / "inputs" / build_unit_hash;
        fs::path kind_root{};
        switch (kind) {
            case analysis_kind::graph_cfg:
                kind_root = artifacts_root / "graphs" / "cfg";
                break;
            case analysis_kind::graph_call:
                kind_root = artifacts_root / "graphs" / "call";
                break;
            case analysis_kind::graph_defuse:
                kind_root = artifacts_root / "graphs" / "defuse";
                break;
            case analysis_kind::inspect_asm_map:
                kind_root = artifacts_root / "inspect" / "asm";
                break;
            case analysis_kind::inspect_mca_summary:
            case analysis_kind::inspect_mca_heatmap:
                kind_root = artifacts_root / "inspect" / "mca";
                break;
            default:
                kind_root = artifacts_root / "{}"_format(kind);
                break;
        }
        auto kind_dir = kind_root / build_unit_hash;

        detail::ensure_dir(inputs_dir);
        detail::ensure_dir(kind_dir);

        auto id = detail::make_artifact_id(build_unit_hash, request, kind);
        auto source_path = inputs_dir / "source.cpp";

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
            case analysis_kind::mem_trace:
                extension = ".trace.txt";
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

        detail::persist_merkle_cache_manifests(request, kind, source_text, build_unit_hash, source_path, artifact_path);

        {
            std::ofstream out{source_path};
            if (!out) {
                throw std::runtime_error("failed to write source file: {}"_format(source_path.string()));
            }
            out << source_text;
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

        if (auto cached_text_result = detail::try_load_cached_text_artifact_result(
                    kind, source_path, artifact_path, stdout_path, stderr_path);
            cached_text_result.has_value()) {
            return std::move(*cached_text_result);
        }
        if (auto cached_summary_result =
                    detail::try_load_cached_summary_result(kind, source_path, artifact_path, stdout_path, stderr_path);
            cached_summary_result.has_value()) {
            return std::move(*cached_summary_result);
        }

        if (kind == analysis_kind::mem_trace) {
            auto try_load = [&]() -> std::optional<analysis_result> {
                return detail::try_load_cached_mem_trace_result(source_path, artifact_path, stdout_path, stderr_path);
            };

            auto build = [&]() -> analysis_result {
                auto mem_result = analysis_result{};
                mem_result.kind = kind;
                mem_result.source_path = source_path;
                mem_result.artifact_path = artifact_path;
                mem_result.stdout_path = stdout_path;
                mem_result.stderr_path = stderr_path;

                auto ir_path = kind_dir / (id + ".trace.ll");
                auto ir_stdout_path = kind_dir / (id + ".ir.stdout.txt");
                auto ir_stderr_path = kind_dir / (id + ".ir.stderr.txt");

                auto ir_command = detail::build_command(request, analysis_kind::ir, source_path, ir_path);
                auto ir_exit = detail::run_process(ir_command, ir_stdout_path, ir_stderr_path);
                auto ir_stdout = detail::read_text_file(ir_stdout_path);
                auto ir_stderr = detail::read_text_file(ir_stderr_path);
                if (ir_exit != 0) {
                    detail::write_text_file(stdout_path, ir_stdout);
                    detail::write_text_file(stderr_path, ir_stderr);
                    detail::write_text_file(artifact_path, ir_stdout);

                    mem_result.exit_code = ir_exit;
                    mem_result.success = false;
                    mem_result.command = std::move(ir_command);
                    mem_result.artifact_text = std::move(ir_stdout);
                    mem_result.diagnostics_text = std::move(ir_stderr);
                    return mem_result;
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
                        resolved_symbol = std::string{*request.symbol};
                    }
                }
                else {
                    if (defined_symbols) {
                        resolved_symbol = detail::resolve_symbol_name(*defined_symbols, "main"sv);
                        if (!resolved_symbol && !defined_symbols->empty()) {
                            resolved_symbol = (*defined_symbols)[0].mangled;
                        }
                    }
                    if (!resolved_symbol) {
                        auto lines = detail::split_lines(ir_text);
                        for (const auto& line : lines) {
                            if (auto symbol = detail::parse_ir_function_name_from_define_line(line);
                                symbol.has_value()) {
                                resolved_symbol = std::string{*symbol};
                                break;
                            }
                        }
                    }
                }

                if (!resolved_symbol) {
                    throw std::runtime_error("unable to resolve symbol for memory trace");
                }

                auto map_entries = std::vector<detail::mem_trace_map_entry>{};
                auto instrumented_ir = detail::build_instrumented_mem_trace_ir(ir_text, *resolved_symbol, map_entries);
                auto instrumented_ir_path = kind_dir / (id + ".trace.instrumented.ll");
                detail::write_text_file(instrumented_ir_path, instrumented_ir);

                auto trace_events_path = kind_dir / (id + ".trace.events.log");
                auto trace_stats_path = kind_dir / (id + ".trace.stats.txt");
                auto runtime_source_path = kind_dir / (id + ".trace.runtime.cpp");
                detail::write_text_file(
                        runtime_source_path,
                        detail::build_mem_trace_runtime_source(trace_events_path.string(), trace_stats_path.string()));

                auto trace_binary_path = kind_dir / (id + ".trace.bin");
                auto compile_stdout_path = kind_dir / (id + ".trace.compile.stdout.txt");
                auto compile_stderr_path = kind_dir / (id + ".trace.compile.stderr.txt");

                auto compile_command = detail::base_clang_args(request);
                compile_command.push_back(instrumented_ir_path.string());
                compile_command.push_back(runtime_source_path.string());
                compile_command.emplace_back(detail::arg_tokens::output_path);
                compile_command.push_back(trace_binary_path.string());
                detail::append_link_flags(compile_command, request);

                auto compile_exit = detail::run_process(compile_command, compile_stdout_path, compile_stderr_path);
                auto compile_stdout = detail::read_text_file(compile_stdout_path);
                auto compile_stderr = detail::read_text_file(compile_stderr_path);
                if (compile_exit != 0) {
                    auto diagnostics = detail::join_text(ir_stderr, compile_stderr);
                    auto combined_stdout = detail::join_text(ir_stdout, compile_stdout);
                    detail::write_text_file(stdout_path, combined_stdout);
                    detail::write_text_file(stderr_path, diagnostics);
                    detail::write_text_file(artifact_path, combined_stdout);

                    mem_result.exit_code = compile_exit;
                    mem_result.success = false;
                    mem_result.command = std::move(compile_command);
                    mem_result.artifact_text = std::move(combined_stdout);
                    mem_result.diagnostics_text = std::move(diagnostics);
                    return mem_result;
                }

                auto run_command = std::vector<std::string>{trace_binary_path.string()};
                auto run_exit = detail::run_process(run_command, stdout_path, stderr_path);
                auto run_stdout = detail::read_text_file(stdout_path);
                auto run_stderr = detail::read_text_file(stderr_path);

                {
                    std::error_code ec{};
                    fs::remove(trace_binary_path, ec);
                }

                auto run_likely_signaled = run_exit >= 128;
                if (run_likely_signaled) {
                    auto diagnostics = detail::join_text(detail::join_text(ir_stderr, compile_stderr), run_stderr);
                    auto combined_stdout = detail::join_text(detail::join_text(ir_stdout, compile_stdout), run_stdout);
                    detail::write_text_file(stdout_path, combined_stdout);
                    detail::write_text_file(stderr_path, diagnostics);
                    detail::write_text_file(artifact_path, combined_stdout);

                    mem_result.exit_code = run_exit;
                    mem_result.success = false;
                    mem_result.command = std::move(run_command);
                    mem_result.artifact_text = std::move(combined_stdout);
                    mem_result.diagnostics_text = std::move(diagnostics);
                    return mem_result;
                }

                auto events = std::vector<detail::mem_trace_event_entry>{};
                auto event_lines = detail::split_lines(detail::read_text_file(trace_events_path));
                for (const auto& line : event_lines) {
                    if (auto parsed = detail::parse_mem_trace_event_line(line); parsed.has_value()) {
                        events.push_back(std::move(*parsed));
                    }
                }
                std::ranges::sort(events, [](const auto& lhs, const auto& rhs) { return lhs.sequence < rhs.sequence; });

                auto stats = detail::parse_mem_trace_runtime_stats(detail::read_text_file(trace_stats_path));
                auto payload = detail::mem_trace_payload{
                        .symbol = *resolved_symbol,
                        .tracee_exit_code = run_exit,
                        .truncated = stats.truncated,
                        .dropped_events = stats.dropped_events,
                        .map_entries = std::move(map_entries),
                        .events = std::move(events)};
                auto artifact_text = detail::render_mem_trace_payload(payload);
                detail::write_text_file(artifact_path, artifact_text);

                auto diagnostics = detail::join_text(detail::join_text(ir_stderr, compile_stderr), run_stderr);
                if (run_exit != 0) {
                    diagnostics = detail::join_text(diagnostics, "tracee_exit_code={}"_format(run_exit));
                }
                auto combined_stdout = detail::join_text(detail::join_text(ir_stdout, compile_stdout), run_stdout);
                detail::write_text_file(stdout_path, combined_stdout);
                detail::write_text_file(stderr_path, diagnostics);

                mem_result.exit_code = run_exit;
                mem_result.success = true;
                mem_result.command = std::move(run_command);
                mem_result.artifact_text = std::move(artifact_text);
                mem_result.diagnostics_text = std::move(diagnostics);
                return mem_result;
            };

            return detail::get_or_create<analysis_result>(try_load, build);
        }

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
                    resolved_symbol = detail::resolve_symbol_name(*defined_symbols, "main");
                }
                if (!resolved_symbol) {
                    resolved_symbol = detail::resolve_symbol_name(request, "main");
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
                artifact_summary = "root: {}\nroot_symbol: {}\nnodes: {}\nedges: {}\ndot: {}\n"_format(
                        call_artifact->root_display_name,
                        call_artifact->root_function.empty() ? "<all>"sv
                                                             : std::string_view{call_artifact->root_function},
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
                artifact_summary = "function: {}\nfunction_symbol: {}\nnodes: {}\nedges: {}\ndot: {}\n"_format(
                        defuse_artifact->function_display_name,
                        defuse_artifact->function_name,
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
            detail::write_summary_sidecar(artifact_path, result.artifact_text);
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
            auto symbol_info = detail::make_missing_symbol_resolution_info(request.symbol.value_or("main"));
            if (request.symbol) {
                if (defined_symbols) {
                    if (auto match = detail::resolve_symbol_match(*defined_symbols, *request.symbol)) {
                        resolved_symbol = match->mangled;
                        symbol_info = match->info;
                    }
                }
                if (!resolved_symbol) {
                    if (auto match = detail::resolve_symbol_match(request, *request.symbol)) {
                        resolved_symbol = match->mangled;
                        symbol_info = match->info;
                    }
                }
                if (!resolved_symbol) {
                    throw std::runtime_error("unable to resolve symbol: {}"_format(*request.symbol));
                }
            }
            else {
                if (defined_symbols) {
                    if (auto match = detail::resolve_symbol_match(*defined_symbols, "main"sv)) {
                        resolved_symbol = match->mangled;
                        symbol_info = match->info;
                    }
                }
                if (!resolved_symbol) {
                    if (auto match = detail::resolve_symbol_match(request, "main"sv)) {
                        resolved_symbol = match->mangled;
                        symbol_info = match->info;
                    }
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
            if (symbol_info.display_name.empty()) {
                symbol_info.display_name = symbol_display;
            }
            if (symbol_info.canonical_name.empty()) {
                symbol_info.canonical_name = std::string{detail::canonical_symbol_for_match(symbol_name)};
            }
            auto inspect_streams = std::array{opcode::operation_stream_input{.name = "asm", .disassembly = asm_text}};
            auto opcode_mapping = detail::build_opcode_mapping(inspect_streams);

            auto payload = detail::inspect_asm_map_payload{
                    .symbol = symbol_name,
                    .symbol_display = symbol_display,
                    .symbol_canonical = symbol_info.canonical_name,
                    .symbol_addendum = symbol_info.addendum,
                    .symbol_status = "{}"_format(symbol_info.status),
                    .symbol_confidence = "{}"_format(symbol_info.confidence),
                    .symbol_source = symbol_info.source,
                    .source = detail::make_line_records(source_text),
                    .ir = detail::make_line_records(ir_text),
                    .asm_lines = detail::make_line_records(asm_text),
                    .opcode_table = detail::to_analysis_opcode_entries(opcode_mapping.opcode_table),
                    .operations = detail::to_analysis_operation_entries(opcode_mapping.streams)};
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
            detail::write_summary_sidecar(artifact_path, result.artifact_text);
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
            auto symbol_info = detail::make_missing_symbol_resolution_info(request.symbol.value_or("main"));
            if (request.symbol) {
                if (defined_symbols) {
                    if (auto match = detail::resolve_symbol_match(*defined_symbols, *request.symbol)) {
                        symbol_name = match->mangled;
                        symbol_info = match->info;
                    }
                }
                if (symbol_name.empty()) {
                    symbol_name = *request.symbol;
                }
            }
            else {
                if (defined_symbols) {
                    if (auto match = detail::resolve_symbol_match(*defined_symbols, "main"sv)) {
                        symbol_name = match->mangled;
                        symbol_info = match->info;
                    }
                }
                if (symbol_name.empty()) {
                    symbol_name = "main";
                }
            }

            auto symbol_display = detail::resolve_symbol_display_name(symbol_name, symbol_display_names);
            if (symbol_info.display_name.empty()) {
                symbol_info.display_name = symbol_display;
            }
            if (symbol_info.canonical_name.empty()) {
                symbol_info.canonical_name = std::string{detail::canonical_symbol_for_match(symbol_name)};
            }
            auto mca_input_path = mca_result.artifact_path;
            mca_input_path.replace_extension(".input.s");
            auto mca_input_text = detail::read_text_file(mca_input_path);
            auto mca_streams = std::array{opcode::operation_stream_input{.name = "asm", .disassembly = mca_input_text}};
            auto opcode_mapping = detail::build_opcode_mapping(mca_streams);

            std::string payload_json{};
            std::string artifact_summary{};
            if (kind == analysis_kind::inspect_mca_summary) {
                auto payload = detail::inspect_mca_summary_payload{
                        .symbol = symbol_name,
                        .symbol_display = symbol_display,
                        .symbol_canonical = symbol_info.canonical_name,
                        .symbol_addendum = symbol_info.addendum,
                        .symbol_status = "{}"_format(symbol_info.status),
                        .symbol_confidence = "{}"_format(symbol_info.confidence),
                        .symbol_source = symbol_info.source,
                        .source_path = mca_result.source_path.string(),
                        .opcode_table = detail::to_analysis_opcode_entries(opcode_mapping.opcode_table),
                        .operations = detail::to_analysis_operation_entries(opcode_mapping.streams)};
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
                        .symbol_canonical = symbol_info.canonical_name,
                        .symbol_addendum = symbol_info.addendum,
                        .symbol_status = "{}"_format(symbol_info.status),
                        .symbol_confidence = "{}"_format(symbol_info.confidence),
                        .symbol_source = symbol_info.source,
                        .rows = detail::parse_mca_heatmap_rows(mca_result.artifact_text),
                        .opcode_table = detail::to_analysis_opcode_entries(opcode_mapping.opcode_table),
                        .operations = detail::to_analysis_operation_entries(opcode_mapping.streams)};
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
            detail::write_summary_sidecar(artifact_path, result.artifact_text);
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

            auto asm_text = detail::read_text_file(asm_path);

            if (request.symbol) {
                auto resolved = detail::resolve_symbol_name(request, *request.symbol);
                if (!resolved) {
                    throw std::runtime_error("unable to resolve symbol: {}"_format(*request.symbol));
                }

                auto extracted = detail::extract_asm_for_symbol(asm_text, *resolved);
                if (extracted.empty()) {
                    auto dump_result = run_analysis(request, analysis_kind::dump);
                    if (dump_result.success && !dump_result.artifact_text.empty()) {
                        asm_text = detail::prepare_mca_from_objdump(dump_result.artifact_text, request.asm_syntax);
                    }
                    else {
                        throw std::runtime_error("symbol not found in artifact: {}"_format(*resolved));
                    }
                }
                else {
                    asm_text = detail::prepare_mca_symbol_input(extracted, request.asm_syntax);
                }
            }
            else {
                asm_text = detail::sanitize_mca_input(asm_text, false);
            }

            detail::write_text_file(asm_path, asm_text);

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
            if (result.success) {
                auto mca_streams = std::array{
                        opcode::operation_stream_input{.name = "asm", .disassembly = detail::read_text_file(asm_path)}};
                detail::attach_opcode_mapping(result, mca_streams);
            }
            return result;
        }

        if (kind == analysis_kind::dump) {
            auto object_path = kind_dir / (id + ".input.o");
            auto binary_path = kind_dir / (id + ".bin");
            auto compile_stdout_path = kind_dir / (id + ".compile.stdout.txt");
            auto compile_stderr_path = kind_dir / (id + ".compile.stderr.txt");

            bool linked = false;
            std::vector<std::string> compile_command{};

            if (!request.no_link) {
                compile_command = detail::base_clang_args(request);
                compile_command.push_back(source_path.string());
                compile_command.emplace_back("-o");
                compile_command.push_back(binary_path.string());
                detail::append_link_flags(compile_command, request);
                auto link_exit = detail::run_process(compile_command, compile_stdout_path, compile_stderr_path);
                linked = (link_exit == 0);
                if (!linked && request.verbose) {
                    auto link_stderr = detail::read_text_file(compile_stderr_path);
                    if (!link_stderr.empty()) {
                        debug_log("dump link failed (exit {}): {}", link_exit, link_stderr);
                    }
                }
            }

            if (!linked) {
                compile_command = detail::build_command(request, analysis_kind::dump, source_path, object_path);
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
            }

            auto objdump_input = linked ? binary_path : object_path;

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
                objdump_command = detail::build_objdump_command(request, objdump_input, candidate, std::nullopt);
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

            if (resolved_symbol) {
                auto display_symbol = detail::demangle_symbol_name(*resolved_symbol);
                auto extracted = detail::extract_objdump_for_symbol(stdout_text, *resolved_symbol, display_symbol);
                if (!extracted.empty()) {
                    stdout_text = std::move(extracted);
                }
                else if (objdump_exit == 0) {
                    stdout_text.clear();
                    stderr_text =
                            detail::join_text(stderr_text, "symbol not found in artifact: {}"_format(*resolved_symbol));
                    objdump_exit = 1;
                    detail::write_text_file(stderr_path, stderr_text);
                }
            }

            if (linked) {
                std::error_code ec{};
                fs::remove(binary_path, ec);
            }

            detail::write_text_file(artifact_path, stdout_text);

            result.exit_code = objdump_exit;
            result.success = (objdump_exit == 0);
            result.binary_path = linked ? std::optional<fs::path>{binary_path} : std::nullopt;
            result.command = std::move(objdump_command);
            result.artifact_text = std::move(stdout_text);
            result.diagnostics_text = std::move(stderr_text);
            if (result.success) {
                auto dump_streams =
                        std::array{opcode::operation_stream_input{.name = "asm", .disassembly = result.artifact_text}};
                detail::attach_opcode_mapping(result, dump_streams);
            }
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
                    if (kind == analysis_kind::asm_text) {
                        auto dump_result = run_analysis(request, analysis_kind::dump);
                        if (dump_result.success && !detail::trim_ascii(dump_result.artifact_text).empty()) {
                            extracted = std::move(dump_result.artifact_text);
                        }
                        else {
                            auto details = dump_result.diagnostics_text.empty()
                                                 ? "symbol not found in artifact: {}"_format(*resolved)
                                                 : detail::join_text(
                                                           dump_result.diagnostics_text,
                                                           "symbol not found in artifact: {}"_format(*resolved));
                            throw std::runtime_error(details);
                        }
                    }
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

        // `:symbols` should reflect snapshot-owned symbols, not full linked runtime inventories.
        std::vector<analysis_symbol> filtered = *symbols | std::views::filter([](auto&& symbol) {
            return symbol.present_in_object;
        }) | std::ranges::to<std::vector<analysis_symbol>>();
        if (!filtered.empty()) {
            return filtered;
        }
        return *symbols;
    }

    std::optional<symbol_resolution_info> resolve_symbol_info(
            const analysis_request& request, std::string_view symbol) {
        auto match = detail::resolve_symbol_match(request, symbol);
        if (match) {
            return match->info;
        }
        return detail::make_missing_symbol_resolution_info(symbol);
    }

    delta_report collect_delta_report(
            const analysis_request& request, std::optional<std::string> symbol, optimization_level target) {
        auto delta = delta_request{.mode = delta_mode::pairwise, .symbol = symbol, .target = target};
        return collect_delta_report(request, delta);
    }

    delta_report collect_delta_report(const analysis_request& request, const delta_request& delta) {
        if (request.decl_cells.empty() && request.exec_cells.empty()) {
            throw std::runtime_error("delta collection requires at least one stored cell");
        }

        auto report = delta_report{};
        report.mode = delta.mode;
        report.baseline = optimization_level::o0;
        report.target = delta.target;
        report.baseline_label = "{}"_format(report.baseline);
        report.target_label = "{}"_format(report.target);

        auto symbol_resolution = detail::resolve_delta_symbol(request, delta.symbol);
        report.symbol = symbol_resolution.mangled.value_or(delta.symbol.value_or("main"));
        report.symbol_display = symbol_resolution.display.empty() ? report.symbol : symbol_resolution.display;
        report.symbol_resolution = symbol_resolution.info;
        if (report.symbol_resolution.display_name.empty()) {
            report.symbol_resolution.display_name = report.symbol_display;
        }
        if (report.symbol_resolution.canonical_name.empty()) {
            report.symbol_resolution.canonical_name = std::string{detail::canonical_symbol_for_match(report.symbol)};
        }
        if (!symbol_resolution.resolved) {
            report.success = false;
            return report;
        }

        auto requested_levels = detail::make_delta_levels(delta);
        std::vector<size_t> mapped_level_indices{};
        std::vector<std::string> mapped_disassembly{};
        std::vector<std::string> level_symbol_disassembly{};
        std::vector<double> level_compile_time_ms{};
        level_symbol_disassembly.reserve(requested_levels.size());
        level_compile_time_ms.reserve(requested_levels.size());
        auto invalid_delta = false;

        for (auto level : requested_levels) {
            auto level_record = delta_level_record{
                    .level = level,
                    .label = "{}"_format(level),
                    .symbol_status = report.symbol_resolution.status,
                    .symbol_confidence = report.symbol_resolution.confidence,
                    .symbol_source = report.symbol_resolution.source};
            auto level_disassembly = std::string{};

            auto level_request = request;
            level_request.opt_level = level;
            level_request.symbol = std::nullopt;
            auto level_start = std::chrono::steady_clock::now();

            try {
                auto dump_result = run_analysis(level_request, analysis_kind::dump);

                level_record.success = dump_result.success;
                level_record.exit_code = dump_result.exit_code;
                level_record.artifact_path = dump_result.artifact_path;
                level_record.diagnostics_text = dump_result.diagnostics_text;

                if (!dump_result.success) {
                    invalid_delta = true;
                }
                else {
                    auto extracted = symbol_resolution.mangled ? detail::extract_objdump_for_symbol(
                                                                         dump_result.artifact_text,
                                                                         *symbol_resolution.mangled,
                                                                         symbol_resolution.display)
                                                               : std::string{};
                    if (symbol_resolution.mangled && extracted.empty()) {
                        level_record.symbol_status = symbol_resolution_status::optimized_out;
                        level_record.symbol_source = "objdump_symbol_missing";
                        level_record.diagnostics_text = detail::join_text(
                                level_record.diagnostics_text,
                                "symbol not found in artifact: {}"_format(*symbol_resolution.mangled));
                        if (level == report.baseline) {
                            invalid_delta = true;
                            level_record.success = false;
                        }
                    }
                    else {
                        if (!extracted.empty()) {
                            dump_result.artifact_text = std::move(extracted);
                        }
                        level_disassembly = dump_result.artifact_text;
                        mapped_level_indices.push_back(report.levels.size());
                        mapped_disassembly.push_back(std::move(dump_result.artifact_text));
                    }
                }
            } catch (const std::exception& e) {
                invalid_delta = true;
                level_record.success = false;
                level_record.exit_code = -1;
                level_record.symbol_status = symbol_resolution_status::missing;
                level_record.symbol_source = "analysis_exception";
                level_record.diagnostics_text = e.what();
            }

            auto level_end = std::chrono::steady_clock::now();
            auto compile_time_ms = std::chrono::duration<double, std::milli>(level_end - level_start).count();

            report.levels.push_back(std::move(level_record));
            level_symbol_disassembly.push_back(std::move(level_disassembly));
            level_compile_time_ms.push_back(compile_time_ms);
        }

        if (!mapped_disassembly.empty()) {
            std::vector<opcode::operation_stream_input> streams{};
            streams.reserve(mapped_disassembly.size());
            for (const auto& disassembly : mapped_disassembly) {
                streams.push_back(opcode::operation_stream_input{.name = "dump", .disassembly = disassembly});
            }

            auto mapped = detail::build_opcode_mapping(streams);
            auto mapped_levels = std::min(mapped_level_indices.size(), mapped.streams.size());
            for (size_t i = 0U; i < mapped_levels; ++i) {
                auto& level_record = report.levels[mapped_level_indices[i]];
                level_record.operations = detail::to_delta_operations(mapped.streams[i].operations);
                if (level_record.operations.empty()) {
                    invalid_delta = true;
                    level_record.success = false;
                    level_record.diagnostics_text =
                            detail::join_text(level_record.diagnostics_text, "no assembly instructions found.");
                }
            }

            report.opcode_table = {};
            report.opcode_table.reserve(mapped.opcode_table.size());
            for (const auto& entry : mapped.opcode_table) {
                report.opcode_table.push_back(delta_opcode_entry{.opcode_uid = entry.uid, .opcode = entry.mnemonic});
            }
        }
        else {
            invalid_delta = true;
        }

        if (!invalid_delta) {
            for (size_t i = 0U; i < report.levels.size(); ++i) {
                auto level_request = request;
                level_request.opt_level = report.levels[i].level;
                report.levels[i].metrics = detail::collect_level_metrics(
                        std::move(level_request),
                        symbol_resolution,
                        report.levels[i],
                        level_symbol_disassembly[i],
                        level_compile_time_ms[i]);
            }
        }

        report.success = !invalid_delta && detail::all_levels_success(report.levels, requested_levels);
        if (report.success) {
            report.counters = detail::compute_pairwise_counters(report.levels, report.baseline, report.target);
        }
        else {
            report.counters = {};
        }

        return report;
    }

    std::string synthesize_source(const analysis_request& request) {
        return detail::render_source(request.decl_cells, request.exec_cells);
    }

}  // namespace sontag
