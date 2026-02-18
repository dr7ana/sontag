#pragma once

#include "config.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace sontag::interpreter {

    using namespace std::string_view_literals;

    enum class record_status : uint8_t {
        ok,
        na,
        error,
    };

    inline constexpr std::string_view to_string(record_status status) {
        switch (status) {
            case record_status::ok:
                return "ok"sv;
            case record_status::na:
                return "na"sv;
            case record_status::error:
                return "error"sv;
        }
        return "na"sv;
    }

    enum class warning_severity : uint8_t {
        info,
        warning,
        error,
    };

    inline constexpr std::string_view to_string(warning_severity severity) {
        switch (severity) {
            case warning_severity::info:
                return "info"sv;
            case warning_severity::warning:
                return "warning"sv;
            case warning_severity::error:
                return "error"sv;
        }
        return "warning"sv;
    }

    enum class operation_stage : uint8_t {
        source,
        ir,
        asm_text,
        mca,
    };

    inline constexpr std::string_view to_string(operation_stage stage) {
        switch (stage) {
            case operation_stage::source:
                return "source"sv;
            case operation_stage::ir:
                return "ir"sv;
            case operation_stage::asm_text:
                return "asm"sv;
            case operation_stage::mca:
                return "mca"sv;
        }
        return "source"sv;
    }

    enum class relation_kind : uint8_t {
        contains,
        calls,
        def_use,
        lowers_to,
        maps_to_source,
    };

    inline constexpr std::string_view to_string(relation_kind kind) {
        switch (kind) {
            case relation_kind::contains:
                return "contains"sv;
            case relation_kind::calls:
                return "calls"sv;
            case relation_kind::def_use:
                return "def_use"sv;
            case relation_kind::lowers_to:
                return "lowers_to"sv;
            case relation_kind::maps_to_source:
                return "maps_to_source"sv;
        }
        return "contains"sv;
    }

    enum class confidence_level : uint8_t {
        exact,
        heuristic,
        unknown,
    };

    inline constexpr std::string_view to_string(confidence_level level) {
        switch (level) {
            case confidence_level::exact:
                return "exact"sv;
            case confidence_level::heuristic:
                return "heuristic"sv;
            case confidence_level::unknown:
                return "unknown"sv;
        }
        return "unknown"sv;
    }

    enum class artifact_kind : uint8_t {
        source,
        diag,
        ir,
        asm_text,
        object,
        mca_raw,
        graph_dot,
        graph_render,
        inspect_json,
    };

    inline constexpr std::string_view to_string(artifact_kind kind) {
        switch (kind) {
            case artifact_kind::source:
                return "source"sv;
            case artifact_kind::diag:
                return "diag"sv;
            case artifact_kind::ir:
                return "ir"sv;
            case artifact_kind::asm_text:
                return "asm"sv;
            case artifact_kind::object:
                return "obj"sv;
            case artifact_kind::mca_raw:
                return "mca_raw"sv;
            case artifact_kind::graph_dot:
                return "graph_dot"sv;
            case artifact_kind::graph_render:
                return "graph_render"sv;
            case artifact_kind::inspect_json:
                return "inspect_json"sv;
        }
        return "source"sv;
    }

    enum class tool_producer : uint8_t {
        clang,
        llvm_mca,
        llvm_objdump,
        dot,
        sontag,
        unknown,
    };

    inline constexpr std::string_view to_string(tool_producer producer) {
        switch (producer) {
            case tool_producer::clang:
                return "clang"sv;
            case tool_producer::llvm_mca:
                return "llvm-mca"sv;
            case tool_producer::llvm_objdump:
                return "llvm-objdump"sv;
            case tool_producer::dot:
                return "dot"sv;
            case tool_producer::sontag:
                return "sontag"sv;
            case tool_producer::unknown:
                return "unknown"sv;
        }
        return "unknown"sv;
    }

    enum class symbol_type : uint8_t {
        global_absolute,   // A: global absolute symbol
        local_absolute,    // a: local absolute symbol
        global_bss,        // B: global bss symbol
        local_bss,         // b: local bss symbol
        global_data,       // D: global data symbol
        local_data,        // d: local data symbol
        source_file,       // f: source file name symbol
        global_read_only,  // R: global read-only symbol
        local_read_only,   // r: local read-only symbol
        global_text,       // T: global text symbol
        local_text,        // t: local text symbol
        undefined,         // U: undefined symbol
        unknown,           // ?: unknown or unsupported symbol type
    };

    inline constexpr symbol_type parse_symbol_type(char raw_kind) {
        switch (raw_kind) {
            case 'A':
                return symbol_type::global_absolute;
            case 'a':
                return symbol_type::local_absolute;
            case 'B':
                return symbol_type::global_bss;
            case 'b':
                return symbol_type::local_bss;
            case 'D':
                return symbol_type::global_data;
            case 'd':
                return symbol_type::local_data;
            case 'f':
                return symbol_type::source_file;
            case 'R':
                return symbol_type::global_read_only;
            case 'r':
                return symbol_type::local_read_only;
            case 'T':
                return symbol_type::global_text;
            case 't':
                return symbol_type::local_text;
            case 'U':
                return symbol_type::undefined;
            default:
                return symbol_type::unknown;
        }
    }

    inline constexpr char to_raw_symbol_type(symbol_type type) {
        switch (type) {
            case symbol_type::global_absolute:
                return 'A';
            case symbol_type::local_absolute:
                return 'a';
            case symbol_type::global_bss:
                return 'B';
            case symbol_type::local_bss:
                return 'b';
            case symbol_type::global_data:
                return 'D';
            case symbol_type::local_data:
                return 'd';
            case symbol_type::source_file:
                return 'f';
            case symbol_type::global_read_only:
                return 'R';
            case symbol_type::local_read_only:
                return 'r';
            case symbol_type::global_text:
                return 'T';
            case symbol_type::local_text:
                return 't';
            case symbol_type::undefined:
                return 'U';
            case symbol_type::unknown:
                return '?';
        }
        return '?';
    }

    struct tool_invocation_record {
        tool_producer producer{tool_producer::unknown};
        std::string executable{};
        std::vector<std::string> args{};
        int exit_code{-1};
        record_status status{record_status::na};
    };

    struct warning_record {
        std::string code{};
        warning_severity severity{warning_severity::warning};
        std::string message{};
        std::optional<std::string> extractor{};
        std::optional<std::string> evidence{};
    };

    struct artifact_ref {
        std::string artifact_id{};
        artifact_kind kind{artifact_kind::source};
        std::filesystem::path path{};
        std::string content_hash{};
        tool_producer producer{tool_producer::unknown};
        record_status status{record_status::na};
    };

    struct source_span {
        size_t begin_line{};
        size_t end_line{};
    };

    using metric_value = std::variant<bool, int64_t, double, std::string>;

    struct subject_record {
        std::string subject_id{};
        std::string origin{};
        std::string source_hash{};
    };

    struct variant_record {
        std::string variant_id{};
        cxx_standard language_standard{cxx_standard::cxx23};
        optimization_level opt_level{optimization_level::o2};
        std::optional<std::string> target_triple{};
        std::optional<std::string> cpu{};
    };

    struct case_record {
        std::string case_id{};
        std::string subject_id{};
        std::string variant_id{};
        std::optional<std::string> symbol_scope{};
        int exit_code{-1};
        record_status status{record_status::na};
        std::vector<warning_record> warnings{};
    };

    struct symbol_record {
        std::string symbol_id{};
        std::string case_id{};
        std::string mangled{};
        std::string demangled{};
        symbol_type type{symbol_type::unknown};
        char raw_kind{'?'};
        std::optional<std::string> linkage{};
        std::optional<std::string> visibility{};
        std::vector<std::string> aliases{};
    };

    struct operation_record {
        std::string operation_id{};
        std::string case_id{};
        std::optional<std::string> symbol_id{};
        operation_stage stage{operation_stage::source};
        std::string block_id{};
        size_t ordinal{};
        std::string opcode{};
        std::vector<std::string> category_tags{};
        std::string raw_text{};
        std::optional<source_span> span{};
    };

    struct relation_record {
        std::string relation_id{};
        std::string case_id{};
        relation_kind relation_type{relation_kind::contains};
        std::string source_id{};
        std::string destination_id{};
        confidence_level confidence{confidence_level::unknown};
        std::optional<std::string> evidence{};
    };

    struct metric_record {
        std::string case_id{};
        std::optional<std::string> symbol_id{};
        std::string name{};
        std::optional<metric_value> value{};
        std::string units{};
        record_status status{record_status::na};
    };

    struct provenance_record {
        std::string run_id{};
        std::string created_at{};
        std::string clang_version{};
        std::string llvm_version{};
        cxx_standard language_standard{cxx_standard::cxx23};
        optimization_level opt_level{optimization_level::o2};
        std::optional<std::string> target_triple{};
        std::optional<std::string> cpu{};
        std::vector<tool_invocation_record> tool_invocations{};
    };

    struct analysis_bundle {
        int schema_version{1};
        std::string bundle_id{};
        subject_record subject{};
        variant_record variant{};
        case_record case_info{};
        provenance_record provenance{};
        std::vector<symbol_record> symbols{};
        std::vector<operation_record> operations{};
        std::vector<relation_record> relations{};
        std::vector<metric_record> metrics{};
        std::vector<warning_record> warnings{};
        std::vector<artifact_ref> artifact_refs{};
    };

}  // namespace sontag::interpreter
