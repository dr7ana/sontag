#pragma once

#include "config.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sontag {

    enum class analysis_kind {
        asm_text,
        ir,
        diag,
        mca,
        dump,
        inspect_asm_map,
        inspect_mca_summary,
        inspect_mca_heatmap,
        graph_cfg,
        graph_call,
        graph_defuse,
    };

    inline constexpr std::string_view to_string(analysis_kind kind) {
        switch (kind) {
            case analysis_kind::asm_text:
                return "asm"sv;
            case analysis_kind::ir:
                return "ir"sv;
            case analysis_kind::diag:
                return "diag"sv;
            case analysis_kind::mca:
                return "mca"sv;
            case analysis_kind::dump:
                return "dump"sv;
            case analysis_kind::inspect_asm_map:
                return "inspect asm"sv;
            case analysis_kind::inspect_mca_summary:
                return "inspect mca summary"sv;
            case analysis_kind::inspect_mca_heatmap:
                return "inspect mca heatmap"sv;
            case analysis_kind::graph_cfg:
                return "graph cfg"sv;
            case analysis_kind::graph_call:
                return "graph call"sv;
            case analysis_kind::graph_defuse:
                return "graph defuse"sv;
        }
        return "diag"sv;
    }

    struct analysis_request {
        std::filesystem::path clang_path{"clang++"};
        std::filesystem::path session_dir{};
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
        cxx_standard language_standard{cxx_standard::cxx23};
        optimization_level opt_level{optimization_level::o2};
        std::optional<std::string> target_triple{};
        std::optional<std::string> cpu{};
        std::string asm_syntax{"intel"};
        std::optional<std::string> symbol{};
        std::optional<std::string> mca_cpu{};
        std::filesystem::path mca_path{"llvm-mca"};
        std::filesystem::path objdump_path{"llvm-objdump"};
        std::string graph_format{"png"};
        std::optional<std::filesystem::path> dot_path{};
        bool verbose{false};
    };

    struct analysis_result {
        analysis_kind kind{analysis_kind::diag};
        bool success{false};
        int exit_code{-1};
        std::filesystem::path source_path{};
        std::filesystem::path artifact_path{};
        std::filesystem::path stdout_path{};
        std::filesystem::path stderr_path{};
        std::string artifact_text{};
        std::string diagnostics_text{};
        std::vector<std::string> command{};
    };

    struct analysis_symbol {
        char kind{'?'};
        std::string mangled{};
        std::string demangled{};
    };

    std::string synthesize_source(const analysis_request& request);
    analysis_result run_analysis(const analysis_request& request, analysis_kind kind);
    std::vector<analysis_symbol> list_symbols(const analysis_request& request);

}  // namespace sontag

namespace std {
    template <>
    struct formatter<sontag::analysis_kind, char> : formatter<std::string_view> {
        template <typename FormatContext>
        auto format(const sontag::analysis_kind& val, FormatContext& ctx) const {
            return formatter<std::string_view>::format(sontag::to_string(val), ctx);
        }
    };
}  // namespace std
