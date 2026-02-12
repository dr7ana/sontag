#pragma once

#include "sontag/config.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sontag {

    enum class analysis_kind { asm_text, ir, diag };

    inline constexpr std::string_view to_string(analysis_kind kind) {
        switch (kind) {
            case analysis_kind::asm_text:
                return "asm";
            case analysis_kind::ir:
                return "ir";
            case analysis_kind::diag:
                return "diag";
        }
        return "diag";
    }

    struct analysis_request {
        std::filesystem::path clang_path{"clang++"};
        std::filesystem::path session_dir{};
        std::vector<std::string> cells{};
        cxx_standard language_standard{cxx_standard::cxx23};
        optimization_level opt_level{optimization_level::o2};
        std::optional<std::string> target_triple{};
        std::optional<std::string> cpu{};
        std::string asm_syntax{"intel"};
        std::optional<std::string> symbol{};
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

    analysis_result run_analysis(const analysis_request& request, analysis_kind kind);

}  // namespace sontag
