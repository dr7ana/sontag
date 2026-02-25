#pragma once

#include "sontag/analysis.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sontag {

    using namespace std::string_view_literals;

    enum class delta_mode : uint8_t { pairwise, spectrum };

    constexpr std::string_view to_string(delta_mode mode) {
        switch (mode) {
            case delta_mode::pairwise:
                return "pairwise"sv;
            case delta_mode::spectrum:
                return "spectrum"sv;
        }
        return "pairwise"sv;
    }

    struct delta_request {
        delta_mode mode{delta_mode::pairwise};
        std::optional<std::string> symbol{};
        optimization_level target{optimization_level::o2};
    };

    struct delta_operation {
        size_t ordinal{};
        uint64_t opcode_uid{};
        std::string opcode{};
        std::string triplet{};
    };

    struct delta_opcode_entry {
        uint64_t opcode_uid{};
        std::string opcode{};
    };

    struct delta_metric_entry {
        std::string name{};
        double value{};
        std::string unit{};
        metric_status status{metric_status::na};
    };

    struct delta_level_record {
        optimization_level level{optimization_level::o0};
        std::string label{};
        bool success{false};
        int exit_code{-1};
        std::filesystem::path artifact_path{};
        symbol_resolution_status symbol_status{symbol_resolution_status::missing};
        symbol_resolution_confidence symbol_confidence{symbol_resolution_confidence::heuristic_match};
        std::string symbol_source{};
        std::vector<delta_operation> operations{};
        std::vector<delta_metric_entry> metrics{};
        std::string diagnostics_text{};
    };

    struct delta_change_counters {
        size_t unchanged_count{};
        size_t modified_count{};
        size_t inserted_count{};
        size_t removed_count{};
        size_t moved_count{};
    };

    struct delta_report {
        int schema_version{1};
        delta_mode mode{delta_mode::pairwise};
        bool success{false};
        std::string symbol{};
        std::string symbol_display{};
        symbol_resolution_info symbol_resolution{};
        optimization_level baseline{optimization_level::o0};
        optimization_level target{optimization_level::o2};
        std::string baseline_label{};
        std::string target_label{};
        std::vector<delta_opcode_entry> opcode_table{};
        std::vector<delta_level_record> levels{};
        delta_change_counters counters{};
    };

    delta_report collect_delta_report(
            const analysis_request& request,
            std::optional<std::string> symbol = std::nullopt,
            optimization_level target = optimization_level::o2);
    delta_report collect_delta_report(const analysis_request& request, const delta_request& delta);

}  // namespace sontag

namespace std {
    template <>
    struct formatter<sontag::delta_mode, char> : formatter<std::string_view> {
        template <typename FormatContext>
        auto format(const sontag::delta_mode& val, FormatContext& ctx) const {
            return formatter<std::string_view>::format(sontag::to_string(val), ctx);
        }
    };
}  // namespace std
