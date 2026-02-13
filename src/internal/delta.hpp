#pragma once

#include "sontag/analysis.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sontag {

    using namespace std::string_view_literals;

    enum class delta_mode { pairwise, spectrum };

    constexpr std::string_view to_string(delta_mode mode) {
        switch (mode) {
            case delta_mode::pairwise:
                return "pairwise"sv;
            case delta_mode::spectrum:
                return "spectrum"sv;
        }
        return "pairwise"sv;
    }

    enum class delta_quality_flag {
        symbol_resolution_failed,
        compile_failed,
        tool_execution_failed,
        symbol_extract_failed,
        empty_operation_stream,
    };

    constexpr std::string_view to_string(delta_quality_flag flag) {
        switch (flag) {
            case delta_quality_flag::symbol_resolution_failed:
                return "symbol_resolution_failed"sv;
            case delta_quality_flag::compile_failed:
                return "compile_failed"sv;
            case delta_quality_flag::tool_execution_failed:
                return "tool_execution_failed"sv;
            case delta_quality_flag::symbol_extract_failed:
                return "symbol_extract_failed"sv;
            case delta_quality_flag::empty_operation_stream:
                return "empty_operation_stream"sv;
        }
        return "tool_execution_failed"sv;
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
        std::vector<std::string> quality_flags{};
    };

    struct delta_level_record {
        optimization_level level{optimization_level::o0};
        bool success{false};
        int exit_code{-1};
        std::filesystem::path artifact_path{};
        std::vector<delta_operation> operations{};
        std::vector<delta_metric_entry> metrics{};
        std::string diagnostics_text{};
        std::vector<delta_quality_flag> quality_flags{};
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
        optimization_level baseline{optimization_level::o0};
        optimization_level target{optimization_level::o2};
        std::vector<delta_opcode_entry> opcode_table{};
        std::vector<delta_level_record> levels{};
        delta_change_counters counters{};
        std::vector<delta_quality_flag> quality_flags{};
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

    template <>
    struct formatter<sontag::delta_quality_flag, char> : formatter<std::string_view> {
        template <typename FormatContext>
        auto format(const sontag::delta_quality_flag& val, FormatContext& ctx) const {
            return formatter<std::string_view>::format(sontag::to_string(val), ctx);
        }
    };
}  // namespace std
