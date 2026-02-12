#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace sontag::graph {

    using symbol_display_map = std::unordered_map<std::string, std::string>;

    struct cfg_graph_artifact {
        std::string function_name{};
        size_t block_count{};
        size_t edge_count{};
        std::string dot_text{};
    };

    struct call_graph_artifact {
        std::string root_function{};
        std::string root_display_name{};
        size_t node_count{};
        size_t edge_count{};
        std::string dot_text{};
    };

    std::optional<std::string> find_first_ir_function_name(std::string_view ir_text);

    std::optional<cfg_graph_artifact> build_cfg_graph_artifact(
            std::string_view ir_text, std::string_view function_name);

    std::optional<call_graph_artifact> build_call_graph_artifact(
            std::string_view ir_text,
            std::string_view root_function,
            const symbol_display_map* display_names = nullptr);

}  // namespace sontag::graph
