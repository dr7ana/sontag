#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sontag::graph {

    using symbol_display_map = std::unordered_map<std::string, std::string>;

    struct cfg_graph_block {
        std::string id{};
        std::vector<std::string> instructions{};
    };

    struct cfg_graph_edge {
        std::string from{};
        std::string to{};
        std::string label{};
    };

    struct cfg_graph_artifact {
        std::string function_name{};
        size_t block_count{};
        size_t edge_count{};
        std::vector<cfg_graph_block> blocks{};
        std::vector<cfg_graph_edge> edges{};
        std::string dot_text{};
    };

    struct call_graph_artifact {
        std::string root_function{};
        std::string root_display_name{};
        size_t node_count{};
        size_t edge_count{};
        struct node {
            std::string name{};
            std::string display_name{};
            std::string annotation{};
            bool is_defined{false};
        };
        struct edge {
            std::string from{};
            std::string to{};
        };
        std::vector<node> nodes{};
        std::vector<edge> edges{};
        std::string dot_text{};
    };

    struct defuse_graph_artifact {
        std::string function_name{};
        std::string function_display_name{};
        size_t node_count{};
        size_t edge_count{};
        struct node {
            size_t id{};
            std::string instruction{};
        };
        struct edge {
            size_t from{};
            size_t to{};
            std::string label{};
        };
        std::vector<node> nodes{};
        std::vector<edge> edges{};
        std::string dot_text{};
    };

    std::optional<std::string> find_first_ir_function_name(std::string_view ir_text);

    std::optional<cfg_graph_artifact> build_cfg_graph_artifact(
            std::string_view ir_text, std::string_view function_name);

    std::optional<call_graph_artifact> build_call_graph_artifact(
            std::string_view ir_text,
            std::string_view root_function,
            const symbol_display_map* display_names = nullptr,
            bool include_inline_annotations = false);

    std::optional<defuse_graph_artifact> build_defuse_graph_artifact(
            std::string_view ir_text,
            std::string_view function_name,
            const symbol_display_map* display_names = nullptr);

}  // namespace sontag::graph
