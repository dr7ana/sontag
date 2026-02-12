#include "sontag/graph.hpp"

#include "sontag/format.hpp"

#include <cxxabi.h>

#include <cctype>
#include <cstdlib>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace sontag::literals;

namespace sontag::graph {
    namespace detail {

        using namespace std::string_view_literals;

        struct cfg_edge {
            std::string from{};
            std::string to{};
            std::string label{};
        };

        struct cfg_block {
            std::string id{};
            std::vector<std::string> instructions{};
        };

        struct cfg_graph {
            std::string function_name{};
            std::vector<cfg_block> blocks{};
            std::vector<cfg_edge> edges{};
        };

        struct call_edge {
            std::string from{};
            std::string to{};
        };

        struct call_node {
            std::string name{};
            std::string display_name{};
            bool is_defined{false};
        };

        struct call_graph {
            std::string root_function{};
            std::string root_display_name{};
            std::vector<call_node> nodes{};
            std::vector<call_edge> edges{};
        };

        static constexpr auto cfg_pseudo_entry = "__entry__"sv;
        static constexpr auto cfg_pseudo_exit = "__exit__"sv;

        static std::string_view trim_ascii(std::string_view value) {
            auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return {};
            }
            auto last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, (last - first) + 1U);
        }

        static std::vector<std::string> split_lines(std::string_view text) {
            std::vector<std::string> lines{};
            std::istringstream in{std::string{text}};
            std::string line{};
            while (std::getline(in, line)) {
                lines.push_back(line);
            }
            return lines;
        }

        static void append_unique(std::vector<std::string>& values, std::string value) {
            if (value.empty()) {
                return;
            }
            for (const auto& existing : values) {
                if (existing == value) {
                    return;
                }
            }
            values.push_back(std::move(value));
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

        static std::string resolve_display_name(std::string_view symbol_name, const symbol_display_map* display_names) {
            if (display_names != nullptr) {
                if (auto it = display_names->find(std::string{symbol_name}); it != display_names->end()) {
                    return it->second;
                }
            }
            return demangle_symbol_name(symbol_name);
        }

        static std::optional<std::string> parse_ir_function_name(std::string_view line) {
            auto at = line.find('@');
            if (at == std::string_view::npos || at + 1U >= line.size()) {
                return std::nullopt;
            }

            auto pos = at + 1U;
            if (line[pos] == '"') {
                ++pos;
                auto end = pos;
                while (end < line.size()) {
                    if (line[end] == '"') {
                        break;
                    }
                    if (line[end] == '\\' && end + 1U < line.size()) {
                        end += 2U;
                        continue;
                    }
                    ++end;
                }
                if (end >= line.size()) {
                    return std::nullopt;
                }
                return std::string{line.substr(pos, end - pos)};
            }

            auto end = line.find('(', pos);
            if (end == std::string_view::npos || end == pos) {
                return std::nullopt;
            }
            return std::string{line.substr(pos, end - pos)};
        }

        static std::optional<std::string> find_first_ir_function_name_impl(std::string_view ir_text) {
            auto lines = split_lines(ir_text);
            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);
                if (!trimmed.starts_with("define "sv)) {
                    continue;
                }
                if (auto name = parse_ir_function_name(trimmed)) {
                    return name;
                }
            }
            return std::nullopt;
        }

        static std::optional<std::string> parse_ir_called_function_name(std::string_view line) {
            auto trimmed = trim_ascii(line);
            if (trimmed.empty() || trimmed.starts_with(';')) {
                return std::nullopt;
            }

            auto call_pos = trimmed.find(" call "sv);
            if (call_pos == std::string_view::npos && trimmed.starts_with("call "sv)) {
                call_pos = 0U;
            }
            auto invoke_pos = trimmed.find("invoke "sv);

            size_t search_pos = std::string_view::npos;
            if (call_pos != std::string_view::npos) {
                search_pos = call_pos;
            }
            if (invoke_pos != std::string_view::npos &&
                (search_pos == std::string_view::npos || invoke_pos < search_pos)) {
                search_pos = invoke_pos;
            }
            if (search_pos == std::string_view::npos) {
                return std::nullopt;
            }

            auto at = trimmed.find('@', search_pos);
            if (at == std::string_view::npos || at + 1U >= trimmed.size()) {
                return std::nullopt;
            }

            auto pos = at + 1U;
            if (trimmed[pos] == '"') {
                ++pos;
                auto end = pos;
                while (end < trimmed.size()) {
                    if (trimmed[end] == '"') {
                        break;
                    }
                    if (trimmed[end] == '\\' && end + 1U < trimmed.size()) {
                        end += 2U;
                        continue;
                    }
                    ++end;
                }
                if (end >= trimmed.size()) {
                    return std::nullopt;
                }
                return std::string{trimmed.substr(pos, end - pos)};
            }

            auto end = pos;
            while (end < trimmed.size()) {
                auto c = trimmed[end];
                if (c == '(' || std::isspace(static_cast<unsigned char>(c))) {
                    break;
                }
                ++end;
            }
            if (end == pos) {
                return std::nullopt;
            }
            return std::string{trimmed.substr(pos, end - pos)};
        }

        static bool is_ir_block_label(std::string_view line) {
            auto trimmed = trim_ascii(line);
            if (trimmed.empty() || trimmed.starts_with(';')) {
                return false;
            }
            if (!trimmed.ends_with(':')) {
                return false;
            }
            if (trimmed.find(' ') != std::string_view::npos || trimmed.find('\t') != std::string_view::npos) {
                return false;
            }
            return true;
        }

        static std::string parse_ir_block_id(std::string_view label_line) {
            auto token = trim_ascii(label_line);
            if (token.ends_with(':')) {
                token.remove_suffix(1U);
            }
            if (token.starts_with('%')) {
                token.remove_prefix(1U);
            }
            if (token.size() >= 2U && token.front() == '"' && token.back() == '"') {
                token.remove_prefix(1U);
                token.remove_suffix(1U);
            }
            return std::string{token};
        }

        static std::vector<std::string> extract_ir_label_targets(std::string_view line) {
            std::vector<std::string> targets{};
            size_t pos = 0U;
            while (true) {
                pos = line.find("label %"sv, pos);
                if (pos == std::string_view::npos) {
                    break;
                }
                pos += std::string_view{"label %"sv}.size();
                if (pos >= line.size()) {
                    break;
                }

                if (line[pos] == '"') {
                    ++pos;
                    auto start = pos;
                    while (pos < line.size() && line[pos] != '"') {
                        if (line[pos] == '\\' && pos + 1U < line.size()) {
                            pos += 2U;
                            continue;
                        }
                        ++pos;
                    }
                    if (pos > start) {
                        append_unique(targets, std::string{line.substr(start, pos - start)});
                    }
                    if (pos < line.size()) {
                        ++pos;
                    }
                    continue;
                }

                auto start = pos;
                while (pos < line.size()) {
                    auto c = line[pos];
                    auto is_label_char =
                            std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '$' || c == '-';
                    if (!is_label_char) {
                        break;
                    }
                    ++pos;
                }
                if (pos > start) {
                    append_unique(targets, std::string{line.substr(start, pos - start)});
                }
            }
            return targets;
        }

        static void append_cfg_edge(std::vector<cfg_edge>& edges, cfg_edge edge) {
            for (const auto& existing : edges) {
                if (existing.from == edge.from && existing.to == edge.to && existing.label == edge.label) {
                    return;
                }
            }
            edges.push_back(std::move(edge));
        }

        static std::vector<cfg_edge> parse_cfg_edges_for_block(const cfg_block& block) {
            std::vector<cfg_edge> edges{};

            for (size_t i = 0U; i < block.instructions.size(); ++i) {
                auto instruction = trim_ascii(block.instructions[i]);
                if (instruction.empty() || instruction.starts_with(';')) {
                    continue;
                }

                if (instruction.starts_with("br i1 "sv)) {
                    auto targets = extract_ir_label_targets(instruction);
                    if (!targets.empty()) {
                        append_cfg_edge(edges, cfg_edge{.from = block.id, .to = targets[0], .label = "true"});
                    }
                    if (targets.size() > 1U) {
                        append_cfg_edge(edges, cfg_edge{.from = block.id, .to = targets[1], .label = "false"});
                    }
                    return edges;
                }

                if (instruction.starts_with("br "sv)) {
                    auto targets = extract_ir_label_targets(instruction);
                    for (const auto& target : targets) {
                        append_cfg_edge(edges, cfg_edge{.from = block.id, .to = target});
                    }
                    return edges;
                }

                if (instruction.starts_with("switch "sv)) {
                    std::string switch_text{instruction};
                    auto j = i + 1U;
                    for (; j < block.instructions.size(); ++j) {
                        switch_text.push_back('\n');
                        switch_text.append(block.instructions[j]);
                        if (block.instructions[j].find(']') != std::string::npos) {
                            break;
                        }
                    }
                    auto targets = extract_ir_label_targets(switch_text);
                    if (!targets.empty()) {
                        append_cfg_edge(edges, cfg_edge{.from = block.id, .to = targets[0], .label = "default"});
                        for (size_t k = 1U; k < targets.size(); ++k) {
                            append_cfg_edge(edges, cfg_edge{.from = block.id, .to = targets[k], .label = "case"});
                        }
                    }
                    return edges;
                }

                if (instruction.starts_with("invoke "sv)) {
                    auto targets = extract_ir_label_targets(instruction);
                    if (!targets.empty()) {
                        append_cfg_edge(edges, cfg_edge{.from = block.id, .to = targets[0], .label = "normal"});
                    }
                    if (targets.size() > 1U) {
                        append_cfg_edge(edges, cfg_edge{.from = block.id, .to = targets[1], .label = "unwind"});
                    }
                    return edges;
                }

                if (instruction.starts_with("indirectbr "sv) || instruction.starts_with("callbr "sv)) {
                    auto targets = extract_ir_label_targets(instruction);
                    for (const auto& target : targets) {
                        append_cfg_edge(edges, cfg_edge{.from = block.id, .to = target});
                    }
                    return edges;
                }

                if (instruction.starts_with("ret "sv) || instruction.starts_with("resume "sv) ||
                    instruction.starts_with("unreachable"sv) || instruction.starts_with("catchret "sv) ||
                    instruction.starts_with("cleanupret "sv)) {
                    append_cfg_edge(edges, cfg_edge{.from = block.id, .to = std::string{cfg_pseudo_exit}});
                    return edges;
                }
            }

            return edges;
        }

        static std::optional<cfg_graph> parse_cfg_graph_from_ir(
                std::string_view ir_text, std::string_view function_name) {
            auto lines = split_lines(ir_text);

            bool found_function = false;
            auto graph = cfg_graph{};
            auto current = cfg_block{.id = "entry"};

            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);

                if (!found_function) {
                    if (!trimmed.starts_with("define "sv)) {
                        continue;
                    }
                    auto name = parse_ir_function_name(trimmed);
                    if (!name || *name != function_name) {
                        continue;
                    }
                    graph.function_name = *name;
                    found_function = true;
                    continue;
                }

                if (trimmed.empty() || trimmed == "{"sv || trimmed.starts_with(';')) {
                    continue;
                }
                if (trimmed == "}"sv) {
                    break;
                }

                if (is_ir_block_label(trimmed)) {
                    if (!current.instructions.empty() || current.id == "entry"sv || graph.blocks.empty()) {
                        graph.blocks.push_back(std::move(current));
                    }
                    current = cfg_block{.id = parse_ir_block_id(trimmed)};
                    continue;
                }

                current.instructions.emplace_back(trimmed);
            }

            if (!found_function) {
                return std::nullopt;
            }

            if (!current.instructions.empty() || current.id == "entry"sv || graph.blocks.empty()) {
                graph.blocks.push_back(std::move(current));
            }

            if (graph.blocks.size() > 1U && graph.blocks.front().id == "entry"sv &&
                graph.blocks.front().instructions.empty()) {
                graph.blocks.erase(graph.blocks.begin());
            }
            if (graph.blocks.empty()) {
                graph.blocks.push_back(cfg_block{.id = "entry"});
            }

            for (const auto& block : graph.blocks) {
                auto block_edges = parse_cfg_edges_for_block(block);
                for (auto& edge : block_edges) {
                    append_cfg_edge(graph.edges, std::move(edge));
                }
            }
            if (!graph.blocks.empty()) {
                append_cfg_edge(
                        graph.edges, cfg_edge{.from = std::string{cfg_pseudo_entry}, .to = graph.blocks.front().id});
            }

            return graph;
        }

        static std::optional<call_graph> parse_call_graph_from_ir(
                std::string_view ir_text, std::string_view root_name, const symbol_display_map* display_names) {
            auto lines = split_lines(ir_text);

            std::unordered_map<std::string, std::vector<std::string>> adjacency{};
            std::unordered_set<std::string> defined{};
            std::vector<std::string> function_order{};

            bool in_function = false;
            int brace_depth = 0;
            std::string current_function{};

            for (const auto& line : lines) {
                auto trimmed = trim_ascii(line);

                if (!in_function) {
                    if (!trimmed.starts_with("define "sv)) {
                        continue;
                    }
                    auto name = parse_ir_function_name(trimmed);
                    if (!name) {
                        continue;
                    }

                    current_function = *name;
                    in_function = true;
                    brace_depth = 0;
                    adjacency.try_emplace(current_function);
                    if (defined.insert(current_function).second) {
                        function_order.push_back(current_function);
                    }

                    for (auto c : trimmed) {
                        if (c == '{') {
                            ++brace_depth;
                        }
                        else if (c == '}') {
                            --brace_depth;
                        }
                    }
                    if (brace_depth <= 0) {
                        in_function = false;
                        current_function.clear();
                    }
                    continue;
                }

                if (auto callee = parse_ir_called_function_name(trimmed)) {
                    append_unique(adjacency[current_function], *callee);
                }

                for (auto c : trimmed) {
                    if (c == '{') {
                        ++brace_depth;
                    }
                    else if (c == '}') {
                        --brace_depth;
                    }
                }
                if (brace_depth <= 0) {
                    in_function = false;
                    current_function.clear();
                }
            }

            if (function_order.empty()) {
                return std::nullopt;
            }

            std::string root{};
            if (!root_name.empty()) {
                root = std::string{root_name};
                if (!defined.contains(root)) {
                    return std::nullopt;
                }
            }
            else {
                root = function_order.front();
            }

            call_graph graph{};
            graph.root_function = root;
            graph.root_display_name = resolve_display_name(root, display_names);

            std::unordered_set<std::string> node_seen{};
            auto append_node = [&](std::string_view name) {
                auto node_name = std::string{name};
                if (!node_seen.insert(node_name).second) {
                    return;
                }
                graph.nodes.push_back(
                        call_node{
                                .name = std::move(node_name),
                                .display_name = resolve_display_name(name, display_names),
                                .is_defined = defined.contains(std::string{name})});
            };

            std::unordered_set<std::string> scheduled{};
            std::vector<std::string> worklist{};
            worklist.push_back(root);
            scheduled.insert(root);

            std::unordered_set<std::string> edge_seen{};
            for (size_t i = 0U; i < worklist.size(); ++i) {
                auto caller = worklist[i];
                append_node(caller);

                auto it = adjacency.find(caller);
                if (it == adjacency.end()) {
                    continue;
                }

                for (const auto& callee : it->second) {
                    append_node(callee);

                    auto edge_key = "{}\n{}"_format(caller, callee);
                    if (edge_seen.insert(edge_key).second) {
                        graph.edges.push_back(call_edge{.from = caller, .to = callee});
                    }

                    if (defined.contains(callee) && !scheduled.contains(callee)) {
                        scheduled.insert(callee);
                        worklist.push_back(callee);
                    }
                }
            }

            return graph;
        }

        static void append_dot_escaped(std::string& out, std::string_view text) {
            for (auto c : text) {
                if (c == '\r' || c == '\n') {
                    continue;
                }
                if (c == '\\' || c == '"') {
                    out.push_back('\\');
                }
                out.push_back(c);
            }
        }

        static std::string sanitize_dot_identifier(std::string_view value) {
            std::string ret{};
            ret.reserve(value.size() + 4U);
            for (auto c : value) {
                auto ok = std::isalnum(static_cast<unsigned char>(c)) || c == '_';
                ret.push_back(ok ? c : '_');
            }
            if (ret.empty()) {
                return "graph";
            }
            if (std::isdigit(static_cast<unsigned char>(ret.front()))) {
                ret.insert(ret.begin(), '_');
            }
            return ret;
        }

        static std::string make_dot_block_label(const cfg_block& block) {
            std::string label{};
            append_dot_escaped(label, block.id);
            label.append("\\l");

            size_t max_lines = 12U;
            size_t shown = 0U;
            for (const auto& instruction : block.instructions) {
                if (shown >= max_lines) {
                    break;
                }
                append_dot_escaped(label, instruction);
                label.append("\\l");
                ++shown;
            }
            if (block.instructions.size() > shown) {
                label.append("...\\l");
            }
            return label;
        }

        static std::string render_cfg_graph_dot(const cfg_graph& graph) {
            std::ostringstream dot{};
            dot << "digraph cfg_" << sanitize_dot_identifier(graph.function_name) << " {\n";
            dot << "  rankdir=TB;\n";
            dot << "  node [shape=box,fontname=\"monospace\"];\n";

            std::unordered_map<std::string, std::string> node_ids{};
            for (size_t i = 0U; i < graph.blocks.size(); ++i) {
                auto node_id = "n{}"_format(i);
                node_ids.emplace(graph.blocks[i].id, node_id);
                dot << "  " << node_id << " [label=\"" << make_dot_block_label(graph.blocks[i]) << "\"];\n";
            }

            std::unordered_map<std::string, std::string> external_nodes{};
            size_t external_count = 0U;

            auto resolve_node = [&](std::string_view name) {
                if (auto it = node_ids.find(std::string{name}); it != node_ids.end()) {
                    return it->second;
                }
                if (auto it = external_nodes.find(std::string{name}); it != external_nodes.end()) {
                    return it->second;
                }

                auto ext_id = "x{}"_format(external_count++);
                external_nodes.emplace(std::string{name}, ext_id);
                if (name == cfg_pseudo_entry || name == cfg_pseudo_exit) {
                    std::string label{};
                    append_dot_escaped(label, name == cfg_pseudo_entry ? "entry"sv : "exit"sv);
                    label.append("\\l");
                    dot << "  " << ext_id << " [label=\"" << label
                        << "\",shape=oval,style=filled,fillcolor=\"#f5f5f5\"];\n";
                }
                else {
                    std::string label{};
                    append_dot_escaped(label, name);
                    label.append("\\l");
                    dot << "  " << ext_id << " [label=\"" << label << "\",style=dashed];\n";
                }
                return ext_id;
            };

            for (const auto& edge : graph.edges) {
                auto from_node = resolve_node(edge.from);
                auto to_node = resolve_node(edge.to);

                dot << "  " << from_node << " -> " << to_node;
                if (!edge.label.empty()) {
                    std::string escaped{};
                    append_dot_escaped(escaped, edge.label);
                    dot << " [label=\"" << escaped << "\"]";
                }
                dot << ";\n";
            }

            dot << "}\n";
            return dot.str();
        }

        static std::string render_call_graph_dot(const call_graph& graph) {
            std::ostringstream dot{};
            dot << "digraph call_" << sanitize_dot_identifier(graph.root_function) << " {\n";
            dot << "  rankdir=TB;\n";
            dot << "  node [shape=box,fontname=\"monospace\"];\n";

            std::unordered_map<std::string, std::string> node_ids{};
            for (size_t i = 0U; i < graph.nodes.size(); ++i) {
                auto node_id = "n{}"_format(i);
                node_ids.emplace(graph.nodes[i].name, node_id);

                std::string label{};
                append_dot_escaped(label, graph.nodes[i].display_name);

                std::string style{};
                if (!graph.nodes[i].is_defined) {
                    style.append("dashed");
                }
                if (graph.nodes[i].name == graph.root_function) {
                    if (!style.empty()) {
                        style.push_back(',');
                    }
                    style.append("bold,filled");
                }

                dot << "  " << node_id << " [label=\"" << label << "\"";
                if (!style.empty()) {
                    dot << ",style=\"" << style << "\"";
                }
                if (graph.nodes[i].name == graph.root_function) {
                    dot << ",fillcolor=\"#f5f5f5\"";
                }
                dot << "];\n";
            }

            for (const auto& edge : graph.edges) {
                auto from = node_ids.find(edge.from);
                auto to = node_ids.find(edge.to);
                if (from == node_ids.end() || to == node_ids.end()) {
                    continue;
                }
                dot << "  " << from->second << " -> " << to->second << ";\n";
            }

            dot << "}\n";
            return dot.str();
        }

    }  // namespace detail

    std::optional<std::string> find_first_ir_function_name(std::string_view ir_text) {
        return detail::find_first_ir_function_name_impl(ir_text);
    }

    std::optional<cfg_graph_artifact> build_cfg_graph_artifact(
            std::string_view ir_text, std::string_view function_name) {
        auto parsed = detail::parse_cfg_graph_from_ir(ir_text, function_name);
        if (!parsed) {
            return std::nullopt;
        }
        return cfg_graph_artifact{
                .function_name = parsed->function_name,
                .block_count = parsed->blocks.size(),
                .edge_count = parsed->edges.size(),
                .dot_text = detail::render_cfg_graph_dot(*parsed)};
    }

    std::optional<call_graph_artifact> build_call_graph_artifact(
            std::string_view ir_text, std::string_view root_function, const symbol_display_map* display_names) {
        auto parsed = detail::parse_call_graph_from_ir(ir_text, root_function, display_names);
        if (!parsed) {
            return std::nullopt;
        }
        return call_graph_artifact{
                .root_function = parsed->root_function,
                .root_display_name = parsed->root_display_name,
                .node_count = parsed->nodes.size(),
                .edge_count = parsed->edges.size(),
                .dot_text = detail::render_call_graph_dot(*parsed)};
    }

}  // namespace sontag::graph
