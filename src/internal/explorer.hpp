#pragma once

#include "sontag/format.hpp"
#include "sontag/utils.hpp"

extern "C" {
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
}

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace sontag::internal::explorer {

    using namespace std::string_view_literals;
    using namespace sontag::literals;

    struct asm_row {
        std::string offset{};
        std::string encodings{};
        std::string instruction{};
    };

    struct instruction_info {
        std::string uops{};
        std::string latency{};
        std::string rthroughput{};
        bool may_load{false};
        bool may_store{false};
        bool has_side_effects{false};
        std::string encoding_size{};
        std::string instruction{};
    };

    struct resource_pressure_table {
        std::vector<std::string> resources{};
        std::vector<std::vector<std::string>> row_values{};
    };

    struct model {
        std::string_view mode_label{"asm"};
        std::string symbol_display{};
        size_t operations_total{};
        std::vector<std::pair<std::string, size_t>> opcode_counts{};
        std::vector<asm_row> rows{};
        std::vector<std::string> table_extra_headers{};
        std::vector<std::vector<std::string>> table_extra_values{};
        std::vector<instruction_info> row_info{};
        resource_pressure_table resource_pressure{};
        std::vector<std::string> instruction_definitions{};
        std::vector<std::string> ir_source_lines{};
        std::vector<std::vector<std::string>> row_detail_lines{};
        std::string_view selected_line_color{};
        std::string_view selected_definition_color{};
        std::string_view call_target_color{};
        size_t initial_cursor{};
    };

    struct graph_node {
        std::string id{};
        std::string short_label{};
        std::string full_label{};
        size_t outgoing_count{};
        size_t incoming_count{};
    };

    struct graph_edge {
        size_t from{};
        size_t to{};
        std::string label{};
    };

    struct graph_model {
        std::string kind_label{};
        std::string title{};
        std::vector<graph_node> nodes{};
        std::vector<graph_edge> edges{};
        std::vector<std::vector<size_t>> outgoing_edges{};
        std::vector<std::vector<size_t>> incoming_edges{};
        std::string_view selected_line_color{};
        std::string_view selected_detail_color{};
        std::string_view unchanged_line_color{};
        std::string_view removed_line_color{};
        size_t initial_cursor{};
    };

    enum class launch_status : uint8_t { completed, fallback };

    struct launch_result {
        launch_status status{launch_status::completed};
        std::string message{};
        std::optional<std::string> next_symbol{};
        size_t selected_row{};
    };

    struct graph_launch_result {
        launch_status status{launch_status::completed};
        std::string message{};
        size_t selected_node{};
    };

    namespace detail {
        static constexpr size_t default_rows{48};
        static constexpr size_t default_cols{120};

        struct terminal_dims {
            size_t rows{default_rows};
            size_t cols{default_cols};
        };

        static terminal_dims query_terminal_dims() {
            auto ws = winsize{};
            if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 || ws.ws_row == 0U || ws.ws_col == 0U) {
                return {};
            }
            return terminal_dims{.rows = ws.ws_row, .cols = ws.ws_col};
        }

        static std::string clip_to_width(std::string_view text, size_t width) {
            if (width == 0U) {
                return {};
            }

            auto out = std::string{};
            out.reserve(text.size());
            auto visible_count = size_t{0U};
            auto truncated = false;

            auto i = size_t{0U};
            while (i < text.size()) {
                auto c = text[i];
                if (c == '\x1b' && i + 1U < text.size() && text[i + 1U] == '[') {
                    auto j = i + 2U;
                    while (j < text.size()) {
                        auto terminator = static_cast<unsigned char>(text[j]);
                        if (terminator >= 0x40U && terminator <= 0x7eU) {
                            ++j;
                            break;
                        }
                        ++j;
                    }
                    out.append(text.substr(i, j - i));
                    i = j;
                    continue;
                }

                if (visible_count >= width) {
                    truncated = true;
                    break;
                }
                out.push_back(c);
                ++visible_count;
                ++i;
            }

            if (truncated) {
                out.append("\x1b[0m");
            }
            return out;
        }

        static std::string pad_cell(std::string_view text, size_t width) {
            auto value = std::string{text};
            if (value.size() < width) {
                value.append(width - value.size(), ' ');
            }
            return value;
        }

        static std::optional<char> read_byte_with_timeout(int fd, int timeout_ms) {
            auto pfd = pollfd{.fd = fd, .events = POLLIN, .revents = 0};
            auto rc = poll(&pfd, 1U, timeout_ms);
            if (rc <= 0 || (pfd.revents & POLLIN) == 0) {
                return std::nullopt;
            }
            char c{};
            auto n = read(fd, &c, 1U);
            if (n != 1) {
                return std::nullopt;
            }
            return c;
        }

        enum class key_event : uint8_t {
            none,
            up,
            down,
            enter,
            quit,
        };

        static key_event read_key_event(int fd) {
            auto read_blocking_byte = [&](int timeout_ms) -> std::optional<char> {
                while (true) {
                    auto pfd = pollfd{.fd = fd, .events = POLLIN, .revents = 0};
                    auto rc = poll(&pfd, 1U, timeout_ms);
                    if (rc < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        return std::nullopt;
                    }
                    if (rc == 0) {
                        return std::nullopt;
                    }
                    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                        return std::nullopt;
                    }
                    if ((pfd.revents & POLLIN) == 0) {
                        continue;
                    }

                    char c{};
                    auto n = read(fd, &c, 1U);
                    if (n == 1) {
                        return c;
                    }
                    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                        continue;
                    }
                    return std::nullopt;
                }
            };

            auto c = read_blocking_byte(-1);
            if (!c) {
                return key_event::quit;
            }

            switch (*c) {
                case 'q':
                    return key_event::quit;
                case 'k':
                    return key_event::up;
                case 'j':
                    return key_event::down;
                case '\r':
                case '\n':
                    return key_event::enter;
                case 27:
                {
                    auto second = read_blocking_byte(20);
                    if (!second) {
                        return key_event::quit;
                    }
                    if (*second != '[') {
                        return key_event::quit;
                    }
                    auto third = read_blocking_byte(20);
                    if (!third) {
                        return key_event::none;
                    }
                    switch (*third) {
                        case 'A':
                            return key_event::up;
                        case 'B':
                            return key_event::down;
                        default:
                            return key_event::none;
                    }
                }
                default:
                    return key_event::none;
            }
        }

        class raw_terminal_guard {
          public:
            explicit raw_terminal_guard(int fd) : fd_value(fd) {}

            raw_terminal_guard(const raw_terminal_guard&) = delete;
            raw_terminal_guard& operator=(const raw_terminal_guard&) = delete;

            ~raw_terminal_guard() { (void)restore(); }

            bool activate(std::string& error) {
                if (tcgetattr(fd_value, &original) != 0) {
                    error = "failed to read terminal attributes: {}"_format(std::strerror(errno));
                    return false;
                }

                auto raw = original;
                raw.c_iflag &= static_cast<tcflag_t>(~(IXON | ICRNL));
                raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON));
                raw.c_cc[VMIN] = 1;
                raw.c_cc[VTIME] = 0;

                if (tcsetattr(fd_value, TCSAFLUSH, &raw) != 0) {
                    error = "failed to set terminal raw mode: {}"_format(std::strerror(errno));
                    return false;
                }
                active = true;
                return true;
            }

            bool restore() {
                if (!active) {
                    return true;
                }
                active = false;
                return tcsetattr(fd_value, TCSAFLUSH, &original) == 0;
            }

          private:
            int fd_value{};
            bool active{false};
            termios original{};
        };

        class screen_guard {
          public:
            explicit screen_guard(int fd) : fd_value(fd) {}

            screen_guard(const screen_guard&) = delete;
            screen_guard& operator=(const screen_guard&) = delete;

            ~screen_guard() { (void)leave(); }

            void enter() {
                if (active) {
                    return;
                }
                write_literal("\x1b[?1049h\x1b[?25l");
                active = true;
            }

            bool leave() {
                if (!active) {
                    return true;
                }
                active = false;
                return write_literal("\x1b[?25h\x1b[?1049l");
            }

          private:
            bool write_literal(std::string_view value) const {
                auto n = write(fd_value, value.data(), value.size());
                return n == static_cast<ssize_t>(value.size());
            }

            int fd_value{};
            bool active{false};
        };

        static size_t calculate_rows_visible(size_t total_rows, size_t opcode_rows, bool has_resource_pressure) {
            // Fixed rows:
            // 3 (title/symbol/operations) + 2 (opcode header) + opcode rows +
            // 1 (blank before pressure) + pressure section +
            // 1 (blank before assembly) + 3 (assembly heading/header/separator) +
            // 1 (controls) + 1 (blank before info) +
            // 3 (info heading/header/separator) + 7 (info body)
            //
            // pressure section:
            // - with data: 4 rows (heading/header/separator/values)
            // - no data:  2 rows (heading/"unavailable")
            auto fixed_rows = (has_resource_pressure ? 26U : 24U) + opcode_rows;
            if (total_rows <= fixed_rows) {
                return 1U;
            }
            return total_rows - fixed_rows;
        }

        static std::string format_offset(std::string_view value) {
            if (value.empty()) {
                return {};
            }
            if (value.starts_with("0x"sv) || value.starts_with("0X"sv)) {
                return std::string{value};
            }
            return "0x{}"_format(value);
        }

        static std::pair<std::string_view, std::string_view> split_instruction_parts(std::string_view instruction) {
            auto trimmed = instruction;
            while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t')) {
                trimmed.remove_prefix(1U);
            }
            while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t')) {
                trimmed.remove_suffix(1U);
            }
            if (trimmed.empty()) {
                return {};
            }

            auto end = size_t{0U};
            while (end < trimmed.size() && trimmed[end] != ' ' && trimmed[end] != '\t') {
                ++end;
            }

            auto mnemonic = trimmed.substr(0U, end);
            auto operands = end < trimmed.size() ? trimmed.substr(end) : std::string_view{};
            while (!operands.empty() && (operands.front() == ' ' || operands.front() == '\t')) {
                operands.remove_prefix(1U);
            }
            return {mnemonic, operands};
        }

        static bool ascii_iequals(std::string_view lhs, std::string_view rhs) {
            if (lhs.size() != rhs.size()) {
                return false;
            }
            for (size_t i = 0U; i < lhs.size(); ++i) {
                if (utils::char_tolower(lhs[i]) != utils::char_tolower(rhs[i])) {
                    return false;
                }
            }
            return true;
        }

        static bool is_call_like_mnemonic(std::string_view mnemonic) {
            return ascii_iequals(mnemonic, "call"sv) || ascii_iequals(mnemonic, "bl"sv);
        }

        static std::optional<std::string_view> extract_call_target_symbol(std::string_view instruction) {
            auto [mnemonic, operands] = split_instruction_parts(instruction);
            if (!is_call_like_mnemonic(mnemonic) || operands.empty()) {
                return std::nullopt;
            }

            auto candidate = operands;
            while (!candidate.empty() && (candidate.front() == ' ' || candidate.front() == '\t')) {
                candidate.remove_prefix(1U);
            }
            while (!candidate.empty() &&
                   (candidate.back() == ' ' || candidate.back() == '\t' || candidate.back() == ',')) {
                candidate.remove_suffix(1U);
            }
            if (candidate.empty()) {
                return std::nullopt;
            }

            if (candidate.front() == '<' || candidate.front() == '*' || candidate.front() == '[' ||
                candidate[0] == '-') {
                return std::nullopt;
            }
            if (candidate.size() >= 2U && candidate[0] == '0' && (candidate[1] == 'x' || candidate[1] == 'X')) {
                return std::nullopt;
            }
            if (candidate.front() >= '0' && candidate.front() <= '9') {
                return std::nullopt;
            }
            if (candidate.find('[') != std::string_view::npos || candidate.find(']') != std::string_view::npos) {
                return std::nullopt;
            }

            return candidate;
        }

        static std::string format_aligned_instruction(std::string_view instruction, size_t mnemonic_width) {
            auto [mnemonic, operands] = split_instruction_parts(instruction);
            if (mnemonic.empty()) {
                return std::string{instruction};
            }

            std::string formatted{};
            formatted.reserve(
                    instruction.size() + (mnemonic_width > mnemonic.size() ? mnemonic_width - mnemonic.size() : 0U));
            formatted.append(mnemonic);
            if (mnemonic.size() < mnemonic_width) {
                formatted.append(mnemonic_width - mnemonic.size(), ' ');
            }
            if (!operands.empty()) {
                formatted.push_back(' ');
                formatted.append(operands);
            }
            return formatted;
        }

        static std::string colorize_instruction_mnemonic(
                std::string_view aligned_instruction,
                size_t mnemonic_length,
                size_t instruction_width,
                std::string_view mnemonic_color,
                std::optional<std::pair<size_t, size_t>> call_target_span,
                std::string_view call_target_color,
                std::string_view restore_color) {
            std::string out{};
            out.reserve(aligned_instruction.size() + instruction_width + 96U);

            auto append_colored = [&](std::string_view value, std::string_view color) {
                if (value.empty()) {
                    return;
                }
                if (color.empty()) {
                    out.append(value);
                    return;
                }
                out.append(color);
                out.append(value);
                out.append("\x1b[0m");
                if (!restore_color.empty()) {
                    out.append(restore_color);
                }
            };

            if (mnemonic_length == 0U || mnemonic_color.empty()) {
                out.append(aligned_instruction);
            }
            else {
                auto safe_mnemonic_len = std::min(mnemonic_length, aligned_instruction.size());
                append_colored(aligned_instruction.substr(0U, safe_mnemonic_len), mnemonic_color);

                auto tail = aligned_instruction.substr(safe_mnemonic_len);
                if (!call_target_span.has_value() || call_target_span->first < safe_mnemonic_len ||
                    call_target_span->first >= aligned_instruction.size()) {
                    out.append(tail);
                }
                else {
                    auto span_start = call_target_span->first;
                    auto span_len = call_target_span->second;
                    auto span_end = std::min(span_start + span_len, aligned_instruction.size());

                    if (span_start > safe_mnemonic_len) {
                        out.append(aligned_instruction.substr(safe_mnemonic_len, span_start - safe_mnemonic_len));
                    }
                    append_colored(aligned_instruction.substr(span_start, span_end - span_start), call_target_color);
                    if (span_end < aligned_instruction.size()) {
                        out.append(aligned_instruction.substr(span_end));
                    }
                }
            }

            if (aligned_instruction.size() < instruction_width) {
                out.append(instruction_width - aligned_instruction.size(), ' ');
            }
            return out;
        }

        static void clamp_viewport(size_t instruction_count, size_t rows_visible, size_t& cursor, size_t& top_row) {
            if (instruction_count == 0U) {
                cursor = 0U;
                top_row = 0U;
                return;
            }

            cursor = std::min(cursor, instruction_count - 1U);
            top_row = std::min(top_row, instruction_count - 1U);

            if (cursor < top_row) {
                top_row = cursor;
            }
            if (cursor >= top_row + rows_visible) {
                top_row = cursor - rows_visible + 1U;
            }

            auto max_top = instruction_count > rows_visible ? instruction_count - rows_visible : 0U;
            top_row = std::min(top_row, max_top);
        }

        static constexpr size_t graph_edge_preview_rows = 4U;

        struct text_span {
            size_t begin{};
            size_t end{};
        };

        struct colored_text_span {
            size_t begin{};
            size_t end{};
            std::string_view color{};
        };

        static constexpr bool spans_overlap(const text_span& lhs, const text_span& rhs) {
            return lhs.begin < rhs.end && rhs.begin < lhs.end;
        }

        static std::optional<std::string> extract_defuse_defined_value_token(std::string_view text) {
            auto trimmed = text;
            while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t')) {
                trimmed.remove_prefix(1U);
            }
            if (trimmed.empty() || trimmed.front() != '%') {
                return std::nullopt;
            }

            auto end = size_t{1U};
            while (end < trimmed.size()) {
                auto c = trimmed[end];
                auto is_token_char = std::isalnum(static_cast<unsigned char>(c)) || c == '_';
                if (!is_token_char) {
                    break;
                }
                ++end;
            }
            if (end <= 1U) {
                return std::nullopt;
            }

            auto suffix = trimmed.substr(end);
            while (!suffix.empty() && (suffix.front() == ' ' || suffix.front() == '\t')) {
                suffix.remove_prefix(1U);
            }
            if (suffix.empty() || suffix.front() != '=') {
                return std::nullopt;
            }

            return std::string{trimmed.substr(0U, end)};
        }

        static std::optional<text_span> find_defuse_opcode_span(std::string_view text) {
            auto start = size_t{0U};
            if (text.starts_with('%')) {
                auto eq = text.find(" = "sv);
                if (eq != std::string_view::npos) {
                    start = eq + 3U;
                }
            }

            while (start < text.size() && (text[start] == ' ' || text[start] == '\t')) {
                ++start;
            }
            if (start >= text.size()) {
                return std::nullopt;
            }

            auto end = start;
            while (end < text.size() && text[end] != ' ' && text[end] != '\t') {
                ++end;
            }
            if (end <= start) {
                return std::nullopt;
            }
            return text_span{.begin = start, .end = end};
        }

        static std::vector<text_span> find_defuse_symbol_spans(std::string_view text) {
            auto spans = std::vector<text_span>{};
            size_t i = 0U;
            while (i < text.size()) {
                if (text[i] != '@') {
                    ++i;
                    continue;
                }

                auto start = i;
                auto end = i + 1U;
                while (end < text.size()) {
                    auto c = text[end];
                    auto is_symbol_char =
                            std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == ':' || c == '$' || c == '.';
                    if (!is_symbol_char) {
                        break;
                    }
                    ++end;
                }

                if (end < text.size() && text[end] == '(') {
                    auto depth = size_t{0U};
                    while (end < text.size()) {
                        if (text[end] == '(') {
                            ++depth;
                        }
                        else if (text[end] == ')') {
                            if (depth > 0U) {
                                --depth;
                            }
                            if (depth == 0U) {
                                ++end;
                                break;
                            }
                        }
                        ++end;
                    }
                }

                if (end > start + 1U) {
                    spans.push_back(text_span{.begin = start, .end = end});
                    i = end;
                    continue;
                }
                ++i;
            }
            return spans;
        }

        static std::vector<colored_text_span> find_defuse_value_spans(
                std::string_view text, const std::unordered_map<std::string, std::string_view>& value_colors) {
            auto spans = std::vector<colored_text_span>{};
            if (value_colors.empty()) {
                return spans;
            }

            size_t i = 0U;
            while (i < text.size()) {
                if (text[i] != '%') {
                    ++i;
                    continue;
                }

                auto start = i;
                ++i;
                while (i < text.size()) {
                    auto c = text[i];
                    auto is_token_char = std::isalnum(static_cast<unsigned char>(c)) || c == '_';
                    if (!is_token_char) {
                        break;
                    }
                    ++i;
                }

                if (i <= start + 1U) {
                    continue;
                }

                auto token = std::string{text.substr(start, i - start)};
                if (auto it = value_colors.find(token); it != value_colors.end() && !it->second.empty()) {
                    spans.push_back(colored_text_span{.begin = start, .end = i, .color = it->second});
                }
            }
            return spans;
        }

        static std::string colorize_defuse_label(
                std::string_view text,
                std::string_view color,
                std::string_view restore_color = {},
                const std::unordered_map<std::string, std::string_view>* value_colors = nullptr) {
            if (text.empty()) {
                return std::string{text};
            }

            auto colored_spans = std::vector<colored_text_span>{};
            auto occupied = std::vector<text_span>{};

            auto add_colored_span = [&](colored_text_span span) {
                if (span.begin >= span.end || span.color.empty()) {
                    return;
                }
                auto raw_span = text_span{.begin = span.begin, .end = span.end};
                if (std::any_of(occupied.begin(), occupied.end(), [&](const text_span& existing) {
                        return spans_overlap(existing, raw_span);
                    })) {
                    return;
                }
                occupied.push_back(raw_span);
                colored_spans.push_back(span);
            };

            if (value_colors != nullptr) {
                for (const auto& span : find_defuse_value_spans(text, *value_colors)) {
                    add_colored_span(span);
                }
            }

            if (!color.empty()) {
                if (auto opcode = find_defuse_opcode_span(text); opcode.has_value()) {
                    add_colored_span(colored_text_span{.begin = opcode->begin, .end = opcode->end, .color = color});
                }
                for (const auto& span : find_defuse_symbol_spans(text)) {
                    add_colored_span(colored_text_span{.begin = span.begin, .end = span.end, .color = color});
                }
            }

            if (colored_spans.empty()) {
                return std::string{text};
            }

            std::sort(
                    colored_spans.begin(),
                    colored_spans.end(),
                    [](const colored_text_span& lhs, const colored_text_span& rhs) {
                        if (lhs.begin != rhs.begin) {
                            return lhs.begin < rhs.begin;
                        }
                        return lhs.end < rhs.end;
                    });

            std::string out{};
            out.reserve(text.size() + (colored_spans.size() * 16U));
            auto cursor = size_t{0U};
            for (const auto& span : colored_spans) {
                if (span.begin < cursor) {
                    continue;
                }
                if (cursor < span.begin) {
                    out.append(text.substr(cursor, span.begin - cursor));
                }
                out.append(span.color);
                out.append(text.substr(span.begin, span.end - span.begin));
                out.append("\x1b[0m");
                if (!restore_color.empty()) {
                    out.append(restore_color);
                }
                cursor = span.end;
            }
            if (cursor < text.size()) {
                out.append(text.substr(cursor));
            }
            return out;
        }

        static size_t calculate_graph_rows_visible(size_t total_rows) {
            // Fixed rows:
            // 5 (header/title/counts/blank) +
            // 3 (node heading/header/separator) +
            // 1 (blank before selected) +
            // 2 (selected heading + id) + 1 (selected label) +
            // 1 (blank before outgoing) +
            // 3 (outgoing heading/header/separator) + preview +
            // 1 (blank before incoming) +
            // 3 (incoming heading/header/separator) + preview +
            // 1 (controls)
            auto fixed_rows = 24U + (graph_edge_preview_rows * 2U);
            if (total_rows <= fixed_rows) {
                return 1U;
            }
            return total_rows - fixed_rows;
        }

        static size_t calculate_graph_rows_visible_table_only(size_t total_rows) {
            // Fixed rows:
            // 5 (header/title/counts/blank) +
            // 3 (node heading/header/separator) +
            // 1 (blank before layout) +
            // 1 (layout heading) +
            // 1 (controls)
            auto fixed_rows = 11U;
            if (total_rows <= fixed_rows) {
                return 1U;
            }
            return total_rows - fixed_rows;
        }

        static void clamp_graph_viewport(size_t node_count, size_t rows_visible, size_t& cursor, size_t& top_row) {
            if (node_count == 0U) {
                cursor = 0U;
                top_row = 0U;
                return;
            }

            cursor = std::min(cursor, node_count - 1U);
            top_row = std::min(top_row, node_count - 1U);

            if (cursor < top_row) {
                top_row = cursor;
            }
            if (cursor >= top_row + rows_visible) {
                top_row = cursor - rows_visible + 1U;
            }

            auto max_top = node_count > rows_visible ? node_count - rows_visible : 0U;
            top_row = std::min(top_row, max_top);
        }

        static std::string render_graph_frame(
                const graph_model& data,
                size_t cursor,
                size_t top_row,
                size_t rows_visible,
                size_t terminal_cols,
                bool clear_screen,
                bool show_controls,
                bool highlight_selection,
                bool show_edge_panels = true) {
            std::string frame{};
            frame.reserve(4096U);
            auto call_layout = data.kind_label == "call"sv;
            auto defuse_layout = data.kind_label == "defuse"sv || data.kind_label == "ir"sv;
            auto safe_cursor = data.nodes.empty() ? 0U : std::min(cursor, data.nodes.size() - 1U);

            auto append_line = [&](std::string_view line) {
                frame.append(line);
                frame.push_back('\n');
            };

            auto colorize_cell = [](std::string_view text, std::string_view color, std::string_view restore_color) {
                if (color.empty()) {
                    return std::string{text};
                }
                std::string out{};
                out.reserve(text.size() + color.size() + restore_color.size() + 8U);
                out.append(color);
                out.append(text);
                out.append("\x1b[0m");
                if (!restore_color.empty()) {
                    out.append(restore_color);
                }
                return out;
            };

            auto outgoing_neighbor = std::vector<bool>{};
            auto incoming_neighbor = std::vector<bool>{};
            if (defuse_layout && !data.nodes.empty()) {
                outgoing_neighbor.assign(data.nodes.size(), false);
                incoming_neighbor.assign(data.nodes.size(), false);

                if (safe_cursor < data.outgoing_edges.size()) {
                    for (auto edge_idx : data.outgoing_edges[safe_cursor]) {
                        if (edge_idx >= data.edges.size()) {
                            continue;
                        }
                        auto to = data.edges[edge_idx].to;
                        if (to < outgoing_neighbor.size()) {
                            outgoing_neighbor[to] = true;
                        }
                    }
                }
                if (safe_cursor < data.incoming_edges.size()) {
                    for (auto edge_idx : data.incoming_edges[safe_cursor]) {
                        if (edge_idx >= data.edges.size()) {
                            continue;
                        }
                        auto from = data.edges[edge_idx].from;
                        if (from < incoming_neighbor.size()) {
                            incoming_neighbor[from] = true;
                        }
                    }
                }
            }

            auto node_highlight_color = [&](size_t node_index) -> std::string_view {
                if (!defuse_layout || node_index >= data.nodes.size()) {
                    return {};
                }
                if (node_index < outgoing_neighbor.size() && outgoing_neighbor[node_index] &&
                    node_index < incoming_neighbor.size() && incoming_neighbor[node_index]) {
                    return data.selected_detail_color;
                }
                if (node_index < outgoing_neighbor.size() && outgoing_neighbor[node_index]) {
                    return data.unchanged_line_color;
                }
                if (node_index < incoming_neighbor.size() && incoming_neighbor[node_index]) {
                    return data.removed_line_color;
                }
                return {};
            };

            auto defuse_value_colors = std::unordered_map<std::string, std::string_view>{};
            if (defuse_layout) {
                for (size_t i = 0U; i < data.nodes.size(); ++i) {
                    auto color = node_highlight_color(i);
                    if (color.empty()) {
                        continue;
                    }
                    auto token = extract_defuse_defined_value_token(data.nodes[i].short_label);
                    if (!token.has_value()) {
                        continue;
                    }
                    defuse_value_colors.insert_or_assign(*token, color);
                }
                if (!data.selected_line_color.empty() && safe_cursor < data.nodes.size()) {
                    if (auto token = extract_defuse_defined_value_token(data.nodes[safe_cursor].short_label);
                        token.has_value()) {
                        auto selected_value_color = data.unchanged_line_color.empty() ? data.selected_line_color
                                                                                      : data.unchanged_line_color;
                        defuse_value_colors.insert_or_assign(*token, selected_value_color);
                    }
                }
            }

            if (clear_screen) {
                frame.append("\x1b[H\x1b[2J");
            }
            append_line("graph explorer:");
            append_line("type: {}"_format(data.kind_label));
            append_line("root: {}"_format(data.title));
            append_line("nodes: {} | edges: {}"_format(data.nodes.size(), data.edges.size()));
            append_line("");

            auto idx_width = std::string_view{"  idx"}.size();
            auto id_width = std::string_view{"id"}.size();
            auto out_width = std::string_view{"out"}.size();
            auto in_width = std::string_view{"in"}.size();
            auto label_width = std::string_view{"label"}.size();
            for (size_t i = 0U; i < data.nodes.size(); ++i) {
                idx_width = std::max(idx_width, "  [{}]"_format(i).size());
                id_width = std::max(id_width, data.nodes[i].id.size());
                out_width = std::max(out_width, "{}"_format(data.nodes[i].outgoing_count).size());
                in_width = std::max(in_width, "{}"_format(data.nodes[i].incoming_count).size());
                if (!call_layout) {
                    label_width = std::max(label_width, data.nodes[i].short_label.size());
                }
            }

            append_line("nodes:");
            if (call_layout) {
                append_line(
                        "{} | {} | {} | {}"_format(
                                pad_cell("  idx", idx_width),
                                pad_cell("id", id_width),
                                pad_cell("out", out_width),
                                pad_cell("in", in_width)));
                append_line(
                        "{}-+-{}-+-{}-+-{}"_format(
                                std::string(idx_width, '-'),
                                std::string(id_width, '-'),
                                std::string(out_width, '-'),
                                std::string(in_width, '-')));
            }
            else {
                if (defuse_layout) {
                    append_line(
                            "{} | {} | {} | {}"_format(
                                    pad_cell("id", id_width),
                                    pad_cell("out", out_width),
                                    pad_cell("in", in_width),
                                    pad_cell("label", label_width)));
                    append_line(
                            "{}-+-{}-+-{}-+-{}"_format(
                                    std::string(id_width, '-'),
                                    std::string(out_width, '-'),
                                    std::string(in_width, '-'),
                                    std::string(label_width, '-')));
                }
                else {
                    append_line(
                            "{} | {} | {} | {} | {}"_format(
                                    pad_cell("  idx", idx_width),
                                    pad_cell("id", id_width),
                                    pad_cell("out", out_width),
                                    pad_cell("in", in_width),
                                    pad_cell("label", label_width)));
                    append_line(
                            "{}-+-{}-+-{}-+-{}-+-{}"_format(
                                    std::string(idx_width, '-'),
                                    std::string(id_width, '-'),
                                    std::string(out_width, '-'),
                                    std::string(in_width, '-'),
                                    std::string(label_width, '-')));
                }
            }

            if (data.nodes.empty()) {
                if (call_layout) {
                    append_line(
                            "{} | {} | {} | {}"_format(
                                    pad_cell("  <none>", idx_width),
                                    pad_cell("", id_width),
                                    pad_cell("", out_width),
                                    pad_cell("", in_width)));
                }
                else {
                    if (defuse_layout) {
                        append_line(
                                "{} | {} | {} | {}"_format(
                                        pad_cell("<none>", id_width),
                                        pad_cell("", out_width),
                                        pad_cell("", in_width),
                                        pad_cell("", label_width)));
                    }
                    else {
                        append_line(
                                "{} | {} | {} | {} | {}"_format(
                                        pad_cell("  <none>", idx_width),
                                        pad_cell("", id_width),
                                        pad_cell("", out_width),
                                        pad_cell("", in_width),
                                        pad_cell("", label_width)));
                    }
                }
            }
            else {
                auto start = std::min(top_row, data.nodes.size() - 1U);
                auto end = std::min(data.nodes.size(), start + rows_visible);
                for (size_t i = start; i < end; ++i) {
                    auto row = std::string{};
                    if (call_layout) {
                        row = "{} | {} | {} | {}"_format(
                                pad_cell("  [{}]"_format(i), idx_width),
                                pad_cell(data.nodes[i].id, id_width),
                                pad_cell("{}"_format(data.nodes[i].outgoing_count), out_width),
                                pad_cell("{}"_format(data.nodes[i].incoming_count), in_width));
                    }
                    else if (defuse_layout) {
                        auto label = colorize_defuse_label(
                                data.nodes[i].short_label,
                                data.selected_detail_color,
                                i == cursor ? data.selected_line_color : std::string_view{},
                                &defuse_value_colors);
                        auto id_cell = pad_cell(data.nodes[i].id, id_width);
                        auto id_highlight = node_highlight_color(i);
                        if (!id_highlight.empty()) {
                            id_cell =
                                    colorize_cell(id_cell, id_highlight, i == cursor ? data.selected_line_color : ""sv);
                        }
                        row = "{} | {} | {} | {}"_format(
                                id_cell,
                                pad_cell("{}"_format(data.nodes[i].outgoing_count), out_width),
                                pad_cell("{}"_format(data.nodes[i].incoming_count), in_width),
                                label);
                    }
                    else {
                        row = "{} | {} | {} | {} | {}"_format(
                                pad_cell("  [{}]"_format(i), idx_width),
                                pad_cell(data.nodes[i].id, id_width),
                                pad_cell("{}"_format(data.nodes[i].outgoing_count), out_width),
                                pad_cell("{}"_format(data.nodes[i].incoming_count), in_width),
                                pad_cell(data.nodes[i].short_label, label_width));
                    }
                    if (i == cursor && highlight_selection) {
                        if (data.selected_line_color.empty()) {
                            frame.append("\x1b[7m");
                        }
                        else {
                            frame.append(data.selected_line_color);
                        }
                        frame.append(clip_to_width(row, terminal_cols));
                        frame.append("\x1b[0m\n");
                    }
                    else {
                        append_line(row);
                    }
                }
            }

            if (show_edge_panels) {
                auto selected_node = data.nodes.empty() ? graph_node{} : data.nodes[safe_cursor];

                append_line("");
                append_line("selected node:");
                if (call_layout && !data.selected_detail_color.empty()) {
                    frame.append("  id: ");
                    frame.append(data.selected_detail_color);
                    frame.append(clip_to_width(selected_node.id, terminal_cols > 6U ? terminal_cols - 6U : 0U));
                    frame.append("\x1b[0m\n");
                }
                else {
                    append_line("  id: {}"_format(selected_node.id));
                }

                if (!call_layout) {
                    if (data.selected_detail_color.empty() || selected_node.full_label.empty()) {
                        append_line("  label: {}"_format(selected_node.full_label));
                    }
                    else {
                        if (defuse_layout) {
                            frame.append("  label: ");
                            auto colored = colorize_defuse_label(
                                    selected_node.full_label, data.selected_detail_color, {}, &defuse_value_colors);
                            frame.append(clip_to_width(colored, terminal_cols > 9U ? terminal_cols - 9U : 0U));
                            frame.append("\n");
                        }
                        else {
                            frame.append("  label: ");
                            frame.append(data.selected_detail_color);
                            frame.append(clip_to_width(
                                    selected_node.full_label, terminal_cols > 9U ? terminal_cols - 9U : 0U));
                            frame.append("\x1b[0m\n");
                        }
                    }
                }

                auto render_edge_table = [&](std::string_view title,
                                             const std::vector<size_t>* edge_indexes,
                                             bool outgoing) {
                    auto idx_w = std::string_view{"  idx"}.size();
                    auto endpoint_w = std::string_view{outgoing ? "to" : "from"}.size();
                    auto label_w = std::string_view{"label"}.size();

                    if (edge_indexes != nullptr) {
                        for (size_t row = 0U; row < edge_indexes->size(); ++row) {
                            idx_w = std::max(idx_w, "  [{}]"_format(row).size());
                            auto edge_idx = (*edge_indexes)[row];
                            if (edge_idx >= data.edges.size()) {
                                continue;
                            }
                            auto endpoint = outgoing ? data.edges[edge_idx].to : data.edges[edge_idx].from;
                            if (endpoint < data.nodes.size()) {
                                endpoint_w = std::max(endpoint_w, data.nodes[endpoint].id.size());
                            }
                            if (!call_layout) {
                                label_w = std::max(label_w, data.edges[edge_idx].label.size());
                            }
                        }
                    }

                    append_line("");
                    append_line("{}:"_format(title));
                    if (call_layout) {
                        append_line(
                                "{} | {}"_format(
                                        pad_cell("  idx", idx_w), pad_cell(outgoing ? "to"sv : "from"sv, endpoint_w)));
                        append_line("{}-+-{}"_format(std::string(idx_w, '-'), std::string(endpoint_w, '-')));
                    }
                    else {
                        append_line(
                                "{} | {} | {}"_format(
                                        pad_cell("  idx", idx_w),
                                        pad_cell(outgoing ? "to"sv : "from"sv, endpoint_w),
                                        pad_cell("label", label_w)));
                        append_line(
                                "{}-+-{}-+-{}"_format(
                                        std::string(idx_w, '-'),
                                        std::string(endpoint_w, '-'),
                                        std::string(label_w, '-')));
                    }

                    for (size_t row = 0U; row < graph_edge_preview_rows; ++row) {
                        if (edge_indexes == nullptr || row >= edge_indexes->size()) {
                            if (call_layout) {
                                append_line("{} | {}"_format(pad_cell("  -", idx_w), pad_cell("", endpoint_w)));
                            }
                            else {
                                append_line(
                                        "{} | {} | {}"_format(
                                                pad_cell("  -", idx_w),
                                                pad_cell("", endpoint_w),
                                                pad_cell("", label_w)));
                            }
                            continue;
                        }

                        auto edge_idx = (*edge_indexes)[row];
                        if (edge_idx >= data.edges.size()) {
                            if (call_layout) {
                                append_line("{} | {}"_format(pad_cell("  -", idx_w), pad_cell("?", endpoint_w)));
                            }
                            else {
                                append_line(
                                        "{} | {} | {}"_format(
                                                pad_cell("  -", idx_w),
                                                pad_cell("?", endpoint_w),
                                                pad_cell("", label_w)));
                            }
                            continue;
                        }

                        auto endpoint = outgoing ? data.edges[edge_idx].to : data.edges[edge_idx].from;
                        auto endpoint_name = endpoint < data.nodes.size() ? std::string_view{data.nodes[endpoint].id}
                                                                          : std::string_view{"?"};
                        if (call_layout) {
                            append_line(
                                    "{} | {}"_format(
                                            pad_cell("  [{}]"_format(row), idx_w),
                                            pad_cell(endpoint_name, endpoint_w)));
                        }
                        else {
                            auto endpoint_cell = pad_cell(endpoint_name, endpoint_w);
                            if (defuse_layout && endpoint < data.nodes.size()) {
                                auto endpoint_color = node_highlight_color(endpoint);
                                if (!endpoint_color.empty()) {
                                    endpoint_cell = colorize_cell(endpoint_cell, endpoint_color, {});
                                }
                            }
                            auto label_text = pad_cell(data.edges[edge_idx].label, label_w);
                            auto label_cell = label_text;
                            if (defuse_layout) {
                                label_cell = colorize_defuse_label(label_text, {}, {}, &defuse_value_colors);
                            }
                            append_line(
                                    "{} | {} | {}"_format(
                                            pad_cell("  [{}]"_format(row), idx_w), endpoint_cell, label_cell));
                        }
                    }
                };

                auto outgoing_edges =
                        safe_cursor < data.outgoing_edges.size() ? &data.outgoing_edges[safe_cursor] : nullptr;
                auto incoming_edges =
                        safe_cursor < data.incoming_edges.size() ? &data.incoming_edges[safe_cursor] : nullptr;
                render_edge_table("outgoing", outgoing_edges, true);
                render_edge_table("incoming", incoming_edges, false);
            }

            if (show_controls) {
                auto total = data.nodes.size();
                auto position = total == 0U ? 0U : safe_cursor + 1U;
                append_line("controls: up/down j/k q | {}/{}"_format(position, total));
            }
            return frame;
        }

        static std::string render_frame(
                const model& data, size_t cursor, size_t top_row, size_t rows_visible, size_t terminal_cols) {
            std::string frame{};
            frame.reserve(4096U);

            auto append_line = [&](std::string_view line) {
                frame.append(line);
                frame.push_back('\n');
            };

            frame.append("\x1b[H\x1b[2J");
            auto label = data.mode_label.empty() ? "asm"sv : data.mode_label;
            append_line("{} explorer:"_format(label));
            append_line("symbol: {}"_format(data.symbol_display));
            append_line("operations: {}"_format(data.operations_total));

            auto opcode_width = std::string_view{"  opcode"}.size();
            auto count_width = std::string_view{"count"}.size();
            for (const auto& [opcode, count] : data.opcode_counts) {
                opcode_width = std::max(opcode_width, opcode.size() + 2U);
                count_width = std::max(count_width, "{}"_format(count).size());
            }

            append_line("{} | {}"_format(pad_cell("  opcode", opcode_width), pad_cell("count", count_width)));
            append_line("{}-+-{}"_format(std::string(opcode_width, '-'), std::string(count_width, '-')));

            if (data.opcode_counts.empty()) {
                append_line("{} | {}"_format(pad_cell("  <none>", opcode_width), pad_cell("0", count_width)));
            }
            else {
                for (const auto& [opcode, count] : data.opcode_counts) {
                    append_line(
                            "{} | {}"_format(
                                    pad_cell("  {}"_format(opcode), opcode_width),
                                    pad_cell("{}"_format(count), count_width)));
                }
            }

            append_line("");
            append_line("resource pressure:");
            if (data.resource_pressure.resources.empty()) {
                append_line("  unavailable");
            }
            else {
                auto column_widths = std::vector<size_t>{};
                column_widths.reserve(data.resource_pressure.resources.size());
                for (size_t i = 0U; i < data.resource_pressure.resources.size(); ++i) {
                    auto width = data.resource_pressure.resources[i].size();
                    for (const auto& row_values : data.resource_pressure.row_values) {
                        auto value = i < row_values.size() ? std::string_view{row_values[i]} : "na"sv;
                        width = std::max(width, value.size());
                    }
                    column_widths.push_back(width);
                }

                std::string header_row{"  "};
                std::string separator_row{};
                std::string value_row{"  "};
                auto append_separator = [&separator_row](size_t width) {
                    if (!separator_row.empty()) {
                        separator_row.append("-+-");
                    }
                    separator_row.append(width, '-');
                };
                auto append_cell = [](std::string& row, std::string_view value, size_t width) {
                    if (row.size() > 2U) {
                        row.append(" | ");
                    }
                    row.append(pad_cell(value, width));
                };

                for (size_t i = 0U; i < data.resource_pressure.resources.size(); ++i) {
                    append_cell(header_row, data.resource_pressure.resources[i], column_widths[i]);
                    append_separator(column_widths[i]);
                    auto has_value = cursor < data.resource_pressure.row_values.size() &&
                                     i < data.resource_pressure.row_values[cursor].size();
                    auto value = has_value ? std::string_view{data.resource_pressure.row_values[cursor][i]} : "na"sv;
                    append_cell(value_row, value, column_widths[i]);
                }

                append_line(header_row);
                append_line("  {}"_format(separator_row));
                append_line(value_row);
            }

            auto line_width = std::string_view{"  line"}.size();
            auto offset_width = std::string_view{"offset"}.size();
            auto encoding_width = std::string_view{"encodings"}.size();
            auto instruction_width = std::string_view{"instruction"}.size();
            auto has_definitions = !data.instruction_definitions.empty();
            auto has_ir_source = !data.ir_source_lines.empty();
            auto definition_width = has_definitions ? std::string_view{"definition"}.size() : size_t{0U};
            auto ir_source_width = has_ir_source ? std::string_view{"ir source"}.size() : size_t{0U};
            auto extra_column_widths = std::vector<size_t>{};
            extra_column_widths.reserve(data.table_extra_headers.size());
            for (size_t i = 0U; i < data.table_extra_headers.size(); ++i) {
                auto width = data.table_extra_headers[i].size();
                for (const auto& row_values : data.table_extra_values) {
                    auto value = i < row_values.size() ? std::string_view{row_values[i]} : std::string_view{};
                    width = std::max(width, value.size());
                }
                extra_column_widths.push_back(width);
            }
            auto mnemonic_width = size_t{0U};
            for (size_t i = 0U; i < data.rows.size(); ++i) {
                auto [mnemonic, _] = split_instruction_parts(data.rows[i].instruction);
                mnemonic_width = std::max(mnemonic_width, mnemonic.size());
            }
            for (size_t i = 0U; i < data.rows.size(); ++i) {
                auto aligned_instruction = format_aligned_instruction(data.rows[i].instruction, mnemonic_width);
                line_width = std::max(line_width, "  [{}]"_format(i).size());
                offset_width = std::max(offset_width, format_offset(data.rows[i].offset).size());
                encoding_width = std::max(encoding_width, data.rows[i].encodings.size());
                instruction_width = std::max(instruction_width, aligned_instruction.size());
                if (has_definitions && i < data.instruction_definitions.size()) {
                    definition_width = std::max(definition_width, data.instruction_definitions[i].size());
                }
                if (has_ir_source && i < data.ir_source_lines.size()) {
                    ir_source_width = std::max(ir_source_width, data.ir_source_lines[i].size());
                }
            }

            append_line("");
            append_line("assembly:");
            auto header_row = "{} | {} | {} | {}"_format(
                    pad_cell("  line", line_width),
                    pad_cell("offset", offset_width),
                    pad_cell("encodings", encoding_width),
                    pad_cell("instruction", instruction_width));
            auto separator_row = "{}-+-{}-+-{}-+-{}"_format(
                    std::string(line_width, '-'),
                    std::string(offset_width, '-'),
                    std::string(encoding_width, '-'),
                    std::string(instruction_width, '-'));
            for (size_t i = 0U; i < data.table_extra_headers.size(); ++i) {
                header_row.append(" | ");
                header_row.append(pad_cell(data.table_extra_headers[i], extra_column_widths[i]));
                separator_row.append("-+-");
                separator_row.append(std::string(extra_column_widths[i], '-'));
            }
            if (has_definitions) {
                header_row.append(" | ");
                header_row.append(pad_cell("definition", definition_width));
                separator_row.append("-+-");
                separator_row.append(std::string(definition_width, '-'));
            }
            if (has_ir_source) {
                header_row.append(" | ");
                header_row.append(pad_cell("ir source", ir_source_width));
                separator_row.append("-+-");
                separator_row.append(std::string(ir_source_width, '-'));
            }

            append_line(header_row);
            append_line(separator_row);

            if (data.rows.empty()) {
                auto empty_row = "{} | {} | {} | {}"_format(
                        pad_cell("  <none>", line_width),
                        pad_cell("", offset_width),
                        pad_cell("", encoding_width),
                        pad_cell("", instruction_width));
                for (size_t i = 0U; i < data.table_extra_headers.size(); ++i) {
                    empty_row.append(" | ");
                    empty_row.append(pad_cell("", extra_column_widths[i]));
                }
                if (has_definitions) {
                    empty_row.append(" | ");
                    empty_row.append(pad_cell("", definition_width));
                }
                if (has_ir_source) {
                    empty_row.append(" | ");
                    empty_row.append(pad_cell("", ir_source_width));
                }
                append_line(empty_row);
            }
            else {
                auto start = std::min(top_row, data.rows.size() - 1U);
                auto end = std::min(data.rows.size(), start + rows_visible);
                for (size_t i = start; i < end; ++i) {
                    auto offset = format_offset(data.rows[i].offset);
                    auto aligned_instruction = format_aligned_instruction(data.rows[i].instruction, mnemonic_width);
                    auto [mnemonic, _] = split_instruction_parts(aligned_instruction);
                    auto call_target_span = std::optional<std::pair<size_t, size_t>>{};
                    if (auto call_target = extract_call_target_symbol(aligned_instruction); call_target.has_value()) {
                        if (auto position = aligned_instruction.find(*call_target);
                            position != std::string_view::npos) {
                            call_target_span = std::pair<size_t, size_t>{position, call_target->size()};
                        }
                    }
                    auto active_call_target_color = i == cursor ? data.call_target_color : std::string_view{};
                    auto instruction_cell = colorize_instruction_mnemonic(
                            aligned_instruction,
                            mnemonic.size(),
                            instruction_width,
                            data.selected_definition_color,
                            call_target_span,
                            active_call_target_color,
                            i == cursor ? data.selected_line_color : std::string_view{});
                    auto row_prefix = "{} | {} | {} | {}"_format(
                            pad_cell("  [{}]"_format(i), line_width),
                            pad_cell(offset, offset_width),
                            pad_cell(data.rows[i].encodings, encoding_width),
                            instruction_cell);
                    if (i < data.table_extra_values.size()) {
                        const auto& row_values = data.table_extra_values[i];
                        for (size_t j = 0U; j < data.table_extra_headers.size(); ++j) {
                            auto value = j < row_values.size() ? std::string_view{row_values[j]} : std::string_view{};
                            row_prefix.append(" | ");
                            row_prefix.append(pad_cell(value, extra_column_widths[j]));
                        }
                    }
                    else {
                        for (size_t j = 0U; j < data.table_extra_headers.size(); ++j) {
                            row_prefix.append(" | ");
                            row_prefix.append(pad_cell("", extra_column_widths[j]));
                        }
                    }
                    auto trailing_columns = std::string{};
                    auto trailing_empty = std::string{};
                    if (has_definitions) {
                        auto def = (i < data.instruction_definitions.size())
                                         ? std::string_view{data.instruction_definitions[i]}
                                         : std::string_view{};
                        trailing_columns.append(" | ");
                        trailing_columns.append(pad_cell(i == cursor ? def : std::string_view{}, definition_width));
                        trailing_empty.append(" | ");
                        trailing_empty.append(pad_cell("", definition_width));
                    }
                    if (has_ir_source) {
                        auto ir = (i < data.ir_source_lines.size()) ? std::string_view{data.ir_source_lines[i]}
                                                                    : std::string_view{};
                        trailing_columns.append(" | ");
                        trailing_columns.append(pad_cell(i == cursor ? ir : std::string_view{}, ir_source_width));
                        trailing_empty.append(" | ");
                        trailing_empty.append(pad_cell("", ir_source_width));
                    }
                    if (i == cursor) {
                        if (data.selected_line_color.empty()) {
                            frame.append("\x1b[7m");
                        }
                        else {
                            frame.append(data.selected_line_color);
                        }
                        frame.append("{}"_format(row_prefix));
                        frame.append("\x1b[0m");
                        if (!data.selected_definition_color.empty()) {
                            frame.append(data.selected_definition_color);
                        }
                        frame.append(trailing_columns);
                        if (!data.selected_definition_color.empty()) {
                            frame.append("\x1b[0m");
                        }
                        frame.push_back('\n');
                    }
                    else {
                        append_line("{}{}"_format(row_prefix, trailing_empty));
                    }
                }
            }

            auto total = data.rows.size();
            auto position = total == 0U ? 0U : cursor + 1U;
            append_line("controls: up/down j/k enter q | {}/{}"_format(position, total));
            append_line("");

            auto info = instruction_info{};
            auto has_info = cursor < data.row_info.size();
            if (has_info) {
                info = data.row_info[cursor];
            }

            auto field_width = std::string_view{"  field"}.size();
            field_width = std::max(field_width, std::string_view{"  #uOps"}.size());
            field_width = std::max(field_width, std::string_view{"  Latency"}.size());
            field_width = std::max(field_width, std::string_view{"  RThroughput"}.size());
            field_width = std::max(field_width, std::string_view{"  MayLoad"}.size());
            field_width = std::max(field_width, std::string_view{"  MayStore"}.size());
            field_width = std::max(field_width, std::string_view{"  HasSideEffects"}.size());
            field_width = std::max(field_width, std::string_view{"  EncodingSize"}.size());

            auto value_width = std::string_view{"value"}.size();
            auto load_value = std::string_view{has_info ? (info.may_load ? "true" : "false") : "na"};
            auto store_value = std::string_view{has_info ? (info.may_store ? "true" : "false") : "na"};
            auto side_effects_value = std::string_view{has_info ? (info.has_side_effects ? "true" : "false") : "na"};
            value_width = std::max(value_width, has_info ? info.uops.size() : std::string_view{"na"}.size());
            value_width = std::max(value_width, has_info ? info.latency.size() : std::string_view{"na"}.size());
            value_width = std::max(value_width, has_info ? info.rthroughput.size() : std::string_view{"na"}.size());
            value_width = std::max(value_width, load_value.size());
            value_width = std::max(value_width, store_value.size());
            value_width = std::max(value_width, side_effects_value.size());
            value_width = std::max(value_width, has_info ? info.encoding_size.size() : std::string_view{"na"}.size());

            append_line("instruction info:");
            append_line("{} | {}"_format(pad_cell("  field", field_width), pad_cell("value", value_width)));
            append_line("{}-+-{}"_format(std::string(field_width, '-'), std::string(value_width, '-')));
            append_line(
                    "{} | {}"_format(
                            pad_cell("  #uOps", field_width),
                            pad_cell(
                                    has_info && !info.uops.empty() ? std::string_view{info.uops} : "na", value_width)));
            append_line(
                    "{} | {}"_format(
                            pad_cell("  Latency", field_width),
                            pad_cell(
                                    has_info && !info.latency.empty() ? std::string_view{info.latency} : "na",
                                    value_width)));
            append_line(
                    "{} | {}"_format(
                            pad_cell("  RThroughput", field_width),
                            pad_cell(
                                    has_info && !info.rthroughput.empty() ? std::string_view{info.rthroughput} : "na",
                                    value_width)));
            append_line("{} | {}"_format(pad_cell("  MayLoad", field_width), pad_cell(load_value, value_width)));
            append_line("{} | {}"_format(pad_cell("  MayStore", field_width), pad_cell(store_value, value_width)));
            append_line(
                    "{} | {}"_format(
                            pad_cell("  HasSideEffects", field_width), pad_cell(side_effects_value, value_width)));
            append_line(
                    "{} | {}"_format(
                            pad_cell("  EncodingSize", field_width),
                            pad_cell(
                                    has_info && !info.encoding_size.empty() ? std::string_view{info.encoding_size}
                                                                            : "na",
                                    value_width)));
            if (cursor < data.row_detail_lines.size() && !data.row_detail_lines[cursor].empty()) {
                append_line("");
                for (const auto& detail_line : data.row_detail_lines[cursor]) {
                    append_line(detail_line);
                }
            }
            return frame;
        }

        struct sugiyama_layout_edge {
            size_t from{};
            size_t to{};
            bool reversed{false};
        };

        static std::string clip_graph_node_label(std::string_view text, size_t width) {
            if (width == 0U) {
                return {};
            }
            if (text.size() <= width) {
                return std::string{text};
            }
            if (width == 1U) {
                return std::string{text.substr(0U, 1U)};
            }
            auto out = std::string{text.substr(0U, width - 1U)};
            out.push_back('~');
            return out;
        }

        static std::vector<sugiyama_layout_edge> build_acyclic_layout_edges(const graph_model& data) {
            auto node_count = data.nodes.size();
            auto adjacency = std::vector<std::vector<size_t>>(node_count);
            for (size_t i = 0U; i < data.edges.size(); ++i) {
                auto from = data.edges[i].from;
                auto to = data.edges[i].to;
                if (from >= node_count || to >= node_count || from == to) {
                    continue;
                }
                adjacency[from].push_back(i);
            }

            auto state = std::vector<uint8_t>(node_count, 0U);
            auto reverse_edge = std::vector<bool>(data.edges.size(), false);
            auto dfs = [&](auto&& self, size_t node) -> void {
                state[node] = 1U;
                for (auto edge_idx : adjacency[node]) {
                    if (edge_idx >= data.edges.size()) {
                        continue;
                    }
                    auto next = data.edges[edge_idx].to;
                    if (state[next] == 0U) {
                        self(self, next);
                    }
                    else if (state[next] == 1U) {
                        reverse_edge[edge_idx] = true;
                    }
                }
                state[node] = 2U;
            };

            for (size_t node = 0U; node < node_count; ++node) {
                if (state[node] == 0U) {
                    dfs(dfs, node);
                }
            }

            auto edges = std::vector<sugiyama_layout_edge>{};
            edges.reserve(data.edges.size());
            for (size_t i = 0U; i < data.edges.size(); ++i) {
                auto from = data.edges[i].from;
                auto to = data.edges[i].to;
                if (from >= node_count || to >= node_count || from == to) {
                    continue;
                }
                if (reverse_edge[i]) {
                    edges.push_back(sugiyama_layout_edge{.from = to, .to = from, .reversed = true});
                }
                else {
                    edges.push_back(sugiyama_layout_edge{.from = from, .to = to, .reversed = false});
                }
            }
            return edges;
        }

        static std::vector<size_t> assign_sugiyama_layers(
                size_t node_count, const std::vector<sugiyama_layout_edge>& edges) {
            auto indegree = std::vector<size_t>(node_count, 0U);
            auto outgoing = std::vector<std::vector<size_t>>(node_count);
            for (size_t i = 0U; i < edges.size(); ++i) {
                auto from = edges[i].from;
                auto to = edges[i].to;
                if (from >= node_count || to >= node_count) {
                    continue;
                }
                outgoing[from].push_back(i);
                ++indegree[to];
            }

            auto queue = std::vector<size_t>{};
            queue.reserve(node_count);
            for (size_t node = 0U; node < node_count; ++node) {
                if (indegree[node] == 0U) {
                    queue.push_back(node);
                }
            }

            auto topo = std::vector<size_t>{};
            topo.reserve(node_count);
            for (size_t head = 0U; head < queue.size(); ++head) {
                auto node = queue[head];
                topo.push_back(node);
                for (auto edge_idx : outgoing[node]) {
                    auto to = edges[edge_idx].to;
                    if (indegree[to] > 0U) {
                        --indegree[to];
                    }
                    if (indegree[to] == 0U) {
                        queue.push_back(to);
                    }
                }
            }
            if (topo.size() < node_count) {
                for (size_t node = 0U; node < node_count; ++node) {
                    if (std::find(topo.begin(), topo.end(), node) == topo.end()) {
                        topo.push_back(node);
                    }
                }
            }

            auto layers = std::vector<size_t>(node_count, 0U);
            for (auto node : topo) {
                for (auto edge_idx : outgoing[node]) {
                    auto to = edges[edge_idx].to;
                    layers[to] = std::max(layers[to], layers[node] + 1U);
                }
            }
            return layers;
        }

        static void minimize_sugiyama_crossings(
                std::vector<std::vector<size_t>>& layers,
                const std::vector<size_t>& node_layers,
                const std::vector<std::vector<size_t>>& incoming_neighbors,
                const std::vector<std::vector<size_t>>& outgoing_neighbors) {
            if (layers.size() <= 2U) {
                return;
            }

            auto order = std::vector<size_t>(node_layers.size(), 0U);
            auto refresh_order = [&]() {
                for (const auto& layer_nodes : layers) {
                    for (size_t idx = 0U; idx < layer_nodes.size(); ++idx) {
                        order[layer_nodes[idx]] = idx;
                    }
                }
            };
            refresh_order();

            auto reorder_layer = [&](size_t layer_idx, bool downward) {
                if (layer_idx >= layers.size()) {
                    return;
                }
                if ((downward && layer_idx == 0U) || (!downward && layer_idx + 1U >= layers.size())) {
                    return;
                }

                struct entry {
                    size_t node{};
                    size_t old_order{};
                    double barycenter{};
                    bool has_anchor{false};
                };

                auto entries = std::vector<entry>{};
                entries.reserve(layers[layer_idx].size());
                for (auto node : layers[layer_idx]) {
                    auto sum = 0.0;
                    auto count = size_t{0U};
                    const auto& neighbors = downward ? incoming_neighbors[node] : outgoing_neighbors[node];
                    for (auto neighbor : neighbors) {
                        if (neighbor >= node_layers.size()) {
                            continue;
                        }
                        if (downward) {
                            if (node_layers[neighbor] + 1U != layer_idx) {
                                continue;
                            }
                        }
                        else {
                            if (node_layers[neighbor] != layer_idx + 1U) {
                                continue;
                            }
                        }
                        sum += static_cast<double>(order[neighbor]);
                        ++count;
                    }

                    entries.push_back(
                            entry{.node = node,
                                  .old_order = order[node],
                                  .barycenter = count > 0U ? (sum / static_cast<double>(count)) : 0.0,
                                  .has_anchor = count > 0U});
                }

                std::stable_sort(entries.begin(), entries.end(), [](const entry& lhs, const entry& rhs) {
                    if (lhs.has_anchor != rhs.has_anchor) {
                        return lhs.has_anchor > rhs.has_anchor;
                    }
                    if (lhs.has_anchor && rhs.has_anchor && lhs.barycenter != rhs.barycenter) {
                        return lhs.barycenter < rhs.barycenter;
                    }
                    return lhs.old_order < rhs.old_order;
                });

                for (size_t i = 0U; i < entries.size(); ++i) {
                    layers[layer_idx][i] = entries[i].node;
                }
                refresh_order();
            };

            constexpr auto sweep_iterations = size_t{4U};
            for (size_t iter = 0U; iter < sweep_iterations; ++iter) {
                for (size_t layer_idx = 1U; layer_idx < layers.size(); ++layer_idx) {
                    reorder_layer(layer_idx, true);
                }
                for (size_t layer_idx = layers.size(); layer_idx-- > 1U;) {
                    reorder_layer(layer_idx - 1U, false);
                }
            }
        }

        static void draw_sugiyama_char(std::vector<std::string>& canvas, size_t row, size_t col, char value) {
            if (row >= canvas.size() || canvas.empty() || col >= canvas.front().size()) {
                return;
            }
            auto& cell = canvas[row][col];
            if (cell == ' ') {
                cell = value;
                return;
            }
            if (cell == value) {
                return;
            }
            if ((cell == '-' && value == '|') || (cell == '|' && value == '-') || cell == '+' || value == '+') {
                cell = '+';
                return;
            }
            if (value == 'v' || value == '^') {
                cell = value;
                return;
            }
            if (cell == 'v' || cell == '^') {
                return;
            }
            cell = '+';
        }

        static void draw_sugiyama_vertical(std::vector<std::string>& canvas, size_t row_a, size_t row_b, size_t col) {
            if (row_a > row_b) {
                std::swap(row_a, row_b);
            }
            for (size_t row = row_a; row <= row_b; ++row) {
                draw_sugiyama_char(canvas, row, col, '|');
            }
        }

        static void draw_sugiyama_horizontal(std::vector<std::string>& canvas, size_t row, size_t col_a, size_t col_b) {
            if (col_a > col_b) {
                std::swap(col_a, col_b);
            }
            for (size_t col = col_a; col <= col_b; ++col) {
                draw_sugiyama_char(canvas, row, col, '-');
            }
        }

        static std::string trim_right_spaces(std::string line) {
            while (!line.empty() && line.back() == ' ') {
                line.pop_back();
            }
            return line;
        }

        static std::string colorize_graph_token(std::string_view text, std::string_view color) {
            if (color.empty() || text.empty()) {
                return std::string{text};
            }
            auto out = std::string{};
            out.reserve(text.size() + color.size() + 8U);
            out.append(color);
            out.append(text);
            out.append("\x1b[0m");
            return out;
        }

        static std::string colorize_sugiyama_node_ids(
                std::string line, const std::unordered_map<std::string, std::string_view>& node_id_colors) {
            if (line.empty() || node_id_colors.empty()) {
                return line;
            }

            for (const auto& [id, color] : node_id_colors) {
                if (id.empty() || color.empty()) {
                    continue;
                }
                auto token = "[{}]"_format(id);
                auto replacement = colorize_graph_token(token, color);
                auto pos = size_t{0U};
                while (true) {
                    pos = line.find(token, pos);
                    if (pos == std::string::npos) {
                        break;
                    }
                    line.replace(pos, token.size(), replacement);
                    pos += replacement.size();
                }
            }
            return line;
        }

        static void render_graph_sugiyama(
                const graph_model& data,
                std::ostream& out,
                bool include_header = true,
                const std::unordered_map<std::string, std::string_view>* node_id_colors = nullptr) {
            auto terminal_cols = isatty(STDOUT_FILENO) ? query_terminal_dims().cols : size_t{4096U};
            auto append_line = [&](std::string_view line) { out << line << '\n'; };

            if (include_header) {
                append_line("graph:");
                append_line("type: {}"_format(data.kind_label));
                append_line("root: {}"_format(data.title));
                append_line("nodes: {} | edges: {}"_format(data.nodes.size(), data.edges.size()));
                append_line("");
            }

            if (data.nodes.empty()) {
                append_line("<empty>");
                return;
            }

            auto layout_edges = build_acyclic_layout_edges(data);
            auto node_layers = assign_sugiyama_layers(data.nodes.size(), layout_edges);
            auto max_layer = size_t{0U};
            for (auto layer : node_layers) {
                max_layer = std::max(max_layer, layer);
            }

            auto layers = std::vector<std::vector<size_t>>(max_layer + 1U);
            for (size_t node = 0U; node < node_layers.size(); ++node) {
                layers[node_layers[node]].push_back(node);
            }

            auto incoming_neighbors = std::vector<std::vector<size_t>>(data.nodes.size());
            auto outgoing_neighbors = std::vector<std::vector<size_t>>(data.nodes.size());
            for (const auto& edge : layout_edges) {
                if (edge.from >= data.nodes.size() || edge.to >= data.nodes.size()) {
                    continue;
                }
                outgoing_neighbors[edge.from].push_back(edge.to);
                incoming_neighbors[edge.to].push_back(edge.from);
            }
            minimize_sugiyama_crossings(layers, node_layers, incoming_neighbors, outgoing_neighbors);

            auto is_defuse_layout = data.kind_label == "defuse"sv;
            auto node_text = std::vector<std::string>(data.nodes.size());
            auto max_node_text_width = size_t{3U};
            auto max_node_label_width = is_defuse_layout ? size_t{34U} : size_t{24U};
            for (size_t node = 0U; node < data.nodes.size(); ++node) {
                auto label = std::string{};
                if (is_defuse_layout) {
                    label = data.nodes[node].short_label;
                }
                else {
                    label = data.nodes[node].id;
                }
                if (label.empty()) {
                    label = "n{}"_format(node);
                }

                auto clipped = clip_graph_node_label(label, max_node_label_width);
                node_text[node] = "[{}]"_format(clipped);
                max_node_text_width = std::max(max_node_text_width, node_text[node].size());
            }

            auto max_layer_width = size_t{1U};
            for (const auto& layer_nodes : layers) {
                max_layer_width = std::max(max_layer_width, layer_nodes.size());
            }

            constexpr auto row_step = size_t{4U};
            auto col_step = max_node_text_width + 8U;
            auto canvas_rows = std::max<size_t>(2U, layers.size() * row_step + 1U);
            auto canvas_cols = std::max<size_t>(12U, 4U + max_layer_width * col_step + 4U);
            auto canvas = std::vector<std::string>(canvas_rows, std::string(canvas_cols, ' '));

            struct placement {
                size_t row{};
                size_t col{};
                size_t center{};
            };
            auto placements = std::vector<placement>(data.nodes.size());
            for (size_t layer_idx = 0U; layer_idx < layers.size(); ++layer_idx) {
                const auto& layer_nodes = layers[layer_idx];
                auto layer_offset = (max_layer_width - layer_nodes.size()) * col_step / 2U;
                for (size_t order = 0U; order < layer_nodes.size(); ++order) {
                    auto node = layer_nodes[order];
                    auto row = layer_idx * row_step;
                    auto center = 2U + layer_offset + order * col_step + (col_step / 2U);
                    center = std::min(center, canvas_cols - 1U);
                    auto col = center > (node_text[node].size() / 2U) ? center - (node_text[node].size() / 2U) : 0U;
                    if (col + node_text[node].size() >= canvas_cols) {
                        col = canvas_cols > node_text[node].size() ? canvas_cols - node_text[node].size() : 0U;
                    }
                    placements[node] = placement{.row = row, .col = col, .center = center};
                }
            }

            auto long_edge_bend_rank = std::unordered_map<uint64_t, size_t>{};
            auto make_bend_rank_key = [](size_t src, bool to_right) {
                return (static_cast<uint64_t>(src) << 1U) | static_cast<uint64_t>(to_right ? 1U : 0U);
            };
            auto reversed_count = size_t{0U};
            for (const auto& edge : layout_edges) {
                if (edge.from >= data.nodes.size() || edge.to >= data.nodes.size()) {
                    continue;
                }
                if (edge.reversed) {
                    ++reversed_count;
                }

                auto src = placements[edge.from];
                auto dst = placements[edge.to];
                if (src.row >= canvas_rows || dst.row >= canvas_rows || src.center >= canvas_cols ||
                    dst.center >= canvas_cols) {
                    continue;
                }

                auto start_row = std::min(canvas_rows - 1U, src.row + 1U);
                auto end_row = dst.row > 0U ? dst.row - 1U : size_t{0U};
                auto from_layer = node_layers[edge.from];
                auto to_layer = node_layers[edge.to];
                auto layer_span = to_layer > from_layer ? (to_layer - from_layer) : size_t{0U};
                if (end_row <= start_row) {
                    draw_sugiyama_horizontal(canvas, start_row, src.center, dst.center);
                    draw_sugiyama_char(canvas, start_row, dst.center, edge.reversed ? '^' : 'v');
                    continue;
                }

                if (src.center == dst.center && layer_span <= 1U) {
                    draw_sugiyama_vertical(canvas, start_row, end_row, src.center);
                }
                else if (layer_span > 1U) {
                    auto to_right = dst.center >= src.center;
                    auto rank_key = make_bend_rank_key(edge.from, to_right);
                    auto rank = long_edge_bend_rank[rank_key]++;
                    auto bend_delta = 2U + rank * 2U;
                    auto bend_col = to_right ? (src.center + bend_delta)
                                             : (src.center > bend_delta ? src.center - bend_delta : 0U);
                    bend_col = std::clamp(bend_col, size_t{1U}, canvas_cols - 2U);
                    if (bend_col == src.center) {
                        bend_col = std::clamp(src.center + (to_right ? 2U : size_t{0U}), size_t{1U}, canvas_cols - 2U);
                    }

                    draw_sugiyama_horizontal(canvas, start_row, src.center, bend_col);
                    draw_sugiyama_vertical(canvas, start_row, end_row, bend_col);
                    draw_sugiyama_horizontal(canvas, end_row, bend_col, dst.center);
                    if (bend_col != src.center) {
                        draw_sugiyama_char(canvas, start_row, src.center, '+');
                        draw_sugiyama_char(canvas, start_row, bend_col, '+');
                    }
                    if (bend_col != dst.center) {
                        draw_sugiyama_char(canvas, end_row, bend_col, '+');
                        draw_sugiyama_char(canvas, end_row, dst.center, '+');
                    }
                }
                else {
                    auto middle_row = start_row + ((end_row - start_row) / 2U);
                    if (src.center != dst.center && end_row >= start_row + 2U) {
                        // Keep one vertical segment before the arrow head when space allows.
                        middle_row = std::min(middle_row, end_row - 2U);
                    }
                    draw_sugiyama_vertical(canvas, start_row, middle_row, src.center);
                    draw_sugiyama_horizontal(canvas, middle_row, src.center, dst.center);
                    draw_sugiyama_vertical(canvas, middle_row, end_row, dst.center);
                    if (src.center != dst.center) {
                        draw_sugiyama_char(canvas, middle_row, src.center, '+');
                        draw_sugiyama_char(canvas, middle_row, dst.center, '+');
                    }
                }

                if (edge.reversed) {
                    draw_sugiyama_char(canvas, start_row, src.center, '^');
                }
                else {
                    draw_sugiyama_char(canvas, end_row, dst.center, 'v');
                }
            }

            for (size_t node = 0U; node < data.nodes.size(); ++node) {
                auto row = placements[node].row;
                auto col = placements[node].col;
                if (row >= canvas_rows || col >= canvas_cols) {
                    continue;
                }
                const auto& text = node_text[node];
                for (size_t i = 0U; i < text.size() && col + i < canvas_cols; ++i) {
                    canvas[row][col + i] = text[i];
                }
            }

            auto last_row = size_t{0U};
            for (size_t row = 0U; row < canvas_rows; ++row) {
                if (trim_right_spaces(canvas[row]).empty()) {
                    continue;
                }
                last_row = row;
            }
            for (size_t row = 0U; row <= last_row; ++row) {
                auto line = trim_right_spaces(canvas[row]);
                if (node_id_colors != nullptr) {
                    line = colorize_sugiyama_node_ids(std::move(line), *node_id_colors);
                }
                append_line(line);
            }
            if (reversed_count > 0U) {
                append_line("");
                append_line("note: '^' marks back-edges reversed only for layering.");
            }
        }

    }  // namespace detail

    inline launch_result run(const model& data, std::ostream& out) {
        auto label = data.mode_label.empty() ? "asm"sv : data.mode_label;
        if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
            return launch_result{
                    .status = launch_status::fallback,
                    .message =
                            "{} explore: requires an interactive tty, falling back to :{} output"_format(label, label)};
        }

        if (data.rows.empty()) {
            return launch_result{
                    .status = launch_status::fallback,
                    .message = "{} explore: no rows available, falling back to :{} output"_format(label, label)};
        }

        auto terminal_guard = detail::raw_terminal_guard{STDIN_FILENO};
        std::string setup_error{};
        if (!terminal_guard.activate(setup_error)) {
            return launch_result{
                    .status = launch_status::fallback,
                    .message = "{} explore: {} (falling back to :{} output)"_format(label, setup_error, label)};
        }

        auto screen = detail::screen_guard{STDOUT_FILENO};
        screen.enter();

        auto cursor = std::min(data.initial_cursor, data.rows.size() - 1U);
        auto top_row = cursor;
        auto running = true;

        while (running) {
            auto dims = detail::query_terminal_dims();
            auto rows_visible = detail::calculate_rows_visible(
                    dims.rows,
                    std::max<size_t>(1U, data.opcode_counts.size()),
                    !data.resource_pressure.resources.empty());
            detail::clamp_viewport(data.rows.size(), rows_visible, cursor, top_row);

            out << detail::render_frame(data, cursor, top_row, rows_visible, dims.cols);
            out.flush();

            auto event = detail::read_key_event(STDIN_FILENO);
            switch (event) {
                case detail::key_event::up:
                    if (cursor > 0U) {
                        --cursor;
                    }
                    break;
                case detail::key_event::down:
                    if (cursor + 1U < data.rows.size()) {
                        ++cursor;
                    }
                    break;
                case detail::key_event::enter:
                    if (cursor < data.rows.size()) {
                        if (auto next = detail::extract_call_target_symbol(data.rows[cursor].instruction);
                            next.has_value()) {
                            return launch_result{
                                    .status = launch_status::completed,
                                    .next_symbol = std::string{*next},
                                    .selected_row = cursor};
                        }
                    }
                    break;
                case detail::key_event::quit:
                    running = false;
                    break;
                case detail::key_event::none:
                    break;
            }
        }

        return launch_result{.status = launch_status::completed, .selected_row = cursor};
    }

    inline graph_launch_result run_graph(const graph_model& data, std::ostream& out) {
        if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
            return graph_launch_result{
                    .status = launch_status::fallback,
                    .message = "graph explore: requires an interactive tty, falling back to export output"};
        }

        if (data.nodes.empty()) {
            return graph_launch_result{
                    .status = launch_status::fallback,
                    .message = "graph explore: no graph nodes available, falling back to export output"};
        }

        auto terminal_guard = detail::raw_terminal_guard{STDIN_FILENO};
        std::string setup_error{};
        if (!terminal_guard.activate(setup_error)) {
            return graph_launch_result{
                    .status = launch_status::fallback,
                    .message = "graph explore: {} (falling back to export output)"_format(setup_error)};
        }

        auto screen = detail::screen_guard{STDOUT_FILENO};
        screen.enter();

        auto cursor = std::min(data.initial_cursor, data.nodes.size() - 1U);
        auto top_row = cursor;
        auto running = true;

        if (data.kind_label == "ir"sv) {
            while (running) {
                auto dims = detail::query_terminal_dims();
                auto rows_visible = detail::calculate_graph_rows_visible_table_only(dims.rows);
                detail::clamp_graph_viewport(data.nodes.size(), rows_visible, cursor, top_row);
                auto safe_cursor = std::min(cursor, data.nodes.size() - 1U);

                auto outgoing_nodes = std::vector<size_t>{};
                auto incoming_nodes = std::vector<size_t>{};
                if (safe_cursor < data.outgoing_edges.size()) {
                    for (auto edge_idx : data.outgoing_edges[safe_cursor]) {
                        if (edge_idx >= data.edges.size()) {
                            continue;
                        }
                        outgoing_nodes.push_back(data.edges[edge_idx].to);
                    }
                }
                if (safe_cursor < data.incoming_edges.size()) {
                    for (auto edge_idx : data.incoming_edges[safe_cursor]) {
                        if (edge_idx >= data.edges.size()) {
                            continue;
                        }
                        incoming_nodes.push_back(data.edges[edge_idx].from);
                    }
                }

                auto node_colors = std::unordered_map<std::string, std::string_view>{};
                for (auto idx : incoming_nodes) {
                    if (idx < data.nodes.size() && !data.removed_line_color.empty()) {
                        node_colors.insert_or_assign(data.nodes[idx].id, data.removed_line_color);
                    }
                }
                for (auto idx : outgoing_nodes) {
                    if (idx < data.nodes.size() && !data.unchanged_line_color.empty()) {
                        node_colors.insert_or_assign(data.nodes[idx].id, data.unchanged_line_color);
                    }
                }
                if (!data.selected_line_color.empty() && safe_cursor < data.nodes.size()) {
                    node_colors.insert_or_assign(data.nodes[safe_cursor].id, data.selected_line_color);
                }

                out << detail::render_graph_frame(
                        data, cursor, top_row, rows_visible, dims.cols, true, false, true, false);
                out << '\n';
                out << "layout:\n";
                detail::render_graph_sugiyama(data, out, false, &node_colors);
                out << "controls: up/down j/k q | {}/{}\n"_format(safe_cursor + 1U, data.nodes.size());
                out.flush();

                auto event = detail::read_key_event(STDIN_FILENO);
                switch (event) {
                    case detail::key_event::up:
                        if (cursor > 0U) {
                            --cursor;
                        }
                        break;
                    case detail::key_event::down:
                        if (cursor + 1U < data.nodes.size()) {
                            ++cursor;
                        }
                        break;
                    case detail::key_event::quit:
                        running = false;
                        break;
                    case detail::key_event::enter:
                    case detail::key_event::none:
                        break;
                }
            }

            return graph_launch_result{.status = launch_status::completed, .selected_node = cursor};
        }

        while (running) {
            auto dims = detail::query_terminal_dims();
            auto rows_visible = detail::calculate_graph_rows_visible(dims.rows);
            detail::clamp_graph_viewport(data.nodes.size(), rows_visible, cursor, top_row);

            out << detail::render_graph_frame(data, cursor, top_row, rows_visible, dims.cols, true, true, true);
            out.flush();

            auto event = detail::read_key_event(STDIN_FILENO);
            switch (event) {
                case detail::key_event::up:
                    if (cursor > 0U) {
                        --cursor;
                    }
                    break;
                case detail::key_event::down:
                    if (cursor + 1U < data.nodes.size()) {
                        ++cursor;
                    }
                    break;
                case detail::key_event::quit:
                    running = false;
                    break;
                case detail::key_event::enter:
                case detail::key_event::none:
                    break;
            }
        }

        return graph_launch_result{.status = launch_status::completed, .selected_node = cursor};
    }

    inline void render_graph_sugiyama(const graph_model& data, std::ostream& out) {
        detail::render_graph_sugiyama(data, out);
    }

    inline void render_graph_static(const graph_model& data, std::ostream& out, size_t selected_node = 0U) {
        if (data.nodes.empty()) {
            out << "graph explorer: no graph nodes available\n";
            return;
        }

        auto cursor = std::min(selected_node, data.nodes.size() - 1U);
        auto rows_visible = std::max<size_t>(1U, data.nodes.size());
        auto frame = detail::render_graph_frame(data, cursor, 0U, rows_visible, 4096U, false, false, false);
        out << frame;
    }

    inline void render_ir_static(const graph_model& data, std::ostream& out) {
        if (data.kind_label != "ir"sv) {
            render_graph_static(data, out);
            return;
        }

        out << "graph explorer:\n";
        out << "type: {}\n"_format(data.kind_label);
        out << "root: {}\n"_format(data.title);
        out << "nodes: {} | edges: {}\n"_format(data.nodes.size(), data.edges.size());
        out << '\n';

        auto id_width = std::string_view{"id"}.size();
        auto out_width = std::string_view{"out"}.size();
        auto in_width = std::string_view{"in"}.size();
        auto label_width = std::string_view{"label"}.size();
        for (const auto& node : data.nodes) {
            id_width = std::max(id_width, node.id.size());
            out_width = std::max(out_width, "{}"_format(node.outgoing_count).size());
            in_width = std::max(in_width, "{}"_format(node.incoming_count).size());
            label_width = std::max(label_width, node.short_label.size());
        }

        out << "nodes:\n";
        out << detail::pad_cell("id", id_width) << " | " << detail::pad_cell("out", out_width) << " | "
            << detail::pad_cell("in", in_width) << " | " << detail::pad_cell("label", label_width) << '\n';
        out << std::string(id_width, '-') << "-+-" << std::string(out_width, '-') << "-+-" << std::string(in_width, '-')
            << "-+-" << std::string(label_width, '-') << '\n';

        if (data.nodes.empty()) {
            out << detail::pad_cell("<none>", id_width) << " | " << detail::pad_cell("", out_width) << " | "
                << detail::pad_cell("", in_width) << " | " << detail::pad_cell("", label_width) << '\n';
            return;
        }

        for (const auto& node : data.nodes) {
            auto label = detail::colorize_defuse_label(node.short_label, data.selected_detail_color);
            out << detail::pad_cell(node.id, id_width) << " | "
                << detail::pad_cell("{}"_format(node.outgoing_count), out_width) << " | "
                << detail::pad_cell("{}"_format(node.incoming_count), in_width) << " | "
                << detail::pad_cell(label, label_width) << '\n';
        }

        out << '\n';
        out << "layout:\n";
        detail::render_graph_sugiyama(data, out, false);
    }

}  // namespace sontag::internal::explorer
