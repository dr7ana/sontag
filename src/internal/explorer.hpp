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
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
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
        std::string symbol_display{};
        size_t operations_total{};
        std::vector<std::pair<std::string, size_t>> opcode_counts{};
        std::vector<asm_row> rows{};
        std::vector<instruction_info> row_info{};
        resource_pressure_table resource_pressure{};
        std::vector<std::string> instruction_definitions{};
        std::string_view selected_line_color{};
        std::string_view selected_definition_color{};
        std::string_view call_target_color{};
        size_t initial_cursor{};
    };

    enum class launch_status : uint8_t { completed, fallback };

    struct launch_result {
        launch_status status{launch_status::completed};
        std::string message{};
        std::optional<std::string> next_symbol{};
        size_t selected_row{};
    };

    namespace detail {

        struct terminal_dims {
            size_t rows{24U};
            size_t cols{80U};
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
            if (text.size() <= width) {
                return std::string{text};
            }
            return std::string{text.substr(0U, width)};
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
            char c{};
            auto n = read(fd, &c, 1U);
            if (n <= 0) {
                return key_event::quit;
            }

            switch (c) {
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
                    auto second = read_byte_with_timeout(fd, 20);
                    if (!second) {
                        return key_event::quit;
                    }
                    if (*second != '[') {
                        return key_event::quit;
                    }
                    auto third = read_byte_with_timeout(fd, 20);
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

        static std::string render_frame(
                const model& data, size_t cursor, size_t top_row, size_t rows_visible, size_t terminal_cols) {
            std::string frame{};
            frame.reserve(4096U);

            auto append_line = [&](std::string_view line) {
                frame.append(clip_to_width(line, terminal_cols));
                frame.push_back('\n');
            };

            frame.append("\x1b[H\x1b[2J");
            append_line("asm explorer:");
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
            auto definition_width = std::string_view{"definition"}.size();
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
                if (i < data.instruction_definitions.size()) {
                    definition_width = std::max(definition_width, data.instruction_definitions[i].size());
                }
            }

            append_line("");
            append_line("assembly:");
            append_line(
                    "{} | {} | {} | {} | {}"_format(
                            pad_cell("  line", line_width),
                            pad_cell("offset", offset_width),
                            pad_cell("encodings", encoding_width),
                            pad_cell("instruction", instruction_width),
                            pad_cell("definition", definition_width)));
            append_line(
                    "{}-+-{}-+-{}-+-{}-+-{}"_format(
                            std::string(line_width, '-'),
                            std::string(offset_width, '-'),
                            std::string(encoding_width, '-'),
                            std::string(instruction_width, '-'),
                            std::string(definition_width, '-')));

            if (data.rows.empty()) {
                append_line(
                        "{} | {} | {} | {} | {}"_format(
                                pad_cell("  <none>", line_width),
                                pad_cell("", offset_width),
                                pad_cell("", encoding_width),
                                pad_cell("", instruction_width),
                                pad_cell("", definition_width)));
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
                    auto selected_definition = std::string_view{};
                    if (i == cursor && i < data.instruction_definitions.size()) {
                        selected_definition = data.instruction_definitions[i];
                    }
                    if (i == cursor) {
                        if (data.selected_line_color.empty()) {
                            frame.append("\x1b[7m");
                        }
                        else {
                            frame.append(data.selected_line_color);
                        }
                        frame.append("{} | "_format(row_prefix));
                        frame.append("\x1b[0m");
                        if (!data.selected_definition_color.empty()) {
                            frame.append(data.selected_definition_color);
                        }
                        frame.append(pad_cell(selected_definition, definition_width));
                        if (!data.selected_definition_color.empty()) {
                            frame.append("\x1b[0m");
                        }
                        frame.push_back('\n');
                    }
                    else {
                        append_line("{} | {}"_format(row_prefix, pad_cell("", definition_width)));
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
            return frame;
        }

    }  // namespace detail

    inline launch_result run(const model& data, std::ostream& out) {
        if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
            return launch_result{
                    .status = launch_status::fallback,
                    .message = "asm explore: requires an interactive tty, falling back to :asm output"};
        }

        if (data.rows.empty()) {
            return launch_result{
                    .status = launch_status::fallback,
                    .message = "asm explore: no assembly instructions available, falling back to :asm output"};
        }

        auto terminal_guard = detail::raw_terminal_guard{STDIN_FILENO};
        std::string setup_error{};
        if (!terminal_guard.activate(setup_error)) {
            return launch_result{
                    .status = launch_status::fallback,
                    .message = "asm explore: {} (falling back to :asm output)"_format(setup_error)};
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

}  // namespace sontag::internal::explorer
