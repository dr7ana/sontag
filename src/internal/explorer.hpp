#pragma once

#include "sontag/format.hpp"

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

    struct model {
        std::string symbol_display{};
        size_t operations_total{};
        std::vector<std::pair<std::string, size_t>> opcode_counts{};
        std::vector<std::string> instructions{};
        std::vector<std::string> instruction_definitions{};
        std::string_view selected_line_color{};
        std::string_view selected_definition_color{};
    };

    enum class launch_status : uint8_t { completed, fallback };

    struct launch_result {
        launch_status status{launch_status::completed};
        std::string message{};
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

        static size_t calculate_rows_visible(size_t total_rows, size_t opcode_rows) {
            auto fixed_rows = 9U + opcode_rows;
            if (total_rows <= fixed_rows) {
                return 1U;
            }
            return total_rows - fixed_rows;
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

            auto line_width = std::string_view{"  line"}.size();
            auto instruction_width = std::string_view{"instruction"}.size();
            auto definition_width = std::string_view{"definition"}.size();
            for (size_t i = 0U; i < data.instructions.size(); ++i) {
                line_width = std::max(line_width, "  [{}]"_format(i).size());
                instruction_width = std::max(instruction_width, data.instructions[i].size());
                if (i < data.instruction_definitions.size()) {
                    definition_width = std::max(definition_width, data.instruction_definitions[i].size());
                }
            }

            append_line("assembly:");
            append_line(
                    "{} | {} | {}"_format(
                            pad_cell("  line", line_width),
                            pad_cell("instruction", instruction_width),
                            pad_cell("definition", definition_width)));
            append_line(
                    "{}-+-{}-+-{}"_format(
                            std::string(line_width, '-'),
                            std::string(instruction_width, '-'),
                            std::string(definition_width, '-')));

            if (data.instructions.empty()) {
                append_line(
                        "{} | {} | {}"_format(
                                pad_cell("  <none>", line_width),
                                pad_cell("", instruction_width),
                                pad_cell("", definition_width)));
            }
            else {
                auto start = std::min(top_row, data.instructions.size() - 1U);
                auto end = std::min(data.instructions.size(), start + rows_visible);
                for (size_t i = start; i < end; ++i) {
                    auto row_prefix = "{} | {}"_format(
                            pad_cell("  [{}]"_format(i), line_width),
                            pad_cell(data.instructions[i], instruction_width));
                    auto selected_definition = std::string_view{};
                    if (i == cursor && i < data.instruction_definitions.size()) {
                        selected_definition = data.instruction_definitions[i];
                    }
                    auto row = "{} | {}"_format(row_prefix, pad_cell(selected_definition, definition_width));
                    if (i == cursor) {
                        auto clipped = clip_to_width(row, terminal_cols);
                        auto split_at = row_prefix.size();
                        if (clipped.size() <= split_at) {
                            if (data.selected_line_color.empty()) {
                                frame.append("\x1b[7m");
                            }
                            else {
                                frame.append(data.selected_line_color);
                            }
                            frame.append(clipped);
                            frame.append("\x1b[0m\n");
                        }
                        else {
                            auto left = clipped.substr(0U, split_at);
                            auto right = clipped.substr(split_at);
                            if (data.selected_line_color.empty()) {
                                frame.append("\x1b[7m");
                            }
                            else {
                                frame.append(data.selected_line_color);
                            }
                            frame.append(left);
                            frame.append("\x1b[0m");
                            if (!right.empty()) {
                                if (!data.selected_definition_color.empty()) {
                                    frame.append(data.selected_definition_color);
                                }
                                frame.append(right);
                                if (!data.selected_definition_color.empty()) {
                                    frame.append("\x1b[0m");
                                }
                            }
                            frame.push_back('\n');
                        }
                    }
                    else {
                        append_line("{} | {}"_format(row_prefix, pad_cell("", definition_width)));
                    }
                }
            }

            auto total = data.instructions.size();
            auto position = total == 0U ? 0U : cursor + 1U;
            append_line("controls: up/down j/k q | {}/{}"_format(position, total));
            return frame;
        }

    }  // namespace detail

    inline launch_result run(const model& data, std::ostream& out) {
        if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
            return launch_result{
                    .status = launch_status::fallback,
                    .message = "asm explore: requires an interactive tty, falling back to :asm output"};
        }

        if (data.instructions.empty()) {
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

        auto cursor = static_cast<size_t>(0U);
        auto top_row = static_cast<size_t>(0U);
        auto running = true;

        while (running) {
            auto dims = detail::query_terminal_dims();
            auto rows_visible =
                    detail::calculate_rows_visible(dims.rows, std::max<size_t>(1U, data.opcode_counts.size()));
            detail::clamp_viewport(data.instructions.size(), rows_visible, cursor, top_row);

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
                    if (cursor + 1U < data.instructions.size()) {
                        ++cursor;
                    }
                    break;
                case detail::key_event::quit:
                    running = false;
                    break;
                case detail::key_event::none:
                    break;
            }
        }

        return launch_result{.status = launch_status::completed};
    }

}  // namespace sontag::internal::explorer
