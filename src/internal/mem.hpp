#pragma once

#include "platform.hpp"
#include "symbols.hpp"

#include "sontag/format.hpp"
#include "sontag/utils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sontag::internal::mem {

    using namespace std::string_view_literals;
    using namespace sontag::literals;

    enum class access_kind : uint8_t {
        none,
        load,
        store,
        rmw,
    };

    enum class address_class : uint8_t {
        none,
        stack,
        global,
        pc_relative,
        register_indirect,
        unknown,
    };

    enum class value_status : uint8_t {
        unknown,
        known,
        varied,
    };

    enum class value_source : uint8_t {
        inferred_none,
        runtime_trace_exact,
        runtime_trace_sampled,
    };

    struct row_input {
        size_t line{};
        std::string_view offset{};
        std::string_view encodings{};
        std::string_view instruction{};
        bool may_load{false};
        bool may_store{false};
    };

    struct row {
        size_t line{};
        std::string offset{};
        std::string encodings{};
        std::string instruction{};
        std::string mnemonic{};
        access_kind access{access_kind::none};
        std::optional<size_t> width_bytes{};
        std::string address_expr{};
        address_class address_kind{address_class::none};
        bool may_load{false};
        bool may_store{false};
        std::optional<std::string> base_reg{};
        std::optional<std::string> index_reg{};
        std::optional<int> scale{};
        std::optional<int64_t> displacement{};
        std::optional<std::string> symbol{};
        std::optional<size_t> alias_group{};
        std::vector<size_t> ir_line_hints{};
        std::optional<uint64_t> runtime_address{};
        std::optional<std::string> observed_value{};
        value_status observed_value_status{value_status::unknown};
        value_source observed_value_source{value_source::inferred_none};
        size_t value_variation_count{};
        std::vector<std::string> trace_samples{};
    };

    struct summary {
        size_t memory_ops{};
        size_t loads{};
        size_t stores{};
        size_t rmw{};
        size_t stack{};
        size_t globals{};
        size_t unknown{};
    };

    struct address_parse {
        std::string expression{};
        address_class klass{address_class::none};
        std::optional<std::string> base{};
        std::optional<std::string> index{};
        std::optional<int> scale{};
        std::optional<int64_t> displacement{};
        std::optional<std::string> symbol{};
    };

    inline constexpr std::string_view to_string(access_kind kind) {
        switch (kind) {
            case access_kind::none:
                return "none"sv;
            case access_kind::load:
                return "load"sv;
            case access_kind::store:
                return "store"sv;
            case access_kind::rmw:
                return "rmw"sv;
        }
        return "none"sv;
    }

    inline constexpr std::string_view to_string(address_class klass) {
        switch (klass) {
            case address_class::none:
                return "none"sv;
            case address_class::stack:
                return "stack"sv;
            case address_class::global:
                return "global"sv;
            case address_class::pc_relative:
                return "pc_relative"sv;
            case address_class::register_indirect:
                return "indirect"sv;
            case address_class::unknown:
                return "unknown"sv;
        }
        return "unknown"sv;
    }

    inline constexpr std::string_view to_string(value_status status) {
        switch (status) {
            case value_status::unknown:
                return "unknown"sv;
            case value_status::known:
                return "known"sv;
            case value_status::varied:
                return "varied"sv;
        }
        return "unknown"sv;
    }

    inline constexpr std::string_view to_string(value_source source) {
        switch (source) {
            case value_source::inferred_none:
                return "inferred_none"sv;
            case value_source::runtime_trace_exact:
                return "runtime_trace_exact"sv;
            case value_source::runtime_trace_sampled:
                return "runtime_trace_sampled"sv;
        }
        return "inferred_none"sv;
    }

    inline constexpr std::string_view trim_ascii(std::string_view value) {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.remove_prefix(1U);
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.remove_suffix(1U);
        }
        return value;
    }

    inline std::string to_lower_ascii(std::string_view value) {
        auto out = std::string{};
        out.reserve(value.size());
        for (auto c : value) {
            out.push_back(utils::char_tolower(c));
        }
        return out;
    }

    inline std::string_view first_token(std::string_view value) {
        value = trim_ascii(value);
        if (value.empty()) {
            return {};
        }
        auto split = value.find_first_of(" \t\r\n");
        return split == std::string_view::npos ? value : value.substr(0U, split);
    }

    inline std::string extract_mnemonic(std::string_view instruction) {
        auto token = first_token(instruction);
        while (!token.empty() && (token.back() == ':' || token.back() == ',')) {
            token.remove_suffix(1U);
        }
        return to_lower_ascii(token);
    }

    inline std::vector<std::string_view> split_operands(std::string_view instruction) {
        auto operands = trim_ascii(instruction.substr(first_token(instruction).size()));
        auto out = std::vector<std::string_view>{};
        if (operands.empty()) {
            return out;
        }

        auto cursor = size_t{0U};
        auto start = size_t{0U};
        auto bracket_depth = int{0};
        auto paren_depth = int{0};
        while (cursor < operands.size()) {
            auto c = operands[cursor];
            if (c == '[') {
                ++bracket_depth;
            }
            else if (c == ']') {
                bracket_depth = std::max(0, bracket_depth - 1);
            }
            else if (c == '(') {
                ++paren_depth;
            }
            else if (c == ')') {
                paren_depth = std::max(0, paren_depth - 1);
            }
            else if (c == ',' && bracket_depth == 0 && paren_depth == 0) {
                out.push_back(trim_ascii(operands.substr(start, cursor - start)));
                start = cursor + 1U;
            }
            ++cursor;
        }
        if (start <= operands.size()) {
            out.push_back(trim_ascii(operands.substr(start)));
        }
        while (!out.empty() && out.back().empty()) {
            out.pop_back();
        }
        return out;
    }

    inline bool parse_signed_integer(std::string_view text, int64_t& out) {
        text = trim_ascii(text);
        if (text.empty()) {
            return false;
        }

        auto sign = int64_t{1};
        if (text.front() == '+') {
            text.remove_prefix(1U);
        }
        else if (text.front() == '-') {
            sign = -1;
            text.remove_prefix(1U);
        }
        if (text.empty()) {
            return false;
        }

        auto base = 10;
        if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
            base = 16;
            text.remove_prefix(2U);
        }
        if (text.empty()) {
            return false;
        }

        auto value = int64_t{0};
        auto first = text.data();
        auto last = text.data() + text.size();
        auto [ptr, ec] = std::from_chars(first, last, value, base);
        if (ec != std::errc{} || ptr != last) {
            return false;
        }
        out = value * sign;
        return true;
    }

    inline bool is_register_token_x86(std::string_view token) {
        auto lower = to_lower_ascii(token);
        static constexpr auto known = std::array{
                "rax"sv,  "rbx"sv,  "rcx"sv,  "rdx"sv,  "rsi"sv,  "rdi"sv,  "rbp"sv,  "rsp"sv,  "rip"sv,  "eax"sv,
                "ebx"sv,  "ecx"sv,  "edx"sv,  "esi"sv,  "edi"sv,  "ebp"sv,  "esp"sv,  "eip"sv,  "ax"sv,   "bx"sv,
                "cx"sv,   "dx"sv,   "si"sv,   "di"sv,   "bp"sv,   "sp"sv,   "al"sv,   "ah"sv,   "bl"sv,   "bh"sv,
                "cl"sv,   "ch"sv,   "dl"sv,   "dh"sv,   "xmm0"sv, "xmm1"sv, "xmm2"sv, "xmm3"sv, "xmm4"sv, "xmm5"sv,
                "xmm6"sv, "xmm7"sv, "ymm0"sv, "ymm1"sv, "ymm2"sv, "ymm3"sv, "ymm4"sv, "ymm5"sv, "ymm6"sv, "ymm7"sv,
                "zmm0"sv, "zmm1"sv, "zmm2"sv, "zmm3"sv, "zmm4"sv, "zmm5"sv, "zmm6"sv, "zmm7"sv};
        if (std::ranges::find(known, std::string_view{lower}) != known.end()) {
            return true;
        }
        if (lower.size() >= 2U && lower[0] == 'r') {
            auto tail = std::string_view{lower}.substr(1U);
            if (!tail.empty() && std::all_of(tail.begin(), tail.end(), [](char c) { return c >= '0' && c <= '9'; })) {
                return true;
            }
            if (tail.size() >= 2U && (tail.back() == 'd' || tail.back() == 'w' || tail.back() == 'b')) {
                tail.remove_suffix(1U);
                return !tail.empty() &&
                       std::all_of(tail.begin(), tail.end(), [](char c) { return c >= '0' && c <= '9'; });
            }
        }
        return false;
    }

    inline bool is_register_token_arm(std::string_view token) {
        auto lower = to_lower_ascii(token);
        if (lower == "sp"sv || lower == "fp"sv || lower == "lr"sv || lower == "pc"sv || lower == "xzr"sv ||
            lower == "wzr"sv) {
            return true;
        }
        if (lower.size() >= 2U && (lower[0] == 'x' || lower[0] == 'w' || lower[0] == 'v' || lower[0] == 'q' ||
                                   lower[0] == 'd' || lower[0] == 's' || lower[0] == 'h' || lower[0] == 'b')) {
            auto tail = lower.substr(1U);
            return !tail.empty() && std::all_of(tail.begin(), tail.end(), [](char c) { return c >= '0' && c <= '9'; });
        }
        return false;
    }

    inline std::optional<std::string> detect_symbol_token(std::string_view token) {
        token = trim_ascii(token);
        if (token.empty()) {
            return std::nullopt;
        }
        while (!token.empty() && (token.front() == '<' || token.front() == '(' || token.front() == '[')) {
            token.remove_prefix(1U);
        }
        while (!token.empty() &&
               (token.back() == '>' || token.back() == ')' || token.back() == ']' || token.back() == ',')) {
            token.remove_suffix(1U);
        }
        if (token.empty()) {
            return std::nullopt;
        }
        if ((token.front() >= '0' && token.front() <= '9') || token.front() == '#') {
            return std::nullopt;
        }
        if (token.size() > 2U && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
            return std::nullopt;
        }
        auto has_alpha = false;
        for (auto c : token) {
            if (std::isalpha(static_cast<unsigned char>(c)) != 0) {
                has_alpha = true;
                continue;
            }
            if (std::isdigit(static_cast<unsigned char>(c)) != 0 || c == '_' || c == ':' || c == '$' || c == '.' ||
                c == '@') {
                continue;
            }
            return std::nullopt;
        }
        if (!has_alpha) {
            return std::nullopt;
        }
        token = symbols::strip_symbol_addendum(token);
        if (token.empty()) {
            return std::nullopt;
        }
        return std::string{token};
    }

    inline std::optional<std::string_view> extract_bracket_expression(std::string_view instruction) {
        auto open = instruction.find('[');
        if (open == std::string_view::npos) {
            return std::nullopt;
        }
        auto close = instruction.find(']', open + 1U);
        if (close == std::string_view::npos || close <= open) {
            return std::nullopt;
        }
        return instruction.substr(open, close - open + 1U);
    }

    inline bool operand_contains_pointer_keyword_x86(std::string_view operand) {
        auto lower = to_lower_ascii(operand);
        return lower.find(" ptr"sv) != std::string::npos || lower.starts_with("ptr "sv) || lower.ends_with(" ptr"sv);
    }

    inline bool is_memory_operand_x86(std::string_view operand) {
        if (extract_bracket_expression(operand).has_value()) {
            return true;
        }
        return operand_contains_pointer_keyword_x86(operand);
    }

    inline std::optional<std::string> detect_angle_symbol_token(std::string_view instruction) {
        auto scan_pos = instruction.size();
        while (scan_pos > 0U) {
            auto open = instruction.rfind('<', scan_pos - 1U);
            if (open == std::string_view::npos || open + 1U >= instruction.size()) {
                break;
            }
            auto close = instruction.find('>', open + 1U);
            if (close == std::string_view::npos || close <= open + 1U) {
                scan_pos = open;
                continue;
            }
            auto token = instruction.substr(open + 1U, close - open - 1U);
            if (auto parsed = detect_symbol_token(token); parsed.has_value()) {
                return parsed;
            }
            scan_pos = open;
        }
        return std::nullopt;
    }

    inline std::optional<address_parse> parse_address_x86(std::string_view instruction) {
        auto mnemonic = extract_mnemonic(instruction);
        if (mnemonic == "push"sv || mnemonic == "pop"sv || mnemonic == "call"sv || mnemonic == "ret"sv) {
            return address_parse{
                    .expression = "[rsp]",
                    .klass = address_class::stack,
                    .base = std::string{"rsp"},
                    .index = std::nullopt,
                    .scale = 1,
                    .displacement = 0,
                    .symbol = std::nullopt};
        }

        auto operands = split_operands(instruction);
        auto bracket = std::optional<std::string_view>{};
        auto pointer_operand = std::optional<std::string_view>{};
        for (auto operand : operands) {
            if (!bracket.has_value()) {
                bracket = extract_bracket_expression(operand);
            }
            if (!pointer_operand.has_value() && operand_contains_pointer_keyword_x86(operand)) {
                pointer_operand = operand;
            }
        }

        if (!bracket.has_value() && !pointer_operand.has_value()) {
            return std::nullopt;
        }

        auto parsed = address_parse{};
        if (bracket.has_value()) {
            parsed.expression = std::string{trim_ascii(*bracket)};
        }
        else {
            parsed.expression = std::string{trim_ascii(*pointer_operand)};
        }
        parsed.klass = address_class::register_indirect;

        if (bracket.has_value()) {
            auto inside = trim_ascii(bracket->substr(1U, bracket->size() - 2U));
            auto cursor = size_t{0U};
            auto sign = int64_t{1};
            while (cursor < inside.size()) {
                while (cursor < inside.size() && std::isspace(static_cast<unsigned char>(inside[cursor])) != 0) {
                    ++cursor;
                }
                if (cursor >= inside.size()) {
                    break;
                }

                if (inside[cursor] == '+') {
                    sign = 1;
                    ++cursor;
                    continue;
                }
                if (inside[cursor] == '-') {
                    sign = -1;
                    ++cursor;
                    continue;
                }

                auto end = cursor;
                while (end < inside.size() && inside[end] != '+' && inside[end] != '-') {
                    ++end;
                }
                auto term = trim_ascii(inside.substr(cursor, end - cursor));
                cursor = end;
                if (term.empty()) {
                    continue;
                }

                if (auto star = term.find('*'); star != std::string_view::npos) {
                    auto lhs = trim_ascii(term.substr(0U, star));
                    auto rhs = trim_ascii(term.substr(star + 1U));
                    auto reg = std::string_view{};
                    auto factor = int64_t{1};
                    if (is_register_token_x86(lhs)) {
                        reg = lhs;
                        (void)parse_signed_integer(rhs, factor);
                    }
                    else if (is_register_token_x86(rhs)) {
                        reg = rhs;
                        (void)parse_signed_integer(lhs, factor);
                    }
                    if (!reg.empty()) {
                        parsed.index = std::string{reg};
                        parsed.scale = static_cast<int>(std::max<int64_t>(1, std::abs(factor)));
                        continue;
                    }
                }

                if (is_register_token_x86(term)) {
                    if (!parsed.base.has_value()) {
                        parsed.base = std::string{term};
                    }
                    else if (!parsed.index.has_value()) {
                        parsed.index = std::string{term};
                        parsed.scale = 1;
                    }
                    continue;
                }

                auto immediate = int64_t{};
                if (parse_signed_integer(term, immediate)) {
                    auto combined = sign * immediate;
                    parsed.displacement = parsed.displacement.value_or(0) + combined;
                    continue;
                }

                if (auto symbol = detect_symbol_token(term); symbol.has_value()) {
                    parsed.symbol = *symbol;
                }
            }
        }
        else if (pointer_operand.has_value()) {
            if (auto symbol = detect_symbol_token(*pointer_operand); symbol.has_value()) {
                parsed.symbol = *symbol;
            }
        }

        if (!parsed.symbol.has_value()) {
            parsed.symbol = detect_angle_symbol_token(instruction);
        }

        auto lower_expr = to_lower_ascii(parsed.expression);
        if (lower_expr.find("rbp"sv) != std::string::npos || lower_expr.find("rsp"sv) != std::string::npos ||
            lower_expr.find("ebp"sv) != std::string::npos || lower_expr.find("esp"sv) != std::string::npos) {
            parsed.klass = address_class::stack;
        }
        else if (lower_expr.find("rip"sv) != std::string::npos || lower_expr.find("eip"sv) != std::string::npos) {
            parsed.klass = address_class::pc_relative;
        }
        else if (parsed.symbol.has_value()) {
            parsed.klass = address_class::global;
            if (!bracket.has_value()) {
                parsed.expression = "[{}]"_format(*parsed.symbol);
            }
        }

        return parsed;
    }

    inline std::optional<std::string> detect_arm_reloc_symbol(std::string_view instruction) {
        auto page = instruction.find("@PAGE"sv);
        if (page == std::string_view::npos) {
            page = instruction.find("@PAGEOFF"sv);
        }
        if (page == std::string_view::npos || page == 0U) {
            return std::nullopt;
        }
        auto start = page;
        while (start > 0U) {
            auto c = instruction[start - 1U];
            auto valid = std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '$' || c == '.';
            if (!valid) {
                break;
            }
            --start;
        }
        if (start >= page) {
            return std::nullopt;
        }
        return std::string{instruction.substr(start, page - start)};
    }

    inline std::optional<address_parse> parse_address_arm(std::string_view instruction) {
        auto bracket = extract_bracket_expression(instruction);
        if (!bracket.has_value()) {
            return std::nullopt;
        }

        auto parsed = address_parse{};
        parsed.expression = std::string{trim_ascii(*bracket)};
        parsed.klass = address_class::register_indirect;

        auto inside = trim_ascii(bracket->substr(1U, bracket->size() - 2U));
        auto parts = std::vector<std::string_view>{};
        auto cursor = size_t{0U};
        auto start = size_t{0U};
        while (cursor < inside.size()) {
            if (inside[cursor] == ',') {
                parts.push_back(trim_ascii(inside.substr(start, cursor - start)));
                start = cursor + 1U;
            }
            ++cursor;
        }
        parts.push_back(trim_ascii(inside.substr(start)));

        if (!parts.empty() && is_register_token_arm(parts[0])) {
            parsed.base = std::string{parts[0]};
        }

        if (parts.size() >= 2U) {
            auto second = parts[1];
            if (!second.empty() && second.front() == '#') {
                second.remove_prefix(1U);
                auto displacement = int64_t{};
                if (parse_signed_integer(second, displacement)) {
                    parsed.displacement = displacement;
                }
            }
            else if (is_register_token_arm(second)) {
                parsed.index = std::string{second};
                parsed.scale = 1;
            }
        }

        if (parts.size() >= 3U) {
            auto third = to_lower_ascii(parts[2]);
            auto marker = std::string_view{"lsl"};
            auto pos = std::string_view{third}.find(marker);
            if (pos != std::string_view::npos) {
                auto shift_text = trim_ascii(std::string_view{third}.substr(pos + marker.size()));
                if (!shift_text.empty() && shift_text.front() == '#') {
                    shift_text.remove_prefix(1U);
                }
                auto shift = int64_t{};
                if (parse_signed_integer(shift_text, shift) && shift >= 0 && shift < 8) {
                    parsed.scale = 1 << shift;
                }
            }
        }

        parsed.symbol = detect_arm_reloc_symbol(instruction);

        auto base_lower = parsed.base.has_value() ? to_lower_ascii(*parsed.base) : std::string{};
        if (base_lower == "sp"sv || base_lower == "fp"sv || base_lower == "x29"sv || base_lower == "w29"sv) {
            parsed.klass = address_class::stack;
        }
        else if (parsed.symbol.has_value()) {
            parsed.klass = address_class::global;
        }

        return parsed;
    }

    inline std::optional<address_parse> parse_address(std::string_view instruction) {
        if constexpr (platform::is_arm64) {
            return parse_address_arm(instruction);
        }
        return parse_address_x86(instruction);
    }

    inline std::optional<size_t> infer_width_x86(std::string_view instruction) {
        auto parse_register_width_x86 = [](std::string_view token) -> std::optional<size_t> {
            token = trim_ascii(token);
            while (!token.empty() && (token.front() == '*' || token.front() == '%' || token.front() == '[')) {
                token.remove_prefix(1U);
            }
            while (!token.empty() &&
                   (token.back() == ']' || token.back() == ',' || token.back() == ')' || token.back() == '(')) {
                token.remove_suffix(1U);
            }
            if (token.empty()) {
                return std::nullopt;
            }

            auto lower = to_lower_ascii(token);
            if (lower.size() >= 3U && lower.starts_with("xmm"sv)) {
                return 16U;
            }
            if (lower.size() >= 3U && lower.starts_with("ymm"sv)) {
                return 32U;
            }
            if (lower.size() >= 3U && lower.starts_with("zmm"sv)) {
                return 64U;
            }
            if (lower.size() >= 2U && lower.starts_with("mm"sv)) {
                return 8U;
            }

            static constexpr auto byte_regs = std::array{
                    "al"sv,  "ah"sv,  "bl"sv,  "bh"sv,  "cl"sv,   "ch"sv,   "dl"sv,   "dh"sv,   "sil"sv,  "dil"sv,
                    "spl"sv, "bpl"sv, "r8b"sv, "r9b"sv, "r10b"sv, "r11b"sv, "r12b"sv, "r13b"sv, "r14b"sv, "r15b"sv};
            static constexpr auto word_regs = std::array{
                    "ax"sv,
                    "bx"sv,
                    "cx"sv,
                    "dx"sv,
                    "si"sv,
                    "di"sv,
                    "sp"sv,
                    "bp"sv,
                    "r8w"sv,
                    "r9w"sv,
                    "r10w"sv,
                    "r11w"sv,
                    "r12w"sv,
                    "r13w"sv,
                    "r14w"sv,
                    "r15w"sv};
            static constexpr auto dword_regs = std::array{
                    "eax"sv,
                    "ebx"sv,
                    "ecx"sv,
                    "edx"sv,
                    "esi"sv,
                    "edi"sv,
                    "esp"sv,
                    "ebp"sv,
                    "r8d"sv,
                    "r9d"sv,
                    "r10d"sv,
                    "r11d"sv,
                    "r12d"sv,
                    "r13d"sv,
                    "r14d"sv,
                    "r15d"sv};
            static constexpr auto qword_regs = std::array{
                    "rax"sv,
                    "rbx"sv,
                    "rcx"sv,
                    "rdx"sv,
                    "rsi"sv,
                    "rdi"sv,
                    "rsp"sv,
                    "rbp"sv,
                    "r8"sv,
                    "r9"sv,
                    "r10"sv,
                    "r11"sv,
                    "r12"sv,
                    "r13"sv,
                    "r14"sv,
                    "r15"sv,
                    "rip"sv};

            if (std::ranges::find(byte_regs, std::string_view{lower}) != byte_regs.end()) {
                return 1U;
            }
            if (std::ranges::find(word_regs, std::string_view{lower}) != word_regs.end()) {
                return 2U;
            }
            if (std::ranges::find(dword_regs, std::string_view{lower}) != dword_regs.end()) {
                return 4U;
            }
            if (std::ranges::find(qword_regs, std::string_view{lower}) != qword_regs.end()) {
                return 8U;
            }
            return std::nullopt;
        };

        auto lower = to_lower_ascii(instruction);
        if (lower.find("zmmword ptr"sv) != std::string::npos) {
            return 64U;
        }
        if (lower.find("ymmword ptr"sv) != std::string::npos) {
            return 32U;
        }
        if (lower.find("xmmword ptr"sv) != std::string::npos) {
            return 16U;
        }
        if (lower.find("qword ptr"sv) != std::string::npos) {
            return 8U;
        }
        if (lower.find("dword ptr"sv) != std::string::npos) {
            return 4U;
        }
        if (lower.find("word ptr"sv) != std::string::npos) {
            return 2U;
        }
        if (lower.find("byte ptr"sv) != std::string::npos) {
            return 1U;
        }

        auto mnemonic = extract_mnemonic(instruction);
        if (mnemonic == "push"sv || mnemonic == "pop"sv || mnemonic == "call"sv || mnemonic == "ret"sv) {
            return 8U;
        }

        auto operands = split_operands(instruction);
        auto is_mem = [](std::string_view operand) {
            return operand.find('[') != std::string_view::npos && operand.find(']') != std::string_view::npos;
        };
        for (const auto operand : operands) {
            if (is_mem(operand)) {
                continue;
            }
            if (auto width = parse_register_width_x86(operand); width.has_value()) {
                return width;
            }
        }

        return std::nullopt;
    }

    inline std::optional<size_t> infer_width_arm(std::string_view instruction) {
        auto mnemonic = extract_mnemonic(instruction);
        if (mnemonic.ends_with("b"sv)) {
            return 1U;
        }
        if (mnemonic.ends_with("h"sv)) {
            return 2U;
        }

        auto operands = split_operands(instruction);
        if (operands.empty()) {
            return std::nullopt;
        }
        auto first = trim_ascii(operands.front());
        if (first.empty()) {
            return std::nullopt;
        }
        auto first_lower = to_lower_ascii(first);
        if (first_lower[0] == 'w' || first_lower[0] == 's') {
            return 4U;
        }
        if (first_lower[0] == 'x' || first_lower[0] == 'd') {
            return 8U;
        }
        if (first_lower[0] == 'q' || first_lower[0] == 'v') {
            return 16U;
        }
        return std::nullopt;
    }

    inline std::optional<size_t> infer_width(std::string_view instruction) {
        if constexpr (platform::is_arm64) {
            return infer_width_arm(instruction);
        }
        return infer_width_x86(instruction);
    }

    inline access_kind infer_access_from_operands_x86(std::string_view instruction) {
        auto mnemonic = extract_mnemonic(instruction);
        if (mnemonic == "push"sv || mnemonic == "call"sv) {
            return access_kind::store;
        }
        if (mnemonic == "pop"sv || mnemonic == "ret"sv) {
            return access_kind::load;
        }

        auto operands = split_operands(instruction);
        if (operands.empty()) {
            return access_kind::none;
        }
        auto dst_mem = !operands.empty() && is_memory_operand_x86(operands[0]);
        auto src_mem = operands.size() >= 2U && is_memory_operand_x86(operands[1]);
        if (dst_mem && src_mem) {
            return access_kind::rmw;
        }
        auto is_rmw_mnemonic = [&](std::string_view value) {
            static constexpr auto rmw =
                    std::array{"inc"sv, "dec"sv, "not"sv, "neg"sv, "add"sv, "sub"sv, "adc"sv,  "sbb"sv,
                               "and"sv, "or"sv,  "xor"sv, "btc"sv, "btr"sv, "bts"sv, "rol"sv,  "ror"sv,
                               "rcl"sv, "rcr"sv, "shl"sv, "shr"sv, "sal"sv, "sar"sv, "xadd"sv, "cmpxchg"sv};
            return std::ranges::find(rmw, value) != rmw.end();
        };
        if (dst_mem && is_rmw_mnemonic(mnemonic)) {
            return access_kind::rmw;
        }
        if (dst_mem) {
            return access_kind::store;
        }
        if (src_mem) {
            return access_kind::load;
        }
        return access_kind::none;
    }

    inline access_kind infer_access_from_operands_arm(std::string_view instruction) {
        auto mnemonic = extract_mnemonic(instruction);
        auto has_mem =
                instruction.find('[') != std::string_view::npos && instruction.find(']') != std::string_view::npos;
        if (!has_mem) {
            return access_kind::none;
        }

        auto is_rmw_mnemonic = [&](std::string_view value) {
            if (value.starts_with("cas"sv)) {
                return true;
            }
            static constexpr auto prefixes = std::array{
                    "ldadd"sv,
                    "ldclr"sv,
                    "ldeor"sv,
                    "ldset"sv,
                    "ldsmax"sv,
                    "ldsmin"sv,
                    "ldumax"sv,
                    "ldumin"sv,
                    "swp"sv};
            for (const auto prefix : prefixes) {
                if (value.starts_with(prefix)) {
                    return true;
                }
            }
            return false;
        };
        if (is_rmw_mnemonic(mnemonic)) {
            return access_kind::rmw;
        }
        if (mnemonic.starts_with("ld"sv)) {
            return access_kind::load;
        }
        if (mnemonic.starts_with("st"sv)) {
            return access_kind::store;
        }

        return access_kind::none;
    }

    inline access_kind infer_access_kind(std::string_view instruction, bool may_load, bool may_store) {
        if (may_load && may_store) {
            return access_kind::rmw;
        }
        if (may_load) {
            return access_kind::load;
        }
        if (may_store) {
            return access_kind::store;
        }

        if constexpr (platform::is_arm64) {
            return infer_access_from_operands_arm(instruction);
        }
        return infer_access_from_operands_x86(instruction);
    }

    inline std::vector<row> build_rows(std::span<const row_input> inputs) {
        auto out = std::vector<row>{};
        out.reserve(inputs.size());

        for (const auto& input : inputs) {
            auto parsed = parse_address(input.instruction);
            auto access = infer_access_kind(input.instruction, input.may_load, input.may_store);

            if (access == access_kind::none && !parsed.has_value()) {
                continue;
            }

            auto mem_row =
                    row{.line = input.line,
                        .offset = std::string{input.offset},
                        .encodings = std::string{input.encodings},
                        .instruction = std::string{trim_ascii(input.instruction)},
                        .mnemonic = extract_mnemonic(input.instruction),
                        .access = access,
                        .width_bytes = infer_width(input.instruction),
                        .address_expr = parsed.has_value() ? parsed->expression : std::string{},
                        .address_kind = parsed.has_value() ? parsed->klass : address_class::none,
                        .may_load = input.may_load,
                        .may_store = input.may_store,
                        .base_reg = parsed.has_value() ? parsed->base : std::nullopt,
                        .index_reg = parsed.has_value() ? parsed->index : std::nullopt,
                        .scale = parsed.has_value() ? parsed->scale : std::nullopt,
                        .displacement = parsed.has_value() ? parsed->displacement : std::nullopt,
                        .symbol = parsed.has_value() ? parsed->symbol : std::nullopt};

            if (mem_row.address_kind == address_class::none) {
                mem_row.address_kind = address_class::unknown;
            }

            out.push_back(std::move(mem_row));
        }

        return out;
    }

    inline summary summarize(std::span<const row> rows) {
        auto out = summary{};
        out.memory_ops = rows.size();
        for (const auto& row : rows) {
            switch (row.access) {
                case access_kind::load:
                    ++out.loads;
                    break;
                case access_kind::store:
                    ++out.stores;
                    break;
                case access_kind::rmw:
                    ++out.rmw;
                    break;
                case access_kind::none:
                    break;
            }

            switch (row.address_kind) {
                case address_class::stack:
                    ++out.stack;
                    break;
                case address_class::global:
                case address_class::pc_relative:
                    ++out.globals;
                    break;
                case address_class::none:
                case address_class::register_indirect:
                case address_class::unknown:
                    ++out.unknown;
                    break;
            }
        }
        return out;
    }

}  // namespace sontag::internal::mem
