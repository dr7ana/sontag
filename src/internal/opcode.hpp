#pragma once

#include "sontag/format.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace sontag::opcode {

    using namespace sontag::literals;
    using namespace std::string_view_literals;

    using opcode_uid = uint64_t;

    struct opcode_entry {
        opcode_uid uid{};
        std::string mnemonic{};
    };

    struct operation_node {
        size_t ordinal{};
        opcode_uid opcode{};
        std::string mnemonic{};
        std::string signature{};
    };

    struct operation_stream_input {
        std::string_view name{};
        std::string_view disassembly{};
    };

    struct mapped_operation_stream {
        std::string name{};
        std::vector<operation_node> operations{};
    };

    struct mapped_operation_set {
        std::vector<opcode_entry> opcode_table{};
        std::vector<mapped_operation_stream> streams{};
    };

    struct transparent_string_hash {
        using is_transparent = void;

        constexpr size_t operator()(std::string_view value) const noexcept {
            return std::hash<std::string_view>{}(value);
        }
    };

    struct transparent_string_equal {
        using is_transparent = void;

        constexpr bool operator()(std::string_view lhs, std::string_view rhs) const noexcept { return lhs == rhs; }
    };

    class opcode_interner {
      public:
        opcode_uid intern(std::string_view mnemonic) {
            if (auto it = by_mnemonic.find(mnemonic); it != by_mnemonic.end()) {
                return it->second;
            }

            auto uid = next_uid++;
            auto inserted = by_mnemonic.emplace(std::string{mnemonic}, uid);
            entries.push_back(opcode_entry{.uid = uid, .mnemonic = inserted.first->first});
            return uid;
        }

        [[nodiscard]] constexpr size_t size(this const auto& self) noexcept { return self.entries.size(); }

        [[nodiscard]] constexpr opcode_uid next_opcode_uid(this const auto& self) noexcept { return self.next_uid; }

        [[nodiscard]] constexpr decltype(auto) opcode_entries(this auto&& self) noexcept {
            return static_cast<decltype(self)>(self).entries;
        }

        [[nodiscard]] constexpr std::optional<std::string_view> mnemonic_for(
                this const auto& self, opcode_uid uid) noexcept {
            if (uid == 0U || uid >= self.next_uid) {
                return std::nullopt;
            }
            return self.entries[uid - 1U].mnemonic;
        }

        void reset() noexcept {
            next_uid = 1U;
            by_mnemonic.clear();
            entries.clear();
        }

      private:
        opcode_uid next_uid{1U};
        std::unordered_map<std::string, opcode_uid, transparent_string_hash, transparent_string_equal> by_mnemonic{};
        std::vector<opcode_entry> entries{};
    };

    constexpr bool ascii_is_hex_digit(char c) noexcept {
        return (c >= '0' && c <= '9') || ((c | 0x20) >= 'a' && (c | 0x20) <= 'f');
    }

    constexpr bool ascii_is_alpha(char c) noexcept {
        auto lower = static_cast<char>(c | 0x20);
        return lower >= 'a' && lower <= 'z';
    }

    constexpr char ascii_tolower(char c) noexcept {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
    }

    constexpr std::string_view trim_ascii(std::string_view value) noexcept {
        auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string_view::npos) {
            return {};
        }
        auto last = value.find_last_not_of(" \t\r\n");
        return value.substr(first, (last - first) + 1U);
    }

    constexpr std::string_view first_token(std::string_view value) noexcept {
        value = trim_ascii(value);
        if (value.empty()) {
            return {};
        }

        auto pos = value.find_first_of(" \t");
        if (pos == std::string_view::npos) {
            return value;
        }
        return value.substr(0U, pos);
    }

    constexpr bool is_hex_blob_token(std::string_view token) noexcept {
        if (token.empty() || token.size() > 16U || (token.size() % 2U) != 0U) {
            return false;
        }
        return std::ranges::all_of(token, [](char c) { return ascii_is_hex_digit(c); });
    }

    constexpr bool is_label_line(std::string_view line) noexcept {
        auto trimmed = trim_ascii(line);
        if (!trimmed.ends_with(':')) {
            return false;
        }

        if (trimmed.find('<') != std::string_view::npos && trimmed.find('>') != std::string_view::npos) {
            return true;
        }
        if (trimmed.find(' ') == std::string_view::npos && trimmed.find('\t') == std::string_view::npos) {
            return true;
        }
        return false;
    }

    inline std::string normalize_opcode(std::string_view token) {
        token = trim_ascii(token);
        while (!token.empty() && (token.back() == ',' || token.back() == ':')) {
            token.remove_suffix(1U);
        }
        while (!token.empty() && (token.front() == '*' || token.front() == '%')) {
            token.remove_prefix(1U);
        }

        if (token.empty()) {
            return {};
        }
        if (!ascii_is_alpha(token.front())) {
            return {};
        }

        std::string out{};
        out.reserve(token.size());
        std::ranges::transform(token, std::back_inserter(out), [](char c) { return ascii_tolower(c); });
        return out;
    }

    struct parsed_operation {
        std::string mnemonic{};
        std::string signature{};
    };

    inline std::string normalize_bracket_expression(std::string_view operand) {
        auto open = operand.find('[');
        if (open == std::string_view::npos) {
            return {};
        }
        auto close = operand.find(']', open + 1U);
        if (close == std::string_view::npos || close <= open + 1U) {
            return {};
        }

        auto inside = trim_ascii(operand.substr(open + 1U, close - open - 1U));
        std::string collapsed{};
        collapsed.reserve(inside.size());

        bool previous_space = false;
        for (char c : inside) {
            auto is_space = c == ' ' || c == '\t' || c == '\r' || c == '\n';
            if (is_space) {
                if (!collapsed.empty() && !previous_space) {
                    collapsed.push_back(' ');
                }
                previous_space = true;
                continue;
            }
            collapsed.push_back(ascii_tolower(c));
            previous_space = false;
        }

        while (!collapsed.empty() && collapsed.back() == ' ') {
            collapsed.pop_back();
        }

        if (collapsed.empty()) {
            return {};
        }
        return "[{}]"_format(collapsed);
    }

    inline std::string normalize_operand_head(std::string_view operand) {
        operand = trim_ascii(operand);
        if (operand.empty()) {
            return {};
        }

        while (!operand.empty() && (operand.front() == '*' || operand.front() == '%')) {
            operand.remove_prefix(1U);
            operand = trim_ascii(operand);
        }
        if (operand.empty()) {
            return {};
        }
        if (operand.front() == '[') {
            auto expr = normalize_bracket_expression(operand);
            return expr.empty() ? "[expr]" : expr;
        }

        auto token = first_token(operand);
        token = trim_ascii(token);
        while (!token.empty() && token.back() == ',') {
            token.remove_suffix(1U);
        }
        if (token.empty()) {
            return {};
        }

        auto token_lower = normalize_opcode(token);
        if (token_lower.empty()) {
            token_lower.assign(token.begin(), token.end());
            std::ranges::transform(token_lower, token_lower.begin(), [](char c) { return ascii_tolower(c); });
        }

        static constexpr auto memory_sizes = {
                "byte"sv, "word"sv, "dword"sv, "qword"sv, "xmmword"sv, "ymmword"sv, "zmmword"sv};
        if (std::ranges::find(memory_sizes, token_lower) != memory_sizes.end()) {
            auto rest = trim_ascii(operand.substr(token.size()));
            auto next = normalize_opcode(first_token(rest));
            if (next == "ptr"sv) {
                auto ptr_token = first_token(rest);
                rest = trim_ascii(rest.substr(ptr_token.size()));
            }

            auto expr = normalize_bracket_expression(rest);
            if (!expr.empty()) {
                return "{} {}"_format(token_lower, expr);
            }
        }

        return token_lower;
    }

    inline std::optional<parsed_operation> extract_operation_from_line(std::string_view line) {
        auto trimmed = trim_ascii(line);
        if (trimmed.empty() || is_label_line(trimmed)) {
            return std::nullopt;
        }

        auto after_colon = trimmed;
        if (auto colon = trimmed.find(':'); colon != std::string_view::npos) {
            auto prefix = trim_ascii(trimmed.substr(0U, colon));
            if (prefix.empty() || !std::ranges::all_of(prefix, [](char c) { return ascii_is_hex_digit(c); })) {
                return std::nullopt;
            }
            after_colon = trim_ascii(trimmed.substr(colon + 1U));
        }

        while (true) {
            auto token = first_token(after_colon);
            if (token.empty() || !is_hex_blob_token(token)) {
                break;
            }
            after_colon = trim_ascii(after_colon.substr(token.size()));
        }

        auto token = first_token(after_colon);
        if (token.empty()) {
            return std::nullopt;
        }

        static constexpr auto prefixes = {"lock"sv, "rep"sv, "repe"sv, "repz"sv, "repne"sv, "repnz"sv};
        auto lowered_token = normalize_opcode(token);
        if (lowered_token.empty()) {
            return std::nullopt;
        }

        if (std::ranges::find(prefixes, lowered_token) != prefixes.end()) {
            after_colon = trim_ascii(after_colon.substr(token.size()));
            token = first_token(after_colon);
            lowered_token = normalize_opcode(token);
        }

        if (lowered_token.empty()) {
            return std::nullopt;
        }

        auto signature = std::string{lowered_token};
        auto operands_view = trim_ascii(after_colon.substr(token.size()));
        if (!operands_view.empty()) {
            auto comma = operands_view.find(',');
            auto lhs = comma == std::string_view::npos ? operands_view : operands_view.substr(0U, comma);
            auto rhs = comma == std::string_view::npos ? std::string_view{} : operands_view.substr(comma + 1U);

            auto lhs_head = normalize_operand_head(lhs);
            auto rhs_head = normalize_operand_head(rhs);
            if (!lhs_head.empty()) {
                signature.append(" ");
                signature.append(lhs_head);
                if (!rhs_head.empty()) {
                    signature.append(", ");
                    signature.append(rhs_head);
                }
            }
        }

        return parsed_operation{.mnemonic = std::move(lowered_token), .signature = std::move(signature)};
    }

    inline std::vector<operation_node> parse_operations(std::string_view disassembly, opcode_interner& interner) {
        std::vector<operation_node> operations{};
        size_t begin = 0U;
        while (begin <= disassembly.size()) {
            auto end = disassembly.find('\n', begin);
            if (end == std::string_view::npos) {
                end = disassembly.size();
            }

            auto line = disassembly.substr(begin, end - begin);
            if (auto operation = extract_operation_from_line(line)) {
                auto uid = interner.intern(operation->mnemonic);
                operations.push_back(
                        operation_node{
                                .ordinal = operations.size(),
                                .opcode = uid,
                                .mnemonic = std::move(operation->mnemonic),
                                .signature = std::move(operation->signature)});
            }

            if (end == disassembly.size()) {
                break;
            }
            begin = end + 1U;
        }
        return operations;
    }

    inline mapped_operation_set map_operation_streams(std::span<const operation_stream_input> inputs) {
        auto interner = opcode_interner{};
        auto mapped = mapped_operation_set{};
        mapped.streams.reserve(inputs.size());

        for (const auto& input : inputs) {
            auto operations = parse_operations(input.disassembly, interner);
            mapped.streams.push_back(
                    mapped_operation_stream{.name = std::string{input.name}, .operations = std::move(operations)});
        }

        mapped.opcode_table = interner.opcode_entries();
        return mapped;
    }

}  // namespace sontag::opcode
