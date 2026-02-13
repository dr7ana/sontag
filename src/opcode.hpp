#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sontag::opcode {

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
    };

    struct transparent_string_hash {
        using is_transparent = void;

        size_t operator()(std::string_view value) const noexcept { return std::hash<std::string_view>{}(value); }

        size_t operator()(const std::string& value) const noexcept { return std::hash<std::string_view>{}(value); }
    };

    struct transparent_string_equal {
        using is_transparent = void;

        bool operator()(std::string_view lhs, std::string_view rhs) const noexcept { return lhs == rhs; }

        bool operator()(const std::string& lhs, const std::string& rhs) const noexcept { return lhs == rhs; }

        bool operator()(const std::string& lhs, std::string_view rhs) const noexcept { return lhs == rhs; }

        bool operator()(std::string_view lhs, const std::string& rhs) const noexcept { return lhs == rhs; }
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

        size_t size() const { return entries.size(); }

        opcode_uid next_opcode_uid() const { return next_uid; }

        const std::vector<opcode_entry>& opcode_entries() const { return entries; }

        std::optional<std::string_view> mnemonic_for(opcode_uid uid) const {
            if (uid == 0U || uid >= next_uid) {
                return std::nullopt;
            }
            return entries[uid - 1U].mnemonic;
        }

        void clear() {
            next_uid = 1U;
            by_mnemonic.clear();
            entries.clear();
        }

      private:
        opcode_uid next_uid{1U};
        std::unordered_map<std::string, opcode_uid, transparent_string_hash, transparent_string_equal> by_mnemonic{};
        std::vector<opcode_entry> entries{};
    };

    inline std::string_view trim_ascii(std::string_view value) {
        auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string_view::npos) {
            return {};
        }
        auto last = value.find_last_not_of(" \t\r\n");
        return value.substr(first, (last - first) + 1U);
    }

    inline std::string_view first_token(std::string_view value) {
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

    inline bool is_hex_blob_token(std::string_view token) {
        if (token.empty() || token.size() > 16U || (token.size() % 2U) != 0U) {
            return false;
        }
        return std::ranges::all_of(token, [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; });
    }

    inline bool is_label_line(std::string_view line) {
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
        if (!std::isalpha(static_cast<unsigned char>(token.front()))) {
            return {};
        }

        std::string out{};
        out.reserve(token.size());
        std::ranges::transform(token, std::back_inserter(out), [](char c) {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        });
        return out;
    }

    inline std::optional<std::string> extract_opcode_from_line(std::string_view line) {
        auto trimmed = trim_ascii(line);
        if (trimmed.empty() || is_label_line(trimmed)) {
            return std::nullopt;
        }

        auto after_colon = trimmed;
        if (auto colon = trimmed.find(':'); colon != std::string_view::npos) {
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
        return lowered_token;
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
            if (auto mnemonic = extract_opcode_from_line(line)) {
                auto uid = interner.intern(*mnemonic);
                operations.push_back(
                        operation_node{.ordinal = operations.size(), .opcode = uid, .mnemonic = std::move(*mnemonic)});
            }

            if (end == disassembly.size()) {
                break;
            }
            begin = end + 1U;
        }
        return operations;
    }

}  // namespace sontag::opcode
