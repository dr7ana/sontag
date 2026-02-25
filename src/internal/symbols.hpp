#pragma once

#include "sontag/utils.hpp"

#include <algorithm>
#include <optional>
#include <string_view>

namespace sontag::internal::symbols {

    using namespace std::string_view_literals;

    inline constexpr std::string_view trim_ascii(std::string_view value) noexcept {
        while (!value.empty() &&
               (value.front() == ' ' || value.front() == '\t' || value.front() == '\r' || value.front() == '\n')) {
            value.remove_prefix(1U);
        }
        while (!value.empty() &&
               (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n')) {
            value.remove_suffix(1U);
        }
        return value;
    }

    inline constexpr bool ascii_is_hex_digit(char c) noexcept {
        auto lower = utils::char_tolower(c);
        return (c >= '0' && c <= '9') || (lower >= 'a' && lower <= 'f');
    }

    inline constexpr bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept {
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

    inline constexpr bool contains_ascii_ci(std::string_view haystack, std::string_view needle) noexcept {
        if (needle.empty() || haystack.size() < needle.size()) {
            return false;
        }
        for (size_t i = 0U; i + needle.size() <= haystack.size(); ++i) {
            if (ascii_iequals(haystack.substr(i, needle.size()), needle)) {
                return true;
            }
        }
        return false;
    }

    inline constexpr std::string_view strip_one_leading_underscore(std::string_view symbol) noexcept {
        if (!symbol.empty() && symbol.front() == '_') {
            symbol.remove_prefix(1U);
        }
        return symbol;
    }

    inline constexpr std::optional<std::string_view> extract_symbol_addendum(std::string_view symbol) noexcept {
        auto at = symbol.find('@');
        if (at == std::string_view::npos || at + 1U >= symbol.size()) {
            return std::nullopt;
        }
        return symbol.substr(at + 1U);
    }

    inline constexpr std::string_view strip_symbol_addendum(std::string_view symbol) noexcept {
        auto at = symbol.find('@');
        if (at != std::string_view::npos && at > 0U) {
            symbol = symbol.substr(0U, at);
        }
        return symbol;
    }

    inline constexpr std::string_view strip_symbol_offset_suffix(std::string_view symbol) noexcept {
        auto plus = symbol.rfind("+0x");
        if (plus == std::string_view::npos || plus == 0U) {
            return symbol;
        }
        auto suffix = symbol.substr(plus + 3U);
        if (!suffix.empty() && std::ranges::all_of(suffix, [](char c) { return ascii_is_hex_digit(c); })) {
            return symbol.substr(0U, plus);
        }
        return symbol;
    }

    inline constexpr std::string_view canonical_symbol_for_match(std::string_view symbol) noexcept {
        symbol = trim_ascii(symbol);
        symbol = strip_one_leading_underscore(symbol);
        symbol = strip_symbol_addendum(symbol);
        symbol = strip_symbol_offset_suffix(symbol);
        symbol = strip_one_leading_underscore(symbol);
        return trim_ascii(symbol);
    }

    inline constexpr bool symbol_names_equivalent(std::string_view lhs, std::string_view rhs) noexcept {
        if (lhs == rhs) {
            return true;
        }
        return canonical_symbol_for_match(lhs) == canonical_symbol_for_match(rhs);
    }

    inline constexpr std::string_view normalize_symbol_candidate(std::string_view candidate) noexcept {
        candidate = trim_ascii(candidate);
        while (!candidate.empty() && (candidate.back() == ' ' || candidate.back() == '\t' || candidate.back() == ',')) {
            candidate.remove_suffix(1U);
        }
        candidate = strip_symbol_addendum(candidate);
        candidate = strip_symbol_offset_suffix(candidate);
        while (!candidate.empty() && (candidate.back() == ' ' || candidate.back() == '\t' || candidate.back() == ',')) {
            candidate.remove_suffix(1U);
        }
        return trim_ascii(candidate);
    }

    inline constexpr bool addendum_implies_stub(std::string_view addendum) noexcept {
        return contains_ascii_ci(addendum, "plt");
    }

    inline constexpr bool addendum_implies_indirect(std::string_view addendum) noexcept {
        return contains_ascii_ci(addendum, "got") || contains_ascii_ci(addendum, "indirect");
    }

}  // namespace sontag::internal::symbols
