#pragma once

#include <algorithm>
#include <charconv>
#include <iostream>
#include <optional>
#include <ranges>
#include <source_location>
#include <string_view>
#include <vector>

namespace sontag {

// Debug logger; no-op on release builds
#ifndef NDEBUG
    constexpr std::string_view sloc_fname(const std::source_location& loc) {
        std::string_view sv{loc.file_name()};
        if (auto p = sv.rfind('/'); p != sv.npos)
            sv.remove_prefix(p + 1);
        return sv;
    }

    inline void prepend_location(std::ostream& os, const std::source_location& loc) {
        os << '[' << sloc_fname(loc) << ':' << loc.line() << "] ";
    }

    template <typename... Args>
    struct debug_log {
        constexpr explicit debug_log(
                Args&&... args, const std::source_location& loc = std::source_location::current()) {
            prepend_location(std::cerr, loc);
            (std::cerr << ... << std::forward<Args>(args)) << std::endl;
        }
    };
#else
    template <typename... Args>
    struct debug_log {
        constexpr explicit debug_log(Args&&...) {}
    };
#endif

    // deduction guide
    template <typename... Args>
    debug_log(Args&&...) -> debug_log<Args...>;

    namespace utils {
        constexpr char char_tolower(char c) {
            if (c >= 'A' && c <= 'Z') {
                return c + ('a' - 'A');
            }
            return c;
        }

        constexpr bool str_case_eq(std::string_view lhs, std::string_view rhs) {
            return std::ranges::equal(
                    lhs | std::views::transform(char_tolower), rhs | std::views::transform(char_tolower));
        }

        namespace detail {
            template <typename T>
            concept arithmetic_type = std::integral<T> || std::floating_point<T>;
        }

        template <detail::arithmetic_type T>
        constexpr std::optional<T> parse_arithmetic(std::string_view input, [[maybe_unused]] int base = 10) {
            T value{};
            std::from_chars_result result;

            if constexpr (std::integral<T>) {
                result = std::from_chars(input.data(), input.data() + input.size(), value, base);
            }
            else {
                result = std::from_chars(input.data(), input.data() + input.size(), value);
            }

            if (result.ec != std::errc{} || result.ptr != input.data() + input.size()) {
                return std::nullopt;
            }

            return {value};
        }

        inline std::string join_with_separator(const std::vector<std::string>& values, std::string_view separator) {
            if (values.empty()) {
                return {};
            }
            return values | std::views::join_with(separator) | std::ranges::to<std::string>();
        }

    }  // namespace utils

}  // namespace sontag
