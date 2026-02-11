#pragma once

#include <algorithm>
#include <iostream>
#include <ranges>
#include <source_location>
#include <string_view>
#include <vector>

namespace sontag {

// Debug logger; no-op on release builds
#ifndef NDEBUG
    inline constexpr std::string_view sloc_fname(const std::source_location& loc) {
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
        inline constexpr char char_tolower(char c) {
            if (c >= 'A' && c <= 'Z') {
                return c + ('a' - 'A');
            }
            return c;
        }

        inline constexpr bool str_case_eq(std::string_view lhs, std::string_view rhs) {
            return std::ranges::equal(
                    lhs | std::views::transform(char_tolower), rhs | std::views::transform(char_tolower));
        }

    }  // namespace utils

}  // namespace sontag
