#pragma once

#include "utils.hpp"

#include <format>

namespace sontag {
    template <typename T, typename U = std::remove_cvref_t<T>>
    concept to_string_formattable = U::to_string_formattable && requires(U a) {
        { a.to_string() } -> std::convertible_to<std::string_view>;
    };

    namespace detail {
        template <size_t N>
        struct string_literal {
            std::array<char, N> str;

            consteval string_literal(const char (&s)[N]) { std::ranges::copy(s, s + N, str.begin()); }
            constexpr std::string_view sv() const { return {str.data(), N - 1}; }
        };

        template <string_literal Format>
        struct format_wrapper {
            consteval format_wrapper() = default;

            template <typename... T>
            constexpr auto operator()(T&&... args) && {
                return std::format(Format.sv(), std::forward<T>(args)...);
            }
        };
    }  // namespace detail

    namespace literals {
        template <detail::string_literal Format>
        inline consteval auto operator""_format() {
            return detail::format_wrapper<Format>{};
        }
    }  // namespace literals
}  // namespace sontag

namespace std {
    template <sontag::to_string_formattable T>
    struct formatter<T, char> : formatter<std::string_view> {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const {
            return formatter<std::string_view>::format(val.to_string(), ctx);
        }
    };
}  // namespace std
