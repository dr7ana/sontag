#include "utils.hpp"

namespace sontag::test {
    using namespace std::string_view_literals;

    TEST_CASE("001: cxx_standard parsing and fallback", "[001][config]") {
        cxx_standard standard = cxx_standard::cxx20;

        REQUIRE(try_parse_cxx_standard("c++20"sv, standard));
        CHECK(standard == cxx_standard::cxx20);

        REQUIRE(try_parse_cxx_standard("CXX23"sv, standard));
        CHECK(standard == cxx_standard::cxx23);

        REQUIRE(try_parse_cxx_standard("c++2C"sv, standard));
        CHECK(standard == cxx_standard::cxx2c);

        CHECK_FALSE(try_parse_cxx_standard("c++17"sv, standard));
        CHECK(parse_cxx_standard("c++17"sv) == cxx_standard::cxx23);
    }

    TEST_CASE("001: mode and optimization parsing", "[001][config]") {
        output_mode out_mode = output_mode::table;
        color_mode clr_mode = color_mode::automatic;
        optimization_level opt = optimization_level::o2;

        REQUIRE(try_parse_output_mode("JSON"sv, out_mode));
        CHECK(out_mode == output_mode::json);
        REQUIRE(try_parse_output_mode("table"sv, out_mode));
        CHECK(out_mode == output_mode::table);
        CHECK_FALSE(try_parse_output_mode("yaml"sv, out_mode));

        REQUIRE(try_parse_color_mode("always"sv, clr_mode));
        CHECK(clr_mode == color_mode::always);
        REQUIRE(try_parse_color_mode("NEVER"sv, clr_mode));
        CHECK(clr_mode == color_mode::never);
        CHECK_FALSE(try_parse_color_mode("sometimes"sv, clr_mode));

        REQUIRE(try_parse_optimization_level("o3"sv, opt));
        CHECK(opt == optimization_level::o3);
        REQUIRE(try_parse_optimization_level("OFAST"sv, opt));
        CHECK(opt == optimization_level::ofast);
        REQUIRE(try_parse_optimization_level("2"sv, opt));
        CHECK(opt == optimization_level::o2);
        REQUIRE(try_parse_optimization_level("fast"sv, opt));
        CHECK(opt == optimization_level::ofast);
        CHECK_FALSE(try_parse_optimization_level("Og"sv, opt));
    }

    TEST_CASE("001: enum string conversion", "[001][config]") {
        CHECK(to_string(cxx_standard::cxx20) == "c++20"sv);
        CHECK(to_string(cxx_standard::cxx23) == "c++23"sv);
        CHECK(to_string(cxx_standard::cxx2c) == "c++2c"sv);

        CHECK(to_string(output_mode::table) == "table"sv);
        CHECK(to_string(output_mode::json) == "json"sv);

        CHECK(to_string(color_mode::automatic) == "auto"sv);
        CHECK(to_string(color_mode::always) == "always"sv);
        CHECK(to_string(color_mode::never) == "never"sv);

        CHECK(to_string(optimization_level::o0) == "O0"sv);
        CHECK(to_string(optimization_level::o1) == "O1"sv);
        CHECK(to_string(optimization_level::o2) == "O2"sv);
        CHECK(to_string(optimization_level::o3) == "O3"sv);
        CHECK(to_string(optimization_level::ofast) == "Ofast"sv);
        CHECK(to_string(optimization_level::oz) == "Oz"sv);
    }
}  // namespace sontag::test
