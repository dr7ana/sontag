#include "utils.hpp"

namespace sontag::test {

    namespace detail {
        std::vector<char*> to_argv(std::vector<std::string>& args) {
            return args | std::views::transform([](auto& arg) { return arg.data(); }) | std::ranges::to<std::vector>();
        }
    }  // namespace detail

    TEST_CASE("002: parse_cli accepts startup options", "[002][cli]") {
        startup_config cfg{};
        std::vector<std::string> args{
                "sontag",
                "--std",
                "c++20",
                "--opt",
                "O3",
                "--target",
                "x86_64-pc-linux-gnu",
                "--cpu",
                "znver4",
                "--mca-cpu",
                "znver4",
                "--mca-path",
                "/usr/bin/llvm-mca",
                "--mca",
                "--resume",
                "latest",
                "--cache-dir",
                "/tmp/sontag_tests",
                "--history-file",
                "/tmp/sontag_tests/history.txt",
                "--banner",
                "false",
                "--output",
                "json",
                "--color",
                "never",
                "--color-scheme",
                "classic"};
        auto argv = detail::to_argv(args);

        auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
        CHECK(!result);
        CHECK(cfg.language_standard == cxx_standard::cxx20);
        CHECK(cfg.opt_level == optimization_level::o3);
        REQUIRE(cfg.target_triple);
        CHECK(*cfg.target_triple == "x86_64-pc-linux-gnu");
        REQUIRE(cfg.cpu);
        CHECK(*cfg.cpu == "znver4");
        REQUIRE(cfg.mca_cpu);
        CHECK(*cfg.mca_cpu == "znver4");
        CHECK(cfg.mca_path == "/usr/bin/llvm-mca");
        CHECK(cfg.mca_enabled);
        REQUIRE(cfg.resume_session);
        CHECK(*cfg.resume_session == "latest");
        CHECK(cfg.cache_dir == "/tmp/sontag_tests");
        CHECK(cfg.history_file == "/tmp/sontag_tests/history.txt");
        CHECK_FALSE(cfg.banner_enabled);
        CHECK(cfg.output == output_mode::json);
        CHECK(cfg.color == color_mode::never);
        CHECK(cfg.delta_color_scheme == color_scheme::classic);
    }

    TEST_CASE("002: parse_cli rejects invalid startup combos", "[002][cli]") {
        SECTION("invalid standard is rejected") {
            startup_config cfg{};
            std::vector<std::string> args{"sontag", "--std", "c++17"};
            auto argv = detail::to_argv(args);

            auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
            REQUIRE(result);
            CHECK(*result == 2);
        }

        SECTION("quiet and verbose cannot be combined") {
            startup_config cfg{};
            std::vector<std::string> args{"sontag", "--quiet", "--verbose"};
            auto argv = detail::to_argv(args);

            auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
            REQUIRE(result);
            CHECK(*result == 2);
        }

        SECTION("invalid banner value is rejected") {
            startup_config cfg{};
            std::vector<std::string> args{"sontag", "--banner", "maybe"};
            auto argv = detail::to_argv(args);

            auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
            REQUIRE(result);
            CHECK(*result == 2);
        }

        SECTION("invalid color scheme value is rejected") {
            startup_config cfg{};
            std::vector<std::string> args{"sontag", "--color-scheme", "synthwave"};
            auto argv = detail::to_argv(args);

            auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
            REQUIRE(result);
            CHECK(*result == 2);
        }
    }

    TEST_CASE("002: parse_cli handles one-shot exits", "[002][cli]") {
        startup_config cfg{};
        std::vector<std::string> args{"sontag", "--version"};
        auto argv = detail::to_argv(args);

        auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
        REQUIRE(result);
        CHECK(*result == 0);
    }

    TEST_CASE("002: parse_cli handles history toggles", "[002][cli]") {
        startup_config cfg{};
        std::vector<std::string> args{"sontag", "--no-history"};
        auto argv = detail::to_argv(args);

        auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
        CHECK(!result);
        CHECK_FALSE(cfg.history_enabled);
    }

    TEST_CASE("002: parse_cli handles banner toggles", "[002][cli]") {
        startup_config cfg{};
        std::vector<std::string> args{"sontag", "--no-banner"};
        auto argv = detail::to_argv(args);

        auto result = cli::parse_cli(static_cast<int>(argv.size()), argv.data(), cfg);
        CHECK(!result);
        CHECK_FALSE(cfg.banner_enabled);
    }

}  // namespace sontag::test
