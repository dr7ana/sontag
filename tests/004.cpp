#include "utils.hpp"

namespace sontag::test { namespace detail {
    struct temp_dir {
        fs::path path{};

        explicit temp_dir(const std::string& prefix) {
            auto now = std::chrono::system_clock::now().time_since_epoch().count();
            std::ostringstream dir_name{};
            dir_name << prefix << "_" << static_cast<long>(::getpid()) << "_" << now;
            path = fs::temp_directory_path() / dir_name.str();
            fs::create_directories(path);
        }

        ~temp_dir() {
            std::error_code ec{};
            fs::remove_all(path, ec);
        }
    };

    struct analysis_json_payload {
        std::string command{};
        bool success{false};
        int exit_code{-1};
        std::string source_path{};
        std::string artifact_path{};
        std::string stderr_path{};
        std::string text{};
        std::vector<std::string> clang_command{};
    };
}}  // namespace sontag::test::detail

namespace glz {
    template <>
    struct meta<sontag::test::detail::analysis_json_payload> {
        using T = sontag::test::detail::analysis_json_payload;
        static constexpr auto value =
                object("command",
                       &T::command,
                       "success",
                       &T::success,
                       "exit_code",
                       &T::exit_code,
                       "source_path",
                       &T::source_path,
                       "artifact_path",
                       &T::artifact_path,
                       "stderr_path",
                       &T::stderr_path,
                       "text",
                       &T::text,
                       "clang_command",
                       &T::clang_command);
    };
}  // namespace glz

namespace sontag::test {

    TEST_CASE("004: analysis result json payload is parseable", "[004][analysis][json]") {
        detail::temp_dir temp{"sontag_m1_json_payload"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.cells = {"int foo(int x) { return x + 1; }"};
        request.symbol = "foo";

        auto result = run_analysis(request, analysis_kind::asm_text);
        REQUIRE(result.success);

        detail::analysis_json_payload payload{};
        payload.command = std::string(to_string(result.kind));
        payload.success = result.success;
        payload.exit_code = result.exit_code;
        payload.source_path = result.source_path.string();
        payload.artifact_path = result.artifact_path.string();
        payload.stderr_path = result.stderr_path.string();
        payload.text = result.artifact_text;
        payload.clang_command = result.command;

        std::string json{};
        auto write_ec = glz::write_json(payload, json);
        CHECK_FALSE(write_ec);

        detail::analysis_json_payload parsed{};
        auto read_ec = glz::read_json(parsed, json);
        CHECK_FALSE(read_ec);
        CHECK(parsed.command == "asm");
        CHECK(parsed.success);
        CHECK(parsed.exit_code == 0);
        CHECK(parsed.artifact_path.find("/artifacts/asm/") != std::string::npos);
        CHECK(parsed.text.find("foo") != std::string::npos);
        REQUIRE_FALSE(parsed.clang_command.empty());
        CHECK(parsed.clang_command[0].find("clang++") != std::string::npos);
        CHECK(std::find(parsed.clang_command.begin(), parsed.clang_command.end(), "-S") != parsed.clang_command.end());
    }

    TEST_CASE("004: unresolved symbol reports clear failure", "[004][analysis][symbol]") {
        detail::temp_dir temp{"sontag_m1_symbol_missing"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.cells = {"int foo(int x) { return x + 1; }"};
        request.symbol = "does_not_exist";

        try {
            (void)run_analysis(request, analysis_kind::asm_text);
            FAIL("expected unresolved symbol failure");
        } catch (const std::runtime_error& e) {
            auto message = std::string{e.what()};
            CHECK(message.find("unable to resolve symbol") != std::string::npos);
            CHECK(message.find("does_not_exist") != std::string::npos);
        }
    }

    TEST_CASE("004: namespace symbol resolution works for asm extraction", "[004][analysis][symbol]") {
        detail::temp_dir temp{"sontag_m1_ns_symbol"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.cells = {"namespace ns { int foo(int x) { return x + 1; } }"};
        request.symbol = "ns::foo";

        auto result = run_analysis(request, analysis_kind::asm_text);
        CHECK(result.success);
        CHECK_FALSE(result.artifact_text.empty());
        CHECK(result.artifact_text.find("foo") != std::string::npos);
    }

    TEST_CASE("004: diagnostics are filtered to selected symbol", "[004][analysis][diag]") {
        detail::temp_dir temp{"sontag_m1_diag_filter"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.cells = {
                "int foo(int x) {\n"
                "  return x + missing_foo;\n"
                "}\n"
                "int bar(int x) {\n"
                "  return x + missing_bar;\n"
                "}\n"};

        request.symbol = "foo";
        auto foo_diag = run_analysis(request, analysis_kind::diag);
        CHECK_FALSE(foo_diag.success);
        CHECK(foo_diag.artifact_text.find("missing_foo") != std::string::npos);
        CHECK(foo_diag.artifact_text.find("missing_bar") == std::string::npos);

        request.symbol = "bar";
        auto bar_diag = run_analysis(request, analysis_kind::diag);
        CHECK_FALSE(bar_diag.success);
        CHECK(bar_diag.artifact_text.find("missing_bar") != std::string::npos);
        CHECK(bar_diag.artifact_text.find("missing_foo") == std::string::npos);
    }

}  // namespace sontag::test
