#include "utils.hpp"

namespace sontag::test {
    namespace detail {
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
    }  // namespace detail

    TEST_CASE("003: analysis pipeline emits asm ir and diagnostics", "[003][analysis]") {
        detail::temp_dir temp{"sontag_m1_analysis"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.cells = {"int add(int a, int b) { return a + b; }"};

        auto asm_result = run_analysis(request, analysis_kind::asm_text);
        CHECK(asm_result.success);
        CHECK(asm_result.exit_code == 0);
        CHECK(std::filesystem::exists(asm_result.artifact_path));
        CHECK_FALSE(asm_result.artifact_text.empty());

        auto ir_result = run_analysis(request, analysis_kind::ir);
        CHECK(ir_result.success);
        CHECK(ir_result.exit_code == 0);
        CHECK(std::filesystem::exists(ir_result.artifact_path));
        CHECK(ir_result.artifact_text.find("define") != std::string::npos);

        request.cells = {"int broken = ;"};
        auto diag_result = run_analysis(request, analysis_kind::diag);
        CHECK_FALSE(diag_result.success);
        CHECK(diag_result.exit_code != 0);
        CHECK(std::filesystem::exists(diag_result.artifact_path));
        CHECK(diag_result.artifact_text.find("error:") != std::string::npos);
    }

    TEST_CASE("003: symbol scoped analysis paths", "[003][analysis][symbol]") {
        detail::temp_dir temp{"sontag_m1_symbol"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.cells = {
                "int foo(int x) { return x + 1; }\n"
                "int bar(int x) { return x + 2; }\n"
                "int call_both(int x) { return foo(x) + bar(x); }"};

        request.symbol = "foo";
        auto asm_result = run_analysis(request, analysis_kind::asm_text);
        CHECK(asm_result.success);
        CHECK(asm_result.artifact_text.find("foo") != std::string::npos);
        CHECK(asm_result.artifact_text.find("bar") == std::string::npos);

        auto ir_result = run_analysis(request, analysis_kind::ir);
        CHECK(ir_result.success);
        CHECK(ir_result.artifact_text.find("foo") != std::string::npos);
        CHECK(ir_result.artifact_text.find("bar") == std::string::npos);

        request.cells = {
                "int foo(int x) { return x + ; }\n"
                "int bar(int x) { return x + ; }\n"};
        request.symbol = "foo";
        auto diag_result = run_analysis(request, analysis_kind::diag);
        CHECK_FALSE(diag_result.success);
        CHECK(diag_result.artifact_text.find("foo") != std::string::npos);
        CHECK(diag_result.artifact_text.find("bar") == std::string::npos);
    }

    TEST_CASE("003: in-process command sequence runs all analysis kinds", "[003][analysis][sequence]") {
        detail::temp_dir temp{"sontag_m1_sequence"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.cells = {"int add(int a, int b) { return a + b; }"};

        std::vector<analysis_kind> commands{analysis_kind::asm_text, analysis_kind::ir, analysis_kind::diag};
        std::vector<analysis_result> results{};
        results.reserve(commands.size());

        for (auto kind : commands) {
            results.push_back(run_analysis(request, kind));
        }

        REQUIRE(results.size() == 3U);
        CHECK(results[0].kind == analysis_kind::asm_text);
        CHECK(results[1].kind == analysis_kind::ir);
        CHECK(results[2].kind == analysis_kind::diag);

        CHECK(results[0].success);
        CHECK(results[1].success);
        CHECK(results[2].success);
        CHECK(results[2].exit_code == 0);
        CHECK(results[2].artifact_text.empty());

        CHECK(std::filesystem::exists(request.session_dir / "artifacts" / "asm"));
        CHECK(std::filesystem::exists(request.session_dir / "artifacts" / "ir"));
        CHECK(std::filesystem::exists(request.session_dir / "artifacts" / "diag"));
    }

}  // namespace sontag::test
