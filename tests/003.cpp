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
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};

        auto asm_result = run_analysis(request, analysis_kind::asm_text);
        CHECK(asm_result.success);
        CHECK(asm_result.exit_code == 0);
        CHECK(std::filesystem::exists(asm_result.artifact_path));
        CHECK_FALSE(asm_result.artifact_text.empty());
        CHECK(std::find(asm_result.command.begin(), asm_result.command.end(), "-Wno-error") !=
              asm_result.command.end());
        CHECK(std::find(asm_result.command.begin(), asm_result.command.end(), "-Wno-unused-variable") !=
              asm_result.command.end());
        CHECK(std::find(asm_result.command.begin(), asm_result.command.end(), "-Wno-unused-parameter") !=
              asm_result.command.end());
        CHECK(std::find(asm_result.command.begin(), asm_result.command.end(), "-Wno-unused-function") !=
              asm_result.command.end());

        auto ir_result = run_analysis(request, analysis_kind::ir);
        CHECK(ir_result.success);
        CHECK(ir_result.exit_code == 0);
        CHECK(std::filesystem::exists(ir_result.artifact_path));
        CHECK(ir_result.artifact_text.find("define") != std::string::npos);

        request.decl_cells = {"int broken = ;"};
        auto diag_result = run_analysis(request, analysis_kind::diag);
        CHECK_FALSE(diag_result.success);
        CHECK(diag_result.exit_code != 0);
        CHECK(std::filesystem::exists(diag_result.artifact_path));
        CHECK(diag_result.artifact_text.find("error:") != std::string::npos);
        CHECK(std::find(diag_result.command.begin(), diag_result.command.end(), "-Wno-error") !=
              diag_result.command.end());
    }

    TEST_CASE("003: symbol scoped analysis paths", "[003][analysis][symbol]") {
        detail::temp_dir temp{"sontag_m1_symbol"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {
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

        request.decl_cells = {
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
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};

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

    TEST_CASE("003: verbose analysis request forwards clang verbose flag", "[003][analysis][verbose]") {
        detail::temp_dir temp{"sontag_m1_verbose"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};
        request.verbose = true;

        auto asm_result = run_analysis(request, analysis_kind::asm_text);
        CHECK(asm_result.success);
        CHECK(std::find(asm_result.command.begin(), asm_result.command.end(), "-v") != asm_result.command.end());
    }

    TEST_CASE("003: symbol listing returns current snapshot symbols", "[003][analysis][symbols]") {
        detail::temp_dir temp{"sontag_m1_symbols"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {"int foo(int x) { return x + 1; }"};
        request.exec_cells = {"int y = foo(5);", "return y;"};

        auto symbols = list_symbols(request);
        REQUIRE_FALSE(symbols.empty());

        auto has_repl_entry = std::ranges::any_of(symbols, [](const analysis_symbol& symbol) {
            return symbol.demangled == "__sontag_repl_main()" || symbol.mangled == "__sontag_repl_main";
        });
        auto has_foo = std::ranges::any_of(symbols, [](const analysis_symbol& symbol) {
            return symbol.demangled.find("foo(") != std::string::npos ||
                   symbol.mangled.find("foo") != std::string::npos;
        });

        CHECK(has_repl_entry);
        CHECK(has_foo);
    }

}  // namespace sontag::test
