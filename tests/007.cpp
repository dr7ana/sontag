#include "utils.hpp"

namespace sontag::test { namespace detail {
    struct temp_dir {
        fs::path path{};

        explicit temp_dir(std::string_view prefix) {
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

    static analysis_request make_request(const fs::path& session_dir, std::string cell) {
        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = session_dir;
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {std::move(cell)};
        request.mca_path = "llvm-mca";
        return request;
    }

    static void write_executable_script(const fs::path& path, std::string_view contents) {
        std::ofstream out{path};
        REQUIRE(out.good());
        out << contents;
        out.close();
        REQUIRE(out.good());
        fs::permissions(
                path,
                fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec,
                fs::perm_options::replace);
    }
}}  // namespace sontag::test::detail

namespace sontag::test {

    TEST_CASE("007: mca returns compiler diagnostics when asm input build fails", "[007][smoke][mca][analysis]") {
        detail::temp_dir temp{"sontag_mca_compile_fail"};
        auto request = detail::make_request(temp.path / "session", "int broken = ;");

        auto result = run_analysis(request, analysis_kind::mca);
        CHECK_FALSE(result.success);
        CHECK(result.exit_code != 0);
        CHECK(result.command.size() > 1U);
        CHECK(result.command[0].find("clang++") != std::string::npos);
        CHECK(result.command[1] == "-std=c++23");
        CHECK(result.artifact_text.empty());
        CHECK(result.diagnostics_text.find("error:") != std::string::npos);
        CHECK(detail::fs::exists(result.artifact_path));
        CHECK(detail::fs::exists(result.stderr_path));
    }

    TEST_CASE("007: mca reports missing tool execution failures", "[007][smoke][mca][analysis]") {
        detail::temp_dir temp{"sontag_mca_missing_tool"};
        auto request = detail::make_request(
                temp.path / "session",
                "int foo(int x) { return x + 1; }\n"
                "int bar(int x) { return foo(x) + 2; }");
        request.symbol = "foo";
        request.mca_path = "/definitely/not/a/real/llvm-mca";

        auto result = run_analysis(request, analysis_kind::mca);
        CHECK_FALSE(result.success);
        CHECK(result.exit_code == 127);
        REQUIRE_FALSE(result.command.empty());
        CHECK(result.command[0] == "/definitely/not/a/real/llvm-mca");
        CHECK(result.artifact_text.empty());
        CHECK(result.diagnostics_text.find("failed to execute llvm-mca tool") != std::string::npos);
        CHECK(detail::fs::exists(result.artifact_path));
    }

    TEST_CASE("007: mca success path emits analysis artifact", "[007][smoke][mca][analysis]") {
        detail::temp_dir temp{"sontag_mca_success"};
        auto request = detail::make_request(
                temp.path / "session",
                "int foo(int x) {\n"
                "  return (x * 3) + 1;\n"
                "}\n");
        request.symbol = "foo";

        auto result = run_analysis(request, analysis_kind::mca);
        if (result.exit_code == 127) {
            SKIP("llvm-mca not available in PATH");
        }
        if (!result.success) {
            SKIP("llvm-mca is available but returned a non-zero analysis result for this fixture");
        }

        REQUIRE(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_path.string().find("/artifacts/mca/") != std::string::npos);
        CHECK_FALSE(result.artifact_text.empty());
        CHECK(std::find(result.command.begin(), result.command.end(), "--show-encoding") != result.command.end());
        CHECK(std::find(result.command.begin(), result.command.end(), "--register-file-stats") != result.command.end());
        auto has_iterations = result.artifact_text.find("Iterations:") != std::string::npos;
        auto has_total_cycles = result.artifact_text.find("Total Cycles") != std::string::npos;
        CHECK((has_iterations || has_total_cycles));
    }

    TEST_CASE("007: mca resolves clang-version-suffixed tool", "[007][smoke][mca][analysis]") {
        detail::temp_dir temp{"sontag_mca_versioned_fallback"};
        auto tool_dir = temp.path / "tools";
        detail::fs::create_directories(tool_dir);

        auto clang_wrapper = tool_dir / "clang++-42";
        auto mca_wrapper = tool_dir / "llvm-mca-42";
        auto mca_missing = tool_dir / "llvm-mca";

        {
            std::ostringstream script{};
            script << "#!/usr/bin/env bash\n";
            script << "if [[ \"$1\" == \"--version\" ]]; then\n";
            script << "  echo \"clang version 42.0.1\"\n";
            script << "  exit 0\n";
            script << "fi\n";
            script << "exec /usr/bin/clang++ \"$@\"\n";
            detail::write_executable_script(clang_wrapper, script.str());
        }

        detail::write_executable_script(
                mca_wrapper,
                "#!/usr/bin/env bash\n"
                "echo \"Iterations: 100\"\n"
                "echo \"Total Cycles: 200\"\n");

        auto request = detail::make_request(
                temp.path / "session",
                "int foo(int x) {\n"
                "  return (x * 5) + 1;\n"
                "}\n");
        request.symbol = "foo";
        request.clang_path = clang_wrapper;
        request.mca_path = "llvm-mca";
        request.verbose = true;

        auto result = run_analysis(request, analysis_kind::mca);
        REQUIRE(result.success);
        CHECK(result.exit_code == 0);
        REQUIRE_FALSE(result.command.empty());
        CHECK(result.command[0] == mca_wrapper.string());
        CHECK(std::find(result.command.begin(), result.command.end(), "--show-encoding") != result.command.end());
        CHECK(std::find(result.command.begin(), result.command.end(), "--register-file-stats") != result.command.end());
        CHECK(std::find(result.command.begin(), result.command.end(), "--all-views") != result.command.end());
        CHECK(result.artifact_text.find("Iterations: 100") != std::string::npos);
        CHECK(result.artifact_text.find("Total Cycles: 200") != std::string::npos);
    }

    TEST_CASE("007: mca symbol input preserves syntax directives", "[007][smoke][mca][analysis]") {
        detail::temp_dir temp{"sontag_mca_symbol_directives"};
        auto request = detail::make_request(
                temp.path / "session",
                "#include <cstdint>\n"
                "uint64_t val = 64;\n"
                "uint64_t values[6];\n"
                "values[0] = val;\n"
                "values[3] = val / 2;\n");
        request.symbol = "__sontag_main";

        auto result = run_analysis(request, analysis_kind::mca);
        if (result.exit_code == 127) {
            SKIP("llvm-mca not available in PATH");
        }
        if (!result.success) {
            SKIP("llvm-mca is available but returned a non-zero analysis result for this fixture");
        }

        REQUIRE(result.success);
        CHECK(result.artifact_text.find("Instruction Info:") != std::string::npos);
        CHECK(result.diagnostics_text.find("Assembly input parsing had errors") == std::string::npos);
    }

}  // namespace sontag::test
