#include "utils.hpp"

namespace sontag::test {
    namespace detail {
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

        static void write_text_file(const fs::path& path, std::string_view text) {
            std::ofstream out{path};
            REQUIRE(out.good());
            out << text;
            REQUIRE(out.good());
        }

        static void make_executable_file(const fs::path& path, std::string_view content) {
            auto parent = path.parent_path();
            if (!parent.empty()) {
                fs::create_directories(parent);
            }

            write_text_file(path, content);
            fs::permissions(
                    path,
                    fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec | fs::perms::group_read |
                            fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec,
                    fs::perm_options::replace);
        }

        static std::vector<std::string> read_lines(const fs::path& path) {
            std::ifstream in{path};
            REQUIRE(in.good());

            std::vector<std::string> lines{};
            std::string line{};
            while (std::getline(in, line)) {
                lines.push_back(line);
            }
            return lines;
        }

        static bool has_exact_arg(const std::vector<std::string>& args, std::string_view token) {
            return std::find(args.begin(), args.end(), token) != args.end();
        }

        static bool has_prefixed_arg(const std::vector<std::string>& args, std::string_view prefix) {
            return std::ranges::any_of(args, [prefix](std::string_view arg) { return arg.starts_with(prefix); });
        }

        static void check_default_dump_arch_args(const std::vector<std::string>& args) {
            if constexpr (internal::platform::is_x86_64) {
                CHECK(has_exact_arg(args, "--x86-asm-syntax=intel"));
                CHECK_FALSE(has_prefixed_arg(args, "--disassembler-options="));
            }
            else if constexpr (internal::platform::is_arm64) {
                CHECK(has_exact_arg(args, "--disassembler-options=no-aliases"));
                CHECK_FALSE(has_prefixed_arg(args, "--x86-asm-syntax="));
            }
        }

        static std::string make_objdump_wrapper_script(const fs::path& args_path) {
            std::ostringstream script{};
            script << "#!/usr/bin/env bash\n";
            script << "set -eu\n";
            script << "printf '%s\\n' \"$@\" > \"" << args_path.string() << "\"\n";
            script << "echo objdump-ok\n";
            return script.str();
        }
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

    TEST_CASE("003: dump analysis uses show-all-symbols without symbol filter", "[003][analysis][dump]") {
        detail::temp_dir temp{"sontag_m1_dump_all"};

        auto args_path = temp.path / "objdump.args.txt";
        auto wrapper_path = temp.path / "tools" / "llvm-objdump";
        auto wrapper_script = detail::make_objdump_wrapper_script(args_path);
        detail::make_executable_file(wrapper_path, wrapper_script);

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.objdump_path = wrapper_path;
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};

        auto dump_result = run_analysis(request, analysis_kind::dump);
        CHECK(dump_result.success);
        CHECK(dump_result.exit_code == 0);
        CHECK(dump_result.command.size() > 1U);
        CHECK(dump_result.command[0] == wrapper_path.string());
        CHECK(dump_result.artifact_text.find("objdump-ok") != std::string::npos);

        auto args = detail::read_lines(args_path);
        CHECK(detail::has_exact_arg(args, "--disassemble"));
        CHECK(detail::has_exact_arg(args, "--demangle"));
        detail::check_default_dump_arch_args(args);
        CHECK(detail::has_exact_arg(args, "--symbolize-operands"));
        CHECK(detail::has_exact_arg(args, "--show-all-symbols"));
        CHECK_FALSE(detail::has_prefixed_arg(args, "--disassemble-symbols="));

        REQUIRE_FALSE(args.empty());
        CHECK(args.back().ends_with(".o"));
    }

    TEST_CASE(
            "003: dump analysis keeps full disassembly args when symbol is provided (post-extract path)",
            "[003][analysis][dump]") {
        detail::temp_dir temp{"sontag_m1_dump_symbol"};

        auto args_path = temp.path / "objdump.args.txt";
        auto wrapper_path = temp.path / "tools" / "llvm-objdump";
        auto wrapper_script = detail::make_objdump_wrapper_script(args_path);
        detail::make_executable_file(wrapper_path, wrapper_script);

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.objdump_path = wrapper_path;
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};
        request.symbol = "add";

        auto dump_result = run_analysis(request, analysis_kind::dump);
        CHECK(dump_result.success);
        CHECK(dump_result.exit_code == 0);
        CHECK(dump_result.command.size() > 1U);
        CHECK(dump_result.command[0] == wrapper_path.string());

        auto args = detail::read_lines(args_path);
        CHECK(detail::has_exact_arg(args, "--disassemble"));
        CHECK(detail::has_exact_arg(args, "--demangle"));
        detail::check_default_dump_arch_args(args);
        CHECK(detail::has_exact_arg(args, "--symbolize-operands"));
        CHECK(detail::has_exact_arg(args, "--show-all-symbols"));
        CHECK_FALSE(detail::has_prefixed_arg(args, "--disassemble-symbols="));
    }

    TEST_CASE("003: dump analysis uses no-aliases for explicit aarch64 target", "[003][analysis][dump][aarch64]") {
        detail::temp_dir temp{"sontag_m1_dump_aarch64"};

        auto args_path = temp.path / "objdump.args.txt";
        auto wrapper_path = temp.path / "tools" / "llvm-objdump";
        auto wrapper_script = detail::make_objdump_wrapper_script(args_path);
        detail::make_executable_file(wrapper_path, wrapper_script);

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.objdump_path = wrapper_path;
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.target_triple = "aarch64-unknown-linux-gnu";
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};

        auto dump_result = run_analysis(request, analysis_kind::dump);
        CHECK(dump_result.success);
        CHECK(dump_result.exit_code == 0);

        auto args = detail::read_lines(args_path);
        CHECK(detail::has_exact_arg(args, "--disassemble"));
        CHECK(detail::has_exact_arg(args, "--demangle"));
#if SONTAG_ARCH_ARM64
        CHECK(detail::has_exact_arg(args, "--disassembler-options=no-aliases"));
        CHECK_FALSE(detail::has_prefixed_arg(args, "--x86-asm-syntax="));
#elif SONTAG_ARCH_X86_64
        CHECK_FALSE(detail::has_exact_arg(args, "--disassembler-options=no-aliases"));
        CHECK(detail::has_prefixed_arg(args, "--x86-asm-syntax="));
#else
#error "unsupported architecture for dump argument checks"
#endif
        CHECK(detail::has_exact_arg(args, "--symbolize-operands"));
        CHECK(detail::has_exact_arg(args, "--show-all-symbols"));
    }

    TEST_CASE("003: graph cfg emits dot artifact and summary", "[003][analysis][graph]") {
        detail::temp_dir temp{"sontag_m3_graph_cfg"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};

        auto result = run_analysis(request, analysis_kind::graph_cfg);
        CHECK(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_path.string().find("/artifacts/graphs/cfg/") != std::string::npos);
        CHECK(result.artifact_path.extension() == ".dot");
        CHECK(result.artifact_text.find("__sontag_main") != std::string::npos);
        CHECK(result.artifact_text.find("dot: ") != std::string::npos);
        CHECK(result.artifact_text.find("rendered: ") != std::string::npos);
        CHECK(detail::fs::exists(result.artifact_path));

        auto dot_text = detail::read_lines(result.artifact_path);
        REQUIRE_FALSE(dot_text.empty());
        CHECK(dot_text.front().find("digraph cfg_") != std::string::npos);
        std::string joined{};
        for (const auto& line : dot_text) {
            joined.append(line);
            joined.push_back('\n');
        }
        CHECK(joined.find("->") != std::string::npos);
    }

    TEST_CASE("003: graph cfg honors symbol target", "[003][analysis][graph][symbol]") {
        detail::temp_dir temp{"sontag_m3_graph_cfg_symbol"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {
                "int foo(int x) { return x + 1; }\n"
                "int bar(int x) { return x + 2; }\n"};
        request.symbol = "foo";

        auto result = run_analysis(request, analysis_kind::graph_cfg);
        CHECK(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_text.find("function: ") != std::string::npos);
        CHECK(result.artifact_text.find("foo") != std::string::npos);

        auto dot_text = detail::read_lines(result.artifact_path);
        std::string joined{};
        for (const auto& line : dot_text) {
            joined.append(line);
            joined.push_back('\n');
        }
        CHECK(joined.find("digraph cfg_") != std::string::npos);
    }

    TEST_CASE("003: graph call emits dot artifact and summary", "[003][analysis][graph][call]") {
        detail::temp_dir temp{"sontag_m3_graph_call"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o0;
        request.decl_cells = {
                "int leaf(int x) { return x + 1; }\n"
                "int helper(int y) { return leaf(y) * 2; }\n"
                "int top(int z) { return helper(z) + leaf(z); }\n"};
        request.symbol = "top";

        auto result = run_analysis(request, analysis_kind::graph_call);
        CHECK(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_path.string().find("/artifacts/graphs/call/") != std::string::npos);
        CHECK(result.artifact_path.extension() == ".dot");
        CHECK(result.artifact_text.find("root: ") != std::string::npos);
        CHECK(result.artifact_text.find("top") != std::string::npos);
        CHECK(result.artifact_text.find("nodes: ") != std::string::npos);
        CHECK(result.artifact_text.find("edges: ") != std::string::npos);
        CHECK(result.artifact_text.find("dot: ") != std::string::npos);
        CHECK(detail::fs::exists(result.artifact_path));

        auto dot_text = detail::read_lines(result.artifact_path);
        REQUIRE_FALSE(dot_text.empty());
        CHECK(dot_text.front().find("digraph call_") != std::string::npos);

        std::string joined{};
        for (const auto& line : dot_text) {
            joined.append(line);
            joined.push_back('\n');
        }
        CHECK(joined.find("top(int)") != std::string::npos);
        CHECK(joined.find("helper(int)") != std::string::npos);
        CHECK(joined.find("leaf(int)") != std::string::npos);
        CHECK(joined.find("label=\"_Z3topi\"") == std::string::npos);
        CHECK(joined.find("->") != std::string::npos);
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
            return symbol.demangled == "__sontag_main()" || symbol.mangled == "__sontag_main";
        });
        auto has_foo = std::ranges::any_of(symbols, [](const analysis_symbol& symbol) {
            return symbol.demangled.find("foo(") != std::string::npos ||
                   symbol.mangled.find("foo") != std::string::npos;
        });

        CHECK(has_repl_entry);
        CHECK(has_foo);
    }

}  // namespace sontag::test
