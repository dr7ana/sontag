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

        static std::string make_nm_object_binary_split_script() {
            std::ostringstream script{};
            script << "#!/usr/bin/env bash\n";
            script << "set -eu\n";
            script << "target=\"${@: -1}\"\n";
            script << "if [[ \"$target\" == *.o ]]; then\n";
            script << "cat <<'EOF'\n";
            script << "square(int) T 0 0\n";
            script << "EOF\n";
            script << "else\n";
            script << "cat <<'EOF'\n";
            script << "square() T 0 0\n";
            script << "EOF\n";
            script << "fi\n";
            return script.str();
        }

        static std::string make_nm_short_token_collision_script() {
            std::ostringstream script{};
            script << "#!/usr/bin/env bash\n";
            script << "set -eu\n";
            script << "target=\"${@: -1}\"\n";
            script << "if [[ \"$target\" == *.o ]]; then\n";
            script << "cat <<'EOF'\n";
            script << "open(int) T 0 0\n";
            script << "EOF\n";
            script << "else\n";
            script << "cat <<'EOF'\n";
            script << "open T 0 0\n";
            script << "EOF\n";
            script << "fi\n";
            return script.str();
        }

        static std::string make_nm_addendum_collision_script() {
            std::ostringstream script{};
            script << "#!/usr/bin/env bash\n";
            script << "set -eu\n";
            script << "target=\"${@: -1}\"\n";
            script << "if [[ \"$target\" == *.o ]]; then\n";
            script << "cat <<'EOF'\n";
            script << "square(int) T 0 0\n";
            script << "EOF\n";
            script << "else\n";
            script << "cat <<'EOF'\n";
            script << "square T 0 0\n";
            script << "EOF\n";
            script << "fi\n";
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

    TEST_CASE("003: analysis namespaces source and artifacts by build hash", "[003][analysis][cache]") {
        detail::temp_dir temp{"sontag_m1_analysis_build_hash_namespace"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};

        auto asm_result = run_analysis(request, analysis_kind::asm_text);
        auto ir_result = run_analysis(request, analysis_kind::ir);

        REQUIRE(asm_result.success);
        REQUIRE(ir_result.success);
        REQUIRE_FALSE(asm_result.command.empty());
        REQUIRE_FALSE(ir_result.command.empty());
        CHECK(asm_result.source_path.parent_path() == ir_result.source_path.parent_path());
        CHECK(asm_result.source_path.parent_path().filename() == asm_result.artifact_path.parent_path().filename());
        CHECK(ir_result.source_path.parent_path().filename() == ir_result.artifact_path.parent_path().filename());
        CHECK(asm_result.source_path.string().find("/artifacts/inputs/") != std::string::npos);

        auto asm_cached_result = run_analysis(request, analysis_kind::asm_text);
        auto ir_cached_result = run_analysis(request, analysis_kind::ir);

        REQUIRE(asm_cached_result.success);
        REQUIRE(ir_cached_result.success);
        CHECK(asm_cached_result.command.empty());
        CHECK(ir_cached_result.command.empty());
        CHECK(asm_cached_result.artifact_text == asm_result.artifact_text);
        CHECK(ir_cached_result.artifact_text == ir_result.artifact_text);
    }

    TEST_CASE("003: build hash changes when linker-arg order changes", "[003][analysis][cache]") {
        detail::temp_dir temp{"sontag_m1_analysis_build_hash_order"};

        analysis_request first_request{};
        first_request.clang_path = "/usr/bin/clang++";
        first_request.session_dir = temp.path / "session";
        first_request.language_standard = cxx_standard::cxx23;
        first_request.opt_level = optimization_level::o2;
        first_request.decl_cells = {"int add(int a, int b) { return a + b; }"};
        first_request.linker_args = {"-Wl,--as-needed", "-Wl,--gc-sections"};

        auto second_request = first_request;
        second_request.linker_args = {"-Wl,--gc-sections", "-Wl,--as-needed"};

        auto first_result = run_analysis(first_request, analysis_kind::asm_text);
        auto second_result = run_analysis(second_request, analysis_kind::asm_text);

        REQUIRE(first_result.success);
        REQUIRE(second_result.success);
        CHECK(first_result.source_path.parent_path() != second_result.source_path.parent_path());
    }

    TEST_CASE("003: mem_trace cache hit preserves trace payload exit code", "[003][analysis][cache][mem]") {
        detail::temp_dir temp{"sontag_m1_mem_trace_cache_hit"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o0;
        request.static_link = true;
        request.decl_cells = {"int square(int x) { int y = x * x; return y; }"};
        request.exec_cells = {"volatile int sink = square(3);", "return sink;"};
        request.symbol = "square";

        auto cold_result = run_analysis(request, analysis_kind::mem_trace);
        REQUIRE(cold_result.success);
        REQUIRE(cold_result.exit_code == 9);
        CHECK_FALSE(cold_result.command.empty());

        auto cached_result = run_analysis(request, analysis_kind::mem_trace);
        REQUIRE(cached_result.success);
        CHECK(cached_result.exit_code == cold_result.exit_code);
        CHECK(cached_result.artifact_text == cold_result.artifact_text);
        CHECK(cached_result.command.empty());
    }

    TEST_CASE("003: dump cache hit preserves disassembly and opcode mapping", "[003][analysis][cache][dump]") {
        detail::temp_dir temp{"sontag_m1_dump_cache_hit"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {"int add(int a, int b) { return a + b; }"};
        request.exec_cells = {"volatile int sink = add(1, 2);", "return sink;"};

        auto cold_result = run_analysis(request, analysis_kind::dump);
        REQUIRE(cold_result.success);
        REQUIRE_FALSE(cold_result.command.empty());
        REQUIRE_FALSE(cold_result.opcode_table.empty());

        auto cached_result = run_analysis(request, analysis_kind::dump);
        REQUIRE(cached_result.success);
        CHECK(cached_result.command.empty());
        CHECK(cached_result.artifact_text == cold_result.artifact_text);
        CHECK_FALSE(cached_result.opcode_table.empty());
        CHECK(cached_result.opcode_table.size() == cold_result.opcode_table.size());
        CHECK(cached_result.operations.size() == cold_result.operations.size());
    }

    TEST_CASE("003: mem_trace command reflects static vs dynamic link policy", "[003][analysis][link]") {
        detail::temp_dir temp{"sontag_m1_link_policy"};

        analysis_request dynamic_request{};
        dynamic_request.clang_path = "/usr/bin/clang++";
        dynamic_request.session_dir = temp.path / "session_dynamic";
        dynamic_request.language_standard = cxx_standard::cxx23;
        dynamic_request.opt_level = optimization_level::o0;
        dynamic_request.decl_cells = {"int square(int x) { return x * x; }"};
        dynamic_request.exec_cells = {"volatile int sink = square(2);", "return sink;"};
        dynamic_request.symbol = "main";
        dynamic_request.linker_args = {"-Wl,--sontag-nonexistent-link-flag"};

        auto dynamic_result = run_analysis(dynamic_request, analysis_kind::mem_trace);
        CHECK_FALSE(dynamic_result.success);
        CHECK(detail::has_exact_arg(dynamic_result.command, "-Wl,--sontag-nonexistent-link-flag"));
        CHECK(detail::has_exact_arg(dynamic_result.command, "-ldl"));
        CHECK_FALSE(detail::has_exact_arg(dynamic_result.command, "-static"));
        CHECK_FALSE(detail::has_exact_arg(dynamic_result.command, "-static-libgcc"));

        auto static_request = dynamic_request;
        static_request.session_dir = temp.path / "session_static";
        static_request.static_link = true;

        auto static_result = run_analysis(static_request, analysis_kind::mem_trace);
        CHECK_FALSE(static_result.success);
        CHECK(detail::has_exact_arg(static_result.command, "-static"));
        CHECK(detail::has_exact_arg(static_result.command, "-static-libgcc"));
        CHECK_FALSE(detail::has_exact_arg(static_result.command, "-ldl"));
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
        CHECK(args.back().ends_with(".bin"));
    }

    TEST_CASE(
            "003: dump analysis fails when symbol extraction misses and avoids full-artifact fallback",
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
        CHECK_FALSE(dump_result.success);
        CHECK(dump_result.exit_code == 1);
        CHECK(dump_result.command.size() > 1U);
        CHECK(dump_result.command[0] == wrapper_path.string());
        CHECK(dump_result.diagnostics_text.find("symbol not found in artifact") != std::string::npos);

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
        CHECK(result.artifact_text.find("main") != std::string::npos);
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
            return symbol.demangled == "main()" || symbol.mangled == "main";
        });
        auto has_foo = std::ranges::any_of(symbols, [](const analysis_symbol& symbol) {
            return symbol.demangled.find("foo(") != std::string::npos ||
                   symbol.mangled.find("foo") != std::string::npos;
        });

        CHECK(has_repl_entry);
        CHECK(has_foo);
    }

    TEST_CASE("003: resolve_symbol_info supports addendum aliases and object fallback", "[003][analysis][symbols]") {
        detail::temp_dir temp{"sontag_m1_resolve_symbol_info"};

        analysis_request linked_request{};
        linked_request.clang_path = "/usr/bin/clang++";
        linked_request.session_dir = temp.path / "session_linked";
        linked_request.language_standard = cxx_standard::cxx23;
        linked_request.opt_level = optimization_level::o0;
        linked_request.decl_cells = {"int add(int a, int b) { return a + b; }"};
        linked_request.exec_cells = {"volatile int sink = add(1, 2);", "return sink;"};

        auto linked_info = resolve_symbol_info(linked_request, "add");
        REQUIRE(linked_info.has_value());
        CHECK(linked_info->status == symbol_resolution_status::resolved_final);
        CHECK(linked_info->display_name.find("add(") != std::string::npos);
        CHECK(linked_info->source.find("symtab") != std::string::npos);

        auto addendum_info = resolve_symbol_info(linked_request, "add@PLT");
        REQUIRE(addendum_info.has_value());
        CHECK(addendum_info->status == symbol_resolution_status::resolved_stub);
        CHECK(addendum_info->confidence == symbol_resolution_confidence::exact_relocation);
        CHECK(addendum_info->canonical_name == linked_info->canonical_name);
        CHECK(addendum_info->source.find("relocation_alias") != std::string::npos);
        REQUIRE(addendum_info->addendum.has_value());
        CHECK(*addendum_info->addendum == "PLT");

        auto indirect_info = resolve_symbol_info(linked_request, "add@GOT");
        REQUIRE(indirect_info.has_value());
        CHECK(indirect_info->status == symbol_resolution_status::unresolved_indirect);
        CHECK(indirect_info->confidence == symbol_resolution_confidence::exact_relocation);
        CHECK(indirect_info->canonical_name == linked_info->canonical_name);
        CHECK(indirect_info->source.find("relocation_alias") != std::string::npos);
        CHECK(indirect_info->source.find("indirect") != std::string::npos);
        REQUIRE(indirect_info->addendum.has_value());
        CHECK(*indirect_info->addendum == "GOT");

        auto missing_info = resolve_symbol_info(linked_request, "not_a_symbol");
        REQUIRE(missing_info.has_value());
        CHECK(missing_info->status == symbol_resolution_status::missing);
        CHECK(missing_info->confidence == symbol_resolution_confidence::heuristic_match);
        CHECK(missing_info->source == "unresolved");
        CHECK(missing_info->canonical_name == "not_a_symbol");

        auto missing_indirect_info = resolve_symbol_info(linked_request, "not_a_symbol@GOT");
        REQUIRE(missing_indirect_info.has_value());
        CHECK(missing_indirect_info->status == symbol_resolution_status::unresolved_indirect);
        CHECK(missing_indirect_info->confidence == symbol_resolution_confidence::heuristic_match);
        CHECK(missing_indirect_info->source == "unresolved_indirect");
        CHECK(missing_indirect_info->canonical_name == "not_a_symbol");
        REQUIRE(missing_indirect_info->addendum.has_value());
        CHECK(*missing_indirect_info->addendum == "GOT");

        auto static_request = linked_request;
        static_request.session_dir = temp.path / "session_static_linked";
        static_request.static_link = true;
        auto static_indirect_info = resolve_symbol_info(static_request, "add@GOT");
        REQUIRE(static_indirect_info.has_value());
        CHECK(static_indirect_info->status == symbol_resolution_status::unresolved_indirect);
        CHECK(static_indirect_info->confidence == symbol_resolution_confidence::exact_relocation);
        CHECK(static_indirect_info->source.find("relocation_alias") != std::string::npos);

        auto object_only_request = linked_request;
        object_only_request.session_dir = temp.path / "session_object_only";
        object_only_request.no_link = true;

        auto object_only_info = resolve_symbol_info(object_only_request, "add");
        REQUIRE(object_only_info.has_value());
        CHECK(object_only_info->status == symbol_resolution_status::resolved_object_only);
        auto object_only_indirect_info = resolve_symbol_info(object_only_request, "add@GOT");
        REQUIRE(object_only_indirect_info.has_value());
        CHECK(object_only_indirect_info->status == symbol_resolution_status::unresolved_indirect);
        CHECK(object_only_indirect_info->confidence == symbol_resolution_confidence::exact_relocation);
        CHECK(object_only_indirect_info->source.find("relocation_alias") != std::string::npos);
    }

    TEST_CASE(
            "003: token-prefix resolver prefers object symbol over binary-only candidate", "[003][analysis][symbols]") {
        detail::temp_dir temp{"sontag_m1_resolve_symbol_prefix_rank"};

        auto nm_wrapper_path = temp.path / "tools" / "llvm-nm";
        detail::make_executable_file(nm_wrapper_path, detail::make_nm_object_binary_split_script());

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.nm_path = nm_wrapper_path;
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o0;
        request.decl_cells = {"int square(int x) { return x * x; }"};

        auto info = resolve_symbol_info(request, "square");
        REQUIRE(info.has_value());
        CHECK(info->display_name == "square(int)");
        CHECK(info->status == symbol_resolution_status::resolved_object_only);
        CHECK(info->source == "symtab_token_prefix");
    }

    TEST_CASE(
            "003: short-token resolver prefers object symbol over binary exact collision", "[003][analysis][symbols]") {
        detail::temp_dir temp{"sontag_m1_resolve_symbol_short_token_rank"};

        auto nm_wrapper_path = temp.path / "tools" / "llvm-nm";
        detail::make_executable_file(nm_wrapper_path, detail::make_nm_short_token_collision_script());

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.nm_path = nm_wrapper_path;
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o0;
        request.decl_cells = {"int open(int x) { return x + 1; }"};

        auto info = resolve_symbol_info(request, "open");
        REQUIRE(info.has_value());
        CHECK(info->display_name == "open(int)");
        CHECK(info->status == symbol_resolution_status::resolved_object_only);
        CHECK(info->source == "symtab_token_prefix");
    }

    TEST_CASE("003: addendum alias prefers object symbol over binary exact collision", "[003][analysis][symbols]") {
        detail::temp_dir temp{"sontag_m1_resolve_symbol_addendum_rank"};

        auto nm_wrapper_path = temp.path / "tools" / "llvm-nm";
        detail::make_executable_file(nm_wrapper_path, detail::make_nm_addendum_collision_script());

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.nm_path = nm_wrapper_path;
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o0;
        request.decl_cells = {"int square(int x) { return x * x; }"};

        auto info = resolve_symbol_info(request, "square@PLT");
        REQUIRE(info.has_value());
        CHECK(info->display_name == "square(int)");
        CHECK(info->status == symbol_resolution_status::resolved_stub);
        CHECK(info->confidence == symbol_resolution_confidence::exact_relocation);
        CHECK(info->source == "symtab_token_prefix_relocation_alias_stub");
    }

    TEST_CASE("003: mem_trace executes for non-main symbol without synthetic entrypoint shim", "[003][analysis][mem]") {
        detail::temp_dir temp{"sontag_m1_mem_trace_non_main"};

        analysis_request request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = temp.path / "session";
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o0;
        request.static_link = true;
        request.decl_cells = {"int square(int x) { int y = x * x; return y; }"};
        request.exec_cells = {"volatile int sink = square(3);", "return sink;"};
        request.symbol = "square";

        auto trace_result = run_analysis(request, analysis_kind::mem_trace);
        CHECK(trace_result.success);
        CHECK(trace_result.exit_code == 9);
        CHECK(trace_result.artifact_text.find("symbol=") != std::string::npos);
        CHECK(trace_result.artifact_text.find("tracee_exit_code=9") != std::string::npos);
        CHECK(trace_result.artifact_text.find("map_count=0") == std::string::npos);
        CHECK(trace_result.artifact_text.find("event_count=0") == std::string::npos);
    }

}  // namespace sontag::test
