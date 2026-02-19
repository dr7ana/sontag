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

    TEST_CASE("008: inspect asm emits json payload with demangled symbol", "[008][inspect][asm_map]") {
        detail::temp_dir temp{"sontag_inspect_asm_map"};

        auto request = detail::make_request(
                temp.path / "session",
                "int foo(int x) { return x + 1; }\n"
                "int bar(int y) { return y * 2; }\n");
        request.symbol = "foo";

        auto result = run_analysis(request, analysis_kind::inspect_asm_map);
        REQUIRE(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_path.string().find("/artifacts/inspect/asm/") != std::string::npos);
        CHECK(result.artifact_path.extension() == ".json");
        CHECK(result.artifact_text.find("symbol:") != std::string::npos);
        CHECK(result.artifact_text.find("foo(") != std::string::npos);

        std::ifstream in{result.artifact_path};
        REQUIRE(in.good());
        std::ostringstream ss{};
        ss << in.rdbuf();
        auto json_text = ss.str();
        CHECK(json_text.find("\"schema_version\":1") != std::string::npos);
        CHECK(json_text.find("\"symbol_display\":\"foo(int)\"") != std::string::npos);
        CHECK(json_text.find("\"source\"") != std::string::npos);
        CHECK(json_text.find("\"ir\"") != std::string::npos);
        CHECK(json_text.find("\"asm\"") != std::string::npos);
        CHECK(json_text.find("\"opcode_table\"") != std::string::npos);
        CHECK(json_text.find("\"operations\"") != std::string::npos);
    }

    TEST_CASE("008: inspect mca summary parses deterministic wrapper output", "[008][inspect][mca]") {
        detail::temp_dir temp{"sontag_inspect_mca_summary"};
        auto tool_dir = temp.path / "tools";
        detail::fs::create_directories(tool_dir);

        auto mca_wrapper = tool_dir / "llvm-mca";
        detail::write_executable_script(
                mca_wrapper,
                "#!/usr/bin/env bash\n"
                "cat <<'EOF'\n"
                "Iterations:        100\n"
                "Instructions:      200\n"
                "Total Cycles:      57\n"
                "Total uOps:        200\n"
                "Dispatch Width:    6\n"
                "uOps Per Cycle:    3.51\n"
                "IPC:               3.51\n"
                "Block RThroughput: 0.5\n"
                "EOF\n");

        auto request = detail::make_request(temp.path / "session", "int foo(int x) { return x + 1; }\n");
        request.symbol = "foo";
        request.mca_path = mca_wrapper;

        auto result = run_analysis(request, analysis_kind::inspect_mca_summary);
        REQUIRE(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_path.string().find("/artifacts/inspect/mca/") != std::string::npos);
        CHECK(result.artifact_path.extension() == ".json");
        CHECK(result.artifact_text.find("iterations: 100") != std::string::npos);
        CHECK(result.artifact_text.find("ipc: 3.51") != std::string::npos);

        std::ifstream in{result.artifact_path};
        REQUIRE(in.good());
        std::ostringstream ss{};
        ss << in.rdbuf();
        auto json_text = ss.str();
        CHECK(json_text.find("\"schema_version\":1") != std::string::npos);
        CHECK(json_text.find("\"iterations\":100") != std::string::npos);
        CHECK(json_text.find("\"instructions\":200") != std::string::npos);
        CHECK(json_text.find("\"ipc\":3.51") != std::string::npos);
        CHECK(json_text.find("\"opcode_table\"") != std::string::npos);
        CHECK(json_text.find("\"operations\"") != std::string::npos);
    }

    TEST_CASE("008: inspect mca heatmap renders resource rows", "[008][inspect][mca]") {
        detail::temp_dir temp{"sontag_inspect_mca_heatmap"};
        auto tool_dir = temp.path / "tools";
        detail::fs::create_directories(tool_dir);

        auto mca_wrapper = tool_dir / "llvm-mca";
        detail::write_executable_script(
                mca_wrapper,
                "#!/usr/bin/env bash\n"
                "cat <<'EOF'\n"
                "Resources:\n"
                "[0]   - ALU\n"
                "[1]   - LSU\n"
                "\n"
                "Resource pressure per iteration:\n"
                "[0]    [1]\n"
                "0.50   0.25\n"
                "EOF\n");

        auto request = detail::make_request(temp.path / "session", "int foo(int x) { return x + 1; }\n");
        request.symbol = "foo";
        request.mca_path = mca_wrapper;

        auto result = run_analysis(request, analysis_kind::inspect_mca_heatmap);
        REQUIRE(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_path.extension() == ".json");
        CHECK(result.artifact_text.find("heatmap rows: 2") != std::string::npos);
        CHECK(result.artifact_text.find("ALU") != std::string::npos);
        CHECK(result.artifact_text.find("LSU") != std::string::npos);

        std::ifstream in{result.artifact_path};
        REQUIRE(in.good());
        std::ostringstream ss{};
        ss << in.rdbuf();
        auto json_text = ss.str();
        CHECK(json_text.find("\"schema_version\":1") != std::string::npos);
        CHECK(json_text.find("\"label\":\"ALU\"") != std::string::npos);
        CHECK(json_text.find("\"label\":\"LSU\"") != std::string::npos);
        CHECK(json_text.find("\"opcode_table\"") != std::string::npos);
        CHECK(json_text.find("\"operations\"") != std::string::npos);
    }

    TEST_CASE("008: graph defuse emits dot graph artifact", "[008][graph][defuse]") {
        detail::temp_dir temp{"sontag_graph_defuse"};

        auto request = detail::make_request(
                temp.path / "session",
                "int foo(int x) {\n"
                "  auto a = x + 1;\n"
                "  auto b = a * 2;\n"
                "  return b;\n"
                "}\n");
        request.symbol = "foo";
        request.opt_level = optimization_level::o0;

        auto result = run_analysis(request, analysis_kind::graph_defuse);
        REQUIRE(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_path.string().find("/artifacts/graphs/defuse/") != std::string::npos);
        CHECK(result.artifact_path.extension() == ".dot");
        CHECK(result.artifact_text.find("function: foo(int)") != std::string::npos);
        CHECK(result.artifact_text.find("nodes: ") != std::string::npos);
        CHECK(result.artifact_text.find("edges: ") != std::string::npos);

        std::ifstream in{result.artifact_path};
        REQUIRE(in.good());
        std::ostringstream ss{};
        ss << in.rdbuf();
        auto dot_text = ss.str();
        CHECK(dot_text.find("digraph defuse_") != std::string::npos);
        CHECK(dot_text.find("->") != std::string::npos);
    }

    TEST_CASE("008: graph call defaults to whole-snapshot graph when symbol omitted", "[008][graph][call]") {
        detail::temp_dir temp{"sontag_graph_call_all"};

        auto request = detail::make_request(
                temp.path / "session",
                "int foo(int x) { return x + 1; }\n"
                "int bar(int y) { return y * 2; }\n");

        auto result = run_analysis(request, analysis_kind::graph_call);
        REQUIRE(result.success);
        CHECK(result.exit_code == 0);
        CHECK(result.artifact_text.find("root: <all>") != std::string::npos);

        std::ifstream in{result.artifact_path};
        REQUIRE(in.good());
        std::ostringstream ss{};
        ss << in.rdbuf();
        auto dot_text = ss.str();
        CHECK(dot_text.find("foo(int)") != std::string::npos);
        CHECK(dot_text.find("bar(int)") != std::string::npos);
        CHECK(dot_text.find("__sontag_main()") != std::string::npos);
    }

}  // namespace sontag::test
