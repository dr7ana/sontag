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

    struct scoped_cwd {
        fs::path original{};

        explicit scoped_cwd(const fs::path& new_cwd) {
            original = fs::current_path();
            fs::current_path(new_cwd);
        }

        ~scoped_cwd() {
            std::error_code ec{};
            fs::current_path(original, ec);
        }
    };

    struct snapshot_record {
        std::string name{};
        size_t cell_count{};
    };

    struct persisted_snapshots {
        int schema_version{1};
        std::string active_snapshot{};
        std::vector<snapshot_record> snapshots{};
    };

    enum class cell_kind { declarative, executable };

    struct cell_record {
        uint64_t cell_id{};
        cell_kind kind{cell_kind::executable};
        std::string text{};
    };

    struct persisted_cells {
        int schema_version{1};
        uint64_t next_cell_id{1U};
        std::vector<cell_record> cells{};
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
    };

    struct persisted_config {
        int schema_version{1};
        std::string clang{};
        std::string cxx_standard{};
        std::string opt_level{};
        std::optional<std::string> target{};
        std::optional<std::string> cpu{};
        std::optional<std::string> mca_cpu{};
        std::string mca_path{};
        std::string cache_dir{};
        std::string output{};
        std::string color{};
        std::string color_scheme{"classic"};
    };

    template <typename T>
    static T read_json_file(const fs::path& path) {
        std::ifstream in{path};
        REQUIRE(in.good());

        std::ostringstream ss{};
        ss << in.rdbuf();
        auto text = ss.str();

        T value{};
        auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(value, text);
        REQUIRE_FALSE(ec);
        return value;
    }

    static void write_text_file(const fs::path& path, std::string_view text) {
        std::ofstream out{path};
        REQUIRE(out.good());
        out << text;
        REQUIRE(out.good());
    }

    static std::optional<size_t> snapshot_cell_count(const persisted_snapshots& snapshots, std::string_view name) {
        for (const auto& record : snapshots.snapshots) {
            if (record.name == name) {
                return record.cell_count;
            }
        }
        return std::nullopt;
    }

    static fs::path find_single_session_dir(const fs::path& cache_dir) {
        auto sessions_root = cache_dir / "sessions";
        REQUIRE(fs::exists(sessions_root));

        std::vector<fs::path> session_dirs{};
        for (const auto& entry : fs::directory_iterator(sessions_root)) {
            if (entry.is_directory()) {
                session_dirs.push_back(entry.path());
            }
        }

        REQUIRE(session_dirs.size() == 1U);
        return session_dirs[0];
    }

    static void write_all(int fd, std::string_view text) {
        size_t offset = 0U;
        while (offset < text.size()) {
            auto* data = text.data() + offset;
            auto remaining = text.size() - offset;
            auto bytes = ::write(fd, data, remaining);
            REQUIRE(bytes > 0);
            offset += static_cast<size_t>(bytes);
        }
    }

    static void run_repl_script(startup_config& cfg, std::string_view script) {
        int pipe_fds[2]{-1, -1};
        REQUIRE(::pipe(pipe_fds) == 0);

        auto read_fd = pipe_fds[0];
        auto write_fd = pipe_fds[1];

        write_all(write_fd, script);
        REQUIRE(::close(write_fd) == 0);

        auto saved_stdin = ::dup(STDIN_FILENO);
        REQUIRE(saved_stdin >= 0);
        REQUIRE(::dup2(read_fd, STDIN_FILENO) >= 0);
        REQUIRE(::close(read_fd) == 0);

        try {
            cli::run_repl(cfg);
        } catch (...) {
            (void)::dup2(saved_stdin, STDIN_FILENO);
            (void)::close(saved_stdin);
            throw;
        }

        REQUIRE(::dup2(saved_stdin, STDIN_FILENO) >= 0);
        REQUIRE(::close(saved_stdin) == 0);
    }

    struct repl_output {
        std::string out{};
        std::string err{};
    };

    static repl_output run_repl_script_capture_output(startup_config& cfg, std::string_view script) {
        int pipe_fds[2]{-1, -1};
        REQUIRE(::pipe(pipe_fds) == 0);

        auto read_fd = pipe_fds[0];
        auto write_fd = pipe_fds[1];

        write_all(write_fd, script);
        REQUIRE(::close(write_fd) == 0);

        auto saved_stdin = ::dup(STDIN_FILENO);
        REQUIRE(saved_stdin >= 0);
        REQUIRE(::dup2(read_fd, STDIN_FILENO) >= 0);
        REQUIRE(::close(read_fd) == 0);

        std::ostringstream captured_out{};
        std::ostringstream captured_err{};
        auto* saved_out_buf = std::cout.rdbuf(captured_out.rdbuf());
        auto* saved_err_buf = std::cerr.rdbuf(captured_err.rdbuf());

        try {
            cli::run_repl(cfg);
        } catch (...) {
            std::cout.rdbuf(saved_out_buf);
            std::cerr.rdbuf(saved_err_buf);
            (void)::dup2(saved_stdin, STDIN_FILENO);
            (void)::close(saved_stdin);
            throw;
        }

        std::cout.flush();
        std::cerr.flush();

        std::cout.rdbuf(saved_out_buf);
        std::cerr.rdbuf(saved_err_buf);
        REQUIRE(::dup2(saved_stdin, STDIN_FILENO) >= 0);
        REQUIRE(::close(saved_stdin) == 0);

        return repl_output{.out = captured_out.str(), .err = captured_err.str()};
    }
}}  // namespace sontag::test::detail

namespace glz {
    template <>
    struct meta<sontag::test::detail::snapshot_record> {
        using T = sontag::test::detail::snapshot_record;
        static constexpr auto value = object("name", &T::name, "cell_count", &T::cell_count);
    };

    template <>
    struct meta<sontag::test::detail::persisted_snapshots> {
        using T = sontag::test::detail::persisted_snapshots;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "active_snapshot",
                       &T::active_snapshot,
                       "snapshots",
                       &T::snapshots);
    };

    template <>
    struct meta<sontag::test::detail::cell_record> {
        using T = sontag::test::detail::cell_record;
        static constexpr auto value = object("cell_id", &T::cell_id, "kind", &T::kind, "text", &T::text);
    };

    template <>
    struct meta<sontag::test::detail::persisted_cells> {
        using T = sontag::test::detail::persisted_cells;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "next_cell_id",
                       &T::next_cell_id,
                       "cells",
                       &T::cells,
                       "decl_cells",
                       &T::decl_cells,
                       "exec_cells",
                       &T::exec_cells);
    };

    template <>
    struct meta<sontag::test::detail::persisted_config> {
        using T = sontag::test::detail::persisted_config;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "clang",
                       &T::clang,
                       "cxx_standard",
                       &T::cxx_standard,
                       "opt_level",
                       &T::opt_level,
                       "target",
                       &T::target,
                       "cpu",
                       &T::cpu,
                       "mca_cpu",
                       &T::mca_cpu,
                       "mca_path",
                       &T::mca_path,
                       "cache_dir",
                       &T::cache_dir,
                       "output",
                       &T::output,
                       "color",
                       &T::color,
                       "color_scheme",
                       &T::color_scheme);
    };
}  // namespace glz

namespace sontag::test {
    using namespace sontag::literals;

    TEST_CASE("005: session bootstrap persists config cells and snapshots", "[005][session]") {
        detail::temp_dir temp{"sontag_session_bootstrap"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.language_standard = cxx_standard::cxx20;
        cfg.opt_level = optimization_level::o1;
        cfg.output = output_mode::json;
        cfg.color = color_mode::never;
        cfg.delta_color_scheme = color_scheme::classic;

        detail::run_repl_script(
                cfg,
                ":decl int seed = 42;\n"
                ":mark baseline\n"
                ":decl int inc(int x) { return x + seed; }\n"
                ":quit\n");

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);

        auto persisted_cfg = detail::read_json_file<detail::persisted_config>(session_dir / "config.json");
        CHECK(persisted_cfg.schema_version == 1);
        CHECK(persisted_cfg.cxx_standard == "c++20");
        CHECK(persisted_cfg.opt_level == "O1");
        CHECK_FALSE(persisted_cfg.mca_cpu.has_value());
        CHECK(persisted_cfg.mca_path == "llvm-mca");
        CHECK(persisted_cfg.cache_dir == cfg.cache_dir.string());
        CHECK(persisted_cfg.output == "json");
        CHECK(persisted_cfg.color == "never");
        CHECK(persisted_cfg.color_scheme == "classic");

        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 2U);
        CHECK(persisted_cells.decl_cells[0].find("seed") != std::string::npos);
        CHECK(persisted_cells.decl_cells[1].find("inc(") != std::string::npos);
        CHECK(persisted_cells.exec_cells.empty());

        auto snapshots = detail::read_json_file<detail::persisted_snapshots>(session_dir / "snapshots.json");
        auto baseline_count = detail::snapshot_cell_count(snapshots, "baseline");
        REQUIRE(baseline_count);
        CHECK(*baseline_count == 1U);

        auto current_count = detail::snapshot_cell_count(snapshots, "current");
        REQUIRE(current_count);
        CHECK(*current_count == 2U);
    }

    TEST_CASE("005: resume latest restores state and reset updates current snapshot", "[005][session][resume]") {
        detail::temp_dir temp{"sontag_session_resume"};

        startup_config initial_cfg{};
        initial_cfg.cache_dir = temp.path / "cache";
        initial_cfg.history_enabled = false;
        initial_cfg.language_standard = cxx_standard::cxx20;
        initial_cfg.opt_level = optimization_level::o3;
        initial_cfg.output = output_mode::json;
        initial_cfg.color = color_mode::never;
        initial_cfg.delta_color_scheme = color_scheme::classic;

        detail::run_repl_script(
                initial_cfg,
                ":decl int value = 7;\n"
                ":decl int twice(int x) { return x * 2; }\n"
                ":mark baseline\n"
                ":quit\n");

        auto session_dir = detail::find_single_session_dir(initial_cfg.cache_dir);

        startup_config resumed_cfg{};
        resumed_cfg.cache_dir = initial_cfg.cache_dir;
        resumed_cfg.history_enabled = false;
        resumed_cfg.resume_session = "latest";
        resumed_cfg.language_standard = cxx_standard::cxx2c;
        resumed_cfg.opt_level = optimization_level::oz;
        resumed_cfg.output = output_mode::table;
        resumed_cfg.color = color_mode::always;
        resumed_cfg.delta_color_scheme = color_scheme::vaporwave;

        detail::run_repl_script(
                resumed_cfg,
                ":mark resumed\n"
                ":reset\n"
                ":quit\n");

        auto resumed_session_dir = detail::find_single_session_dir(initial_cfg.cache_dir);
        CHECK(resumed_session_dir == session_dir);

        CHECK(resumed_cfg.language_standard == initial_cfg.language_standard);
        CHECK(resumed_cfg.opt_level == initial_cfg.opt_level);
        CHECK(resumed_cfg.output == initial_cfg.output);
        CHECK(resumed_cfg.color == initial_cfg.color);
        CHECK(resumed_cfg.delta_color_scheme == initial_cfg.delta_color_scheme);

        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());

        auto snapshots = detail::read_json_file<detail::persisted_snapshots>(session_dir / "snapshots.json");

        auto baseline_count = detail::snapshot_cell_count(snapshots, "baseline");
        REQUIRE(baseline_count);
        CHECK(*baseline_count == 2U);

        auto resumed_count = detail::snapshot_cell_count(snapshots, "resumed");
        REQUIRE(resumed_count);
        CHECK(*resumed_count == 2U);

        auto current_count = detail::snapshot_cell_count(snapshots, "current");
        REQUIRE(current_count);
        CHECK(*current_count == 0U);
    }

    TEST_CASE("005: show all prints declarative and executable regions", "[005][session][show]") {
        detail::temp_dir temp{"sontag_show_code"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl #include <cstdint>\n"
                "uint64_t first = 1;\n"
                "uint64_t second = first + 1;\n"
                ":show all\n"
                ":quit\n");

        auto decl_pos = output.out.find("#include <cstdint>");
        auto main_pos = output.out.find("int __sontag_main() {");
        auto first_pos = output.out.find("uint64_t first = 1;");
        auto second_pos = output.out.find("uint64_t second = first + 1;");
        REQUIRE(decl_pos != std::string::npos);
        REQUIRE(main_pos != std::string::npos);
        REQUIRE(first_pos != std::string::npos);
        REQUIRE(second_pos != std::string::npos);
        CHECK(decl_pos < main_pos);
        CHECK(main_pos < first_pos);
        CHECK(first_pos < second_pos);
    }

    TEST_CASE("005: symbols command lists current snapshot symbols", "[005][session][symbols]") {
        detail::temp_dir temp{"sontag_symbols"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int foo(int x) { return x + 1; }\n"
                ":symbols\n"
                ":quit\n");

        CHECK(output.out.find("symbols:") != std::string::npos);
        CHECK(output.out.find("__sontag_main") != std::string::npos);
        CHECK(output.out.find("foo(") != std::string::npos);
    }

    TEST_CASE("005: delta command renders pairwise summary and opcode table info", "[005][session][delta]") {
        detail::temp_dir temp{"sontag_delta_command_table"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl volatile int sink = 0;\n"
                "sink = 7 + 11;\n"
                ":delta\n"
                ":quit\n");

        CHECK(output.out.find("delta: ") != std::string::npos);
        CHECK(output.out.find("mode: pairwise") != std::string::npos);
        CHECK(output.out.find("baseline: O0") != std::string::npos);
        CHECK(output.out.find("target: O2") != std::string::npos);
        CHECK(output.out.find("opcode table entries: ") != std::string::npos);
        CHECK(output.out.find("levels:") != std::string::npos);
        CHECK(output.out.find("success=true | operations=") != std::string::npos);
        CHECK(output.out.find("| opcodes: ") != std::string::npos);
        CHECK(output.out.find("diff (O0 -> O2, full side-by-side):") != std::string::npos);
        CHECK(output.out.find("alignment anchor: ") != std::string::npos);
        CHECK(output.out.find("metrics:") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: delta spectrum renders multi-level side-by-side output", "[005][session][delta][spectrum]") {
        detail::temp_dir temp{"sontag_delta_command_spectrum"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl volatile int sink = 0;\n"
                "sink = 5 * 13;\n"
                ":delta spectrum O3\n"
                ":quit\n");

        CHECK(output.out.find("mode: spectrum") != std::string::npos);
        CHECK(output.out.find("baseline: O0") != std::string::npos);
        CHECK(output.out.find("target: O3") != std::string::npos);
        CHECK(output.out.find("spectrum (O0 -> O3):") != std::string::npos);
        CHECK(output.out.find("alignment anchors: O0[") != std::string::npos);
        CHECK(output.out.find("<-> O1[") != std::string::npos);
        CHECK(output.out.find("<-> O2[") != std::string::npos);
        CHECK(output.out.find("<-> O3[") != std::string::npos);
        CHECK(output.out.find("metrics:") != std::string::npos);
        CHECK(output.out.find("size.symbol_text_bytes (bytes)") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: delta command emits typed json payload including opcode mapping", "[005][session][delta][json]") {
        detail::temp_dir temp{"sontag_delta_command_json"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.output = output_mode::json;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl volatile int sink = 0;\n"
                "sink = 3 * 9;\n"
                ":delta O3\n"
                ":quit\n");

        CHECK(output.out.find("\"command\":\"delta\"") != std::string::npos);
        CHECK(output.out.find("\"mode\":\"pairwise\"") != std::string::npos);
        CHECK(output.out.find("\"opcode_table\"") != std::string::npos);
        CHECK(output.out.find("\"levels\"") != std::string::npos);
        CHECK(output.out.find("\"baseline\":\"O0\"") != std::string::npos);
        CHECK(output.out.find("\"target\":\"O3\"") != std::string::npos);
        CHECK(output.out.find("\"triplet\"") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: delta spectrum emits typed json payload with intermediate levels", "[005][session][delta][json]") {
        detail::temp_dir temp{"sontag_delta_command_spectrum_json"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.output = output_mode::json;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl volatile int sink = 0;\n"
                "sink = 2 * 17;\n"
                ":delta spectrum O3\n"
                ":quit\n");

        CHECK(output.out.find("\"command\":\"delta\"") != std::string::npos);
        CHECK(output.out.find("\"mode\":\"spectrum\"") != std::string::npos);
        CHECK(output.out.find("\"baseline\":\"O0\"") != std::string::npos);
        CHECK(output.out.find("\"target\":\"O3\"") != std::string::npos);
        CHECK(output.out.find("\"level\":\"O1\"") != std::string::npos);
        CHECK(output.out.find("\"level\":\"O2\"") != std::string::npos);
        CHECK(output.out.find("\"level\":\"O3\"") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: invalid cell is rejected and state remains unchanged", "[005][session][validation]") {
        detail::temp_dir temp{"sontag_state_validation"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl #include <cstdint>\n"
                "uint64_t value{64};\n"
                "value = ;\n"
                ":quit\n");

        CHECK(output.out.find("stored decl #1 (state: valid)") != std::string::npos);
        CHECK(output.out.find("stored cell #1 (state: valid)") != std::string::npos);
        CHECK(output.err.find("cell rejected, state unchanged") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0] == "#include <cstdint>");
        CHECK(persisted_cells.exec_cells[0] == "uint64_t value{64};");
    }

    TEST_CASE("005: clear last removes only most recent executable cell", "[005][session][clear_last]") {
        detail::temp_dir temp{"sontag_clear_last"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int base = 5;\n"
                "int x = base;\n"
                "int y = x + 1;\n"
                ":clear last\n"
                ":show exec\n"
                ":quit\n");

        CHECK(output.out.find("stored decl #1 (state: valid)") != std::string::npos);
        CHECK(output.out.find("stored cell #1 (state: valid)") != std::string::npos);
        CHECK(output.out.find("stored cell #2 (state: valid)") != std::string::npos);
        CHECK(output.out.find("cleared last executable cell") != std::string::npos);
        CHECK(output.out.find("int x = base;") != std::string::npos);
        CHECK(output.out.find("int y = x + 1;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0] == "int base = 5;");
        CHECK(persisted_cells.exec_cells[0] == "int x = base;");
    }

    TEST_CASE("005: clear last removes most recently added declarative cell", "[005][session][clear_last]") {
        detail::temp_dir temp{"sontag_clear_last_decl"};
        auto source_path = temp.path / "from_file.cpp";
        detail::write_text_file(
                source_path,
                "int seed = 9;\n"
                "int __sontag_main() {\n"
                "    int x = seed + 1;\n"
                "    return x;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:decl int v = 6;\n:clear last\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find("stored decl #2 (state: valid)") != std::string::npos);
        CHECK(output.out.find("cleared last declarative cell") != std::string::npos);
        CHECK(output.out.find("int v = 6;") == std::string::npos);
        CHECK(output.out.find("int seed = 9;") != std::string::npos);
        CHECK(output.out.find("int x = seed + 1;") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("int seed = 9;") != std::string::npos);
        CHECK(persisted_cells.decl_cells[0].find("int v = 6;") == std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("int x = seed + 1;") != std::string::npos);
    }

    TEST_CASE("005: persisted cell ids stay monotonic after clear last", "[005][session][cell_id]") {
        detail::temp_dir temp{"sontag_cell_id_monotonic"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int base = 1;\n"
                "int temp = base;\n"
                ":clear last\n"
                ":decl int next = base + 1;\n"
                ":quit\n");

        CHECK(output.out.find("stored decl #1 (state: valid)") != std::string::npos);
        CHECK(output.out.find("stored cell #1 (state: valid)") != std::string::npos);
        CHECK(output.out.find("cleared last executable cell") != std::string::npos);
        CHECK(output.out.find("stored decl #2 (state: valid)") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");

        REQUIRE(persisted_cells.cells.size() == 2U);
        CHECK(persisted_cells.cells[0].kind == detail::cell_kind::declarative);
        CHECK(persisted_cells.cells[1].kind == detail::cell_kind::declarative);
        CHECK(persisted_cells.cells[0].cell_id < persisted_cells.cells[1].cell_id);
        CHECK(persisted_cells.next_cell_id == persisted_cells.cells[1].cell_id + 1U);
    }

    TEST_CASE("005: declfile appends full file as a declarative cell", "[005][session][declfile]") {
        detail::temp_dir temp{"sontag_declfile"};
        auto source_path = temp.path / "decl_only.hpp";
        detail::write_text_file(
                source_path,
                "#include <cstdint>\n"
                "using u64 = std::uint64_t;\n"
                "u64 base = 8;\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":declfile \"{}\"\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("stored decl #1 (state: valid)") != std::string::npos);
        CHECK(output.out.find("#include <cstdint>") != std::string::npos);
        CHECK(output.out.find("using u64 = std::uint64_t;") != std::string::npos);
        CHECK(output.out.find("u64 base = 8;") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: file loads declarative prefix and driver body", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_load"};
        auto source_path = temp.path / "program.cpp";
        detail::write_text_file(
                source_path,
                "#include <cstdint>\n"
                "uint64_t value = 64;\n"
                "\n"
                "int __sontag_main() {\n"
                "    uint64_t doubled = value * 2;\n"
                "    return static_cast<int>(doubled);\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find("#include <cstdint>") != std::string::npos);
        CHECK(output.out.find("uint64_t value = 64;") != std::string::npos);
        CHECK(output.out.find("uint64_t doubled = value * 2;") != std::string::npos);
        CHECK(output.out.find("return static_cast<int>(doubled);") != std::string::npos);
        CHECK(output.out.find("return 0;") == std::string::npos);
        CHECK(output.out.find("return static_cast<int>(doubled);\n\n}") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("uint64_t value = 64;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("uint64_t doubled = value * 2;") != std::string::npos);
    }

    TEST_CASE("005: file rejects source with both main and __sontag_main", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_conflict"};
        auto source_path = temp.path / "conflict.cpp";
        detail::write_text_file(
                source_path,
                "int main() { return 0; }\n"
                "int __sontag_main() { return 0; }\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.err.find("file contains both __sontag_main and main; keep only one driver function") !=
              std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: file rejects source with no driver and suggests declfile", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_no_driver"};
        auto source_path = temp.path / "no_driver.cpp";
        detail::write_text_file(
                source_path,
                "#include <cstdint>\n"
                "uint64_t value = 64;\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.err.find("no driver function found (expected main or __sontag_main)") != std::string::npos);
        CHECK(output.err.find("use :declfile <path>") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: file accepts quoted relative path and normalizes resolution", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_relative"};
        auto nested_dir = temp.path / "inputs";
        detail::fs::create_directories(nested_dir);
        auto source_path = nested_dir / "program.cpp";
        detail::write_text_file(
                source_path,
                "int seed = 5;\n"
                "int __sontag_main() {\n"
                "    int value = seed + 1;\n"
                "    return value;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::repl_output{};
        {
            auto cwd = detail::scoped_cwd{temp.path};
            output = detail::run_repl_script_capture_output(
                    cfg,
                    ":file \"inputs/program.cpp\"\n"
                    ":quit\n");
        }

        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find(source_path.string()) != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("int seed = 5;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("int value = seed + 1;") != std::string::npos);
    }

    TEST_CASE("005: file loads nested brace-heavy control flow with comments", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_nested_braces"};
        auto source_path = temp.path / "nested.cpp";
        detail::write_text_file(
                source_path,
                R"(#include <array>
#include <cstdint>
#include <vector>

struct sample_point {
    int x{0};
    int y{0};
};

struct layout {
    std::array<int, 4> bins{};
    int bias{1};
};

static int accumulate(const std::vector<int>& values);
static int normalize(sample_point point, int scale);

static int accumulate(const std::vector<int>& values) {
    int sum = 0;
    for (int value : values) {
        sum += value;
    }
    return sum;
}

static int normalize(sample_point point, int scale) {
    return (point.x + point.y) * scale;
}

int seed = 7;

int __sontag_main() {
    // braces in comment: { nested } still comment
    layout state{};
    sample_point point{2, 3};
    std::vector<int> values{1, 2, 3, 4};
    int total = normalize(point, seed);

    if (seed > 0) {
        for (int i = 0; i < static_cast<int>(state.bins.size()); ++i) {
            state.bins[static_cast<size_t>(i)] = i + total;
        }

        for (int value : values) {
            if ((value % 2) == 0) {
                total += value;
            }
            else {
                total -= value;
            }
        }
    }

    total += accumulate(values);
    return total + state.bins[0];
}
)");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);
        CHECK(output.out.find("loaded file") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("#include <array>") != std::string::npos);
        CHECK(persisted_cells.decl_cells[0].find("struct layout") != std::string::npos);
        CHECK(persisted_cells.decl_cells[0].find("static int accumulate(const std::vector<int>& values);") !=
              std::string::npos);
        CHECK(persisted_cells.decl_cells[0].find("int seed = 7;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("for (int i = 0; i < static_cast<int>(state.bins.size()); ++i)") !=
              std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("total += accumulate(values);") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("return total + state.bins[0];") != std::string::npos);
    }

    TEST_CASE("005: file preserves macro-heavy declarative prefixes", "[005][session][file][macro]") {
        detail::temp_dir temp{"sontag_file_macros"};
        auto source_path = temp.path / "macros.cpp";
        detail::write_text_file(
                source_path,
                R"(#define APPLY2(a, b) ((a) + (b))
#define SCALE3(x) \
    ((x) * 3)
#define ASSIGN_AND_BUMP(dst, src) \
    do {                          \
        (dst) = (src);            \
        ++(dst);                  \
    } while (false)

int seed = 7;

int __sontag_main() {
    int value = APPLY2(seed, 4);
    ASSIGN_AND_BUMP(value, SCALE3(value));
    return value;
}
)");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);
        CHECK(output.out.find("loaded file") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("#define APPLY2(a, b)") != std::string::npos);
        CHECK(persisted_cells.decl_cells[0].find("#define SCALE3(x)") != std::string::npos);
        CHECK(persisted_cells.decl_cells[0].find("#define ASSIGN_AND_BUMP(dst, src)") != std::string::npos);
        CHECK(persisted_cells.decl_cells[0].find("int seed = 7;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("int value = APPLY2(seed, 4);") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("ASSIGN_AND_BUMP(value, SCALE3(value));") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("return value;") != std::string::npos);
    }

    TEST_CASE("005: file loads braces in strings and raw strings inside driver body", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_string_braces"};
        auto source_path = temp.path / "string_braces.cpp";
        detail::write_text_file(
                source_path,
                R"(int __sontag_main() {
    const char* text = "{not a block}";
    const char* raw = R"json({
  "payload": "value with } and { braces"
})json";
    if (text[0] == '{') { return 1; }
    return raw[0] == '{' ? 2 : 0;
}
)");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);
        CHECK(output.out.find("loaded file") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.empty());
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells[0].find(R"(const char* text = "{not a block}";)") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find(R"(const char* raw = R"json({)") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("return raw[0] == '{' ? 2 : 0;") != std::string::npos);
    }

    TEST_CASE("005: file uses main as driver when __sontag_main is absent", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_main_driver"};
        auto source_path = temp.path / "main_driver.cpp";
        detail::write_text_file(
                source_path,
                R"(const char* note = "__sontag_main is not defined in this file";
int main() {
    int v = 11;
    return v;
}
)");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);
        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.err.find("both __sontag_main and main") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("__sontag_main is not defined") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("int v = 11;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("return v;") != std::string::npos);
    }

}  // namespace sontag::test
