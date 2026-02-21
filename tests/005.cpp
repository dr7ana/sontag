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

    using internal::cell_kind;
    using internal::persisted_cells;
    using internal::persisted_config;
    using internal::persisted_snapshots;
    using internal::snapshot_record;

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

    struct scoped_env_var {
        std::string key{};
        std::optional<std::string> previous{};

        scoped_env_var(std::string key_value, std::optional<std::string> next) : key(std::move(key_value)) {
            if (auto* existing = std::getenv(key.c_str()); existing != nullptr) {
                previous = std::string{existing};
            }

            if (next) {
                REQUIRE(::setenv(key.c_str(), next->c_str(), 1) == 0);
            }
            else {
                REQUIRE(::unsetenv(key.c_str()) == 0);
            }
        }

        ~scoped_env_var() {
            if (previous) {
                (void)::setenv(key.c_str(), previous->c_str(), 1);
            }
            else {
                (void)::unsetenv(key.c_str());
            }
        }
    };

    static const snapshot_record* snapshot_by_name(const persisted_snapshots& snapshots, std::string_view name) {
        for (const auto& record : snapshots.snapshots) {
            if (record.name == name) {
                return &record;
            }
        }
        return nullptr;
    }

    static std::optional<size_t> snapshot_cell_count(const persisted_snapshots& snapshots, std::string_view name) {
        if (auto* record = snapshot_by_name(snapshots, name)) {
            return record->cell_count;
        }
        return std::nullopt;
    }

    static size_t count_occurrences(std::string_view haystack, std::string_view needle) {
        if (needle.empty()) {
            return 0U;
        }
        auto count = size_t{0U};
        auto pos = size_t{0U};
        while (true) {
            auto found = haystack.find(needle, pos);
            if (found == std::string_view::npos) {
                break;
            }
            ++count;
            pos = found + needle.size();
        }
        return count;
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
        CHECK(persisted_cfg.mca_path == SONTAG_LLVM_MCA_EXECUTABLE_PATH);
        CHECK(persisted_cfg.nm_path == SONTAG_LLVM_NM_EXECUTABLE_PATH);
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
        auto* baseline = detail::snapshot_by_name(snapshots, "baseline");
        REQUIRE(baseline != nullptr);
        CHECK(baseline->cell_count == 1U);
        REQUIRE(baseline->decl_cells.size() == 1U);
        CHECK(baseline->decl_cells[0].find("seed") != std::string::npos);
        CHECK(baseline->exec_cells.empty());

        auto* current = detail::snapshot_by_name(snapshots, "current");
        REQUIRE(current != nullptr);
        CHECK(current->cell_count == 2U);
        REQUIRE(current->decl_cells.size() == 2U);
        CHECK(current->decl_cells[0].find("seed") != std::string::npos);
        CHECK(current->decl_cells[1].find("inc(") != std::string::npos);
        CHECK(current->exec_cells.empty());
    }

    TEST_CASE("005: resume latest restores state and reset preserves named snapshots", "[005][session][resume]") {
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
        CHECK(snapshots.active_snapshot == "current");
        REQUIRE(snapshots.snapshots.size() == 3U);

        auto* baseline = detail::snapshot_by_name(snapshots, "baseline");
        REQUIRE(baseline != nullptr);
        CHECK(baseline->cell_count == 2U);
        REQUIRE(baseline->decl_cells.size() == 2U);
        CHECK(baseline->exec_cells.empty());

        auto* resumed = detail::snapshot_by_name(snapshots, "resumed");
        REQUIRE(resumed != nullptr);
        CHECK(resumed->cell_count == 2U);
        REQUIRE(resumed->decl_cells.size() == 2U);
        CHECK(resumed->exec_cells.empty());

        auto* current = detail::snapshot_by_name(snapshots, "current");
        REQUIRE(current != nullptr);
        CHECK(current->cell_count == 0U);
        CHECK(current->decl_cells.empty());
        CHECK(current->exec_cells.empty());
    }

    TEST_CASE("005: reset snapshots clears named snapshots and keeps current", "[005][session][reset_snapshots]") {
        detail::temp_dir temp{"sontag_reset_snapshots"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int value = 7;\n"
                ":mark baseline\n"
                ":decl int next = value + 1;\n"
                ":mark expanded\n"
                ":reset snapshots\n"
                ":quit\n");

        CHECK(output.out.find("snapshots reset") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 2U);
        CHECK(persisted_cells.exec_cells.empty());

        auto snapshots = detail::read_json_file<detail::persisted_snapshots>(session_dir / "snapshots.json");
        CHECK(snapshots.active_snapshot == "current");
        REQUIRE(snapshots.snapshots.size() == 1U);

        CHECK_FALSE(detail::snapshot_cell_count(snapshots, "baseline"));
        CHECK_FALSE(detail::snapshot_cell_count(snapshots, "expanded"));

        auto* current = detail::snapshot_by_name(snapshots, "current");
        REQUIRE(current != nullptr);
        CHECK(current->cell_count == 2U);
        REQUIRE(current->decl_cells.size() == 2U);
        CHECK(current->exec_cells.empty());
    }

    TEST_CASE("005: config command lists categories and category values", "[005][session][config]") {
        detail::temp_dir temp{"sontag_config_categories"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":config\n"
                "build\n"
                "q\n"
                ":config\n"
                "ui\n"
                "q\n"
                ":config\n"
                "session\n"
                "q\n"
                ":config\n"
                "editor\n"
                "q\n"
                ":quit\n");

        CHECK(output.out.find("build:\n") != std::string::npos);
        CHECK(output.out.find("  std=") != std::string::npos);
        CHECK(output.out.find("  opt=") != std::string::npos);
        CHECK(output.out.find("  toolchain_dir=") != std::string::npos);
        CHECK(output.out.find("  clang=") == std::string::npos);
        CHECK(output.out.find("  mca_path=") == std::string::npos);

        CHECK(output.out.find("ui:\n") != std::string::npos);
        CHECK(output.out.find("  output=") != std::string::npos);
        CHECK(output.out.find("  color=") != std::string::npos);

        CHECK(output.out.find("session:\n") != std::string::npos);
        CHECK(output.out.find("  cache_dir=") != std::string::npos);
        CHECK(output.out.find("  history_file=") != std::string::npos);

        CHECK(output.out.find("editor:\n") != std::string::npos);
        CHECK(output.out.find("  editor=") != std::string::npos);
        CHECK(output.out.find("  formatter=") != std::string::npos);
    }

    TEST_CASE("005: config assignment and reset update mutable settings", "[005][session][config]") {
        detail::temp_dir temp{"sontag_config_set_reset"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":config build.opt=O3\n"
                ":config ui.color=always\n"
                ":config editor.editor=vim\n"
                ":config editor.formatter=clang-format-21\n"
                ":config session.history_file=.sontag/test_history\n"
                ":config build\n"
                ":config ui\n"
                ":config editor\n"
                ":config session\n"
                ":config reset\n"
                ":config build\n"
                ":config ui\n"
                ":config editor\n"
                ":config session\n"
                ":quit\n");

        CHECK(output.out.find("updated build.opt=O3") != std::string::npos);
        CHECK(output.out.find("updated ui.color=always") != std::string::npos);
        CHECK(output.out.find("updated editor.editor=vim") != std::string::npos);
        CHECK(output.out.find("updated editor.formatter=clang-format-21") != std::string::npos);
        CHECK(output.out.find("updated session.history_file=.sontag/test_history") != std::string::npos);

        CHECK(output.out.find("  opt=O3") != std::string::npos);
        CHECK(output.out.find("  color=always") != std::string::npos);
        CHECK(output.out.find("  editor=vim") != std::string::npos);
        CHECK(output.out.find("  formatter=clang-format-21") != std::string::npos);
        CHECK(output.out.find("  history_file=.sontag/test_history") != std::string::npos);

        CHECK(output.out.find("config reset") != std::string::npos);
        CHECK(output.out.find("  opt=O0") != std::string::npos);
        CHECK(output.out.find("  color=auto") != std::string::npos);
        CHECK(output.out.find("  editor=") != std::string::npos);
        CHECK(output.out.find("  editor=auto") == std::string::npos);
        CHECK(output.out.find("  formatter=clang-format") != std::string::npos);
        CHECK(output.out.find("  history_file=.sontag/history") != std::string::npos);
    }

    TEST_CASE("005: config menu accepts category key=value updates", "[005][session][config]") {
        detail::temp_dir temp{"sontag_config_menu_assignment"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":config\n"
                "ui\n"
                "color_scheme=vaporwave\n"
                ":config ui\n"
                ":quit\n");

        CHECK(output.out.find("updated ui.color_scheme=vaporwave") != std::string::npos);
        CHECK(output.out.find("  color_scheme=vaporwave") != std::string::npos);
    }

    TEST_CASE("005: config menu bare key prompts for value", "[005][session][config]") {
        detail::temp_dir temp{"sontag_config_menu_bare_key"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":config\n"
                "ui\n"
                "output\n"
                "json\n"
                ":config ui\n"
                ":quit\n");

        CHECK(output.out.find("updated ui.output=json") != std::string::npos);
        CHECK(output.out.find("  output=json") != std::string::npos);
    }

    TEST_CASE("005: config command reports invalid inputs", "[005][session][config]") {
        detail::temp_dir temp{"sontag_config_invalid"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":config unknown\n"
                ":config build.opt=Og\n"
                ":config nope=value\n"
                ":config build.opt=\n"
                ":quit\n");

        CHECK(output.err.find("invalid :config, expected category|key=value|reset") != std::string::npos);
        CHECK(output.err.find("invalid build.opt: Og (expected O0|O1|O2|O3|Ofast|Oz)") != std::string::npos);
        CHECK(output.err.find("unknown :config key: nope") != std::string::npos);
        CHECK(output.err.find("invalid :config, key and value must be non-empty") != std::string::npos);
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

    TEST_CASE("005: asm command defaults to __sontag_main when no symbol is provided", "[005][session][asm]") {
        detail::temp_dir temp{"sontag_asm_default_symbol"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int zeta_default_asm_visibility_probe(int x) { return x + 7; }\n"
                ":asm\n"
                ":quit\n");

        CHECK(output.out.find("symbol: ") != std::string::npos);
        CHECK(output.out.find("__sontag_main") != std::string::npos);
        CHECK(output.out.find("zeta_default_asm_visibility_probe") == std::string::npos);
        CHECK(output.out.find("asm:") != std::string::npos);
        CHECK(output.out.find("operations: ") != std::string::npos);
        CHECK(output.out.find("  opcode") != std::string::npos);
        CHECK(output.out.find("assembly:") != std::string::npos);
        CHECK(output.out.find("  line") != std::string::npos);
        CHECK(output.out.find("  [0] ") != std::string::npos);
        CHECK(output.out.find("summary:") == std::string::npos);
        CHECK(output.out.find("instructions:") == std::string::npos);
        CHECK(output.err.empty());
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

    TEST_CASE("005: delta snapshot uses snapshot labels with current as baseline", "[005][session][delta][snapshot]") {
        detail::temp_dir temp{"sontag_delta_snapshot_labels"};
        auto baseline_path = temp.path / "baseline.cpp";
        auto current_path = temp.path / "current.cpp";
        detail::write_text_file(
                baseline_path,
                "int seed = 9;\n"
                "int __sontag_main() {\n"
                "    int value = seed + 1;\n"
                "    return value;\n"
                "}\n");
        detail::write_text_file(
                current_path,
                "int seed = 3;\n"
                "int __sontag_main() {\n"
                "    return seed * 2;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto script = ":file {}\n:mark snap1\n:reset file {}\n:file {}\n:delta snap1\n:quit\n"_format(
                baseline_path.string(), baseline_path.string(), current_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("mode: pairwise") != std::string::npos);
        CHECK(output.out.find("baseline: current") != std::string::npos);
        CHECK(output.out.find("target: snap1") != std::string::npos);
        CHECK(output.out.find("levels:") != std::string::npos);
        CHECK(output.out.find("  current success=") != std::string::npos);
        CHECK(output.out.find("  snap1 success=") != std::string::npos);
        CHECK(output.out.find("diff (current -> snap1, full side-by-side):") != std::string::npos);
        CHECK(output.out.find("alignment anchor: current[") != std::string::npos);
        CHECK(output.out.find("<-> snap1[") != std::string::npos);
        CHECK(output.out.find("baseline: O0") == std::string::npos);
        CHECK(output.out.find("target: O2") == std::string::npos);
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

        CHECK(output.out.find("stored decl #1 -> state: valid") != std::string::npos);
        CHECK(output.out.find("stored cell #1 -> state: valid") != std::string::npos);
        CHECK(output.err.find("state unchanged") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0] == "#include <cstdint>");
        CHECK(persisted_cells.exec_cells[0] == "uint64_t value{64};");
    }

    TEST_CASE("005: reset last removes only most recent executable cell", "[005][session][reset_last]") {
        detail::temp_dir temp{"sontag_clear_last"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int base = 5;\n"
                "int x = base;\n"
                "int y = x + 1;\n"
                ":reset last\n"
                ":show exec\n"
                ":quit\n");

        CHECK(output.out.find("stored decl #1 -> state: valid") != std::string::npos);
        CHECK(output.out.find("stored cell #1 -> state: valid") != std::string::npos);
        CHECK(output.out.find("stored cell #2 -> state: valid") != std::string::npos);
        CHECK(output.out.find("cleared last transaction (cleared decl=0, exec=1) -> state: valid") !=
              std::string::npos);
        CHECK(output.out.find("int x = base;") != std::string::npos);
        CHECK(output.out.find("int y = x + 1;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0] == "int base = 5;");
        CHECK(persisted_cells.exec_cells[0] == "int x = base;");
    }

    TEST_CASE("005: reset last removes most recently added declarative cell", "[005][session][reset_last]") {
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

        auto script = ":file {}\n:decl int v = 6;\n:reset last\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find("stored decl #2 -> state: valid") != std::string::npos);
        CHECK(output.out.find("cleared last transaction (cleared decl=1, exec=0) -> state: valid") !=
              std::string::npos);
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

    TEST_CASE("005: persisted cell ids stay monotonic after reset last", "[005][session][cell_id]") {
        detail::temp_dir temp{"sontag_cell_id_monotonic"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int base = 1;\n"
                "int temp = base;\n"
                ":reset last\n"
                ":decl int next = base + 1;\n"
                ":quit\n");

        CHECK(output.out.find("stored decl #1 -> state: valid") != std::string::npos);
        CHECK(output.out.find("stored cell #1 -> state: valid") != std::string::npos);
        CHECK(output.out.find("cleared last transaction (cleared decl=0, exec=1) -> state: valid") !=
              std::string::npos);
        CHECK(output.out.find("stored decl #2 -> state: valid") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");

        REQUIRE(persisted_cells.cells.size() == 2U);
        CHECK(persisted_cells.cells[0].kind == detail::cell_kind::decl);
        CHECK(persisted_cells.cells[1].kind == detail::cell_kind::decl);
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

        CHECK(output.out.find("loaded declfile") != std::string::npos);
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
        CHECK(output.out.find("return static_cast<int>(doubled);") == std::string::npos);
        CHECK(output.out.find("return 0;") != std::string::npos);
        CHECK(output.out.find("return 0;\n}") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("uint64_t value = 64;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("uint64_t doubled = value * 2;") != std::string::npos);
    }

    TEST_CASE("005: file keeps early returns but replaces terminal return", "[005][session][file][return]") {
        detail::temp_dir temp{"sontag_file_trailing_return"};
        auto source_path = temp.path / "returns.cpp";
        detail::write_text_file(
                source_path,
                "int __sontag_main() {\n"
                "    int value = 4;\n"
                "    if (value < 0) {\n"
                "        return -1;\n"
                "    }\n"
                "    return value + 2;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("return -1;") != std::string::npos);
        CHECK(output.out.find("return value + 2;") == std::string::npos);
        CHECK(output.out.find("return 0;") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells[0].find("return value + 2;") != std::string::npos);
    }

    TEST_CASE("005: executable cells replace terminal return with canonical return", "[005][session][return]") {
        detail::temp_dir temp{"sontag_exec_trailing_return"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                "int value = 12;\n"
                "return value;\n"
                ":show all\n"
                ":quit\n");

        CHECK(output.out.find("int value = 12;") != std::string::npos);
        CHECK(output.out.find("return value;") == std::string::npos);
        CHECK(output.out.find("return 0;") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.exec_cells.size() == 2U);
        CHECK(persisted_cells.exec_cells[1] == "return value;");
    }

    TEST_CASE("005: file appends onto existing state", "[005][session][file][append]") {
        detail::temp_dir temp{"sontag_file_append"};
        auto source_path = temp.path / "append.cpp";
        detail::write_text_file(
                source_path,
                "int seed = 11;\n"
                "int __sontag_main() {\n"
                "    int value = seed + 2;\n"
                "    return value;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":decl int baseline = 5;\n:file {}\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("stored decl #1 -> state: valid") != std::string::npos);
        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find("int baseline = 5;") != std::string::npos);
        CHECK(output.out.find("int seed = 11;") != std::string::npos);
        CHECK(output.out.find("int value = seed + 2;") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 2U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("int baseline = 5;") != std::string::npos);
        CHECK(persisted_cells.decl_cells[1].find("int seed = 11;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("int value = seed + 2;") != std::string::npos);
    }

    TEST_CASE("005: multiple file imports synthesize a single canonical return", "[005][session][file][return]") {
        detail::temp_dir temp{"sontag_file_multi_return"};
        auto first_path = temp.path / "first.cpp";
        auto second_path = temp.path / "second.cpp";
        detail::write_text_file(
                first_path,
                "int seed = 4;\n"
                "int __sontag_main() {\n"
                "    int lhs = seed + 1;\n"
                "    return lhs;\n"
                "}\n");
        detail::write_text_file(
                second_path,
                "int value = 7;\n"
                "int __sontag_main() {\n"
                "    int rhs = value * 2;\n"
                "    return rhs;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:file {}\n:show all\n:quit\n"_format(first_path.string(), second_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("int lhs = seed + 1;") != std::string::npos);
        CHECK(output.out.find("int rhs = value * 2;") != std::string::npos);
        CHECK(output.out.find("return lhs;") == std::string::npos);
        CHECK(output.out.find("return rhs;") == std::string::npos);
        CHECK(detail::count_occurrences(output.out, "return 0;") == 1U);
        CHECK(output.out.find("\n\n\n    // exec cell 2") == std::string::npos);
        CHECK(output.out.find("\n\n\n    return 0;") == std::string::npos);
    }

    TEST_CASE("005: reset last undoes full file import transaction", "[005][session][reset_last][file]") {
        detail::temp_dir temp{"sontag_clear_last_file_transaction"};
        auto source_path = temp.path / "program.cpp";
        detail::write_text_file(
                source_path,
                "int seed = 9;\n"
                "int __sontag_main() {\n"
                "    int value = seed + 1;\n"
                "    return value;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:reset last\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find("cleared last transaction (cleared decl=1, exec=1) -> state: valid") !=
              std::string::npos);
        CHECK(output.out.find("int seed = 9;") == std::string::npos);
        CHECK(output.out.find("int value = seed + 1;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: reset file removes matching file import after later commands", "[005][session][reset_file]") {
        detail::temp_dir temp{"sontag_clear_file_after_mutations"};
        auto source_path = temp.path / "imported.cpp";
        detail::write_text_file(
                source_path,
                "int seed = 7;\n"
                "int __sontag_main() {\n"
                "    int value = seed + 3;\n"
                "    return value;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:decl int tail = 9;\n:reset file {}\n:show all\n:quit\n"_format(
                source_path.string(), source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find("stored decl #2 -> state: valid") != std::string::npos);
        CHECK(output.out.find("cleared file import") != std::string::npos);
        CHECK(output.out.find("cleared decl=1, exec=1") != std::string::npos);
        CHECK(output.out.find("int tail = 9;") != std::string::npos);
        CHECK(output.out.find("int seed = 7;") == std::string::npos);
        CHECK(output.out.find("int value = seed + 3;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells.empty());
        CHECK(persisted_cells.decl_cells[0].find("int tail = 9;") != std::string::npos);
    }

    TEST_CASE("005: reset file removes matching declfile import", "[005][session][reset_file][declfile]") {
        detail::temp_dir temp{"sontag_clear_file_declfile"};
        auto source_path = temp.path / "decl.hpp";
        detail::write_text_file(
                source_path,
                "#include <cstdint>\n"
                "using u64 = std::uint64_t;\n"
                "u64 seed = 4;\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script =
                ":declfile {}\n:reset file {}\n:show all\n:quit\n"_format(source_path.string(), source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("loaded declfile") != std::string::npos);
        CHECK(output.out.find("cleared file import") != std::string::npos);
        CHECK(output.out.find("cleared decl=1, exec=0") != std::string::npos);
        CHECK(output.out.find("using u64 = std::uint64_t;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: reset file no-op when path has no matching import", "[005][session][reset_file]") {
        detail::temp_dir temp{"sontag_clear_file_no_match"};
        auto missing_path = temp.path / "missing.cpp";

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":decl int baseline = 1;\n:reset file {}\n:quit\n"_format(missing_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("stored decl #1 -> state: valid") != std::string::npos);
        CHECK(output.out.find("no matching file import found for") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells.empty());
        CHECK(persisted_cells.decl_cells[0].find("int baseline = 1;") != std::string::npos);
    }

    TEST_CASE("005: openfile launches editor then imports file", "[005][session][openfile]") {
        detail::temp_dir temp{"sontag_openfile_success"};
        auto source_path = temp.path / "edited.cpp";
        auto tools_path = temp.path / "tools";
        detail::fs::create_directories(tools_path);

        auto editor_args_path = temp.path / "hx.args.txt";
        auto format_args_path = temp.path / "format.args.txt";
        std::string hx_script{};
        hx_script.append("#!/usr/bin/env bash\n");
        hx_script.append("set -eu\n");
        hx_script.append("printf '%s\\n' \"$@\" > \"");
        hx_script.append(editor_args_path.string());
        hx_script.append("\"\n");
        hx_script.append("cat > \"$1\" <<'EOF'\n");
        hx_script.append("int seed = 5;\n");
        hx_script.append("int __sontag_main() {\n");
        hx_script.append("    int value = seed + 2;\n");
        hx_script.append("    return value;\n");
        hx_script.append("}\n");
        hx_script.append("EOF\n");

        std::string clang_format_script{};
        clang_format_script.append("#!/usr/bin/env bash\n");
        clang_format_script.append("set -eu\n");
        clang_format_script.append("printf '%s\\n' \"$@\" > \"");
        clang_format_script.append(format_args_path.string());
        clang_format_script.append("\"\n");
        clang_format_script.append("exit 0\n");
        detail::make_executable_file(tools_path / "hx", hx_script);
        detail::make_executable_file(tools_path / "clang-format", clang_format_script);

        auto existing_path = std::getenv("PATH");
        auto combined_path = tools_path.string();
        if (existing_path != nullptr && *existing_path != '\0') {
            combined_path.append(":");
            combined_path.append(existing_path);
        }

        auto scoped_path = detail::scoped_env_var{"PATH", combined_path};
        auto scoped_visual = detail::scoped_env_var{"VISUAL", std::nullopt};
        auto scoped_editor = detail::scoped_env_var{"EDITOR", std::nullopt};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":openfile {}\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("opened file") != std::string::npos);
        CHECK(output.out.find("loaded file") != std::string::npos);
        CHECK(output.out.find("int seed = 5;") != std::string::npos);
        CHECK(output.out.find("int value = seed + 2;") != std::string::npos);
        CHECK(output.out.find("return value;") == std::string::npos);
        CHECK(output.out.find("return 0;") != std::string::npos);

        auto editor_args = detail::read_lines(editor_args_path);
        REQUIRE(editor_args.size() == 1U);
        CHECK(editor_args[0] == source_path.string());

        auto format_args = detail::read_lines(format_args_path);
        CHECK(std::ranges::find(format_args, "-i") != format_args.end());
        CHECK(std::ranges::find(format_args, source_path.string()) != format_args.end());
        CHECK(std::ranges::any_of(format_args, [](std::string_view arg) { return arg.starts_with("-style=file:"); }));
    }

    TEST_CASE("005: openfile keeps state unchanged when editor exits non-zero", "[005][session][openfile]") {
        detail::temp_dir temp{"sontag_openfile_editor_failure"};
        auto source_path = temp.path / "edited.cpp";
        auto tools_path = temp.path / "tools";
        detail::fs::create_directories(tools_path);

        detail::make_executable_file(tools_path / "hx", "#!/usr/bin/env bash\nset -eu\nexit 13\n");

        auto existing_path = std::getenv("PATH");
        auto combined_path = tools_path.string();
        if (existing_path != nullptr && *existing_path != '\0') {
            combined_path.append(":");
            combined_path.append(existing_path);
        }

        auto scoped_path = detail::scoped_env_var{"PATH", combined_path};
        auto scoped_visual = detail::scoped_env_var{"VISUAL", std::nullopt};
        auto scoped_editor = detail::scoped_env_var{"EDITOR", std::nullopt};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":openfile {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("editor exited with code 13, state unchanged") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: openfile keeps state unchanged when clang-format fails", "[005][session][openfile]") {
        detail::temp_dir temp{"sontag_openfile_format_failure"};
        auto source_path = temp.path / "edited.cpp";
        auto tools_path = temp.path / "tools";
        detail::fs::create_directories(tools_path);

        detail::make_executable_file(
                tools_path / "hx",
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "cat > \"$1\" <<'EOF'\n"
                "int seed = 5;\n"
                "int __sontag_main() {\n"
                "    int value = seed + 2;\n"
                "    return value;\n"
                "}\n"
                "EOF\n");
        detail::make_executable_file(
                tools_path / "clang-format",
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "echo format-error\n"
                "exit 7\n");

        auto existing_path = std::getenv("PATH");
        auto combined_path = tools_path.string();
        if (existing_path != nullptr && *existing_path != '\0') {
            combined_path.append(":");
            combined_path.append(existing_path);
        }

        auto scoped_path = detail::scoped_env_var{"PATH", combined_path};
        auto scoped_visual = detail::scoped_env_var{"VISUAL", std::nullopt};
        auto scoped_editor = detail::scoped_env_var{"EDITOR", std::nullopt};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":openfile {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.err.find("clang-format failed for") != std::string::npos);
        CHECK(output.err.find("state unchanged") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: clear command rejects subcommands", "[005][session][clear]") {
        detail::temp_dir temp{"sontag_clear_no_subcommands"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int baseline = 1;\n"
                ":clear last\n"
                ":quit\n");

        CHECK(output.err.find("invalid :clear, expected no arguments") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells.empty());
        CHECK(persisted_cells.decl_cells[0].find("int baseline = 1;") != std::string::npos);
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
