#include "utils.hpp"

#include "../src/internal/explorer.hpp"

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
    using internal::transaction_kind;

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

    static std::string read_text_file(const fs::path& path) {
        std::ifstream in{path};
        REQUIRE(in.good());

        std::ostringstream ss{};
        ss << in.rdbuf();
        return ss.str();
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

    static size_t visible_width_without_ansi(std::string_view line) {
        auto width = size_t{0U};
        auto i = size_t{0U};
        while (i < line.size()) {
            auto c = line[i];
            if (c == '\x1b' && i + 1U < line.size() && line[i + 1U] == '[') {
                auto j = i + 2U;
                while (j < line.size()) {
                    auto terminator = static_cast<unsigned char>(line[j]);
                    if (terminator >= 0x40U && terminator <= 0x7eU) {
                        ++j;
                        break;
                    }
                    ++j;
                }
                i = j;
                continue;
            }
            ++width;
            ++i;
        }
        return width;
    }

    static size_t line_count(std::string_view text) {
        return static_cast<size_t>(std::count(text.begin(), text.end(), '\n'));
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

    static std::vector<fs::path> list_session_dirs(const fs::path& cache_dir) {
        auto sessions_root = cache_dir / "sessions";
        std::error_code ec{};
        if (!fs::exists(sessions_root, ec) || ec) {
            return {};
        }

        std::vector<fs::path> session_dirs{};
        for (const auto& entry : fs::directory_iterator(sessions_root)) {
            if (entry.is_directory()) {
                session_dirs.push_back(entry.path());
            }
        }
        std::ranges::sort(session_dirs);
        return session_dirs;
    }

    static std::vector<fs::path> list_directory_children(const fs::path& root) {
        std::error_code ec{};
        if (!fs::exists(root, ec) || ec) {
            return {};
        }

        std::vector<fs::path> children{};
        for (const auto& entry : fs::directory_iterator(root)) {
            children.push_back(entry.path());
        }
        std::ranges::sort(children);
        return children;
    }

    static std::vector<fs::path> find_files_named_recursive(const fs::path& root, std::string_view filename) {
        std::error_code ec{};
        if (!fs::exists(root, ec) || ec) {
            return {};
        }

        std::vector<fs::path> matches{};
        for (fs::recursive_directory_iterator it{root, fs::directory_options::skip_permission_denied, ec}, end;
             it != end && !ec;
             it.increment(ec)) {
            if (!it->is_regular_file(ec) || ec) {
                continue;
            }
            if (it->path().filename() == filename) {
                matches.push_back(it->path());
            }
        }
        std::ranges::sort(matches);
        return matches;
    }

    static bool has_merkle_node_artifacts(const fs::path& root) {
        auto children = list_directory_children(root);
        for (const auto& child : children) {
            if (!fs::is_directory(child)) {
                continue;
            }
            if (fs::exists(child / "manifest.txt") && fs::exists(child / "payload.txt")) {
                return true;
            }
        }
        return false;
    }

    static void write_merkle_cache_node(
            const fs::path& bucket_root,
            std::string_view node_hash,
            std::string_view node_kind,
            std::initializer_list<std::string_view> child_hashes = {}) {
        auto node_dir = bucket_root / std::string(node_hash);
        fs::create_directories(node_dir);
        write_text_file(node_dir / "payload.txt", "payload");

        std::ostringstream manifest{};
        manifest << "node_kind=" << node_kind << '\n';
        manifest << "node_hash=" << node_hash << '\n';
        manifest << "payload_hash=fixture\n";
        manifest << "payload_file=payload.txt\n";
        size_t child_index = 0U;
        for (auto child_hash : child_hashes) {
            manifest << "child[" << child_index << "]=" << child_hash << '\n';
            ++child_index;
        }
        write_text_file(node_dir / "manifest.txt", manifest.str());
    }

    static void set_tree_last_write_time(const fs::path& path, fs::file_time_type time_point) {
        std::error_code ec{};
        if (fs::is_directory(path, ec) && !ec) {
            for (fs::recursive_directory_iterator it(path, fs::directory_options::skip_permission_denied, ec), end;
                 it != end;
                 it.increment(ec)) {
                REQUIRE_FALSE(static_cast<bool>(ec));
                std::error_code ts_ec{};
                fs::last_write_time(it->path(), time_point, ts_ec);
                REQUIRE_FALSE(static_cast<bool>(ts_ec));
            }
            REQUIRE_FALSE(static_cast<bool>(ec));
        }

        ec.clear();
        fs::last_write_time(path, time_point, ec);
        REQUIRE_FALSE(static_cast<bool>(ec));
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
        CHECK(persisted_cfg.cache_ttl_days == 3U);
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
        initial_cfg.cache_ttl_days = 11U;
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
        resumed_cfg.cache_ttl_days = 1U;
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
        CHECK(resumed_cfg.cache_ttl_days == initial_cfg.cache_ttl_days);
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

    TEST_CASE("005: startup prunes stale session directories by cache_ttl_days", "[005][session][cache]") {
        detail::temp_dir temp{"sontag_session_prune_stale"};

        auto sessions_root = temp.path / "cache" / "sessions";
        auto stale_dir = sessions_root / "stale_session";
        auto fresh_dir = sessions_root / "fresh_session";
        detail::fs::create_directories(stale_dir);
        detail::fs::create_directories(fresh_dir);
        detail::write_text_file(stale_dir / "note.txt", "stale");
        detail::write_text_file(fresh_dir / "note.txt", "fresh");

        auto stale_time = detail::fs::file_time_type::clock::now() - std::chrono::hours{24 * 10};
        detail::set_tree_last_write_time(stale_dir, stale_time);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.cache_ttl_days = 3U;

        detail::run_repl_script(cfg, ":quit\n");

        CHECK_FALSE(detail::fs::exists(stale_dir));
        CHECK(detail::fs::exists(fresh_dir));

        auto session_dirs = detail::list_session_dirs(cfg.cache_dir);
        CHECK(std::ranges::find(session_dirs, fresh_dir) != session_dirs.end());
    }

    TEST_CASE("005: resume preserves target session while pruning stale peers", "[005][session][cache][resume]") {
        detail::temp_dir temp{"sontag_session_prune_resume_preserve"};

        startup_config seed_cfg{};
        seed_cfg.cache_dir = temp.path / "cache";
        seed_cfg.history_enabled = false;
        seed_cfg.banner_enabled = false;
        seed_cfg.cache_ttl_days = 3U;

        detail::run_repl_script(seed_cfg, ":quit\n");
        auto preserved_session = detail::find_single_session_dir(seed_cfg.cache_dir);
        auto stale_peer = seed_cfg.cache_dir / "sessions" / "stale_peer";
        detail::fs::create_directories(stale_peer);
        detail::write_text_file(stale_peer / "note.txt", "stale");
        auto stale_time = detail::fs::file_time_type::clock::now() - std::chrono::hours{24 * 10};
        detail::set_tree_last_write_time(preserved_session, stale_time);
        detail::set_tree_last_write_time(stale_peer, stale_time);

        startup_config resume_cfg{};
        resume_cfg.cache_dir = seed_cfg.cache_dir;
        resume_cfg.history_enabled = false;
        resume_cfg.banner_enabled = false;
        resume_cfg.cache_ttl_days = 3U;
        resume_cfg.resume_session = preserved_session.filename().string();

        detail::run_repl_script(resume_cfg, ":quit\n");

        CHECK(detail::fs::exists(preserved_session));
        CHECK_FALSE(detail::fs::exists(stale_peer));
    }

    TEST_CASE("005: startup prunes stale shared cache nodes by cache_ttl_days", "[005][session][cache][shared]") {
        detail::temp_dir temp{"sontag_shared_cache_prune_stale"};

        auto cache_root = temp.path / "cache" / "cache";
        auto units_root = cache_root / "units";
        auto symbols_root = cache_root / "symbols";
        auto traces_root = cache_root / "traces";

        detail::write_merkle_cache_node(units_root, "unit_stale", "build_unit");
        detail::write_merkle_cache_node(symbols_root, "symbol_stale", "symbol_view");
        detail::write_merkle_cache_node(traces_root, "trace_stale", "trace");
        detail::write_merkle_cache_node(units_root, "unit_fresh", "build_unit");
        detail::write_merkle_cache_node(symbols_root, "symbol_fresh", "symbol_view");
        detail::write_merkle_cache_node(traces_root, "trace_fresh", "trace");

        auto stale_time = detail::fs::file_time_type::clock::now() - std::chrono::hours{24 * 10};
        detail::set_tree_last_write_time(units_root / "unit_stale", stale_time);
        detail::set_tree_last_write_time(symbols_root / "symbol_stale", stale_time);
        detail::set_tree_last_write_time(traces_root / "trace_stale", stale_time);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.cache_ttl_days = 3U;

        detail::run_repl_script(cfg, ":quit\n");

        CHECK_FALSE(detail::fs::exists(units_root / "unit_stale"));
        CHECK_FALSE(detail::fs::exists(symbols_root / "symbol_stale"));
        CHECK_FALSE(detail::fs::exists(traces_root / "trace_stale"));
        CHECK(detail::fs::exists(units_root / "unit_fresh"));
        CHECK(detail::fs::exists(symbols_root / "symbol_fresh"));
        CHECK(detail::fs::exists(traces_root / "trace_fresh"));
    }

    TEST_CASE("005: resume flow also prunes stale shared cache nodes", "[005][session][cache][shared][resume]") {
        detail::temp_dir temp{"sontag_shared_cache_prune_resume"};

        startup_config seed_cfg{};
        seed_cfg.cache_dir = temp.path / "cache";
        seed_cfg.history_enabled = false;
        seed_cfg.banner_enabled = false;
        seed_cfg.cache_ttl_days = 3U;

        detail::run_repl_script(seed_cfg, ":quit\n");
        auto preserved_session = detail::find_single_session_dir(seed_cfg.cache_dir);

        auto units_root = seed_cfg.cache_dir / "cache" / "units";
        detail::write_merkle_cache_node(units_root, "unit_stale", "build_unit");
        auto stale_time = detail::fs::file_time_type::clock::now() - std::chrono::hours{24 * 10};
        detail::set_tree_last_write_time(units_root / "unit_stale", stale_time);

        startup_config resume_cfg{};
        resume_cfg.cache_dir = seed_cfg.cache_dir;
        resume_cfg.history_enabled = false;
        resume_cfg.banner_enabled = false;
        resume_cfg.cache_ttl_days = 3U;
        resume_cfg.resume_session = preserved_session.filename().string();

        detail::run_repl_script(resume_cfg, ":quit\n");

        CHECK(detail::fs::exists(preserved_session));
        CHECK_FALSE(detail::fs::exists(units_root / "unit_stale"));
    }

    TEST_CASE(
            "005: shared cache GC preserves stale build units referenced by fresh nodes",
            "[005][session][cache][shared]") {
        detail::temp_dir temp{"sontag_shared_cache_preserve_referenced_units"};

        auto cache_root = temp.path / "cache" / "cache";
        auto units_root = cache_root / "units";
        auto symbols_root = cache_root / "symbols";
        auto traces_root = cache_root / "traces";

        detail::write_merkle_cache_node(units_root, "unit_from_symbol", "build_unit");
        detail::write_merkle_cache_node(units_root, "unit_from_trace", "build_unit");
        detail::write_merkle_cache_node(units_root, "unit_unreferenced", "build_unit");

        detail::write_merkle_cache_node(symbols_root, "symbol_recent", "symbol_view", {"unit_from_symbol"});
        detail::write_merkle_cache_node(traces_root, "trace_recent", "trace", {"unit_from_trace"});

        auto stale_time = detail::fs::file_time_type::clock::now() - std::chrono::hours{24 * 10};
        detail::set_tree_last_write_time(units_root / "unit_from_symbol", stale_time);
        detail::set_tree_last_write_time(units_root / "unit_from_trace", stale_time);
        detail::set_tree_last_write_time(units_root / "unit_unreferenced", stale_time);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.cache_ttl_days = 3U;

        detail::run_repl_script(cfg, ":quit\n");

        CHECK(detail::fs::exists(symbols_root / "symbol_recent"));
        CHECK(detail::fs::exists(traces_root / "trace_recent"));
        CHECK(detail::fs::exists(units_root / "unit_from_symbol"));
        CHECK(detail::fs::exists(units_root / "unit_from_trace"));
        CHECK_FALSE(detail::fs::exists(units_root / "unit_unreferenced"));
    }

    TEST_CASE("005: shared cache GC is disabled when cache_ttl_days is zero", "[005][session][cache][shared]") {
        detail::temp_dir temp{"sontag_shared_cache_ttl_disabled"};

        auto cache_root = temp.path / "cache" / "cache";
        auto units_root = cache_root / "units";
        auto symbols_root = cache_root / "symbols";

        detail::write_merkle_cache_node(units_root, "unit_stale", "build_unit");
        detail::write_merkle_cache_node(symbols_root, "symbol_stale", "symbol_view", {"unit_stale"});

        auto stale_time = detail::fs::file_time_type::clock::now() - std::chrono::hours{24 * 10};
        detail::set_tree_last_write_time(units_root / "unit_stale", stale_time);
        detail::set_tree_last_write_time(symbols_root / "symbol_stale", stale_time);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.cache_ttl_days = 0U;

        detail::run_repl_script(cfg, ":quit\n");

        CHECK(detail::fs::exists(units_root / "unit_stale"));
        CHECK(detail::fs::exists(symbols_root / "symbol_stale"));
    }

    TEST_CASE("005: asm analysis writes merkle cache nodes for units and symbols", "[005][session][cache]") {
        detail::temp_dir temp{"sontag_cache_merkle_asm"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        detail::run_repl_script(
                cfg,
                ":decl int square(int x) { return x * x; }\n"
                ":asm\n"
                ":quit\n");

        auto cache_root = cfg.cache_dir / "cache";
        CHECK(detail::has_merkle_node_artifacts(cache_root / "units"));
        CHECK(detail::has_merkle_node_artifacts(cache_root / "symbols"));
    }

    TEST_CASE("005: mem trace analysis writes merkle trace cache nodes", "[005][session][cache][mem]") {
        detail::temp_dir temp{"sontag_cache_merkle_mem_trace"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.color = color_mode::never;
        cfg.link = link_mode::staticlink;

        detail::run_repl_script(
                cfg,
                ":decl int square(int x) { return x * x; }\n"
                "volatile int sink = square(3);\n"
                "return sink;\n"
                ":mem square\n"
                ":quit\n");

        auto cache_root = cfg.cache_dir / "cache";
        CHECK(detail::has_merkle_node_artifacts(cache_root / "units"));
        CHECK(detail::has_merkle_node_artifacts(cache_root / "symbols"));
        CHECK(detail::has_merkle_node_artifacts(cache_root / "traces"));
    }

    TEST_CASE("005: reset last returns to prior build-hash cache branch", "[005][session][cache][reset_last]") {
        detail::temp_dir temp{"sontag_cache_reset_last_merkle_stepback"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int seed = 1;\n"
                "int x = seed + 1;\n"
                ":asm\n"
                "int y = x + 2;\n"
                ":asm\n"
                ":reset last\n"
                ":asm\n"
                ":quit\n");

        CHECK(output.out.find("cleared last transaction (cleared decl=0, exec=1) -> state: valid") !=
              std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto inputs_dirs = detail::list_directory_children(session_dir / "artifacts" / "inputs");
        auto asm_dirs = detail::list_directory_children(session_dir / "artifacts" / "asm");

        auto count_dirs = [](const std::vector<detail::fs::path>& entries) {
            size_t count = 0U;
            for (const auto& entry : entries) {
                if (detail::fs::is_directory(entry)) {
                    ++count;
                }
            }
            return count;
        };

        CHECK(count_dirs(inputs_dirs) >= 2U);
        CHECK(count_dirs(asm_dirs) == 2U);
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
        CHECK(output.out.find("  cache_ttl_days=") != std::string::npos);

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
                ":config build.static=false\n"
                ":config ui.color=always\n"
                ":config editor.editor=vim\n"
                ":config editor.formatter=clang-format-21\n"
                ":config session.history_file=.sontag/test_history\n"
                ":config session.cache_ttl_days=7\n"
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
        CHECK(output.out.find("updated build.static=false") != std::string::npos);
        CHECK(output.out.find("updated ui.color=always") != std::string::npos);
        CHECK(output.out.find("updated editor.editor=vim") != std::string::npos);
        CHECK(output.out.find("updated editor.formatter=clang-format-21") != std::string::npos);
        CHECK(output.out.find("updated session.history_file=.sontag/test_history") != std::string::npos);
        CHECK(output.out.find("updated session.cache_ttl_days=7") != std::string::npos);

        CHECK(output.out.find("  opt=O3") != std::string::npos);
        CHECK(output.out.find("  static=false") != std::string::npos);
        CHECK(output.out.find("  color=always") != std::string::npos);
        CHECK(output.out.find("  editor=vim") != std::string::npos);
        CHECK(output.out.find("  formatter=clang-format-21") != std::string::npos);
        CHECK(output.out.find("  history_file=.sontag/test_history") != std::string::npos);
        CHECK(output.out.find("  cache_ttl_days=7") != std::string::npos);

        CHECK(output.out.find("config reset") != std::string::npos);
        CHECK(output.out.find("  opt=O0") != std::string::npos);
        CHECK(output.out.find("  static=true") != std::string::npos);
        CHECK(output.out.find("  color=auto") != std::string::npos);
        CHECK(output.out.find("  editor=") != std::string::npos);
        CHECK(output.out.find("  editor=auto") == std::string::npos);
        CHECK(output.out.find("  formatter=clang-format") != std::string::npos);
        CHECK(output.out.find("  history_file=.sontag/history") != std::string::npos);
        CHECK(output.out.find("  cache_ttl_days=3") != std::string::npos);
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
                ":config session.cache_ttl_days=abc\n"
                ":quit\n");

        CHECK(output.err.find("invalid :config, expected category|key=value|reset") != std::string::npos);
        CHECK(output.err.find("invalid build.opt: Og (expected O0|O1|O2|O3|Ofast|Oz)") != std::string::npos);
        CHECK(output.err.find("unknown :config key: nope") != std::string::npos);
        CHECK(output.err.find("invalid :config, key and value must be non-empty") != std::string::npos);
        CHECK(output.err.find("invalid session.cache_ttl_days: abc (expected unsigned integer)") != std::string::npos);
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
        auto main_pos = output.out.find("int main() {");
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
        CHECK(output.out.find("main") != std::string::npos);
        CHECK(output.out.find("foo(") != std::string::npos);
        CHECK(output.out.find("global text/function") != std::string::npos);
        CHECK(output.out.find("legend:") != std::string::npos);
    }

    TEST_CASE("005: symbols highlights user-origin symbols with new-line palette color", "[005][session][symbols]") {
        detail::temp_dir temp{"sontag_symbols_user_highlight"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.color = color_mode::always;
        cfg.delta_color_scheme = color_scheme::classic;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int ready = 0;\n"
                ":decl int foo(int x) { return x + ready; }\n"
                ":symbols\n"
                ":quit\n");

        CHECK(output.out.find("\x1b[38;5;117m    ready") != std::string::npos);
        CHECK(output.out.find("\x1b[38;5;117m    foo(") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: asm command defaults to main when no symbol is provided", "[005][session][asm]") {
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
        CHECK(output.out.find("main") != std::string::npos);
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

    TEST_CASE("005: asm output aggregates trailing linker padding rows", "[005][session][asm]") {
        detail::temp_dir temp{"sontag_asm_trim_int3_padding"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl double sq_root(int x) { return static_cast<double>(x); }\n"
                ":decl int mySqrt(int x) { return x; }\n"
                "auto root = sq_root(9);\n"
                "auto value = mySqrt(9);\n"
                "(void)root;\n"
                "(void)value;\n"
                ":asm\n"
                ":quit\n");

        CHECK(output.out.find("asm:") != std::string::npos);
        CHECK(output.out.find("symbol: main") != std::string::npos);
        CHECK(output.out.find("padding ops: rows=") != std::string::npos);
        CHECK(output.out.find("| int3") == std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: ir command defaults to main when no symbol is provided", "[005][session][ir]") {
        detail::temp_dir temp{"sontag_ir_default_symbol"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int zeta_default_ir_visibility_probe(int x) { return x + 17; }\n"
                ":ir\n"
                ":quit\n");

        CHECK(output.out.find("main") != std::string::npos);
        CHECK(output.out.find("zeta_default_ir_visibility_probe") == std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: ir explore fallback bounds node and layout rows", "[005][session][ir][explore]") {
        detail::temp_dir temp{"sontag_ir_explore_bounded_rows"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto decl_path = temp.path / "ir_explore_chain.hpp";
        auto decl = std::ostringstream{};
        decl << "int ir_explore_chain(int x) {\n";
        decl << "  int v = x;\n";
        for (int i = 0; i < 140; ++i) {
            decl << "  if (((v + " << i << ") & 1) == 0) {\n";
            decl << "    v += " << (i + 1) << ";\n";
            decl << "  } else {\n";
            decl << "    v -= " << (i + 1) << ";\n";
            decl << "  }\n";
        }
        decl << "  return v;\n";
        decl << "}\n";
        detail::write_text_file(decl_path, decl.str());

        auto script = std::string{};
        script.append(":declfile {}\n"_format(decl_path.string()));
        script.append("int ir_explore_sink = ir_explore_chain(7);\n");
        script.append(":ir explore ir_explore_chain\n");
        script.append(":quit\n");

        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("graph explore: requires an interactive tty") != std::string::npos);
        CHECK(output.out.find("type: ir") != std::string::npos);
        CHECK(output.out.find("note: node table truncated (showing first ") != std::string::npos);
        CHECK(output.out.find("note: layout truncated (showing first ") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: ir graph frame clips all rows to terminal width in interactive mode", "[005][explorer][ir]") {
        auto model = internal::explorer::graph_model{};
        model.kind_label = "ir";
        model.title = "main()";
        model.nodes = {
                internal::explorer::graph_node{
                        .id = "n0",
                        .short_label = "invoke void @std::__1::condition_variable::wait[abi:ne210108]<bool (*)()>(ptr "
                                       "%cv, ptr %lk, ptr @is_not_ready())",
                        .full_label = "n0 full",
                        .outgoing_count = 0U,
                        .incoming_count = 0U},
                internal::explorer::graph_node{
                        .id = "n1",
                        .short_label = "call void @std::__1::thread::thread[abi:ne210108]<void (&)(), 0>(void "
                                       "(&)())(ptr %3, ptr @waiter())",
                        .full_label = "n1 full",
                        .outgoing_count = 0U,
                        .incoming_count = 0U}};
        model.edges = {};
        model.outgoing_edges.assign(model.nodes.size(), {});
        model.incoming_edges.assign(model.nodes.size(), {});
        model.selected_line_color = "\x1b[38;5;22m";
        model.selected_detail_color = "\x1b[33m";
        model.unchanged_line_color = "\x1b[38;5;117m";
        model.removed_line_color = "\x1b[31m";

        constexpr auto terminal_cols = size_t{72U};
        auto frame = internal::explorer::detail::render_graph_frame(
                model, 0U, 0U, model.nodes.size(), terminal_cols, true, false, true, false);

        auto begin = size_t{0U};
        while (begin < frame.size()) {
            auto end = frame.find('\n', begin);
            if (end == std::string::npos) {
                end = frame.size();
            }
            auto line = std::string_view{frame}.substr(begin, end - begin);
            CHECK(detail::visible_width_without_ansi(line) <= terminal_cols);
            if (end == frame.size()) {
                break;
            }
            begin = end + 1U;
        }
    }

    TEST_CASE("005: ir sugiyama layout clips to terminal width in interactive mode", "[005][explorer][ir]") {
        auto model = internal::explorer::graph_model{};
        model.kind_label = "ir";
        model.title = "main()";
        model.nodes = {
                internal::explorer::graph_node{
                        .id = "n0",
                        .short_label = "%0 = call void "
                                       "@very_long_symbol_name_with_many_segments_and_template_args<aaaa,bbbb,cccc>()",
                        .full_label = {},
                        .outgoing_count = 1U,
                        .incoming_count = 0U},
                internal::explorer::graph_node{
                        .id = "n1",
                        .short_label = "%1 = call void "
                                       "@another_symbol_name_with_many_segments_and_template_args<dddd,eeee,ffff>()",
                        .full_label = {},
                        .outgoing_count = 0U,
                        .incoming_count = 1U}};
        model.edges = {internal::explorer::graph_edge{.from = 0U, .to = 1U, .label = "edge"}};
        model.outgoing_edges = {{0U}, {}};
        model.incoming_edges = {{}, {0U}};

        constexpr auto terminal_cols = size_t{48U};
        auto ss = std::ostringstream{};
        internal::explorer::detail::render_graph_sugiyama(model, ss, false, nullptr, 8U, terminal_cols);

        auto text = ss.str();
        auto begin = size_t{0U};
        while (begin < text.size()) {
            auto end = text.find('\n', begin);
            if (end == std::string::npos) {
                end = text.size();
            }
            auto line = std::string_view{text}.substr(begin, end - begin);
            CHECK(detail::visible_width_without_ansi(line) <= terminal_cols);
            if (end == text.size()) {
                break;
            }
            begin = end + 1U;
        }
    }

    TEST_CASE("005: mem frame height stays stable across rows with varying detail lines", "[005][explorer][mem]") {
        auto model = internal::explorer::model{};
        model.mode_label = "mem";
        model.symbol_display = "main()";
        model.operations_total = 2U;
        model.opcode_counts = {{"mov", 2U}};
        model.rows = {
                internal::explorer::asm_row{.offset = "10", .encodings = "aa", .instruction = "mov eax, ebx"},
                internal::explorer::asm_row{.offset = "11", .encodings = "bb", .instruction = "mov ecx, edx"}};
        model.row_info = {internal::explorer::instruction_info{}, internal::explorer::instruction_info{}};
        model.row_detail_lines = {
                {}, {"address:", "  class=stack", "alias:", "  group=A0", "extra:", "  item1", "  item2", "  item3"}};

        auto frame_row0 = internal::explorer::detail::render_frame(model, 0U, 0U, 2U);
        auto frame_row1 = internal::explorer::detail::render_frame(model, 1U, 0U, 2U);

        CHECK(detail::line_count(frame_row0) == detail::line_count(frame_row1));
    }

    TEST_CASE("005: asm explore falls back on non-interactive terminals", "[005][session][asm][explore]") {
        detail::temp_dir temp{"sontag_asm_explore_fallback"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int zeta_explore_probe(int x) { return x + 9; }\n"
                ":asm explore\n"
                ":quit\n");

        CHECK(output.out.find("asm explore: requires an interactive tty") != std::string::npos);
        CHECK(output.out.find("asm:") != std::string::npos);
        CHECK(output.out.find("symbol: main") != std::string::npos);
        CHECK(output.out.find("assembly:") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: call target extraction ignores template argument lists", "[005][session][asm][explore]") {
        using internal::explorer::detail::extract_call_target_symbol;

        auto wrapped = extract_call_target_symbol("call 0x401120 <waiter()>");
        REQUIRE(wrapped.has_value());
        CHECK(*wrapped == "waiter()");

        auto templated =
                extract_call_target_symbol("call std::__1::thread::thread[abi:ne210108]<void (&)(), 0>(void (&)())");
        REQUIRE(templated.has_value());
        CHECK(*templated == "std::__1::thread::thread[abi:ne210108]<void (&)(), 0>(void (&)())");
    }

    TEST_CASE("005: mem reports trace disabled message in dynamic mode", "[005][session][mem]") {
        detail::temp_dir temp{"sontag_mem_dynamic_trace_message"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.link = link_mode::dynamiclink;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int square(int x) { return x * x; }\n"
                "auto value = square(3);\n"
                ":mem\n"
                ":quit\n");

        CHECK(output.out.find("mem:") != std::string::npos);
        CHECK(output.out.find("trace: disabled in dynamic mode (set build.static=true)") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: mem main reports square result in static mode", "[005][session][mem]") {
        detail::temp_dir temp{"sontag_mem_static_main_value"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.color = color_mode::never;
        cfg.link = link_mode::staticlink;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int square(int x) { return x * x; }\n"
                "auto value = square(3);\n"
                ":mem\n"
                ":quit\n");

        CHECK(output.out.find("mem:") != std::string::npos);
        CHECK(output.out.find("trace: disabled in dynamic mode (set build.static=true)") == std::string::npos);
        CHECK(output.out.find("0x00000009") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: mem static mode reports bool stores as 0x01", "[005][session][mem]") {
        detail::temp_dir temp{"sontag_mem_static_bool_true_value"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.color = color_mode::never;
        cfg.link = link_mode::staticlink;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl bool ready = false;\n"
                "ready = true;\n"
                ":mem\n"
                ":quit\n");

        CHECK(output.out.find("mem:") != std::string::npos);
        CHECK(output.out.find("trace: enabled") != std::string::npos);
        CHECK(output.out.find("ready") != std::string::npos);
        CHECK(output.out.find("0x01") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: mem reports nonzero trace exit inline while keeping trace data", "[005][session][mem]") {
        detail::temp_dir temp{"sontag_mem_trace_nonzero_exit"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.color = color_mode::never;
        cfg.link = link_mode::staticlink;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int square(int x) { int y = x * x; return y; }\n"
                "volatile int sink = square(3);\n"
                "return sink;\n"
                ":mem square\n"
                ":quit\n");

        CHECK(output.out.find("mem:") != std::string::npos);
        CHECK(output.out.find("trace: enabled (exit_code=9)") != std::string::npos);
        CHECK(output.out.find("trace: unavailable (compilation or execution failed)") == std::string::npos);
        CHECK(output.out.find("0x00000003") != std::string::npos);
        CHECK(output.out.find("0x00000009") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: inspect mem json includes value status and source", "[005][session][mem][json]") {
        detail::temp_dir temp{"sontag_mem_inspect_value_status_json"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.output = output_mode::json;
        cfg.link = link_mode::staticlink;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int square(int x) { int y = x * x; return y; }\n"
                "volatile int sink = square(3);\n"
                "return sink;\n"
                ":inspect mem square\n"
                ":quit\n");

        CHECK(output.out.find("\"command\":\"inspect mem\"") != std::string::npos);
        CHECK(output.out.find("\"observed_value\":\"0x00000003\"") != std::string::npos);
        CHECK(output.out.find("\"observed_value\":\"0x00000009\"") != std::string::npos);
        CHECK(output.out.find("\"value_status\":\"known\"") != std::string::npos);
        CHECK(output.out.find("\"value_source\":\"runtime_trace_exact\"") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: inspect mem json reports varied sampled values", "[005][session][mem][json]") {
        detail::temp_dir temp{"sontag_mem_inspect_value_status_varied_json"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.output = output_mode::json;
        cfg.link = link_mode::staticlink;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int square(int x) { int y = x * x; return y; }\n"
                "volatile int a = square(3);\n"
                "volatile int b = square(4);\n"
                "return a + b;\n"
                ":inspect mem square\n"
                ":quit\n");

        CHECK(output.out.find("\"command\":\"inspect mem\"") != std::string::npos);
        CHECK(output.out.find("\"observed_value\":\"<varied>\"") != std::string::npos);
        CHECK(output.out.find("\"value_status\":\"varied\"") != std::string::npos);
        CHECK(output.out.find("\"value_source\":\"runtime_trace_sampled\"") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: inspect mem json reports unknown values when trace is disabled", "[005][session][mem][json]") {
        detail::temp_dir temp{"sontag_mem_inspect_value_status_unknown_json"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.output = output_mode::json;
        cfg.link = link_mode::dynamiclink;
        auto output = detail::run_repl_script_capture_output(
                cfg,
                ":decl int square(int x) { int y = x * x; return y; }\n"
                "volatile int sink = square(3);\n"
                "return sink;\n"
                ":inspect mem square\n"
                ":quit\n");

        CHECK(output.out.find("\"command\":\"inspect mem\"") != std::string::npos);
        CHECK(output.out.find("\"value_status\":\"unknown\"") != std::string::npos);
        CHECK(output.out.find("\"value_source\":\"inferred_none\"") != std::string::npos);
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
                "int main() {\n"
                "    int value = seed + 1;\n"
                "    return value;\n"
                "}\n");
        detail::write_text_file(
                current_path,
                "int seed = 3;\n"
                "int main() {\n"
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
                "int main() {\n"
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

    TEST_CASE("005: file loads declarative prefix and preserves driver return value", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_load"};
        auto source_path = temp.path / "program.cpp";
        detail::write_text_file(
                source_path,
                "#include <cstdint>\n"
                "uint64_t value = 64;\n"
                "\n"
                "int main() {\n"
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

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("uint64_t value = 64;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("uint64_t doubled = value * 2;") != std::string::npos);
    }

    TEST_CASE("005: file keeps return-only driver body visible in show output", "[005][session][file][return]") {
        detail::temp_dir temp{"sontag_file_return_only"};
        auto source_path = temp.path / "return_only.cpp";
        detail::write_text_file(
                source_path,
                "int square(int x) {\n"
                "    return x * x;\n"
                "}\n"
                "\n"
                "int main() {\n"
                "    return square(3);\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":file {}\n:show all\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("    return square(3);") != std::string::npos);
        CHECK(output.out.find("    return 0;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells[0].find("return square(3);") != std::string::npos);
    }

    TEST_CASE("005: file keeps early returns and preserves terminal return", "[005][session][file][return]") {
        detail::temp_dir temp{"sontag_file_trailing_return"};
        auto source_path = temp.path / "returns.cpp";
        detail::write_text_file(
                source_path,
                "int main() {\n"
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
        CHECK(output.out.find("return value + 2;") != std::string::npos);
        CHECK(output.out.find("return 0;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells[0].find("return value + 2;") != std::string::npos);
    }

    TEST_CASE("005: executable cells preserve terminal return values", "[005][session][return]") {
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
        CHECK(output.out.find("return value;") != std::string::npos);
        CHECK(output.out.find("return 0;") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.exec_cells.size() == 2U);
        CHECK(persisted_cells.exec_cells[1] == "return value;");
    }

    TEST_CASE("005: executable bare trailing return normalizes to canonical return", "[005][session][return]") {
        detail::temp_dir temp{"sontag_exec_bare_return"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto output = detail::run_repl_script_capture_output(
                cfg,
                "int value = 12;\n"
                "return;\n"
                ":show all\n"
                ":quit\n");

        CHECK(output.out.find("int value = 12;") != std::string::npos);
        CHECK(output.out.find("    return;\n") == std::string::npos);
        CHECK(output.out.find("return 0;") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.exec_cells.size() == 2U);
        CHECK(persisted_cells.exec_cells[1] == "return;");
    }

    TEST_CASE("005: file appends onto existing state", "[005][session][file][append]") {
        detail::temp_dir temp{"sontag_file_append"};
        auto source_path = temp.path / "append.cpp";
        detail::write_text_file(
                source_path,
                "int seed = 11;\n"
                "int main() {\n"
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

    TEST_CASE("005: multiple file imports keep explicit returns from imported mains", "[005][session][file][return]") {
        detail::temp_dir temp{"sontag_file_multi_return"};
        auto first_path = temp.path / "first.cpp";
        auto second_path = temp.path / "second.cpp";
        detail::write_text_file(
                first_path,
                "int seed = 4;\n"
                "int main() {\n"
                "    int lhs = seed + 1;\n"
                "    return lhs;\n"
                "}\n");
        detail::write_text_file(
                second_path,
                "int value = 7;\n"
                "int main() {\n"
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
        CHECK(output.out.find("return lhs;") != std::string::npos);
        CHECK(output.out.find("return rhs;") != std::string::npos);
        CHECK(detail::count_occurrences(output.out, "return 0;") == 0U);
        CHECK(output.out.find("\n\n\n    // exec cell 2") == std::string::npos);
        CHECK(output.out.find("\n\n\n    return 0;") == std::string::npos);
    }

    TEST_CASE("005: reset last undoes full file import transaction", "[005][session][reset_last][file]") {
        detail::temp_dir temp{"sontag_clear_last_file_transaction"};
        auto source_path = temp.path / "program.cpp";
        detail::write_text_file(
                source_path,
                "int seed = 9;\n"
                "int main() {\n"
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
                "int main() {\n"
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

    TEST_CASE("005: import rejects file path and requires directory roots", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_file_reject"};
        auto source_path = temp.path / "single.cpp";
        detail::write_text_file(source_path, "int main() { return 0; }\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {}\n:quit\n"_format(source_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.err.find(":import is directory-only; use :file/:declfile for single files") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: import auto-detects single in-scope main as app", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_auto_app"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        auto main_path = project_dir / "main.cpp";
        auto util_path = project_dir / "util.cpp";
        detail::write_text_file(
                main_path,
                "int seed = 4;\n"
                "int helper() { return seed + 1; }\n"
                "int main() {\n"
                "    int value = helper();\n"
                "    return value;\n"
                "}\n");
        detail::write_text_file(util_path, "int bias = 3;\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {}\n:show all\n:quit\n"_format(project_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=app") != std::string::npos);
        CHECK(output.out.find("entry={}"_format(main_path.string())) != std::string::npos);
        CHECK(output.out.find("#include \"{}\""_format(util_path.string())) != std::string::npos);
        CHECK(output.out.find("int value = helper();") != std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE_FALSE(persisted_cells.decl_cells.empty());
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells[0].find("int value = helper();") != std::string::npos);
        REQUIRE(persisted_cells.transactions.size() == 1U);
        CHECK(persisted_cells.transactions[0].kind == detail::transaction_kind::import);
        REQUIRE(persisted_cells.transactions[0].import_record.has_value());
        CHECK(persisted_cells.transactions[0].import_record->mode == "app");
        CHECK(persisted_cells.transactions[0].import_record->entry == main_path.string());
    }

    TEST_CASE("005: import app validates with root include paths for local headers", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_local_header"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        auto main_path = project_dir / "main.cpp";
        auto template_path = project_dir / "template.hpp";
        detail::write_text_file(
                template_path,
                "inline int square(int x) {\n"
                "    return x * x;\n"
                "}\n");
        detail::write_text_file(
                main_path,
                "#include \"template.hpp\"\n"
                "int main() {\n"
                "    return square(3);\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {}\n:show all\n:quit\n"_format(project_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=app") != std::string::npos);
        CHECK(output.out.find("#include \"template.hpp\"") != std::string::npos);
        CHECK(output.out.find("return square(3);") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE(
            "005: import mem retains global bool trace value and avoids abi tag symbols",
            "[005][session][import][mem]") {
        detail::temp_dir temp{"sontag_import_mem_ready_value"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        detail::write_text_file(
                project_dir / "sync.hpp",
                "#pragma once\n"
                "#include <mutex>\n"
                "inline std::mutex m;\n"
                "inline bool ready = false;\n");
        detail::write_text_file(
                project_dir / "main.cpp",
                "#include \"sync.hpp\"\n"
                "int main() {\n"
                "    std::lock_guard lock{m};\n"
                "    ready = true;\n"
                "    return 0;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.banner_enabled = false;
        cfg.color = color_mode::never;
        cfg.link = link_mode::staticlink;

        auto script = ":import {}\n:mem\n:quit\n"_format(project_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("trace: enabled") != std::string::npos);
        CHECK(output.out.find("ready") != std::string::npos);
        CHECK(output.out.find("0x01") != std::string::npos);
        CHECK(output.out.find("abi:ne210108") == std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: import reports ambiguity when multiple mains are in scope", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_ambiguous_main"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        detail::write_text_file(project_dir / "app_a.cpp", "int main() { return 1; }\n");
        detail::write_text_file(project_dir / "app_b.cpp", "int main() { return 2; }\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {}\n:quit\n"_format(project_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.err.find("multiple main() functions found under import roots") != std::string::npos);
        CHECK(output.err.find("entry <file>") != std::string::npos);
        CHECK(output.err.find("library") != std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.decl_cells.empty());
        CHECK(persisted_cells.exec_cells.empty());
    }

    TEST_CASE("005: import entry resolves ambiguous mains to selected file", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_entry_resolution"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        auto app_a_path = project_dir / "app_a.cpp";
        auto app_b_path = project_dir / "app_b.cpp";
        auto lib_path = project_dir / "lib.hpp";
        detail::write_text_file(app_a_path, "int main() { return 1; }\n");
        detail::write_text_file(
                app_b_path,
                "int seed = 8;\n"
                "int main() {\n"
                "    return seed;\n"
                "}\n");
        detail::write_text_file(lib_path, "inline int imported_bias = 6;\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} entry {}\n:show all\n:quit\n"_format(project_dir.string(), app_b_path.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=app") != std::string::npos);
        CHECK(output.out.find("entry={}"_format(app_b_path.string())) != std::string::npos);
        CHECK(output.out.find("#include \"{}\""_format(lib_path.string())) != std::string::npos);
        CHECK(output.out.find("int seed = 8;") != std::string::npos);
        CHECK(output.out.find("return seed;") != std::string::npos);
        CHECK(output.out.find("return 1;") == std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE_FALSE(persisted_cells.decl_cells.empty());
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells[0].find("return seed;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("return 1;") == std::string::npos);
    }

    TEST_CASE("005: import library ignores main files and keeps non-main sources", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_library_mode"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        detail::write_text_file(project_dir / "app_a.cpp", "int main() { return 1; }\n");
        detail::write_text_file(project_dir / "app_b.cpp", "int main() { return 2; }\n");
        detail::write_text_file(project_dir / "library.hpp", "inline int library_seed = 17;\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:show all\n:quit\n"_format(project_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=library") != std::string::npos);
        CHECK(output.out.find("#include \"{}\""_format((project_dir / "library.hpp").string())) != std::string::npos);
        CHECK(output.out.find("return 1;") == std::string::npos);
        CHECK(output.out.find("return 2;") == std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.exec_cells.empty());
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("#include \"{}\""_format((project_dir / "library.hpp").string())) !=
              std::string::npos);
        REQUIRE(persisted_cells.transactions.size() == 1U);
        CHECK(persisted_cells.transactions[0].kind == detail::transaction_kind::import);
        REQUIRE(persisted_cells.transactions[0].import_record.has_value());
        CHECK(persisted_cells.transactions[0].import_record->mode == "library");
        CHECK_FALSE(persisted_cells.transactions[0].import_record->entry.has_value());
    }

    TEST_CASE("005: import library symbols omit synthetic main and keep library TUs", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_library_symbols"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        detail::write_text_file(project_dir / "app_main.cpp", "int main() { return 42; }\n");
        detail::write_text_file(
                project_dir / "library.cpp",
                "int square(int x) {\n"
                "    return x * x;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:symbols\n:quit\n"_format(project_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=library") != std::string::npos);
        CHECK(output.out.find("square(int)") != std::string::npos);
        CHECK(output.out.find("  [T] main\n") == std::string::npos);
        CHECK(output.out.find("  [t] main\n") == std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: import symbols consume compile_commands include flags", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_compile_db_flags"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        detail::fs::create_directories(src_dir);

        detail::write_text_file(
                src_dir / "mathlib.cpp",
                "int square_with_bias(int x) {\n"
                "    return x * x;\n"
                "}\n"
                "#ifdef ENABLE_EXTRA\n"
                "int compile_db_only_symbol() {\n"
                "    return 7;\n"
                "}\n"
                "#endif\n");

        auto compile_db = std::string{};
        compile_db.append("[\n");
        compile_db.append("  {\n");
        compile_db.append("    \"directory\": \"");
        compile_db.append(project_dir.string());
        compile_db.append("\",\n");
        compile_db.append("    \"file\": \"src/mathlib.cpp\",\n");
        compile_db.append(
                "    \"arguments\": [\"clang++\", \"-std=c++23\", \"-DENABLE_EXTRA\", \"-c\", \"src/mathlib.cpp\", "
                "\"-o\", "
                "\"build/mathlib.o\"]\n");
        compile_db.append("  }\n");
        compile_db.append("]\n");
        detail::write_text_file(project_dir / "compile_commands.json", compile_db);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:symbols\n:quit\n"_format(src_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=library") != std::string::npos);
        CHECK(output.out.find("compile_db_only_symbol()") != std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto snapshots =
                detail::find_files_named_recursive(session_dir / "artifacts", "compile_commands.snapshot.json");
        REQUIRE_FALSE(snapshots.empty());

        auto has_expected_entry = false;
        for (const auto& snapshot_path : snapshots) {
            auto parsed = detail::read_json_file<std::vector<glz::generic>>(snapshot_path);
            if (parsed.empty()) {
                continue;
            }
            auto text = detail::read_text_file(snapshot_path);
            if (text.find("src/mathlib.cpp") != std::string::npos && text.find("ENABLE_EXTRA") != std::string::npos) {
                has_expected_entry = true;
                break;
            }
        }
        CHECK(has_expected_entry);
    }

    TEST_CASE("005: import symbols consume compile_commands command string", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_compile_db_command"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        detail::fs::create_directories(src_dir);

        detail::write_text_file(
                src_dir / "cmd.cpp",
                "int baseline_symbol(int x) {\n"
                "    return x + 2;\n"
                "}\n"
                "#ifdef ENABLE_CMD_ONLY\n"
                "int command_db_only_symbol() {\n"
                "    return 11;\n"
                "}\n"
                "#endif\n");

        auto compile_db = std::string{};
        compile_db.append("[\n");
        compile_db.append("  {\n");
        compile_db.append("    \"directory\": \"");
        compile_db.append(project_dir.string());
        compile_db.append("\",\n");
        compile_db.append("    \"file\": \"src/cmd.cpp\",\n");
        compile_db.append("    \"command\": \"clang++ -std=c++23 -DENABLE_CMD_ONLY -c src/cmd.cpp -o build/cmd.o\"\n");
        compile_db.append("  }\n");
        compile_db.append("]\n");
        detail::write_text_file(project_dir / "compile_commands.json", compile_db);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:symbols\n:quit\n"_format(src_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=library") != std::string::npos);
        CHECK(output.out.find("command_db_only_symbol()") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: import symbols emit multi-tu compile_commands snapshot entries", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_compile_db_multi_tu_snapshot"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        detail::fs::create_directories(src_dir);

        detail::write_text_file(src_dir / "a.cpp", "int snapshot_symbol_a() { return 1; }\n");
        detail::write_text_file(src_dir / "b.cpp", "int snapshot_symbol_b() { return 2; }\n");

        auto compile_db = std::string{};
        compile_db.append("[\n");
        compile_db.append("  {\n");
        compile_db.append("    \"directory\": \"");
        compile_db.append(project_dir.string());
        compile_db.append("\",\n");
        compile_db.append("    \"file\": \"src/a.cpp\",\n");
        compile_db.append(
                "    \"arguments\": [\"clang++\", \"-std=c++23\", \"-c\", \"src/a.cpp\", \"-o\", \"build/a.o\"]\n");
        compile_db.append("  },\n");
        compile_db.append("  {\n");
        compile_db.append("    \"directory\": \"");
        compile_db.append(project_dir.string());
        compile_db.append("\",\n");
        compile_db.append("    \"file\": \"src/b.cpp\",\n");
        compile_db.append(
                "    \"arguments\": [\"clang++\", \"-std=c++23\", \"-c\", \"src/b.cpp\", \"-o\", \"build/b.o\"]\n");
        compile_db.append("  }\n");
        compile_db.append("]\n");
        detail::write_text_file(project_dir / "compile_commands.json", compile_db);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:symbols\n:quit\n"_format(src_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("snapshot_symbol_a()") != std::string::npos);
        CHECK(output.out.find("snapshot_symbol_b()") != std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto snapshots =
                detail::find_files_named_recursive(session_dir / "artifacts", "compile_commands.snapshot.json");
        REQUIRE_FALSE(snapshots.empty());

        auto found_multi_tu_snapshot = false;
        for (const auto& snapshot_path : snapshots) {
            auto text = detail::read_text_file(snapshot_path);
            if (text.find("src/a.cpp") != std::string::npos && text.find("src/b.cpp") != std::string::npos) {
                found_multi_tu_snapshot = true;
                break;
            }
        }
        CHECK(found_multi_tu_snapshot);
    }

    TEST_CASE("005: import symbols prefer existing compile_commands over cmake fallback", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_compile_db_precedence"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        detail::fs::create_directories(src_dir);

        detail::write_text_file(
                src_dir / "core.cpp",
                "#ifdef ENABLE_DB_ONLY\n"
                "int from_compile_db_symbol() {\n"
                "    return 21;\n"
                "}\n"
                "#endif\n"
                "#ifdef ENABLE_CMAKE_ONLY\n"
                "int from_cmake_symbol() {\n"
                "    return 34;\n"
                "}\n"
                "#endif\n");

        auto compile_db = std::string{};
        compile_db.append("[\n");
        compile_db.append("  {\n");
        compile_db.append("    \"directory\": \"");
        compile_db.append(project_dir.string());
        compile_db.append("\",\n");
        compile_db.append("    \"file\": \"src/core.cpp\",\n");
        compile_db.append(
                "    \"arguments\": [\"clang++\", \"-std=c++23\", \"-DENABLE_DB_ONLY\", \"-c\", \"src/core.cpp\", "
                "\"-o\", \"build/core.o\"]\n");
        compile_db.append("  }\n");
        compile_db.append("]\n");
        detail::write_text_file(project_dir / "compile_commands.json", compile_db);

        detail::write_text_file(
                project_dir / "CMakeLists.txt",
                "cmake_minimum_required(VERSION 3.16)\n"
                "project(sontag_import_precedence LANGUAGES CXX)\n"
                "add_library(import_core src/core.cpp)\n"
                "target_compile_definitions(import_core PRIVATE ENABLE_CMAKE_ONLY=1)\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:symbols\n:quit\n"_format(src_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=library") != std::string::npos);
        CHECK(output.out.find("from_compile_db_symbol()") != std::string::npos);
        CHECK(output.out.find("from_cmake_symbol()") == std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto generated_compile_dbs =
                detail::find_files_named_recursive(session_dir / "artifacts", "compile_commands.json");
        auto has_cmake_generated_db = false;
        for (const auto& path : generated_compile_dbs) {
            if (path.string().find("cmake_compdb") != std::string::npos) {
                has_cmake_generated_db = true;
                break;
            }
        }
        CHECK_FALSE(has_cmake_generated_db);
    }

    TEST_CASE("005: import symbols fallback to root include paths without compile database", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_symbols_root_include_fallback"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        auto include_dir = project_dir / "include";
        detail::fs::create_directories(src_dir);
        detail::fs::create_directories(include_dir);

        detail::write_text_file(
                include_dir / "helper.hpp",
                "inline int helper_value(int x) {\n"
                "    return x + 7;\n"
                "}\n");
        detail::write_text_file(
                src_dir / "library.cpp",
                "#include \"helper.hpp\"\n"
                "int fallback_include_symbol(int x) {\n"
                "    return helper_value(x);\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} {} library\n:symbols\n:quit\n"_format(src_dir.string(), include_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=library") != std::string::npos);
        CHECK(output.out.find("fallback_include_symbol(int)") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: import ir consumes compile_commands flags", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_ir_compile_db_flags"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        detail::fs::create_directories(src_dir);

        detail::write_text_file(
                src_dir / "ir.cpp",
                "int baseline_ir_symbol(int x) {\n"
                "    return x + 3;\n"
                "}\n"
                "#ifdef ENABLE_IR_ONLY\n"
                "extern \"C\" int ir_db_only_symbol() {\n"
                "    return 77;\n"
                "}\n"
                "#endif\n");

        auto compile_db = std::string{};
        compile_db.append("[\n");
        compile_db.append("  {\n");
        compile_db.append("    \"directory\": \"");
        compile_db.append(project_dir.string());
        compile_db.append("\",\n");
        compile_db.append("    \"file\": \"src/ir.cpp\",\n");
        compile_db.append(
                "    \"arguments\": [\"clang++\", \"-std=c++23\", \"-DENABLE_IR_ONLY\", \"-c\", \"src/ir.cpp\", "
                "\"-o\", \"build/ir.o\"]\n");
        compile_db.append("  }\n");
        compile_db.append("]\n");
        detail::write_text_file(project_dir / "compile_commands.json", compile_db);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.output = output_mode::json;

        auto script = ":import {} library\n:ir ir_db_only_symbol\n:quit\n"_format(src_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("ir_db_only_symbol") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: import asm consumes compile_commands flags", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_asm_compile_db_flags"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        detail::fs::create_directories(src_dir);

        detail::write_text_file(
                src_dir / "dump.cpp",
                "int baseline_dump_symbol(int x) {\n"
                "    return x + 4;\n"
                "}\n"
                "#ifdef ENABLE_DUMP_ONLY\n"
                "int dump_db_only_symbol() {\n"
                "    return 101;\n"
                "}\n"
                "#endif\n");

        auto compile_db = std::string{};
        compile_db.append("[\n");
        compile_db.append("  {\n");
        compile_db.append("    \"directory\": \"");
        compile_db.append(project_dir.string());
        compile_db.append("\",\n");
        compile_db.append("    \"file\": \"src/dump.cpp\",\n");
        compile_db.append(
                "    \"arguments\": [\"clang++\", \"-std=c++23\", \"-DENABLE_DUMP_ONLY\", \"-c\", \"src/dump.cpp\", "
                "\"-o\", \"build/dump.o\"]\n");
        compile_db.append("  }\n");
        compile_db.append("]\n");
        detail::write_text_file(project_dir / "compile_commands.json", compile_db);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:asm dump_db_only_symbol\n:quit\n"_format(src_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mov  eax, 101") != std::string::npos);
        CHECK(output.err.empty());
    }

    TEST_CASE("005: import symbols fall back to cmake generated compile_commands", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_cmake_compile_db"};
        auto project_dir = temp.path / "project";
        auto src_dir = project_dir / "src";
        detail::fs::create_directories(src_dir);

        detail::write_text_file(
                src_dir / "core.cpp",
                "int baseline_symbol() {\n"
                "    return 1;\n"
                "}\n"
                "#ifdef ENABLE_CMAKE_ONLY\n"
                "int cmake_generated_symbol() {\n"
                "    return 13;\n"
                "}\n"
                "#endif\n");
        detail::write_text_file(
                project_dir / "CMakeLists.txt",
                "cmake_minimum_required(VERSION 3.16)\n"
                "project(sontag_import_cmake LANGUAGES CXX)\n"
                "add_library(import_core src/core.cpp)\n"
                "target_compile_definitions(import_core PRIVATE ENABLE_CMAKE_ONLY=1)\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} library\n:symbols\n:quit\n"_format(src_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("cmake_generated_symbol()") != std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto generated_compile_dbs =
                detail::find_files_named_recursive(session_dir / "artifacts", "compile_commands.json");
        auto has_cmake_generated_db = false;
        for (const auto& path : generated_compile_dbs) {
            if (path.string().find("cmake_compdb") != std::string::npos) {
                has_cmake_generated_db = true;
                break;
            }
        }
        CHECK(has_cmake_generated_db);
    }

    TEST_CASE("005: reset import removes matching directory import transaction", "[005][session][reset_import]") {
        detail::temp_dir temp{"sontag_reset_import"};
        auto project_dir = temp.path / "project";
        detail::fs::create_directories(project_dir);

        auto main_path = project_dir / "main.cpp";
        detail::write_text_file(
                main_path,
                "int seed = 7;\n"
                "int main() {\n"
                "    return seed;\n"
                "}\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {}\n:decl int tail = 42;\n:reset import {}\n:show all\n:quit\n"_format(
                project_dir.string(), project_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("stored decl #2 -> state: valid") != std::string::npos);
        CHECK(output.out.find("cleared import roots=1") != std::string::npos);
        CHECK(output.out.find("int tail = 42;") != std::string::npos);
        CHECK(output.out.find("int seed = 7;") == std::string::npos);
        CHECK(output.out.find("return seed;") == std::string::npos);
        CHECK(output.err.empty());

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        CHECK(persisted_cells.exec_cells.empty());
        CHECK(persisted_cells.decl_cells[0].find("int tail = 42;") != std::string::npos);
    }

    TEST_CASE("005: import roots scope excludes mains outside selected directories", "[005][session][import]") {
        detail::temp_dir temp{"sontag_import_root_scope"};
        auto root_dir = temp.path / "project";
        auto src_dir = root_dir / "src";
        auto include_dir = root_dir / "include";
        auto app_dir = root_dir / "app";
        auto test_dir = root_dir / "test";
        detail::fs::create_directories(src_dir);
        detail::fs::create_directories(include_dir);
        detail::fs::create_directories(app_dir);
        detail::fs::create_directories(test_dir);

        detail::write_text_file(src_dir / "library.cpp", "int library_value = 21;\n");
        detail::write_text_file(include_dir / "library.hpp", "inline int include_value = 5;\n");
        detail::write_text_file(app_dir / "main.cpp", "int main() { return 100; }\n");
        detail::write_text_file(test_dir / "test_main.cpp", "int main() { return 200; }\n");

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;

        auto script = ":import {} {}\n:show all\n:quit\n"_format(src_dir.string(), include_dir.string());
        auto output = detail::run_repl_script_capture_output(cfg, script);

        CHECK(output.out.find("imported directories") != std::string::npos);
        CHECK(output.out.find("mode=library") != std::string::npos);
        CHECK(output.out.find("#include \"{}\""_format((src_dir / "library.cpp").string())) != std::string::npos);
        CHECK(output.out.find("#include \"{}\""_format((include_dir / "library.hpp").string())) != std::string::npos);
        CHECK(output.out.find("return 100;") == std::string::npos);
        CHECK(output.out.find("return 200;") == std::string::npos);
        CHECK(output.err.empty());
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
        hx_script.append("int main() {\n");
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
        CHECK(output.out.find("return value;") != std::string::npos);
        CHECK(output.out.find("return 0;") == std::string::npos);

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
                "int main() {\n"
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

        CHECK(output.err.find("no main() function found") != std::string::npos);
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
                "int main() {\n"
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

int main() {
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

int main() {
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
                R"(int main() {
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

    TEST_CASE("005: file uses main as driver when main is absent", "[005][session][file]") {
        detail::temp_dir temp{"sontag_file_main_driver"};
        auto source_path = temp.path / "main_driver.cpp";
        detail::write_text_file(
                source_path,
                R"(const char* note = "main is not defined in this file";
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
        CHECK(output.err.find("both main and main") == std::string::npos);

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);
        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.decl_cells.size() == 1U);
        REQUIRE(persisted_cells.exec_cells.size() == 1U);
        CHECK(persisted_cells.decl_cells[0].find("main is not defined") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("int v = 11;") != std::string::npos);
        CHECK(persisted_cells.exec_cells[0].find("return v;") != std::string::npos);
    }

}  // namespace sontag::test
