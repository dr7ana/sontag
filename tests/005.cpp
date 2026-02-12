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

    struct snapshot_record {
        std::string name{};
        std::size_t cell_count{};
    };

    struct persisted_snapshots {
        int schema_version{1};
        std::string active_snapshot{};
        std::vector<snapshot_record> snapshots{};
    };

    struct persisted_cells {
        int schema_version{1};
        std::vector<std::string> cells{};
    };

    struct persisted_config {
        int schema_version{1};
        std::string clang{};
        std::string cxx_standard{};
        std::string opt_level{};
        std::optional<std::string> target{};
        std::optional<std::string> cpu{};
        std::string cache_dir{};
        std::string output{};
        std::string color{};
    };

    template <typename T>
    static T read_json_file(const fs::path& path) {
        std::ifstream in{path};
        REQUIRE(in.good());

        std::ostringstream ss{};
        ss << in.rdbuf();
        auto text = ss.str();

        T value{};
        auto ec = glz::read_json(value, text);
        REQUIRE_FALSE(ec);
        return value;
    }

    static std::optional<std::size_t> snapshot_cell_count(const persisted_snapshots& snapshots, std::string_view name) {
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
        auto offset = std::size_t{0};
        while (offset < text.size()) {
            auto* data = text.data() + offset;
            auto remaining = text.size() - offset;
            auto bytes = ::write(fd, data, remaining);
            REQUIRE(bytes > 0);
            offset += static_cast<std::size_t>(bytes);
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
    struct meta<sontag::test::detail::persisted_cells> {
        using T = sontag::test::detail::persisted_cells;
        static constexpr auto value = object("schema_version", &T::schema_version, "cells", &T::cells);
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
                       "cache_dir",
                       &T::cache_dir,
                       "output",
                       &T::output,
                       "color",
                       &T::color);
    };
}  // namespace glz

namespace sontag::test {

    TEST_CASE("005: session bootstrap persists config cells and snapshots", "[005][session]") {
        detail::temp_dir temp{"sontag_session_bootstrap"};

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.language_standard = cxx_standard::cxx20;
        cfg.opt_level = optimization_level::o1;
        cfg.output = output_mode::json;
        cfg.color = color_mode::never;

        detail::run_repl_script(
                cfg,
                "int seed = 42;\n"
                ":mark baseline\n"
                "int inc(int x) { return x + seed; }\n"
                ":quit\n");

        auto session_dir = detail::find_single_session_dir(cfg.cache_dir);

        auto persisted_cfg = detail::read_json_file<detail::persisted_config>(session_dir / "config.json");
        CHECK(persisted_cfg.schema_version == 1);
        CHECK(persisted_cfg.cxx_standard == "c++20");
        CHECK(persisted_cfg.opt_level == "O1");
        CHECK(persisted_cfg.cache_dir == cfg.cache_dir.string());
        CHECK(persisted_cfg.output == "json");
        CHECK(persisted_cfg.color == "never");

        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        REQUIRE(persisted_cells.cells.size() == 2U);
        CHECK(persisted_cells.cells[0].find("seed") != std::string::npos);
        CHECK(persisted_cells.cells[1].find("inc(") != std::string::npos);

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

        detail::run_repl_script(
                initial_cfg,
                "int value = 7;\n"
                "int twice(int x) { return x * 2; }\n"
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

        auto persisted_cells = detail::read_json_file<detail::persisted_cells>(session_dir / "cells.json");
        CHECK(persisted_cells.cells.empty());

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

}  // namespace sontag::test
