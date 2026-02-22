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

    struct persisted_config {
        int schema_version{1};
        std::string clang{};
        std::string cxx_standard{};
        std::string opt_level{};
        std::optional<std::string> target{};
        std::optional<std::string> cpu{};
        std::optional<std::string> mca_cpu{};
        std::string mca_path{};
        std::string nm_path{};
        std::string cache_dir{};
        std::string output{};
        std::string color{};
        std::string color_scheme{"vaporwave"};
    };

    struct persisted_snapshots {
        int schema_version{1};
        std::string active_snapshot{"current"};
        std::vector<std::string> snapshots{};
    };

    struct persisted_cells {
        int schema_version{1};
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
    };

    static void write_text_file(const fs::path& path, std::string_view text) {
        std::error_code ec{};
        auto parent = path.parent_path();
        if (!parent.empty()) {
            fs::create_directories(parent, ec);
        }

        std::ofstream out{path};
        REQUIRE(out.good());
        out << text;
        REQUIRE(out.good());
    }

    static void write_json_config(const fs::path& path, int schema_version, bool with_unknown_key) {
        std::ostringstream json{};
        json << "{";
        json << "\"schema_version\":" << schema_version << ",";
        json << "\"clang\":\"/usr/bin/clang++\",";
        json << "\"cxx_standard\":\"c++23\",";
        json << "\"opt_level\":\"O2\",";
        json << "\"target\":null,";
        json << "\"cpu\":null,";
        json << "\"mca_cpu\":null,";
        json << "\"mca_path\":\"llvm-mca\",";
        json << "\"nm_path\":\"nm\",";
        json << "\"cache_dir\":\"" << path.parent_path().parent_path().parent_path().string() << "\",";
        json << "\"output\":\"table\",";
        json << "\"color\":\"auto\",";
        json << "\"color_scheme\":\"vaporwave\"";
        if (with_unknown_key) {
            json << ",\"new_field_from_future\":42";
        }
        json << "}\n";
        write_text_file(path, json.str());
    }

    static void write_json_snapshots(const fs::path& path, int schema_version, bool with_unknown_key) {
        std::ostringstream json{};
        json << "{";
        json << "\"schema_version\":" << schema_version << ",";
        json << "\"active_snapshot\":\"current\",";
        json << "\"snapshots\":[{\"name\":\"current\",\"cell_count\":0}]";
        if (with_unknown_key) {
            json << ",\"new_snapshots_field\":true";
        }
        json << "}\n";
        write_text_file(path, json.str());
    }

    static void write_json_cells(const fs::path& path, int schema_version, bool with_unknown_key) {
        std::ostringstream json{};
        json << "{";
        json << "\"schema_version\":" << schema_version << ",";
        json << "\"decl_cells\":[],";
        json << "\"exec_cells\":[]";
        if (with_unknown_key) {
            json << ",\"new_cells_field\":\"ok\"";
        }
        json << "}\n";
        write_text_file(path, json.str());
    }

    static void run_repl_script(startup_config& cfg, std::string_view script) {
        int pipe_fds[2]{-1, -1};
        REQUIRE(::pipe(pipe_fds) == 0);

        auto read_fd = pipe_fds[0];
        auto write_fd = pipe_fds[1];

        size_t offset = 0U;
        while (offset < script.size()) {
            auto bytes = ::write(write_fd, script.data() + offset, script.size() - offset);
            REQUIRE(bytes > 0);
            offset += static_cast<size_t>(bytes);
        }
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
                       "nm_path",
                       &T::nm_path,
                       "cache_dir",
                       &T::cache_dir,
                       "output",
                       &T::output,
                       "color",
                       &T::color,
                       "color_scheme",
                       &T::color_scheme);
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
        static constexpr auto value = object(
                "schema_version", &T::schema_version, "decl_cells", &T::decl_cells, "exec_cells", &T::exec_cells);
    };
}  // namespace glz

namespace sontag::test {
    using namespace std::string_view_literals;

    TEST_CASE("006: strict vs permissive parser behavior for unknown keys", "[006][json][policy]") {
        detail::persisted_config parsed{};
        auto json =
                R"({"schema_version":1,"clang":"clang++","cxx_standard":"c++23","opt_level":"O2","target":null,"cpu":null,"cache_dir":".sontag","output":"table","color":"auto","color_scheme":"classic","future_key":123})";

        auto strict_ec = glz::read_json(parsed, json);
        CHECK(static_cast<bool>(strict_ec));

        auto permissive_ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(parsed, json);
        CHECK_FALSE(permissive_ec);
        CHECK(parsed.cxx_standard == "c++23"sv);
    }

    TEST_CASE("006: resume accepts unknown keys in persisted session json", "[006][json][policy][resume]") {
        detail::temp_dir temp{"sontag_json_policy_unknown"};

        auto sessions_root = temp.path / "cache" / "sessions";
        auto session_dir = sessions_root / "20990101_000000_000_pid1";
        std::error_code ec{};
        detail::fs::create_directories(session_dir, ec);
        REQUIRE_FALSE(static_cast<bool>(ec));

        detail::write_json_config(session_dir / "config.json", 1, true);
        detail::write_json_snapshots(session_dir / "snapshots.json", 1, true);
        detail::write_json_cells(session_dir / "cells.json", 1, true);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.resume_session = "latest";

        CHECK_NOTHROW(detail::run_repl_script(cfg, ":quit\n"sv));
    }

    TEST_CASE("006: resume rejects unsupported schema version", "[006][json][policy][resume]") {
        detail::temp_dir temp{"sontag_json_policy_schema"};

        auto sessions_root = temp.path / "cache" / "sessions";
        auto session_dir = sessions_root / "20990101_000000_000_pid1";
        std::error_code ec{};
        detail::fs::create_directories(session_dir, ec);
        REQUIRE_FALSE(static_cast<bool>(ec));

        detail::write_json_config(session_dir / "config.json", 2, false);
        detail::write_json_snapshots(session_dir / "snapshots.json", 1, false);
        detail::write_json_cells(session_dir / "cells.json", 1, false);

        startup_config cfg{};
        cfg.cache_dir = temp.path / "cache";
        cfg.history_enabled = false;
        cfg.resume_session = "latest";

        try {
            detail::run_repl_script(cfg, ":quit\n"sv);
            FAIL("expected unsupported schema_version failure");
        } catch (const std::runtime_error& e) {
            std::string message{e.what()};
            CHECK(message.find("unsupported schema_version") != std::string::npos);
        }
    }

}  // namespace sontag::test
