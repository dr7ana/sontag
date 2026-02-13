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

    static analysis_request make_request(const fs::path& session_dir, std::string decl_cell, std::string exec_cell) {
        auto request = analysis_request{};
        request.clang_path = "/usr/bin/clang++";
        request.session_dir = session_dir;
        request.language_standard = cxx_standard::cxx23;
        request.opt_level = optimization_level::o2;
        request.decl_cells = {std::move(decl_cell)};
        request.exec_cells = {std::move(exec_cell)};
        return request;
    }

    static bool contains_quality_flag(const std::vector<delta_quality_flag>& quality_flags, delta_quality_flag wanted) {
        return std::find(quality_flags.begin(), quality_flags.end(), wanted) != quality_flags.end();
    }
}}  // namespace sontag::test::detail

namespace sontag::test {

    TEST_CASE("010: delta default is pairwise o0->o2", "[010][delta]") {
        detail::temp_dir temp{"sontag_delta_default"};

        auto request = detail::make_request(temp.path / "session", "volatile int sink = 0;\n", "sink = 7 + 11;");

        auto report = collect_delta_report(request);

        CHECK(report.schema_version == 1);
        CHECK(report.mode == delta_mode::pairwise);
        CHECK(report.baseline == optimization_level::o0);
        CHECK(report.target == optimization_level::o2);
        REQUIRE(report.levels.size() == 2U);
        CHECK(report.levels[0].level == optimization_level::o0);
        CHECK(report.levels[1].level == optimization_level::o2);
        CHECK(report.symbol_display.find("__sontag_main") != std::string::npos);

        bool any_operations = false;
        bool any_triplets = false;
        for (const auto& level : report.levels) {
            CHECK(level.artifact_path.string().find("/artifacts/dump/") != std::string::npos);
            any_operations = any_operations || !level.operations.empty();
            any_triplets = any_triplets || std::ranges::any_of(level.operations, [](const delta_operation& op) {
                               return !op.triplet.empty();
                           });
        }
        CHECK(any_operations);
        CHECK(any_triplets);
        CHECK(!report.opcode_table.empty());
    }

    TEST_CASE("010: delta resolves explicit symbol scope and normalizes opcodes", "[010][delta]") {
        detail::temp_dir temp{"sontag_delta_symbol_scope"};

        auto request = detail::make_request(
                temp.path / "session",
                "volatile int sink = 0;\n"
                "__attribute__((noinline)) int add(int a, int b) { return a + b; }\n",
                "sink = add(7, 11);");

        auto report = collect_delta_report(request, delta_request{.symbol = "add"});

        CHECK(report.mode == delta_mode::pairwise);
        CHECK_FALSE(detail::contains_quality_flag(report.quality_flags, delta_quality_flag::symbol_resolution_failed));
        CHECK(report.symbol_display.find("add") != std::string::npos);
        REQUIRE(report.levels.size() == 2U);
        CHECK(report.levels[0].level == optimization_level::o0);
        CHECK(report.levels[1].level == optimization_level::o2);
        CHECK(report.success);

        bool any_level_has_operations = false;
        for (const auto& level : report.levels) {
            any_level_has_operations = any_level_has_operations || !level.operations.empty();
        }
        CHECK(any_level_has_operations);
    }

    TEST_CASE("010: delta with explicit target remains pairwise", "[010][delta]") {
        detail::temp_dir temp{"sontag_delta_explicit_target"};

        auto request = detail::make_request(temp.path / "session", "volatile int sink = 0;\n", "sink = 3 * 9;");

        auto report_o3 = collect_delta_report(request, std::nullopt, optimization_level::o3);
        CHECK(report_o3.mode == delta_mode::pairwise);
        CHECK(report_o3.target == optimization_level::o3);
        REQUIRE(report_o3.levels.size() == 2U);
        CHECK(report_o3.levels[0].level == optimization_level::o0);
        CHECK(report_o3.levels[1].level == optimization_level::o3);

        auto report_o1 = collect_delta_report(request, delta_request{.target = optimization_level::o1});
        CHECK(report_o1.mode == delta_mode::pairwise);
        CHECK(report_o1.target == optimization_level::o1);
        REQUIRE(report_o1.levels.size() == 2U);
        CHECK(report_o1.levels[0].level == optimization_level::o0);
        CHECK(report_o1.levels[1].level == optimization_level::o1);
    }

    TEST_CASE("010: delta spectrum uses configurable upper bound", "[010][delta][spectrum]") {
        detail::temp_dir temp{"sontag_delta_spectrum_levels"};

        auto request = detail::make_request(temp.path / "session", "volatile int sink = 0;\n", "sink = 3 * 9;");

        auto default_spectrum = collect_delta_report(request, delta_request{.mode = delta_mode::spectrum});
        CHECK(default_spectrum.mode == delta_mode::spectrum);
        CHECK(default_spectrum.target == optimization_level::o2);
        REQUIRE(default_spectrum.levels.size() == 3U);
        CHECK(default_spectrum.levels[0].level == optimization_level::o0);
        CHECK(default_spectrum.levels[1].level == optimization_level::o1);
        CHECK(default_spectrum.levels[2].level == optimization_level::o2);

        auto spectrum_o3 = collect_delta_report(
                request, delta_request{.mode = delta_mode::spectrum, .target = optimization_level::o3});
        CHECK(spectrum_o3.mode == delta_mode::spectrum);
        CHECK(spectrum_o3.target == optimization_level::o3);
        REQUIRE(spectrum_o3.levels.size() == 4U);
        CHECK(spectrum_o3.levels[0].level == optimization_level::o0);
        CHECK(spectrum_o3.levels[1].level == optimization_level::o1);
        CHECK(spectrum_o3.levels[2].level == optimization_level::o2);
        CHECK(spectrum_o3.levels[3].level == optimization_level::o3);
    }

    TEST_CASE("010: delta flags unresolved symbol while still collecting levels", "[010][delta]") {
        detail::temp_dir temp{"sontag_delta_missing_symbol"};

        auto request = detail::make_request(temp.path / "session", "volatile int sink = 0;\n", "sink = 3 * 9;");

        auto report = collect_delta_report(request, delta_request{.symbol = "does_not_exist"});

        CHECK(detail::contains_quality_flag(report.quality_flags, delta_quality_flag::symbol_resolution_failed));
        REQUIRE(report.levels.size() == 2U);
        CHECK(report.levels[0].level == optimization_level::o0);
        CHECK(report.levels[1].level == optimization_level::o2);
    }

    TEST_CASE("010: delta opcode mapping is ephemeral with no sidecar artifacts", "[010][delta]") {
        detail::temp_dir temp{"sontag_delta_ephemeral_mapping"};

        auto request = detail::make_request(temp.path / "session", "volatile int sink = 0;\n", "sink = 3 * 9;");
        auto report = collect_delta_report(request);
        CHECK_FALSE(report.opcode_table.empty());

        auto artifacts_dir = request.session_dir / "artifacts";
        REQUIRE(detail::fs::exists(artifacts_dir));

        bool found_opcode_sidecar = false;
        for (const auto& entry : detail::fs::recursive_directory_iterator(artifacts_dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            auto filename = entry.path().filename().string();
            if (filename.find("opcode") != std::string::npos || filename.find("opcodes") != std::string::npos) {
                found_opcode_sidecar = true;
                break;
            }
        }

        CHECK_FALSE(found_opcode_sidecar);
    }

}  // namespace sontag::test
