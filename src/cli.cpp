#include "sontag/cli.hpp"

#include "editor.hpp"

#include "sontag/analysis.hpp"
#include "sontag/format.hpp"

#include <glaze/glaze.hpp>

#include <CLI/CLI.hpp>

extern "C" {
#include <unistd.h>
}

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace sontag::literals;

namespace sontag::cli { namespace detail {

    using namespace std::string_view_literals;
    namespace fs = std::filesystem;

    struct persisted_config {
        int schema_version{1};
        std::string clang{};
        std::string cxx_standard{};
        std::string opt_level{};
        std::optional<std::string> target{};
        std::optional<std::string> cpu{};
        std::optional<std::string> mca_cpu{};
        std::string mca_path{"llvm-mca"};
        std::string cache_dir{};
        std::string output{};
        std::string color{};
    };

    struct snapshot_record {
        std::string name{};
        std::size_t cell_count{};
    };

    struct persisted_snapshots {
        int schema_version{1};
        std::string active_snapshot{"current"};
        std::vector<snapshot_record> snapshots{{snapshot_record{"current", 0U}}};
    };

    struct persisted_cells {
        int schema_version{1};
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
    };

    struct repl_state {
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
        persisted_snapshots snapshot_data{};
        fs::path session_dir{};
        fs::path config_path{};
        fs::path snapshots_path{};
        fs::path cells_path{};
        std::string session_id{};
    };

    struct code_balance_state {
        int paren_depth{0};
        int brace_depth{0};
        int bracket_depth{0};

        bool in_single_quote{false};
        bool in_double_quote{false};
        bool escape_next{false};
        bool in_line_comment{false};
        bool in_block_comment{false};
    };

    struct analysis_output_record {
        std::string command{};
        bool success{false};
        int exit_code{-1};
        std::string source_path{};
        std::string artifact_path{};
        std::string stderr_path{};
        std::string text{};
        std::vector<std::string> clang_command{};
    };

}}  // namespace sontag::cli::detail

namespace glz {

    template <>
    struct meta<sontag::cli::detail::persisted_config> {
        using T = sontag::cli::detail::persisted_config;
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
                       &T::color);
    };

    template <>
    struct meta<sontag::cli::detail::snapshot_record> {
        using T = sontag::cli::detail::snapshot_record;
        static constexpr auto value = object("name", &T::name, "cell_count", &T::cell_count);
    };

    template <>
    struct meta<sontag::cli::detail::persisted_snapshots> {
        using T = sontag::cli::detail::persisted_snapshots;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "active_snapshot",
                       &T::active_snapshot,
                       "snapshots",
                       &T::snapshots);
    };

    template <>
    struct meta<sontag::cli::detail::persisted_cells> {
        using T = sontag::cli::detail::persisted_cells;
        static constexpr auto value = object(
                "schema_version", &T::schema_version, "decl_cells", &T::decl_cells, "exec_cells", &T::exec_cells);
    };

    template <>
    struct meta<sontag::cli::detail::analysis_output_record> {
        using T = sontag::cli::detail::analysis_output_record;
        static constexpr auto value =
                object("command",
                       &T::command,
                       "success",
                       &T::success,
                       "exit_code",
                       &T::exit_code,
                       "source_path",
                       &T::source_path,
                       "artifact_path",
                       &T::artifact_path,
                       "stderr_path",
                       &T::stderr_path,
                       "text",
                       &T::text,
                       "clang_command",
                       &T::clang_command);
    };

}  // namespace glz

namespace sontag::cli {

    namespace detail {

        static constexpr auto default_value = "<default>"sv;

        static std::string_view optional_or_default(const std::optional<std::string>& value) {
            if (value) {
                return *value;
            }
            return default_value;
        }

        static constexpr std::string_view trim_view(std::string_view value) {
            auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return {};
            }
            auto last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, (last - first) + 1U);
        }

        static constexpr void update_depth(int& depth, int delta) {
            depth += delta;
            if (depth < 0) {
                depth = 0;
            }
        }

        static constexpr void update_code_balance_state(code_balance_state& state, std::string_view line) {
            std::size_t i = 0U;
            while (i < line.size()) {
                auto c = line[i];
                auto next = (i + 1U < line.size()) ? line[i + 1U] : '\0';

                if (state.in_line_comment) {
                    break;
                }

                if (state.in_block_comment) {
                    if (c == '*' && next == '/') {
                        state.in_block_comment = false;
                        i += 2U;
                        continue;
                    }
                    ++i;
                    continue;
                }

                if (state.in_single_quote) {
                    if (state.escape_next) {
                        state.escape_next = false;
                        ++i;
                        continue;
                    }
                    if (c == '\\') {
                        state.escape_next = true;
                        ++i;
                        continue;
                    }
                    if (c == '\'') {
                        state.in_single_quote = false;
                    }
                    ++i;
                    continue;
                }

                if (state.in_double_quote) {
                    if (state.escape_next) {
                        state.escape_next = false;
                        ++i;
                        continue;
                    }
                    if (c == '\\') {
                        state.escape_next = true;
                        ++i;
                        continue;
                    }
                    if (c == '"') {
                        state.in_double_quote = false;
                    }
                    ++i;
                    continue;
                }

                if (c == '/' && next == '/') {
                    state.in_line_comment = true;
                    break;
                }
                if (c == '/' && next == '*') {
                    state.in_block_comment = true;
                    i += 2U;
                    continue;
                }

                if (c == '\'') {
                    state.in_single_quote = true;
                    ++i;
                    continue;
                }
                if (c == '"') {
                    state.in_double_quote = true;
                    ++i;
                    continue;
                }

                switch (c) {
                    case '(':
                        update_depth(state.paren_depth, 1);
                        break;
                    case ')':
                        update_depth(state.paren_depth, -1);
                        break;
                    case '{':
                        update_depth(state.brace_depth, 1);
                        break;
                    case '}':
                        update_depth(state.brace_depth, -1);
                        break;
                    case '[':
                        update_depth(state.bracket_depth, 1);
                        break;
                    case ']':
                        update_depth(state.bracket_depth, -1);
                        break;
                    default:
                        break;
                }

                ++i;
            }

            state.in_line_comment = false;
        }

        static constexpr bool cell_is_complete(const code_balance_state& state) {
            return state.paren_depth == 0 && state.brace_depth == 0 && state.bracket_depth == 0 &&
                   !state.in_single_quote && !state.in_double_quote && !state.in_block_comment;
        }

        static persisted_config make_persisted_config(const startup_config& cfg) {
            persisted_config data{};
            data.clang = cfg.clang_path.string();
            data.cxx_standard = std::string(to_string(cfg.language_standard));
            data.opt_level = std::string(to_string(cfg.opt_level));
            data.target = cfg.target_triple;
            data.cpu = cfg.cpu;
            data.mca_cpu = cfg.mca_cpu;
            data.mca_path = cfg.mca_path.string();
            data.cache_dir = cfg.cache_dir.string();
            data.output = std::string(to_string(cfg.output));
            data.color = std::string(to_string(cfg.color));
            return data;
        }

        static void apply_persisted_config(const persisted_config& data, startup_config& cfg) {
            cfg.clang_path = data.clang;

            if (!try_parse_cxx_standard(data.cxx_standard, cfg.language_standard)) {
                throw std::runtime_error("invalid cxx_standard in persisted config: " + data.cxx_standard);
            }
            if (!try_parse_optimization_level(data.opt_level, cfg.opt_level)) {
                throw std::runtime_error("invalid opt_level in persisted config: " + data.opt_level);
            }
            if (!try_parse_output_mode(data.output, cfg.output)) {
                throw std::runtime_error("invalid output in persisted config: " + data.output);
            }
            if (!try_parse_color_mode(data.color, cfg.color)) {
                throw std::runtime_error("invalid color in persisted config: " + data.color);
            }

            cfg.target_triple = data.target;
            cfg.cpu = data.cpu;
            cfg.mca_cpu = data.mca_cpu;
            if (data.mca_path.empty()) {
                cfg.mca_path = "llvm-mca";
            }
            else {
                cfg.mca_path = data.mca_path;
            }
            cfg.cache_dir = data.cache_dir;
        }

        static std::string read_text_file(const fs::path& path) {
            std::ifstream in{path};
            if (!in) {
                throw std::runtime_error("failed to open " + path.string());
            }
            std::ostringstream ss{};
            ss << in.rdbuf();
            if (!in.good() && !in.eof()) {
                throw std::runtime_error("failed to read " + path.string());
            }
            return ss.str();
        }

        template <typename T>
        static void write_json_file(const T& value, const fs::path& path) {
            std::string json{};
            auto ec = glz::write_json(value, json);
            if (ec) {
                throw std::runtime_error("failed to serialize json for {}"_format(path.string()));
            }

            std::ofstream out{path};
            if (!out) {
                throw std::runtime_error("failed to open {}"_format(path.string()));
            }
            out << json << '\n';
            if (!out) {
                throw std::runtime_error("failed to write {}"_format(path.string()));
            }
        }

        template <typename T>
        static T read_json_file(const fs::path& path, bool allow_unknown_keys = false) {
            T value{};
            auto json = read_text_file(path);
            if (allow_unknown_keys) {
                auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(value, json);
                if (ec) {
                    throw std::runtime_error("failed to parse json file {}"_format(path.string()));
                }
            }
            else {
                auto ec = glz::read_json(value, json);
                if (ec) {
                    throw std::runtime_error("failed to parse json file {}"_format(path.string()));
                }
            }
            return value;
        }

        static void validate_supported_schema_version(int schema_version, const fs::path& path) {
            constexpr int supported_schema_version = 1;
            if (schema_version > supported_schema_version) {
                throw std::runtime_error(
                        "unsupported schema_version in {}: {} > {}"_format(
                                path.string(), schema_version, supported_schema_version));
            }
        }

        static std::string make_session_id() {
            auto now = std::chrono::system_clock::now();
            auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
            auto timestamp_ms = static_cast<long long>(epoch_ms % 1000LL);
            auto timestamp_s = std::chrono::system_clock::to_time_t(now);

            std::tm local_tm{};
            localtime_r(&timestamp_s, &local_tm);

            std::ostringstream os{};
            os << std::put_time(&local_tm, "%Y%m%d_%H%M%S");
            os << '_' << std::setw(3) << std::setfill('0') << timestamp_ms;
            os << "_pid" << static_cast<long>(::getpid());
            return os.str();
        }

        static void upsert_snapshot(persisted_snapshots& data, std::string_view name, std::size_t cell_count) {
            auto it = std::find_if(data.snapshots.begin(), data.snapshots.end(), [name](const snapshot_record& entry) {
                return entry.name == name;
            });
            if (it == data.snapshots.end()) {
                data.snapshots.push_back(snapshot_record{std::string(name), cell_count});
                return;
            }
            it->cell_count = cell_count;
        }

        static void persist_snapshots(const repl_state& state) {
            write_json_file(state.snapshot_data, state.snapshots_path);
        }

        static std::size_t total_cell_count(const repl_state& state) {
            return state.decl_cells.size() + state.exec_cells.size();
        }

        static void persist_cells(const repl_state& state) {
            persisted_cells data{};
            data.decl_cells = state.decl_cells;
            data.exec_cells = state.exec_cells;
            write_json_file(data, state.cells_path);
        }

        static void persist_current_snapshot(repl_state& state) {
            upsert_snapshot(state.snapshot_data, "current"sv, total_cell_count(state));
            persist_snapshots(state);
        }

        static fs::path session_root(const startup_config& cfg) {
            return cfg.cache_dir / "sessions";
        }

        static repl_state make_state_paths(const fs::path& session_dir) {
            repl_state state{};
            state.session_dir = session_dir;
            state.session_id = session_dir.filename().string();
            state.config_path = state.session_dir / "config.json";
            state.snapshots_path = state.session_dir / "snapshots.json";
            state.cells_path = state.session_dir / "cells.json";
            return state;
        }

        static std::optional<fs::path> find_latest_session(const fs::path& sessions_root) {
            std::error_code ec{};
            if (!fs::exists(sessions_root, ec) || ec) {
                return std::nullopt;
            }

            std::optional<fs::path> latest{};
            for (const auto& entry : fs::directory_iterator(sessions_root, ec)) {
                if (ec) {
                    throw std::runtime_error("failed to enumerate {}"_format(sessions_root.string()));
                }
                if (!entry.is_directory()) {
                    continue;
                }
                if (!latest || entry.path().filename().string() > latest->filename().string()) {
                    latest = entry.path();
                }
            }
            return latest;
        }

        static repl_state bootstrap_session(const startup_config& cfg) {
            auto sessions_root = cfg.cache_dir / "sessions";
            std::error_code ec{};
            fs::create_directories(sessions_root, ec);
            if (ec) {
                throw std::runtime_error("failed to create sessions root: {}"_format(sessions_root.string()));
            }

            auto session_id = make_session_id();
            auto session_dir = sessions_root / session_id;

            fs::create_directories(session_dir, ec);
            if (ec) {
                throw std::runtime_error("failed to create session dir: {}"_format(session_dir.string()));
            }

            auto state = make_state_paths(session_dir);

            write_json_file(make_persisted_config(cfg), state.config_path);
            write_json_file(state.snapshot_data, state.snapshots_path);
            persist_cells(state);

            return state;
        }

        static repl_state resume_session(startup_config& cfg, std::string_view resume_id) {
            auto sessions_root = session_root(cfg);

            std::optional<fs::path> session_dir{};
            if (resume_id == "latest"sv) {
                session_dir = find_latest_session(sessions_root);
            }
            else {
                auto candidate = sessions_root / std::string(resume_id);
                std::error_code ec{};
                if (fs::exists(candidate, ec) && !ec && fs::is_directory(candidate, ec) && !ec) {
                    session_dir = candidate;
                }
            }

            if (!session_dir) {
                throw std::runtime_error("unable to resolve --resume target: {}"_format(resume_id));
            }

            auto state = make_state_paths(*session_dir);
            auto persisted_cfg = read_json_file<persisted_config>(state.config_path, true);
            validate_supported_schema_version(persisted_cfg.schema_version, state.config_path);
            apply_persisted_config(persisted_cfg, cfg);

            if (fs::exists(state.snapshots_path)) {
                auto snapshot_data = read_json_file<persisted_snapshots>(state.snapshots_path, true);
                validate_supported_schema_version(snapshot_data.schema_version, state.snapshots_path);
                state.snapshot_data = std::move(snapshot_data);
            }
            if (fs::exists(state.cells_path)) {
                auto cell_data = read_json_file<persisted_cells>(state.cells_path, true);
                validate_supported_schema_version(cell_data.schema_version, state.cells_path);
                state.decl_cells = std::move(cell_data.decl_cells);
                state.exec_cells = std::move(cell_data.exec_cells);
            }

            persist_current_snapshot(state);
            persist_cells(state);
            return state;
        }

        static repl_state start_session(startup_config& cfg) {
            if (cfg.resume_session) {
                return resume_session(cfg, *cfg.resume_session);
            }
            return bootstrap_session(cfg);
        }

        static void print_config(const startup_config& cfg, std::ostream& os) {
            os << ("  language_standard={}\n"
                   "  opt_level={}\n"
                   "  target={}\n"
                   "  cpu={}\n"
                   "  clang={}\n"
                   "  mca_cpu={}\n"
                   "  mca_path={}\n"
                   "  cache_dir={}\n"
                   "  output={}\n"
                   "  color={}\n"_format(
                           to_string(cfg.language_standard),
                           to_string(cfg.opt_level),
                           optional_or_default(cfg.target_triple),
                           optional_or_default(cfg.cpu),
                           cfg.clang_path.string(),
                           optional_or_default(cfg.mca_cpu),
                           cfg.mca_path.string(),
                           cfg.cache_dir.string(),
                           to_string(cfg.output),
                           to_string(cfg.color)));
        }

        static void print_snapshots(const repl_state& state, std::ostream& os) {
            os << "snapshots:\n";
            for (const auto& entry : state.snapshot_data.snapshots) {
                os << "  " << entry.name << " (cells=" << entry.cell_count << ")";
                if (entry.name == "current") {
                    os << " [current]";
                }
                os << '\n';
            }
        }

        static void print_cells(
                const std::vector<std::string>& cells, std::ostream& os, std::string_view empty_message) {
            if (cells.empty()) {
                os << empty_message << '\n';
                return;
            }

            for (auto i = std::size_t{0}; i < cells.size(); ++i) {
                auto& cell = cells[i];
                os << cell;
                if (!cell.ends_with('\n')) {
                    os << '\n';
                }
                if (i + 1U < cells.size()) {
                    os << '\n';
                }
            }
        }

        static void print_decl_cells(const repl_state& state, std::ostream& os) {
            print_cells(state.decl_cells, os, "no declarative cells");
        }

        static void print_exec_cells(const repl_state& state, std::ostream& os) {
            print_cells(state.exec_cells, os, "no executable cells");
        }

        static void print_all_cells(const repl_state& state, std::ostream& os) {
            analysis_request request{};
            request.decl_cells = state.decl_cells;
            request.exec_cells = state.exec_cells;
            os << synthesize_source(request);
        }

        static void print_symbols(const std::vector<analysis_symbol>& symbols, bool verbose, std::ostream& os) {
            if (symbols.empty()) {
                os << "no symbols found\n";
                return;
            }

            os << "symbols:\n";
            for (const auto& symbol : symbols) {
                os << "  [" << symbol.kind << "] " << symbol.demangled;
                if (verbose && symbol.demangled != symbol.mangled) {
                    os << " <" << symbol.mangled << '>';
                }
                os << '\n';
            }
        }

        static bool apply_set_command(startup_config& cfg, std::string_view assignment, std::ostream& err) {
            auto eq = assignment.find('=');
            if (eq == std::string_view::npos) {
                err << "invalid :set, expected key=value\n";
                return false;
            }

            auto key = trim_view(assignment.substr(0, eq));
            auto value = trim_view(assignment.substr(eq + 1U));
            if (key.empty() || value.empty()) {
                err << "invalid :set, key and value must be non-empty\n";
                return false;
            }

            if (key == "std"sv || key == "lang.std"sv) {
                if (!try_parse_cxx_standard(value, cfg.language_standard)) {
                    err << "invalid std: " << value << " (expected c++20|c++23|c++2c)\n";
                    return false;
                }
                return true;
            }

            if (key == "opt"sv || key == "build.opt"sv) {
                if (!try_parse_optimization_level(value, cfg.opt_level)) {
                    err << "invalid opt: " << value << " (expected O0|O1|O2|O3|Ofast|Oz)\n";
                    return false;
                }
                return true;
            }

            if (key == "target"sv || key == "build.target"sv) {
                cfg.target_triple = std::string(value);
                return true;
            }

            if (key == "cpu"sv || key == "build.cpu"sv) {
                cfg.cpu = std::string(value);
                return true;
            }

            if (key == "output"sv) {
                if (!try_parse_output_mode(value, cfg.output)) {
                    err << "invalid output: " << value << " (expected table|json)\n";
                    return false;
                }
                return true;
            }

            if (key == "color"sv) {
                if (!try_parse_color_mode(value, cfg.color)) {
                    err << "invalid color: " << value << " (expected auto|always|never)\n";
                    return false;
                }
                return true;
            }

            err << "unknown :set key: " << key << '\n';
            return false;
        }

        static void print_help(std::ostream& os) {
            static constexpr auto help_text = R"(commands:
  :help
  :clear
  :clear last
  :show <config|decl|exec|all>
  :symbols
  :decl <code>
  :set <key>=<value>
  :reset
  :mark <name>
  :snapshots
  :asm [symbol|@last]
  :ir [symbol|@last]
  :diag [symbol|@last]
  :mca [symbol|@last]
  :quit
examples:
  :decl #include <cstdint>
  :decl struct point { int x; int y; };
  :set std=c++23
  :set opt=O3
  :set output=json
  :show all
  :symbols
  :mark baseline
  :asm
)";
            os << help_text;
        }

        static void clear_terminal(std::ostream& os) {
            os << "\x1b[2J\x1b[H";
            os.flush();
        }

        static bool matches_command(std::string_view cmd, std::string_view name) {
            if (!cmd.starts_with(name)) {
                return false;
            }
            if (cmd.size() == name.size()) {
                return true;
            }
            auto next = cmd[name.size()];
            return next == ' ' || next == '\t';
        }

        static std::optional<std::string_view> command_argument(std::string_view cmd, std::string_view name) {
            if (!matches_command(cmd, name)) {
                return std::nullopt;
            }
            auto tail = trim_view(cmd.substr(name.size()));
            if (tail.empty()) {
                return std::optional<std::string_view>{std::string_view{}};
            }
            return std::optional<std::string_view>{tail};
        }

        static analysis_request make_analysis_request(const startup_config& cfg, const repl_state& state) {
            analysis_request request{};
            request.clang_path = cfg.clang_path;
            request.session_dir = state.session_dir;
            request.decl_cells = state.decl_cells;
            request.exec_cells = state.exec_cells;
            request.language_standard = cfg.language_standard;
            request.opt_level = cfg.opt_level;
            request.target_triple = cfg.target_triple;
            request.cpu = cfg.cpu;
            request.asm_syntax = cfg.asm_syntax;
            request.mca_cpu = cfg.mca_cpu;
            request.mca_path = cfg.mca_path;
            request.verbose = cfg.verbose;
            return request;
        }

        struct validation_result {
            bool success{true};
            std::string diagnostics{};
        };

        static validation_result validate_candidate_state(
                const startup_config& cfg, const repl_state& state, std::string_view candidate_cell, bool declarative) {
            auto request = make_analysis_request(cfg, state);
            request.symbol = std::nullopt;
            if (declarative) {
                request.decl_cells.emplace_back(candidate_cell);
            }
            else {
                request.exec_cells.emplace_back(candidate_cell);
            }

            auto diag = run_analysis(request, analysis_kind::diag);
            return validation_result{.success = diag.success, .diagnostics = std::move(diag.artifact_text)};
        }

        static bool append_validated_cell(
                startup_config& cfg,
                repl_state& state,
                std::string_view cell,
                bool declarative,
                std::ostream& out,
                std::ostream& err) {
            try {
                auto validation = validate_candidate_state(cfg, state, cell, declarative);
                if (!validation.success && !validation.diagnostics.empty()) {
                    err << validation.diagnostics;
                    if (!validation.diagnostics.ends_with('\n')) {
                        err << '\n';
                    }
                }
                if (!validation.success) {
                    err << "cell rejected, state unchanged\n";
                    return false;
                }
            } catch (const std::exception& e) {
                err << "state validation error: " << e.what() << '\n';
                return false;
            }

            if (declarative) {
                state.decl_cells.emplace_back(cell);
                persist_cells(state);
                persist_current_snapshot(state);
                out << "stored decl #" << state.decl_cells.size() << " (state: valid)\n";
                return true;
            }

            state.exec_cells.emplace_back(cell);
            persist_cells(state);
            persist_current_snapshot(state);
            out << "stored cell #" << state.exec_cells.size() << " (state: valid)\n";
            return true;
        }

        static void render_analysis_result_table(const analysis_result& result, bool verbose, std::ostream& os) {
            if (result.kind == analysis_kind::mca && !verbose) {
                os << "mca: " << (result.success ? "success"sv : "failed"sv) << '\n';

                if (!result.success && !result.diagnostics_text.empty()) {
                    os << result.diagnostics_text;
                    if (!result.diagnostics_text.ends_with('\n')) {
                        os << '\n';
                    }
                    return;
                }

                if (result.artifact_text.empty()) {
                    os << "artifact is empty\n";
                    return;
                }

                os << result.artifact_text;
                if (!result.artifact_text.ends_with('\n')) {
                    os << '\n';
                }
                return;
            }

            os << ("{} result:\n"
                   "  success: {}\n"
                   "  exit_code: {}\n"
                   "  source: {}\n"
                   "  artifact: {}\n"
                   "  stderr: {}\n"_format(
                           to_string(result.kind),
                           result.success ? "true"sv : "false"sv,
                           result.exit_code,
                           result.source_path.string(),
                           result.artifact_path.string(),
                           result.stderr_path.string()));

            if (result.kind != analysis_kind::diag && !result.diagnostics_text.empty()) {
                os << "diagnostics:\n";
                os << result.diagnostics_text;
                if (!result.diagnostics_text.ends_with('\n')) {
                    os << '\n';
                }
            }

            if (result.kind == analysis_kind::diag) {
                if (result.artifact_text.empty()) {
                    os << "no diagnostics\n";
                    return;
                }
                os << result.artifact_text;
                if (!result.artifact_text.ends_with('\n')) {
                    os << '\n';
                }
                return;
            }

            if (result.artifact_text.empty()) {
                os << "artifact is empty\n";
                return;
            }

            os << result.artifact_text;
            if (!result.artifact_text.ends_with('\n')) {
                os << '\n';
            }
        }

        static void render_analysis_result_json(const analysis_result& result, std::ostream& os) {
            analysis_output_record payload{};
            payload.command = std::string(to_string(result.kind));
            payload.success = result.success;
            payload.exit_code = result.exit_code;
            payload.source_path = result.source_path.string();
            payload.artifact_path = result.artifact_path.string();
            payload.stderr_path = result.stderr_path.string();
            payload.text = result.artifact_text;
            payload.clang_command = result.command;

            std::string json{};
            auto ec = glz::write_json(payload, json);
            if (ec) {
                throw std::runtime_error("failed to serialize analysis output");
            }
            os << json << '\n';
        }

        static void render_analysis_result(
                const analysis_result& result, output_mode mode, bool verbose, std::ostream& os) {
            if (mode == output_mode::json) {
                render_analysis_result_json(result, os);
                return;
            }
            render_analysis_result_table(result, verbose, os);
        }

        static bool process_analysis_command(
                std::string_view cmd,
                std::string_view command_name,
                analysis_kind kind,
                startup_config& cfg,
                repl_state& state,
                std::ostream& out,
                std::ostream& err) {
            auto arg = command_argument(cmd, command_name);
            if (!arg) {
                return false;
            }

            if (state.decl_cells.empty() && state.exec_cells.empty()) {
                err << "no stored cells available for analysis\n";
                return true;
            }

            try {
                auto request = make_analysis_request(cfg, state);
                if (!arg->empty() && *arg != "@last"sv) {
                    request.symbol = std::string(*arg);
                }
                auto result = run_analysis(request, kind);
                render_analysis_result(result, cfg.output, cfg.verbose, out);
            } catch (const std::exception& e) {
                err << "analysis error: " << e.what() << '\n';
            }

            return true;
        }

        static bool process_command(
                const std::string& line, startup_config& cfg, repl_state& state, bool& should_quit) {
            auto cmd = trim_view(line);
            if (cmd == ":quit"sv || cmd == ":q"sv) {
                should_quit = true;
                return true;
            }
            if (cmd == ":help"sv) {
                print_help(std::cout);
                return true;
            }
            if (cmd == ":clear last"sv) {
                if (state.exec_cells.empty()) {
                    std::cout << "no executable cells to clear\n";
                    return true;
                }
                state.exec_cells.pop_back();
                persist_cells(state);
                persist_current_snapshot(state);
                std::cout << "cleared last executable cell\n";
                return true;
            }
            if (cmd == ":clear"sv) {
                clear_terminal(std::cout);
                return true;
            }
            if (auto show_arg = command_argument(cmd, ":show"sv)) {
                if (show_arg->empty()) {
                    std::cerr << "invalid :show, expected config|decl|exec|all\n";
                    return true;
                }

                if (*show_arg == "config"sv) {
                    print_config(cfg, std::cout);
                    return true;
                }

                if (*show_arg == "decl"sv) {
                    print_decl_cells(state, std::cout);
                    std::cout << '\n';
                    return true;
                }

                if (*show_arg == "exec"sv) {
                    print_exec_cells(state, std::cout);
                    std::cout << '\n';
                    return true;
                }

                if (*show_arg == "all"sv || *show_arg == "code"sv || *show_arg == "cells"sv) {
                    print_all_cells(state, std::cout);
                    std::cout << '\n';
                    return true;
                }

                std::cerr << "unknown :show value: " << *show_arg << " (expected config|decl|exec|all)\n";
                return true;
            }
            if (auto decl_arg = command_argument(cmd, ":decl"sv)) {
                if (decl_arg->empty()) {
                    std::cerr << "invalid :decl, expected code after command\n";
                    return true;
                }
                (void)append_validated_cell(cfg, state, *decl_arg, true, std::cout, std::cerr);
                return true;
            }
            if (cmd == ":reset"sv) {
                state.decl_cells.clear();
                state.exec_cells.clear();
                persist_cells(state);
                persist_current_snapshot(state);
                std::cout << "session reset\n";
                return true;
            }
            if (cmd == ":snapshots"sv) {
                print_snapshots(state, std::cout);
                return true;
            }
            if (cmd == ":symbols"sv) {
                if (state.decl_cells.empty() && state.exec_cells.empty()) {
                    std::cerr << "no stored cells available for symbol listing\n";
                    return true;
                }

                try {
                    auto request = make_analysis_request(cfg, state);
                    auto symbols = list_symbols(request);
                    print_symbols(symbols, cfg.verbose, std::cout);
                } catch (const std::exception& e) {
                    std::cerr << "symbol listing error: " << e.what() << '\n';
                }
                return true;
            }
            if (cmd.starts_with(":mark "sv)) {
                auto name = trim_view(cmd.substr(6U));
                if (name.empty()) {
                    std::cerr << "invalid :mark, expected a snapshot name\n";
                    return true;
                }
                upsert_snapshot(state.snapshot_data, name, total_cell_count(state));
                persist_snapshots(state);
                std::cout << "marked snapshot '" << name << "' at cell_count=" << total_cell_count(state) << '\n';
                return true;
            }
            if (cmd.starts_with(":set "sv)) {
                auto assignment = trim_view(cmd.substr(5U));
                if (apply_set_command(cfg, assignment, std::cerr)) {
                    std::cout << "updated " << assignment << '\n';
                }
                return true;
            }
            if (process_analysis_command(cmd, ":asm"sv, analysis_kind::asm_text, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":ir"sv, analysis_kind::ir, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":diag"sv, analysis_kind::diag, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (process_analysis_command(cmd, ":mca"sv, analysis_kind::mca, cfg, state, std::cout, std::cerr)) {
                return true;
            }
            if (cmd.starts_with(":"sv)) {
                std::cerr << "unknown command: " << cmd << '\n';
                return true;
            }
            return false;
        }

        static std::optional<std::string> normalize_optional(std::string value) {
            auto trimmed = trim_view(value);
            if (trimmed.empty()) {
                return std::nullopt;
            }
            return std::string(trimmed);
        }

    }  // namespace detail

    static constexpr auto banner = R"(
███████╗ ██████╗ ███╗   ██╗████████╗ █████╗  ██████╗ 
██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ 
███████╗██║   ██║██╔██╗ ██║   ██║   ███████║██║  ███╗
╚════██║██║   ██║██║╚██╗██║   ██║   ██╔══██║██║   ██║
███████║╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╔╝
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ 
)";

    void run_repl(startup_config& cfg) {
        auto resumed_session = cfg.resume_session;
        auto state = detail::start_session(cfg);
        line_editor editor{cfg};
        std::string line{};
        std::string pending_cell{};
        detail::code_balance_state balance{};
        bool should_quit = false;

        std::cout << banner << '\n';
        if (resumed_session) {
            std::cout << "resumed session from: " << *resumed_session << '\n';
        }
        std::cout << "session: " << state.session_id << '\n';
        std::cout << "session dir: " << state.session_dir.string() << '\n';
        std::cout << "type :help for commands\n";

        while (!should_quit) {
            std::string_view prompt = pending_cell.empty() ? "sontag> "sv : "...> "sv;
            auto next_line = editor.read_line(prompt);
            if (!next_line) {
                if (!pending_cell.empty()) {
                    std::cerr << "warning: discarding incomplete cell at EOF\n";
                }
                std::cout << '\n';
                break;
            }
            line = std::move(*next_line);

            if (line.empty()) {
                if (!pending_cell.empty()) {
                    pending_cell.push_back('\n');
                }
                continue;
            }

            editor.record_history(line);

            if (pending_cell.empty() && detail::process_command(line, cfg, state, should_quit)) {
                continue;
            }

            if (!pending_cell.empty()) {
                pending_cell.push_back('\n');
            }
            pending_cell += line;
            detail::update_code_balance_state(balance, line);

            if (!detail::cell_is_complete(balance)) {
                continue;
            }

            (void)detail::append_validated_cell(cfg, state, pending_cell, false, std::cout, std::cerr);
            pending_cell.clear();
            balance = detail::code_balance_state{};
        }

        return;
    }

    std::optional<int> parse_cli(int argc, char** argv, startup_config& cfg) {
        CLI::App app{"sontag"};

        bool show_version = false;
        std::string std_arg{std::string{to_string(cfg.language_standard)}};
        std::string opt_arg{std::string{to_string(cfg.opt_level)}};
        std::string output_arg{std::string{to_string(cfg.output)}};
        std::string color_arg{std::string{to_string(cfg.color)}};
        std::string target_arg{};
        std::string cpu_arg{};
        std::string mca_cpu_arg{};
        std::string resume_arg{};
        std::string clang_arg{cfg.clang_path.string()};
        std::string mca_path_arg{cfg.mca_path.string()};
        std::string cache_dir_arg{cfg.cache_dir.string()};
        std::string history_file_arg{cfg.history_file.string()};
        bool no_history = false;

        app.add_flag("--version", show_version, "Print version and exit");
        app.add_option("--std", std_arg, "C++ standard: c++20|c++23|c++2c");
        app.add_option("-O,--opt", opt_arg, "Optimization level: O0|O1|O2|O3|Ofast|Oz");
        app.add_option("--target", target_arg, "LLVM target triple");
        app.add_option("--cpu", cpu_arg, "Target CPU");
        app.add_option("--mca-cpu", mca_cpu_arg, "CPU model override for llvm-mca");
        app.add_option("--mca-path", mca_path_arg, "llvm-mca executable path");
        app.add_flag("--mca", cfg.mca_enabled, "Enable llvm-mca command support");
        app.add_option("--resume", resume_arg, "Resume session id or latest");
        app.add_option("--clang", clang_arg, "clang++ executable path");
        app.add_option("--cache-dir", cache_dir_arg, "Cache/artifact directory");
        app.add_option("--history-file", history_file_arg, "Persistent REPL history path");
        app.add_flag("--no-history", no_history, "Disable persistent REPL history");
        app.add_option("--output", output_arg, "Output mode: table|json");
        app.add_option("--color", color_arg, "Color mode: auto|always|never");
        app.add_flag("--no-color", "Force color mode to never");
        app.add_flag("--print-config", cfg.print_config, "Print resolved config and exit");
        app.add_flag("--quiet", cfg.quiet, "Suppress non-essential output");
        app.add_flag("--verbose", cfg.verbose, "Enable verbose output");

        try {
            app.parse(argc, argv);
        } catch (const CLI::ParseError& e) {
            return std::optional<int>{app.exit(e)};
        }

        if (cfg.quiet && cfg.verbose) {
            std::cerr << "--quiet and --verbose are mutually exclusive\n";
            return std::optional<int>{2};
        }

        if (!try_parse_cxx_standard(std_arg, cfg.language_standard)) {
            std::cerr << "invalid --std value: " << std_arg << " (expected c++20|c++23|c++2c)\n";
            return std::optional<int>{2};
        }
        if (!try_parse_optimization_level(opt_arg, cfg.opt_level)) {
            std::cerr << "invalid --opt value: " << opt_arg << " (expected O0|O1|O2|O3|Ofast|Oz)\n";
            return std::optional<int>{2};
        }
        if (!try_parse_output_mode(output_arg, cfg.output)) {
            std::cerr << "invalid --output value: " << output_arg << " (expected table|json)\n";
            return std::optional<int>{2};
        }
        if (!try_parse_color_mode(color_arg, cfg.color)) {
            std::cerr << "invalid --color value: " << color_arg << " (expected auto|always|never)\n";
            return std::optional<int>{2};
        }

        cfg.target_triple = detail::normalize_optional(target_arg);
        cfg.cpu = detail::normalize_optional(cpu_arg);
        cfg.mca_cpu = detail::normalize_optional(mca_cpu_arg);
        cfg.resume_session = detail::normalize_optional(resume_arg);
        cfg.clang_path = clang_arg;
        cfg.mca_path = mca_path_arg;
        cfg.cache_dir = cache_dir_arg;
        cfg.history_file = history_file_arg;
        if (no_history) {
            cfg.history_enabled = false;
        }

        if (app.get_option("--no-color")->count() > 0U) {
            cfg.color = color_mode::never;
        }

        if (show_version) {
            std::cout << "sontag 0.1.0\n";
            return std::optional<int>{0};
        }

        if (cfg.print_config) {
            detail::print_config(cfg, std::cout);
            return std::optional<int>{0};
        }

        return std::nullopt;
    }

}  // namespace sontag::cli
