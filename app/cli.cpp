#include "cli.hpp"

#include <CLI/CLI.hpp>

#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sontag::cli {

    namespace detail {

        using namespace std::string_view_literals;

        static constexpr std::string_view trim_view(std::string_view value) {
            auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return {};
            }
            auto last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, (last - first) + 1U);
        }

        static void print_config(const startup_config& cfg, std::ostream& os) {
            os << "language_standard=" << to_string(cfg.language_standard) << '\n';
            os << "opt_level=" << to_string(cfg.opt_level) << '\n';
            os << "target=" << (cfg.target_triple ? *cfg.target_triple : "<default>") << '\n';
            os << "cpu=" << (cfg.cpu ? *cfg.cpu : "<default>") << '\n';
            os << "clang=" << cfg.clang_path.string() << '\n';
            os << "cache_dir=" << cfg.cache_dir.string() << '\n';
            os << "output=" << to_string(cfg.output) << '\n';
            os << "color=" << to_string(cfg.color) << '\n';
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
            os << "commands:\n";
            os << "  :help\n";
            os << "  :show config\n";
            os << "  :set <key>=<value>\n";
            os << "  :reset\n";
            os << "  :quit\n";
            os << "examples:\n";
            os << "  :set std=c++23\n";
            os << "  :set opt=O3\n";
            os << "  :set output=json\n";
        }

        static bool process_command(
                const std::string& line, startup_config& cfg, std::vector<std::string>& cells, bool& should_quit) {
            auto cmd = trim_view(line);
            if (cmd == ":quit"sv || cmd == ":q"sv) {
                should_quit = true;
                return true;
            }
            if (cmd == ":help"sv) {
                print_help(std::cout);
                return true;
            }
            if (cmd == ":show config"sv) {
                print_config(cfg, std::cout);
                return true;
            }
            if (cmd == ":reset"sv) {
                cells.clear();
                std::cout << "session reset\n";
                return true;
            }
            if (cmd.starts_with(":set "sv)) {
                auto assignment = trim_view(cmd.substr(5U));
                if (apply_set_command(cfg, assignment, std::cerr)) {
                    std::cout << "updated " << assignment << '\n';
                }
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

    void run_repl(startup_config& cfg) {
        std::vector<std::string> cells{};
        std::string line{};
        bool should_quit = false;

        std::cout << "sontag m0 repl\n";
        std::cout << "type :help for commands\n";

        while (!should_quit) {
            std::cout << "sontag> " << std::flush;
            if (!std::getline(std::cin, line)) {
                std::cout << '\n';
                break;
            }

            if (line.empty()) {
                continue;
            }

            if (detail::process_command(line, cfg, cells, should_quit)) {
                continue;
            }

            cells.push_back(line);
            std::cout << "stored cell #" << cells.size() << '\n';
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
        std::string clang_arg{cfg.clang_path.string()};
        std::string cache_dir_arg{cfg.cache_dir.string()};

        app.add_flag("--version", show_version, "Print version and exit");
        app.add_option("--std", std_arg, "C++ standard: c++20|c++23|c++2c");
        app.add_option("-O,--opt", opt_arg, "Optimization level: O0|O1|O2|O3|Ofast|Oz");
        app.add_option("--target", target_arg, "LLVM target triple");
        app.add_option("--cpu", cpu_arg, "Target CPU");
        app.add_option("--clang", clang_arg, "clang++ executable path");
        app.add_option("--cache-dir", cache_dir_arg, "Cache/artifact directory");
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
        cfg.clang_path = clang_arg;
        cfg.cache_dir = cache_dir_arg;

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
