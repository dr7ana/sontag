#pragma once

#include "utils.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace sontag {

    using namespace std::string_view_literals;

    /*
     * Sontag Startup Config Options
     *
     * Session and UX
     * - session_name: Human-readable label for the current session.
     * - resume_session: Session id (or "latest") to resume previous state/artifacts.
     * - cache_dir: Root directory for all session metadata and generated artifacts.
     * - history_file: Path to persisted interactive command history.
     * - history_enabled: Enable/disable persistent history writes.
     * - color_mode: ANSI color behavior for terminal output.
     * - pager_enabled: Pipe long outputs (asm/ir/diag) through a pager.
     * - output_mode: Default machine/human output shape ("table" or "json").
     * - quiet/verbose: Coarse output verbosity knobs for app logs.
     *
     * Toolchain and language mode
     * - clang_path: clang++ executable path.
     * - cxx_standard: Language standard enum selected from accepted tokens.
     * - opt_level: Optimization level used for compilation/analysis.
     * - debug_info: Debug info policy for generated objects/IR.
     * - target_triple: LLVM target triple override.
     * - cpu: Target CPU model for code generation.
     * - mattr: Target feature toggles (+feat/-feat).
     * - sysroot: Sysroot override when cross-compiling.
     * - stdlib: Requested C++ standard library implementation.
     * - resource_dir: Optional clang resource dir override.
     *
     * Preprocessor and link context
     * - include_dirs: Additional include search paths (-I).
     * - system_include_dirs: System include search paths (--isystem).
     * - defines: Preprocessor definitions (-D).
     * - undefines: Preprocessor undefinitions (-U).
     * - preinclude_headers: Headers force-included before user code.
     * - library_dirs: Link search paths (-L).
     * - libraries: Link libraries (-l), mainly for run/benchmark harnesses.
     * - linker_args: Raw linker args passed through unchanged.
     *
     * Safety and resource limits
     * - compile_timeout_ms: Max compile-time budget per analysis action.
     * - run_timeout_ms: Max wall-time budget for runtime A/B runs.
     * - max_cell_bytes: Reject over-sized code cells in the REPL.
     * - max_artifact_mb: Soft cap for generated artifact sizes.
     * - jobs: Worker concurrency for non-interactive analysis tasks.
     *
     * Analysis defaults
     * - default_symbol: Fallback symbol when commands omit a target.
     * - diag_level: Baseline diagnostics verbosity (error/warning/remark/all).
     * - remark_pass: Optional pass filter for optimization remarks.
     * - asm_syntax: Disassembly syntax flavor (intel or att).
     * - mca_enabled: Enable llvm-mca checks/commands by default.
     * - mca_cpu: Optional CPU override specifically for llvm-mca.
     * - mca_path: llvm-mca executable path override.
     *
     * A/B runtime defaults
     * - ab_iters: Default measured iteration count.
     * - ab_warmup: Default warmup iteration count.
     * - ab_min_samples: Minimum sample count before reporting.
     * - ab_confidence: Confidence interval target (for example 0.95).
     * - ab_pin_cpu: Optional CPU core id for affinity pinning.
     * - ab_seed: Deterministic seed for generated benchmark inputs.
     * - ab_input_size: Default generated fixture/input size.
     *
     * Graph defaults
     * - graph_format: Default render format (dot/svg/png).
     * - dot_path: Optional explicit Graphviz dot binary path.
     * - graph_max_nodes: Readability cap for generated graphs.
     * - graph_depth: Default traversal depth for call/type graph generation.
     * - graph_build_dir: Build directory used by :graph build (ninja -t graph).
     *
     * Introspection flags (one-shot startup actions)
     * - print_config: Print resolved startup config and exit.
     * - print_clang_version: Print detected clang/LLVM version and exit.
     * - dump_defaults: Print compiled-in defaults and exit.
     */

    enum class output_mode { table, json };
    enum class color_mode { automatic, always, never };
    enum class debug_info_level { none, line, full };
    enum class cxx_standard { cxx20, cxx23, cxx2c };
    enum class optimization_level { o0, o1, o2, o3, ofast, oz };

    inline constexpr std::string_view to_string(output_mode mode) {
        switch (mode) {
            case output_mode::table:
                return "table"sv;
            case output_mode::json:
                return "json"sv;
        }
        return "table"sv;
    }

    inline constexpr std::string_view to_string(color_mode mode) {
        switch (mode) {
            case color_mode::automatic:
                return "auto"sv;
            case color_mode::always:
                return "always"sv;
            case color_mode::never:
                return "never"sv;
        }
        return "auto"sv;
    }

    inline constexpr std::string_view to_string(cxx_standard standard) {
        switch (standard) {
            case cxx_standard::cxx20:
                return "c++20"sv;
            case cxx_standard::cxx23:
                return "c++23"sv;
            case cxx_standard::cxx2c:
                return "c++2c"sv;
        }
        return "c++23"sv;
    }

    inline constexpr bool try_parse_cxx_standard(std::string_view text, cxx_standard& out) {
        if (utils::str_case_eq(text, "c++20"sv) || utils::str_case_eq(text, "cxx20"sv)) {
            out = cxx_standard::cxx20;
            return true;
        }
        if (utils::str_case_eq(text, "c++23"sv) || utils::str_case_eq(text, "cxx23"sv)) {
            out = cxx_standard::cxx23;
            return true;
        }
        if (utils::str_case_eq(text, "c++2c"sv) || utils::str_case_eq(text, "cxx2c"sv)) {
            out = cxx_standard::cxx2c;
            return true;
        }
        return false;
    }

    inline constexpr cxx_standard parse_cxx_standard(std::string_view text) {
        cxx_standard parsed = cxx_standard::cxx23;
        if (try_parse_cxx_standard(text, parsed)) {
            return parsed;
        }
        return cxx_standard::cxx23;
    }

    inline constexpr std::string_view to_string(optimization_level level) {
        switch (level) {
            case optimization_level::o0:
                return "O0"sv;
            case optimization_level::o1:
                return "O1"sv;
            case optimization_level::o2:
                return "O2"sv;
            case optimization_level::o3:
                return "O3"sv;
            case optimization_level::ofast:
                return "Ofast"sv;
            case optimization_level::oz:
                return "Oz"sv;
        }
        return "O2"sv;
    }

    inline constexpr bool try_parse_optimization_level(std::string_view text, optimization_level& out) {
        if (utils::str_case_eq(text, "O0"sv) || utils::str_case_eq(text, "0"sv)) {
            out = optimization_level::o0;
            return true;
        }
        if (utils::str_case_eq(text, "O1"sv) || utils::str_case_eq(text, "1"sv)) {
            out = optimization_level::o1;
            return true;
        }
        if (utils::str_case_eq(text, "O2"sv) || utils::str_case_eq(text, "2"sv)) {
            out = optimization_level::o2;
            return true;
        }
        if (utils::str_case_eq(text, "O3"sv) || utils::str_case_eq(text, "3"sv)) {
            out = optimization_level::o3;
            return true;
        }
        if (utils::str_case_eq(text, "Ofast"sv) || utils::str_case_eq(text, "fast"sv)) {
            out = optimization_level::ofast;
            return true;
        }
        if (utils::str_case_eq(text, "Oz"sv) || utils::str_case_eq(text, "z"sv)) {
            out = optimization_level::oz;
            return true;
        }
        return false;
    }

    inline constexpr bool try_parse_output_mode(std::string_view text, output_mode& out) {
        if (utils::str_case_eq(text, "table"sv)) {
            out = output_mode::table;
            return true;
        }
        if (utils::str_case_eq(text, "json"sv)) {
            out = output_mode::json;
            return true;
        }
        return false;
    }

    inline constexpr bool try_parse_color_mode(std::string_view text, color_mode& out) {
        if (utils::str_case_eq(text, "auto"sv)) {
            out = color_mode::automatic;
            return true;
        }
        if (utils::str_case_eq(text, "always"sv)) {
            out = color_mode::always;
            return true;
        }
        if (utils::str_case_eq(text, "never"sv)) {
            out = color_mode::never;
            return true;
        }
        return false;
    }

    struct startup_config {
        std::optional<std::string> session_name{};
        std::optional<std::string> resume_session{};
        std::filesystem::path cache_dir{".sontag"};
        std::filesystem::path history_file{".sontag/history"};
        bool history_enabled{true};
        color_mode color{color_mode::automatic};
        bool pager_enabled{false};
        output_mode output{output_mode::table};
        bool quiet{false};
        bool verbose{false};

        std::filesystem::path clang_path{"clang++"};
        cxx_standard language_standard{cxx_standard::cxx23};
        optimization_level opt_level{optimization_level::o2};
        debug_info_level debug_info{debug_info_level::line};
        std::optional<std::string> target_triple{};
        std::optional<std::string> cpu{};
        std::vector<std::string> mattr{};
        std::optional<std::filesystem::path> sysroot{};
        std::optional<std::string> stdlib{};
        std::optional<std::filesystem::path> resource_dir{};

        std::vector<std::filesystem::path> include_dirs{};
        std::vector<std::filesystem::path> system_include_dirs{};
        std::vector<std::string> defines{};
        std::vector<std::string> undefines{};
        std::vector<std::string> preinclude_headers{};
        std::vector<std::filesystem::path> library_dirs{};
        std::vector<std::string> libraries{};
        std::vector<std::string> linker_args{};

        int compile_timeout_ms{30'000};
        int run_timeout_ms{30'000};
        std::size_t max_cell_bytes{1U << 20U};
        std::size_t max_artifact_mb{64U};
        unsigned jobs{1U};

        std::optional<std::string> default_symbol{};
        std::string diag_level{"warning"};
        std::optional<std::string> remark_pass{};
        std::string asm_syntax{"intel"};
        bool mca_enabled{false};
        std::optional<std::string> mca_cpu{};
        std::filesystem::path mca_path{"llvm-mca"};

        int ab_iters{1'000};
        int ab_warmup{100};
        int ab_min_samples{25};
        double ab_confidence{0.95};
        std::optional<int> ab_pin_cpu{};
        std::optional<std::uint64_t> ab_seed{};
        int ab_input_size{1'024};

        std::string graph_format{"png"};
        std::optional<std::filesystem::path> dot_path{};
        int graph_max_nodes{250};
        int graph_depth{3};
        std::optional<std::filesystem::path> graph_build_dir{};

        bool print_config{false};
        bool print_clang_version{false};
        bool dump_defaults{false};
    };

}  // namespace sontag
