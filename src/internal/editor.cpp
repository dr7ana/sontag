#include "editor.hpp"

extern "C" {
#include <isocline.h>
#include <sys/ioctl.h>
#include <unistd.h>
}

#include <array>
#include <filesystem>
#include <string_view>

namespace sontag::cli { namespace detail {

    using namespace std::string_view_literals;

    static std::array<const char*, 23> command_completions{
            ":help",   ":clear", ":show",    ":symbols",   ":decl", ":declfile", ":file", ":openfile",
            ":config", ":reset", ":mark",    ":snapshots", ":asm",  ":dump",     ":ir",   ":diag",
            ":mca",    ":delta", ":inspect", ":graph",     ":quit", ":q",        nullptr};

    static std::array<const char*, 2> clear_completions{"last", nullptr};
    static std::array<const char*, 4> reset_completions{"last", "snapshots", "file", nullptr};
    static std::array<const char*, 5> show_completions{"config", "decl", "exec", "all", nullptr};
    static std::array<const char*, 20> config_completions{
            "build",
            "ui",
            "session",
            "editor",
            "reset",
            "build.std=",
            "build.opt=",
            "build.target=",
            "build.cpu=",
            "build.clang=",
            "build.mca_cpu=",
            "build.mca_path=",
            "ui.output=",
            "ui.color=",
            "ui.color_scheme=",
            "session.cache_dir=",
            "session.history_file=",
            "editor.editor=",
            "editor.formatter=",
            nullptr};
    static std::array<const char*, 4> graph_completions{"cfg", "call", "defuse", nullptr};
    static std::array<const char*, 3> inspect_completions{"asm", "mca", nullptr};
    static std::array<const char*, 3> inspect_mca_completions{"summary", "heatmap", nullptr};
    static std::array<const char*, 3> analysis_target_completions{"@last", "__sontag_main", nullptr};
    static std::array<const char*, 10> delta_completions{
            "spectrum", "O0", "O1", "O2", "O3", "Ofast", "Oz", "@last", "__sontag_main", nullptr};

    static constexpr std::string_view trim_left(std::string_view value) {
        auto start = value.find_first_not_of(" \t\r\n");
        if (start == std::string_view::npos) {
            return {};
        }
        return value.substr(start);
    }

    static constexpr std::string_view first_token(std::string_view value) {
        auto end = value.find_first_of(" \t\r\n");
        if (end == std::string_view::npos) {
            return value;
        }
        return value.substr(0, end);
    }

    static bool is_command_char(const char* s, long len) {
        if (len == 1 && s[0] == ':') {
            return true;
        }
        return ic_char_is_idletter(s, len);
    }

    static void complete_from(ic_completion_env_t* cenv, const char* prefix, const char** completions) {
        (void)ic_add_completions(cenv, prefix, completions);
    }

    static void complete_commands(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, command_completions.data());
    }

    static void complete_clear_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, clear_completions.data());
    }

    static void complete_reset_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, reset_completions.data());
    }

    static void complete_show_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, show_completions.data());
    }

    static void complete_config_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, config_completions.data());
    }

    static void complete_graph_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, graph_completions.data());
    }

    static void complete_inspect_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, inspect_completions.data());
    }

    static void complete_inspect_mca_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, inspect_mca_completions.data());
    }

    static void complete_analysis_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, analysis_target_completions.data());
    }

    static void complete_delta_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, delta_completions.data());
    }

    static void complete_menu_word_items(ic_completion_env_t* cenv, const char* word) {
        auto* completions = static_cast<const char**>(ic_completion_arg(cenv));
        if (completions == nullptr) {
            return;
        }
        complete_from(cenv, word, completions);
    }

    static void complete_menu_items(ic_completion_env_t* cenv, const char* prefix) {
        ic_complete_word(cenv, prefix, complete_menu_word_items, nullptr);
    }

    static void trigger_menu_completion_once() {
#ifdef TIOCSTI
        if (::isatty(STDIN_FILENO) != 1) {
            return;
        }
        char tab = '\t';
        (void)::ioctl(STDIN_FILENO, TIOCSTI, &tab);
#endif
    }

    static void complete_repl(ic_completion_env_t* cenv, const char* prefix) {
        if (prefix == nullptr) {
            return;
        }

        auto trimmed = trim_left(std::string_view{prefix});
        if (trimmed.empty()) {
            ic_complete_word(cenv, prefix, complete_commands, is_command_char);
            return;
        }

        if (!trimmed.starts_with(':')) {
            return;
        }

        auto command = first_token(trimmed);
        auto has_args = command.size() < trimmed.size();
        if (!has_args) {
            ic_complete_word(cenv, prefix, complete_commands, is_command_char);
            return;
        }

        if (command == ":clear"sv) {
            ic_complete_word(cenv, prefix, complete_clear_args, nullptr);
            return;
        }
        if (command == ":show"sv) {
            ic_complete_word(cenv, prefix, complete_show_args, nullptr);
            return;
        }
        if (command == ":config"sv) {
            ic_complete_word(cenv, prefix, complete_config_args, nullptr);
            return;
        }
        if (command == ":reset"sv) {
            ic_complete_word(cenv, prefix, complete_reset_args, nullptr);
            return;
        }
        if (command == ":graph"sv) {
            auto rest = trim_left(trimmed.substr(command.size()));
            auto graph_subcommand = first_token(rest);
            auto has_graph_arg = graph_subcommand.size() < rest.size();
            if ((graph_subcommand == "cfg"sv || graph_subcommand == "call"sv || graph_subcommand == "defuse"sv) &&
                has_graph_arg) {
                ic_complete_word(cenv, prefix, complete_analysis_args, nullptr);
                return;
            }
            ic_complete_word(cenv, prefix, complete_graph_args, nullptr);
            return;
        }
        if (command == ":inspect"sv) {
            auto rest = trim_left(trimmed.substr(command.size()));
            auto inspect_subcommand = first_token(rest);
            if (inspect_subcommand == "asm"sv) {
                auto has_asm_arg = inspect_subcommand.size() < rest.size();
                if (has_asm_arg) {
                    ic_complete_word(cenv, prefix, complete_analysis_args, nullptr);
                    return;
                }
                ic_complete_word(cenv, prefix, complete_inspect_args, nullptr);
                return;
            }
            if (inspect_subcommand == "mca"sv) {
                auto mca_rest = trim_left(rest.substr(inspect_subcommand.size()));
                auto mca_subcommand = first_token(mca_rest);
                auto has_mca_arg = mca_subcommand.size() < mca_rest.size();
                if ((mca_subcommand == "summary"sv || mca_subcommand == "heatmap"sv) && has_mca_arg) {
                    ic_complete_word(cenv, prefix, complete_analysis_args, nullptr);
                    return;
                }
                if (mca_subcommand.empty()) {
                    ic_complete_word(cenv, prefix, complete_inspect_mca_args, nullptr);
                    return;
                }
                ic_complete_word(cenv, prefix, complete_analysis_args, nullptr);
                return;
            }
            ic_complete_word(cenv, prefix, complete_inspect_args, nullptr);
            return;
        }
        if (command == ":asm"sv || command == ":dump"sv || command == ":ir"sv || command == ":diag"sv ||
            command == ":mca"sv) {
            ic_complete_word(cenv, prefix, complete_analysis_args, nullptr);
            return;
        }
        if (command == ":delta"sv) {
            ic_complete_word(cenv, prefix, complete_delta_args, nullptr);
            return;
        }
    }

}}  // namespace sontag::cli::detail

namespace sontag::cli {

    namespace fs = std::filesystem;

    line_editor::line_editor(const startup_config& cfg) {
        ic_enable_multiline(true);
        ic_enable_multiline_indent(true);
        ic_enable_history_duplicates(false);
        ic_set_prompt_marker("", "");
        ic_set_default_completer(detail::complete_repl, nullptr);

        switch (cfg.color) {
            case color_mode::automatic:
                break;
            case color_mode::always:
                ic_enable_color(true);
                break;
            case color_mode::never:
                ic_enable_color(false);
                break;
        }

        if (!cfg.history_enabled) {
            ic_set_history(nullptr, 1000);
            return;
        }

        std::error_code ec{};
        auto history_parent = cfg.history_file.parent_path();
        if (!history_parent.empty()) {
            fs::create_directories(history_parent, ec);
        }

        auto history_file = cfg.history_file.string();
        ic_set_history(history_file.c_str(), 1000);
    }

    std::optional<std::string> line_editor::read_line(std::string_view prompt) {
        auto prompt_text = std::string(prompt);
        auto* raw = ic_readline(prompt_text.c_str());
        if (raw == nullptr) {
            return std::nullopt;
        }

        std::string line{raw};
        ic_free(raw);
        return line;
    }

    std::optional<std::string> line_editor::read_menu_line(std::string_view prompt, const char** completions) {
        auto prompt_text = std::string(prompt);
        auto previous_auto_tab = ic_enable_auto_tab(false);
        auto previous_hint = ic_enable_hint(false);
        detail::trigger_menu_completion_once();
        auto* raw = ic_readline_ex(prompt_text.c_str(), detail::complete_menu_items, completions, nullptr, nullptr);
        (void)ic_enable_hint(previous_hint);
        (void)ic_enable_auto_tab(previous_auto_tab);
        if (raw == nullptr) {
            return std::nullopt;
        }

        std::string line{raw};
        ic_free(raw);
        return line;
    }

}  // namespace sontag::cli
