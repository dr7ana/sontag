#include "editor.hpp"

extern "C" {
#include <isocline.h>
}

#include <filesystem>
#include <string_view>

namespace sontag::cli { namespace detail {

    using namespace std::string_view_literals;

    static const char* command_completions[] = {
            ":help",
            ":clear",
            ":show",
            ":symbols",
            ":decl",
            ":set",
            ":reset",
            ":mark",
            ":snapshots",
            ":asm",
            ":dump",
            ":ir",
            ":diag",
            ":mca",
            ":quit",
            ":q",
            nullptr};

    static const char* clear_completions[] = {"last", nullptr};
    static const char* show_completions[] = {"config", "decl", "exec", "all", nullptr};
    static const char* set_completions[] = {"std", "opt", "output", "color", nullptr};
    static const char* analysis_target_completions[] = {"@last", "__sontag_repl_main", nullptr};

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
        complete_from(cenv, prefix, command_completions);
    }

    static void complete_clear_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, clear_completions);
    }

    static void complete_show_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, show_completions);
    }

    static void complete_set_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, set_completions);
    }

    static void complete_analysis_args(ic_completion_env_t* cenv, const char* prefix) {
        complete_from(cenv, prefix, analysis_target_completions);
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
        if (command == ":set"sv) {
            ic_complete_word(cenv, prefix, complete_set_args, nullptr);
            return;
        }
        if (command == ":asm"sv || command == ":dump"sv || command == ":ir"sv || command == ":diag"sv ||
            command == ":mca"sv) {
            ic_complete_word(cenv, prefix, complete_analysis_args, nullptr);
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

}  // namespace sontag::cli
