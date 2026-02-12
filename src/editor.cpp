#include "editor.hpp"

extern "C" {
#include <isocline.h>
}

#include <filesystem>

namespace sontag::cli {

    namespace fs = std::filesystem;

    line_editor::line_editor(const startup_config& cfg) {
        ic_enable_multiline(true);
        ic_enable_multiline_indent(true);
        ic_enable_history_duplicates(false);
        ic_set_prompt_marker("", "");

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
