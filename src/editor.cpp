#include "editor.hpp"

#include <linenoise.h>

#include <filesystem>

namespace sontag::cli {

    line_editor::line_editor(const startup_config& cfg) :
            history_file_(cfg.history_file.string()), history_enabled_(cfg.history_enabled) {
        linenoiseSetMultiLine(1);
        linenoiseHistorySetMaxLen(1000);

        if (!history_enabled_) {
            return;
        }

        auto history_path = std::filesystem::path(history_file_);
        std::error_code ec{};
        auto parent = history_path.parent_path();
        if (!parent.empty()) {
            std::filesystem::create_directories(parent, ec);
        }
        (void)linenoiseHistoryLoad(history_file_.c_str());
    }

    line_editor::~line_editor() {
        flush_history();
    }

    std::optional<std::string> line_editor::read_line(std::string_view prompt) {
        auto prompt_text = std::string(prompt);
        auto* raw = linenoise(prompt_text.c_str());
        if (raw == nullptr) {
            return std::nullopt;
        }

        std::string line{raw};
        linenoiseFree(raw);
        return line;
    }

    void line_editor::record_history(std::string_view line) {
        if (!history_enabled_ || line.empty()) {
            return;
        }

        std::string line_copy{line};
        (void)linenoiseHistoryAdd(line_copy.c_str());
        history_dirty_ = true;
    }

    void line_editor::flush_history() {
        if (!history_enabled_ || !history_dirty_) {
            return;
        }

        (void)linenoiseHistorySave(history_file_.c_str());
        history_dirty_ = false;
    }

}  // namespace sontag::cli
