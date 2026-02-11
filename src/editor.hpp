#pragma once

#include "sontag/config.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace sontag::cli {

    class line_editor {
      public:
        explicit line_editor(const startup_config& cfg);
        ~line_editor();

        std::optional<std::string> read_line(std::string_view prompt);
        void record_history(std::string_view line);
        void flush_history();

      private:
        std::string history_file_{};
        bool history_enabled_{true};
        bool history_dirty_{false};
    };

}  // namespace sontag::cli
