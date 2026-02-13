#pragma once

#include "sontag/config.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace sontag::cli {

    class line_editor {
      public:
        explicit line_editor(const startup_config& cfg);

        std::optional<std::string> read_line(std::string_view prompt);
    };

}  // namespace sontag::cli
