#pragma once

#include "sontag.hpp"

#include <optional>

namespace sontag::cli {

    std::optional<int> parse_cli(int argc, char** argv, startup_config& cfg);
    void run_repl(startup_config& cfg);

}  // namespace sontag::cli
