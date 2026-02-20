#pragma once

#include "sontag.hpp"

#include <catch2/catch_test_macros.hpp>
#include <glaze/glaze.hpp>

#include "../src/internal/delta.hpp"
#include "../src/internal/metrics.hpp"
#include "../src/internal/opcode.hpp"
#include "../src/internal/types.hpp"

extern "C" {
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
}

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace sontag {
    struct test_helper {
        //
    };
}  // namespace sontag

namespace sontag::test::detail {
    namespace fs = std::filesystem;
}  // namespace sontag::test::detail
