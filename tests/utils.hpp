#pragma once

#include "sontag.hpp"

#include <catch2/catch_test_macros.hpp>
#include <glaze/glaze.hpp>

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace sontag {
    struct test_helper {
        //
    };
}  // namespace sontag

namespace sontag::test::detail {
    namespace fs = std::filesystem;
}  // namespace sontag::test::detail
