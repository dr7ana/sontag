#pragma once

#include <string_view>

using namespace std::string_view_literals;

namespace sontag::internal::platform {

    inline constexpr bool is_linux = SONTAG_PLATFORM_LINUX != 0;
    inline constexpr bool is_macos = SONTAG_PLATFORM_MACOS != 0;
    inline constexpr bool is_x86_64 = SONTAG_ARCH_X86_64 != 0;
    inline constexpr bool is_arm64 = SONTAG_ARCH_ARM64 != 0;

    inline constexpr int clang_version_major = SONTAG_CLANG_VERSION_MAJOR;

    inline constexpr std::string_view toolchain_bin_prefix{SONTAG_TOOLCHAIN_BIN_PREFIX};

    namespace tool {
        inline constexpr auto clangxx = "clang++"sv;
        inline constexpr auto llvm_nm = "llvm-nm"sv;
        inline constexpr auto llvm_objdump = "llvm-objdump"sv;
        inline constexpr auto llvm_mca = "llvm-mca"sv;
    }  // namespace tool

}  // namespace sontag::internal::platform
