#pragma once

#include <string_view>

namespace sontag::internal::platform {
    using namespace std::string_view_literals;

    inline constexpr bool is_linux = SONTAG_PLATFORM_LINUX != 0;
    inline constexpr bool is_macos = SONTAG_PLATFORM_MACOS != 0;
    inline constexpr bool is_x86_64 = SONTAG_ARCH_X86_64 != 0;
    inline constexpr bool is_arm64 = SONTAG_ARCH_ARM64 != 0;
    inline constexpr bool mca_supported = !(is_macos && is_arm64);

    inline constexpr int clang_version_major = SONTAG_CLANG_VERSION_MAJOR;

    inline constexpr auto toolchain_bin_prefix = std::string_view{SONTAG_TOOLCHAIN_BIN_PREFIX};

    namespace tool {
        inline constexpr auto clangxx = "clang++"sv;
        inline constexpr auto llvm_nm = "llvm-nm"sv;
        inline constexpr auto llvm_objdump = "llvm-objdump"sv;
        inline constexpr auto llvm_mca = "llvm-mca"sv;
        inline constexpr auto clangxx_path = std::string_view{SONTAG_CLANG_EXECUTABLE_PATH};
        inline constexpr auto llvm_nm_path = std::string_view{SONTAG_LLVM_NM_EXECUTABLE_PATH};
        inline constexpr auto llvm_objdump_path = std::string_view{SONTAG_LLVM_OBJDUMP_EXECUTABLE_PATH};
        inline constexpr auto llvm_mca_path = std::string_view{SONTAG_LLVM_MCA_EXECUTABLE_PATH};
    }  // namespace tool

}  // namespace sontag::internal::platform
