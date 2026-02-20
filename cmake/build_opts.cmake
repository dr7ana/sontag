function(configure_build_opts)
    option(WARNINGS_AS_ERRORS "Treat all warnings as errors. turn off for development, on for release" OFF)
    option(SONTAG_BUILD_TESTS "Build sontag test suite" ${SONTAG_IS_TOPLEVEL_PROJECT})
    option(SONTAG_SMOKE "Build sontag smoke tests" OFF)
    option(SONTAG_USE_LIBCXX "Build C++ targets with libc++ instead of libstdc++ when using clang" ON)
    set(SONTAG_TOOLCHAIN_BIN_DIR "" CACHE PATH
        "Optional override for LLVM toolchain bin directory (used to resolve llvm-* tools)")

    set(SONTAG_PLATFORM_LINUX 0)
    set(SONTAG_PLATFORM_MACOS 0)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(SONTAG_PLATFORM_LINUX 1)
    elseif(APPLE)
        set(SONTAG_PLATFORM_MACOS 1)
    else()
        message(FATAL_ERROR "sontag supports Linux and macOS only")
    endif()

    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" sontag_target_arch_raw)
    set(SONTAG_ARCH_X86_64 0)
    set(SONTAG_ARCH_ARM64 0)

    if(sontag_target_arch_raw MATCHES "^(x86_64|amd64)$")
        set(SONTAG_ARCH_X86_64 1)
    elseif(sontag_target_arch_raw MATCHES "^(aarch64|arm64)$")
        set(SONTAG_ARCH_ARM64 1)
    else()
        message(FATAL_ERROR "unsupported target architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    add_compile_definitions(
        SONTAG_PLATFORM_LINUX=${SONTAG_PLATFORM_LINUX}
        SONTAG_PLATFORM_MACOS=${SONTAG_PLATFORM_MACOS}
        SONTAG_ARCH_X86_64=${SONTAG_ARCH_X86_64}
        SONTAG_ARCH_ARM64=${SONTAG_ARCH_ARM64}
    )

    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        if(SONTAG_PLATFORM_MACOS AND CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
            message(FATAL_ERROR
                "sontag requires Homebrew clang >= 20 (AppleClang is unsupported). "
                "Configure with -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang "
                "-DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++")
        endif()
        message(FATAL_ERROR "sontag requires clang >= 20")
    endif()

    if(SONTAG_PLATFORM_MACOS)
        if(EXISTS "/usr/bin/ar")
            set(CMAKE_AR "/usr/bin/ar" CACHE FILEPATH "Archive tool for static libraries" FORCE)
            set(CMAKE_C_COMPILER_AR "/usr/bin/ar" CACHE FILEPATH "C archive tool" FORCE)
            set(CMAKE_CXX_COMPILER_AR "/usr/bin/ar" CACHE FILEPATH "CXX archive tool" FORCE)
        endif()
        if(EXISTS "/usr/bin/ranlib")
            set(CMAKE_RANLIB "/usr/bin/ranlib" CACHE FILEPATH "ranlib tool for static libraries" FORCE)
            set(CMAKE_C_COMPILER_RANLIB "/usr/bin/ranlib" CACHE FILEPATH "C ranlib tool" FORCE)
            set(CMAKE_CXX_COMPILER_RANLIB "/usr/bin/ranlib" CACHE FILEPATH "CXX ranlib tool" FORCE)
        endif()
        message(STATUS
            "sontag archive tools: "
            "ar=${CMAKE_AR}, ranlib=${CMAKE_RANLIB}, "
            "c_ar=${CMAKE_C_COMPILER_AR}, cxx_ar=${CMAKE_CXX_COMPILER_AR}, "
            "c_ranlib=${CMAKE_C_COMPILER_RANLIB}, cxx_ranlib=${CMAKE_CXX_COMPILER_RANLIB}")
    endif()

    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 20.0)
        if(SONTAG_PLATFORM_MACOS)
            message(FATAL_ERROR
                "sontag requires clang >= 20, found ${CMAKE_CXX_COMPILER_VERSION}. "
                "Use Homebrew LLVM: -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang "
                "-DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++")
        endif()
        message(FATAL_ERROR "sontag requires clang >= 20, found ${CMAKE_CXX_COMPILER_VERSION}")
    endif()

    string(REPLACE "." ";" sontag_clang_version_parts "${CMAKE_CXX_COMPILER_VERSION}")
    list(GET sontag_clang_version_parts 0 sontag_clang_version_major)

    get_filename_component(sontag_clang_bin_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(sontag_toolchain_bin_dir_resolved "")
    if(SONTAG_TOOLCHAIN_BIN_DIR)
        if(EXISTS "${SONTAG_TOOLCHAIN_BIN_DIR}" AND IS_DIRECTORY "${SONTAG_TOOLCHAIN_BIN_DIR}")
            set(sontag_toolchain_bin_dir_resolved "${SONTAG_TOOLCHAIN_BIN_DIR}")
        else()
            message(FATAL_ERROR
                "SONTAG_TOOLCHAIN_BIN_DIR is not a valid directory: ${SONTAG_TOOLCHAIN_BIN_DIR}")
        endif()
    endif()

    if(NOT sontag_toolchain_bin_dir_resolved)
        if(SONTAG_PLATFORM_MACOS AND EXISTS "/opt/homebrew/opt/llvm/bin")
            set(sontag_toolchain_bin_dir_resolved "/opt/homebrew/opt/llvm/bin")
        elseif(SONTAG_PLATFORM_MACOS AND EXISTS "/usr/local/opt/llvm/bin")
            set(sontag_toolchain_bin_dir_resolved "/usr/local/opt/llvm/bin")
        else()
            set(sontag_toolchain_bin_dir_resolved "${sontag_clang_bin_dir}")
        endif()
    endif()

    set(sontag_clang_candidate "${sontag_toolchain_bin_dir_resolved}/clang++")
    if(NOT EXISTS "${sontag_clang_candidate}")
        set(sontag_clang_candidate "${sontag_toolchain_bin_dir_resolved}/clang++-${sontag_clang_version_major}")
    endif()
    if(NOT EXISTS "${sontag_clang_candidate}")
        message(FATAL_ERROR
            "required clang++ executable not found in toolchain bin dir: ${sontag_toolchain_bin_dir_resolved}")
    endif()

    set(sontag_llvm_mca_candidate "${sontag_toolchain_bin_dir_resolved}/llvm-mca-${sontag_clang_version_major}")
    if(NOT EXISTS "${sontag_llvm_mca_candidate}")
        set(sontag_llvm_mca_candidate "${sontag_toolchain_bin_dir_resolved}/llvm-mca")
    endif()
    if(NOT EXISTS "${sontag_llvm_mca_candidate}")
        message(FATAL_ERROR
            "required llvm-mca executable not found in toolchain bin dir: ${sontag_toolchain_bin_dir_resolved}")
    endif()

    set(sontag_llvm_objdump_candidate "${sontag_toolchain_bin_dir_resolved}/llvm-objdump-${sontag_clang_version_major}")
    if(NOT EXISTS "${sontag_llvm_objdump_candidate}")
        set(sontag_llvm_objdump_candidate "${sontag_toolchain_bin_dir_resolved}/llvm-objdump")
    endif()
    if(NOT EXISTS "${sontag_llvm_objdump_candidate}")
        message(FATAL_ERROR
            "required llvm-objdump executable not found in toolchain bin dir: ${sontag_toolchain_bin_dir_resolved}")
    endif()

    set(sontag_llvm_nm_candidate "${sontag_toolchain_bin_dir_resolved}/llvm-nm-${sontag_clang_version_major}")
    if(NOT EXISTS "${sontag_llvm_nm_candidate}")
        set(sontag_llvm_nm_candidate "${sontag_toolchain_bin_dir_resolved}/llvm-nm")
    endif()
    if(NOT EXISTS "${sontag_llvm_nm_candidate}")
        message(FATAL_ERROR
            "required llvm-nm executable not found in toolchain bin dir: ${sontag_toolchain_bin_dir_resolved}")
    endif()

    set(SONTAG_TOOLCHAIN_BIN_DIR_RESOLVED "${sontag_toolchain_bin_dir_resolved}" CACHE PATH
        "resolved LLVM toolchain binary directory used by sontag" FORCE)
    set(SONTAG_CLANG_EXECUTABLE "${sontag_clang_candidate}" CACHE FILEPATH
        "clang++ executable path used by sontag" FORCE)
    set(SONTAG_CLANG_VERSION_MAJOR "${sontag_clang_version_major}" CACHE STRING
        "clang major version used by sontag" FORCE)
    set(SONTAG_LLVM_MCA_EXECUTABLE "${sontag_llvm_mca_candidate}" CACHE FILEPATH
        "llvm-mca executable path used by sontag" FORCE)
    set(SONTAG_LLVM_OBJDUMP_EXECUTABLE "${sontag_llvm_objdump_candidate}" CACHE FILEPATH
        "llvm-objdump executable path used by sontag" FORCE)
    set(SONTAG_LLVM_NM_EXECUTABLE "${sontag_llvm_nm_candidate}" CACHE FILEPATH
        "llvm-nm executable path used by sontag" FORCE)

    set(sontag_toolchain_bin_dir_resolved_escaped "${sontag_toolchain_bin_dir_resolved}")
    string(REPLACE "\\" "\\\\" sontag_toolchain_bin_dir_resolved_escaped "${sontag_toolchain_bin_dir_resolved_escaped}")
    string(REPLACE "\"" "\\\"" sontag_toolchain_bin_dir_resolved_escaped "${sontag_toolchain_bin_dir_resolved_escaped}")

    set(sontag_clang_candidate_escaped "${sontag_clang_candidate}")
    string(REPLACE "\\" "\\\\" sontag_clang_candidate_escaped "${sontag_clang_candidate_escaped}")
    string(REPLACE "\"" "\\\"" sontag_clang_candidate_escaped "${sontag_clang_candidate_escaped}")

    set(sontag_llvm_mca_candidate_escaped "${sontag_llvm_mca_candidate}")
    string(REPLACE "\\" "\\\\" sontag_llvm_mca_candidate_escaped "${sontag_llvm_mca_candidate_escaped}")
    string(REPLACE "\"" "\\\"" sontag_llvm_mca_candidate_escaped "${sontag_llvm_mca_candidate_escaped}")

    set(sontag_llvm_objdump_candidate_escaped "${sontag_llvm_objdump_candidate}")
    string(REPLACE "\\" "\\\\" sontag_llvm_objdump_candidate_escaped "${sontag_llvm_objdump_candidate_escaped}")
    string(REPLACE "\"" "\\\"" sontag_llvm_objdump_candidate_escaped "${sontag_llvm_objdump_candidate_escaped}")

    set(sontag_llvm_nm_candidate_escaped "${sontag_llvm_nm_candidate}")
    string(REPLACE "\\" "\\\\" sontag_llvm_nm_candidate_escaped "${sontag_llvm_nm_candidate_escaped}")
    string(REPLACE "\"" "\\\"" sontag_llvm_nm_candidate_escaped "${sontag_llvm_nm_candidate_escaped}")

    add_compile_definitions(
        SONTAG_COMPILER_CLANG=1
        SONTAG_CLANG_VERSION_MAJOR=${sontag_clang_version_major}
        SONTAG_TOOLCHAIN_BIN_PREFIX="${sontag_toolchain_bin_dir_resolved_escaped}"
        SONTAG_CLANG_EXECUTABLE_PATH="${sontag_clang_candidate_escaped}"
        SONTAG_LLVM_MCA_EXECUTABLE_PATH="${sontag_llvm_mca_candidate_escaped}"
        SONTAG_LLVM_OBJDUMP_EXECUTABLE_PATH="${sontag_llvm_objdump_candidate_escaped}"
        SONTAG_LLVM_NM_EXECUTABLE_PATH="${sontag_llvm_nm_candidate_escaped}"
    )

    message(STATUS
        "Using ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} at ${CMAKE_CXX_COMPILER}")
    if(SONTAG_TOOLCHAIN_BIN_DIR)
        message(STATUS "sontag toolchain bin dir override: ${SONTAG_TOOLCHAIN_BIN_DIR}")
    endif()
    message(STATUS "sontag toolchain bin dir resolved: ${SONTAG_TOOLCHAIN_BIN_DIR_RESOLVED}")
    message(STATUS "sontag clang executable: ${SONTAG_CLANG_EXECUTABLE}")
    message(STATUS "sontag llvm-mca executable: ${SONTAG_LLVM_MCA_EXECUTABLE}")
    message(STATUS "sontag llvm-objdump executable: ${SONTAG_LLVM_OBJDUMP_EXECUTABLE}")
    message(STATUS "sontag llvm-nm executable: ${SONTAG_LLVM_NM_EXECUTABLE}")

    if(SONTAG_USE_LIBCXX)
        add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>")
        add_link_options("$<$<LINK_LANGUAGE:CXX>:-stdlib=libc++>")

        if(SONTAG_PLATFORM_MACOS)
            get_filename_component(sontag_toolchain_root "${sontag_toolchain_bin_dir_resolved}" DIRECTORY)
            set(sontag_libcxx_lib_dir "${sontag_toolchain_root}/lib/c++")

            if(EXISTS "${sontag_libcxx_lib_dir}/libc++.dylib")
                add_link_options(
                    "$<$<LINK_LANGUAGE:CXX>:-L${sontag_libcxx_lib_dir}>"
                    "$<$<LINK_LANGUAGE:CXX>:-Wl,-rpath,${sontag_libcxx_lib_dir}>"
                )
                message(STATUS "sontag libc++ runtime dir: ${sontag_libcxx_lib_dir}")
            else()
                message(WARNING
                    "Homebrew libc++ runtime not found at ${sontag_libcxx_lib_dir}; "
                    "linking will fall back to system default runtime paths.")
            endif()
        endif()
    else()
        message(FATAL_ERROR "sontag currently requires libc++; set -DSONTAG_USE_LIBCXX=ON")
    endif()
endfunction()
