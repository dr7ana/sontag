cmake_minimum_required(VERSION 3.13...3.25)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# macOS defaults: prefer Homebrew LLVM toolchain when compilers are not explicitly provided.
if(APPLE)
    if(NOT DEFINED CMAKE_C_COMPILER)
        find_program(
            sontag_default_clang
            NAMES clang
            HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
            NO_DEFAULT_PATH
        )
        if(sontag_default_clang)
            set(CMAKE_C_COMPILER "${sontag_default_clang}" CACHE FILEPATH "Default C compiler for sontag" FORCE)
        endif()
    endif()

    if(NOT DEFINED CMAKE_CXX_COMPILER)
        find_program(
            sontag_default_clangxx
            NAMES clang++
            HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
            NO_DEFAULT_PATH
        )
        if(sontag_default_clangxx)
            set(CMAKE_CXX_COMPILER "${sontag_default_clangxx}" CACHE FILEPATH "Default CXX compiler for sontag" FORCE)
        endif()
    endif()
endif()

# If Ninja generator is selected explicitly, try to resolve ninja binary automatically.
if(CMAKE_GENERATOR STREQUAL "Ninja" AND NOT CMAKE_MAKE_PROGRAM)
    find_program(
        sontag_ninja_program
        NAMES ninja ninja-build
        HINTS /opt/homebrew/bin /usr/local/bin
    )
    if(sontag_ninja_program)
        set(CMAKE_MAKE_PROGRAM "${sontag_ninja_program}" CACHE FILEPATH "Ninja build tool" FORCE)
    endif()
endif()

set(LANGS C CXX)
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
	foreach(lang ${LANGS})
    	if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      		message(STATUS "Enabling ccache for ${lang}")
      		set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    	endif()
  endforeach()
endif()

project(sontag
    VERSION 0.1.0
    DESCRIPTION "the C++ interpreter against simply interpreting"
    LANGUAGES ${LANGS})

include(build_opts)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(SONTAG_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(SONTAG_IS_TOPLEVEL_PROJECT FALSE)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

configure_build_opts()

set(SONTAG_SOURCES
    src/analysis.cpp
    src/cli.cpp
    src/internal/editor.cpp
    src/graph.cpp
)

if(SONTAG_MCP)
    list(APPEND SONTAG_SOURCES src/mcp.cpp)
endif()

add_library(sontag ${SONTAG_SOURCES})

target_include_directories(sontag PUBLIC include)
target_compile_features(sontag PUBLIC cxx_std_23)

if(SONTAG_MCP)
    target_compile_definitions(sontag PUBLIC SONTAG_MCP)
endif()

add_subdirectory(external)

target_link_libraries(sontag 
    PUBLIC 
    glaze::glaze
    CLI11::CLI11
    isocline
)

add_executable(
    sontag_bin
    app/sontag.cpp
)
target_link_libraries(sontag_bin PRIVATE sontag)
set_target_properties(sontag_bin PROPERTIES OUTPUT_NAME sontag)

set(warning_flags -Wall -Wextra -Wno-unknown-pragmas -Wno-unused-function -Werror=vla -Wno-deprecated-declaration)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    list(APPEND warning_flags -Wno-unknown-warning-option)
endif()

if(WARNINGS_AS_ERRORS)
    list(APPEND warning_flags -Werror)
endif()

add_library(sontag_warnings INTERFACE)

target_compile_options(sontag_warnings INTERFACE "$<$<OR:$<COMPILE_LANGUAGE:CXX>,$<COMPILE_LANGUAGE:C>>:${warning_flags}>")

target_link_libraries(sontag INTERFACE sontag_warnings)

if(SONTAG_BUILD_TESTS)
    add_subdirectory(tests)
endif()

#add_library(son::tag ALIAS sontag)
