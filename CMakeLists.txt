cmake_minimum_required(VERSION 3.13...3.25)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "sontag supports Linux only")
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(SONTAG_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(SONTAG_IS_TOPLEVEL_PROJECT FALSE)
endif()

# TODO: not configured yet for shared vs static
#option(BUILD_SHARED_LIBS "Build as shared library" OFF)
#option(BUILD_STATIC_DEPS "Build and link against static dependencies" OFF)
option(WARNINGS_AS_ERRORS "Treat all warnings as errors. turn off for development, on for release" OFF)
option(SONTAG_BUILD_TESTS "Build sontag test suite" ${SONTAG_IS_TOPLEVEL_PROJECT})
option(SONTAG_SMOKE "Build sontag smoke tests" OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(sontag
    src/analysis.cpp
    src/cli.cpp
    src/editor.cpp
)

target_include_directories(sontag PUBLIC include)
target_compile_features(sontag PUBLIC cxx_std_23)

add_subdirectory(external)

target_link_libraries(sontag 
    PUBLIC 
    glaze::glaze
    CLI11::CLI11
    linenoise::linenoise
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
