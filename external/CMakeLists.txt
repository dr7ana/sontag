include(ExternalProject)

find_package(Git)
if(GIT_FOUND)
    message(STATUS "Checking submodules")
    include(check_submodule)
    check_submodule(CLI11)
    check_submodule(glaze)
    check_submodule(linenoise)
endif()

# CLI11
add_subdirectory(CLI11)

# glaze
add_subdirectory(glaze)

# linenoise
add_library(linenoise STATIC linenoise/linenoise.c)
target_include_directories(linenoise PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/linenoise)
add_library(linenoise::linenoise ALIAS linenoise)
