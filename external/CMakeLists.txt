include(ExternalProject)

find_package(Git)
if(GIT_FOUND)
    message(STATUS "Checking submodules")
    include(check_submodule)
    check_submodule(CLI11)
    check_submodule(glaze)
    check_submodule(isocline)
endif()

# CLI11
add_subdirectory(CLI11)

# glaze
add_subdirectory(glaze)

# isocline
# Pull in only the library target; do not build upstream sample binaries.
add_subdirectory(isocline EXCLUDE_FROM_ALL)
