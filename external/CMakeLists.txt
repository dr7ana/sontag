include(ExternalProject)

find_package(Git)
if(GIT_FOUND)
    message(STATUS "Checking submodules")
    include(check_submodule)
    check_submodule(CLI11)
    check_submodule(glaze)
endif()

# CLI11
add_subdirectory(CLI11)

# glaze
add_subdirectory(glaze)

