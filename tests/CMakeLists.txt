add_subdirectory(Catch2)

add_library(tests_common STATIC utils.cpp)

target_link_libraries(
    tests_common

    PUBLIC
    sontag
    sontag_warnings
)
    

add_executable(
    alltests

    001.cpp
    002.cpp
)

target_link_libraries(alltests PRIVATE tests_common Catch2::Catch2WithMain)
