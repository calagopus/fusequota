include(FetchContent)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)

FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.18.0
    GIT_SHALLOW TRUE
    FIND_PACKAGE_ARGS NAMES GTest
)

set(FUSEQUOTA_SAVED_IPO ${CMAKE_INTERPROCEDURAL_OPTIMIZATION})
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
FetchContent_MakeAvailable(googletest)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ${FUSEQUOTA_SAVED_IPO})

add_executable(fusequota_tests
    unique_fd_test.cpp
    quota_manager_test.cpp
    socket_server_test.cpp
    mount_test.cpp
)

target_link_libraries(fusequota_tests PRIVATE
    fusequota_core
    GTest::gtest_main
)

add_dependencies(fusequota_tests fusequota)
target_compile_definitions(fusequota_tests PRIVATE
    FUSEQUOTA_BIN="$<TARGET_FILE:fusequota>"
)

include(GoogleTest)
gtest_discover_tests(fusequota_tests
    TEST_FILTER "-Mount*"
    PROPERTIES LABELS unit
)
gtest_discover_tests(fusequota_tests
    TEST_FILTER "Mount*"
    PROPERTIES LABELS integration
    DISCOVERY_TIMEOUT 30
)
