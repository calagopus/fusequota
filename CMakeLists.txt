cmake_minimum_required(VERSION 3.24)
project(fuse_quota_passthrough LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(FUSEQUOTA_BUILD_TESTS "Build the fusequota test suite" OFF)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    message(STATUS "LTO/IPO is enabled")
else()
    message(STATUS "LTO/IPO not supported: ${error}")
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

string(APPEND CMAKE_EXE_LINKER_FLAGS " -static")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "${CMAKE_SOURCE_DIR}/external/libfuse/build/meson-uninstalled:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

find_library(FUSE3_STATIC_LIB 
    NAMES libfuse3.a 
    PATHS "${CMAKE_SOURCE_DIR}/external/libfuse/build/lib"
    NO_DEFAULT_PATH
)

set(FUSEQUOTA_RELEASE_COMPILE_OPTIONS
    $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:
        -O2
        -ffunction-sections
        -fdata-sections
        -fno-rtti
    >
)

add_library(fusequota_core OBJECT
    src/operations.cpp
    src/quota.cpp
    src/socket_server.cpp
)

target_include_directories(fusequota_core PUBLIC src)
target_compile_options(fusequota_core PRIVATE ${FUSEQUOTA_RELEASE_COMPILE_OPTIONS})

target_link_libraries(fusequota_core PUBLIC
    PkgConfig::FUSE3
    ${FUSE3_STATIC_LIB}
    Threads::Threads
    dl
    m
)

find_library(URING_STATIC_LIB NAMES liburing.a)
if(URING_STATIC_LIB)
    message(STATUS "Linking liburing for fuse-over-io-uring")
    target_link_libraries(fusequota_core PUBLIC ${URING_STATIC_LIB})
endif()

add_executable(fusequota src/main.cpp)

find_library(MIMALLOC_STATIC_LIB NAMES libmimalloc.a)
if(MIMALLOC_STATIC_LIB)
    message(STATUS "Linking mimalloc: ${MIMALLOC_STATIC_LIB}")
    target_link_libraries(fusequota PRIVATE
        -Wl,--whole-archive ${MIMALLOC_STATIC_LIB} -Wl,--no-whole-archive)
endif()

target_link_libraries(fusequota PRIVATE fusequota_core)

target_compile_options(fusequota PRIVATE ${FUSEQUOTA_RELEASE_COMPILE_OPTIONS})

target_link_options(fusequota PRIVATE 
    $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:
        -Wl,--gc-sections
    >
)

target_compile_definitions(fusequota PRIVATE CXXOPTS_NO_RTTI)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET fusequota POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-all -R .comment -R .note $<TARGET_FILE:fusequota>
        COMMENT "Aggressively stripping symbols from fusequota"
    )
endif()

if(FUSEQUOTA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
