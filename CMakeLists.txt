cmake_minimum_required(VERSION 3.20)
project(fuse_quota_passthrough LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "${CMAKE_SOURCE_DIR}/external/libfuse/build/meson-uninstalled:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

add_executable(fusequota
    src/main.cpp
    src/operations.cpp
    src/quota.cpp
    src/socket_server.cpp
)

target_compile_options(fusequota PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:-O3>)

target_link_libraries(fusequota PRIVATE PkgConfig::FUSE3)

find_package(Threads REQUIRED)
target_link_libraries(fusequota PRIVATE Threads::Threads)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET fusequota POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:fusequota>
        COMMENT "Stripping symbols from fusequota"
    )
endif()
