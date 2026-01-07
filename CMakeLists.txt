cmake_minimum_required(VERSION 3.10)
project(fuse_quota_passthrough LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIBFUSE_DIR "${CMAKE_SOURCE_DIR}/external/libfuse/build")
set(ENV{PKG_CONFIG_PATH} "${LIBFUSE_DIR}/meson-uninstalled:$ENV{PKG_CONFIG_PATH}")

find_package(PkgConfig REQUIRED)

pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

add_executable(fusequota
	src/main.cpp
	src/operations.cpp
	src/quota.cpp
	src/socket_server.cpp
)

target_link_libraries(fusequota PRIVATE PkgConfig::FUSE3)

find_package(Threads REQUIRED)
target_link_libraries(fusequota PRIVATE Threads::Threads)
