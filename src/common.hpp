#pragma once

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 14)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fuse_lowlevel.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <pthread.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

class UniqueFd
{
public:
	UniqueFd() = default;
	explicit UniqueFd(int fd) : fd_(fd) {}
	UniqueFd(const UniqueFd &) = delete;
	UniqueFd &operator=(const UniqueFd &) = delete;
	UniqueFd(UniqueFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
	UniqueFd &operator=(UniqueFd &&other) noexcept
	{
		if (this != &other)
			reset(std::exchange(other.fd_, -1));
		return *this;
	}
	~UniqueFd() { reset(); }

	void reset(int new_fd = -1)
	{
		if (fd_ >= 0)
			::close(fd_);
		fd_ = new_fd;
	}
	[[nodiscard]] int get() const { return fd_; }
	[[nodiscard]] bool is_valid() const { return fd_ >= 0; }
	int release() { return std::exchange(fd_, -1); }
	operator int() const { return fd_; }

private:
	int fd_ = -1;
};

struct Fs;
extern Fs fs;

template <typename... Args>
void debug_print(std::format_string<Args...> fmt, Args &&...args);

template <typename... Args>
void error_print(std::format_string<Args...> fmt, Args &&...args)
{
	std::println(stderr, "ERROR: {}", std::format(fmt, std::forward<Args>(args)...));
}