#include "quota.hpp"
#include <condition_variable>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <system_error>
#include <unordered_set>
#include "inode.hpp"

QuotaManager::~QuotaManager() {
    // jthread automatically requests stop and joins on destruction
}

void QuotaManager::init(const std::string &source_path, uint64_t limit, int rescan_seconds) {
    source_dir = source_path;
    quota_limit = limit;
    rescan_interval = std::chrono::seconds(rescan_seconds);
    enabled = true;

    calculate_usage(std::stop_token{});

    if (rescan_interval.count() > 0) {
        std::println("QUOTA: Starting background rescan thread (Interval: {}s)", rescan_seconds);
        scanner_thread = std::jthread(std::bind_front(&QuotaManager::background_scanner, this));
    }
}

namespace {

struct UsageScan {
    std::stop_token st;
    std::unordered_set<SrcId> seen_inodes;
    uint64_t total = 0;

    bool scan(int parent_fd, const char *name) {
        int fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd == -1) {
            // Entries can vanish between readdir and open while the tree is live
            if (parent_fd != AT_FDCWD && (errno == ENOENT || errno == ENOTDIR || errno == ELOOP))
                return true;
            throw std::system_error(errno, std::generic_category(), name);
        }

        DIR *dp = fdopendir(fd);
        if (!dp) {
            int saved = errno;
            close(fd);
            throw std::system_error(saved, std::generic_category(), name);
        }
        struct DirCloser {
            DIR *dp;
            ~DirCloser() {
                closedir(dp);
            }
        } closer{dp};

        while (true) {
            if (st.stop_requested())
                return false;

            errno = 0;
            struct dirent *entry = readdir(dp);
            if (!entry) {
                if (errno)
                    throw std::system_error(errno, std::generic_category(), name);
                return true;
            }
            std::string_view entry_name{entry->d_name};
            if (entry_name == "." || entry_name == "..")
                continue;

            struct stat file_stat;
            if (fstatat(fd, entry->d_name, &file_stat, AT_SYMLINK_NOFOLLOW) != 0)
                continue;

            if (file_stat.st_nlink > 1 && !S_ISDIR(file_stat.st_mode)) {
                SrcId id{file_stat.st_ino, file_stat.st_dev};
                if (!seen_inodes.insert(id).second)
                    continue;
            }

            if (S_ISREG(file_stat.st_mode) || S_ISDIR(file_stat.st_mode) ||
                S_ISLNK(file_stat.st_mode)) {
                total += file_stat.st_blocks * 512;
            }

            if (S_ISDIR(file_stat.st_mode) && !scan(fd, entry->d_name))
                return false;
        }
    }
};

} // namespace

void QuotaManager::calculate_usage(std::stop_token st) {
    try {
        UsageScan usage_scan{.st = st};
        if (!usage_scan.scan(AT_FDCWD, source_dir.c_str()))
            return;
        uint64_t total = usage_scan.total;

        uint64_t tracked = used_bytes.load();
        if (total != tracked) {
            if (total > tracked) {
                uint64_t correction = total - tracked;
                used_bytes.fetch_add(correction);
            } else {
                uint64_t correction = tracked - total;
                uint64_t current = used_bytes.load();
                while (true) {
                    uint64_t next = (correction > current) ? 0 : (current - correction);
                    if (used_bytes.compare_exchange_weak(current, next))
                        break;
                }
            }

            uint64_t corrected = used_bytes.load();
            int64_t diff = static_cast<int64_t>(corrected) - static_cast<int64_t>(tracked);
            if (std::abs(diff) > 1024 * 1024) {
                std::println("QUOTA RESCAN: Corrected usage drift. Was: {}, Now: {} (Delta: {})",
                             tracked, corrected, diff);
            }
        }
    } catch (const std::exception &e) {
        std::println(stderr, "QUOTA ERROR: Failed to scan source directory: {}", e.what());
    }
}

void QuotaManager::background_scanner(std::stop_token st) {
    std::mutex mtx;
    std::condition_variable_any cv;

    while (!st.stop_requested()) {
        std::unique_lock lock(mtx);

        bool stop_now =
            cv.wait_for(lock, st, rescan_interval, [&st] { return st.stop_requested(); });

        if (stop_now) {
            break;
        }

        calculate_usage(st);
    }
}

bool QuotaManager::reserve_bytes(uint64_t bytes) {
    if (!enabled || bytes == 0)
        return true;

    uint64_t limit = quota_limit.load(std::memory_order_relaxed);
    uint64_t prev = used_bytes.fetch_add(bytes, std::memory_order_relaxed);
    if (limit != 0 && prev + bytes > limit) {
        release_bytes(bytes);
        return false;
    }
    return true;
}

void QuotaManager::release_bytes(uint64_t bytes) {
    if (!enabled || bytes == 0)
        return;

    uint64_t current_usage = used_bytes.load(std::memory_order_relaxed);
    while (true) {
        uint64_t next_usage = (bytes > current_usage) ? 0 : (current_usage - bytes);
        if (used_bytes.compare_exchange_weak(current_usage, next_usage, std::memory_order_relaxed))
            break;
    }
}

bool QuotaManager::reserve(uint64_t current_file_size, uint64_t new_file_size) {
    if (new_file_size <= current_file_size)
        return true;
    return reserve_bytes(new_file_size - current_file_size);
}

void QuotaManager::release(uint64_t current_file_size, uint64_t new_file_size) {
    if (new_file_size >= current_file_size)
        return;
    release_bytes(current_file_size - new_file_size);
}

bool QuotaManager::check_available(uint64_t bytes) const {
    if (!enabled)
        return true;
    uint64_t limit = quota_limit.load(std::memory_order_relaxed);
    if (limit == 0)
        return true;
    return used_bytes.load(std::memory_order_relaxed) + bytes <= limit;
}
