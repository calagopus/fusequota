#include "quota.hpp"
#include <condition_variable>
#include <mutex>
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

void QuotaManager::calculate_usage(std::stop_token st) {
    namespace fsys = std::filesystem;

    std::unordered_set<SrcId> seen_inodes;
    uint64_t total = 0;

    try {
        for (const auto &entry : fsys::recursive_directory_iterator(source_dir)) {
            if (st.stop_requested()) {
                return;
            }

            struct stat file_stat;
            if (lstat(entry.path().c_str(), &file_stat) != 0)
                continue;

            SrcId id{file_stat.st_ino, file_stat.st_dev};
            if (seen_inodes.find(id) != seen_inodes.end())
                continue;
            seen_inodes.insert(id);

            if (entry.is_regular_file()) {
                total += file_stat.st_size;
            } else if (entry.is_directory()) {
                total += file_stat.st_size;
            } else if (entry.is_symlink()) {
                total += file_stat.st_size;
            }
        }

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

bool QuotaManager::reserve(uint64_t current_file_size, uint64_t new_file_size) {
    if (!enabled)
        return true;
    if (new_file_size <= current_file_size)
        return true;

    uint64_t delta = new_file_size - current_file_size;
    uint64_t current_usage = used_bytes.load();

    do {
        uint64_t limit = quota_limit.load();
        if (limit != 0 && current_usage + delta > limit)
            return false;
    } while (!used_bytes.compare_exchange_weak(current_usage, current_usage + delta));

    return true;
}

void QuotaManager::release(uint64_t current_file_size, uint64_t new_file_size) {
    if (!enabled || new_file_size >= current_file_size)
        return;

    uint64_t delta = current_file_size - new_file_size;
    uint64_t current_usage = used_bytes.load();
    while (true) {
        uint64_t next_usage = (delta > current_usage) ? 0 : (current_usage - delta);
        if (used_bytes.compare_exchange_weak(current_usage, next_usage))
            break;
    }
}

bool QuotaManager::check_available(uint64_t bytes) const {
    if (!enabled)
        return true;
    uint64_t limit = quota_limit.load();
    if (limit == 0)
        return true;
    return used_bytes.load() + bytes <= limit;
}
