#pragma once
#include <chrono>
#include <thread>
#include "common.hpp"

class QuotaManager {
  public:
    QuotaManager() = default;
    ~QuotaManager();

    void init(const std::string &source_path, uint64_t limit, int rescan_seconds);

    bool reserve(uint64_t current_file_size, uint64_t new_file_size);
    void release(uint64_t current_file_size, uint64_t new_file_size);

    uint64_t get_usage() const {
        return used_bytes.load();
    }
    void set_usage(uint64_t new_usage) {
        used_bytes.store(new_usage);
    }
    uint64_t get_limit() const {
        return quota_limit.load(std::memory_order_relaxed);
    }
    void set_limit(uint64_t new_limit) {
        quota_limit.store(new_limit, std::memory_order_relaxed);
    }
    bool is_enabled() const {
        return enabled;
    }

  private:
    void calculate_usage(std::stop_token st);
    void background_scanner(std::stop_token st);

    bool enabled{false};
    std::string source_dir;
    std::atomic<uint64_t> quota_limit{0};
    std::atomic<uint64_t> used_bytes{0};

    std::chrono::seconds rescan_interval{0};
    std::jthread scanner_thread;
};
