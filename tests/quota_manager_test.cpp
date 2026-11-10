#include <chrono>
#include <fcntl.h>
#include <grp.h>
#include <gtest/gtest.h>
#include <memory>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include "quota.hpp"
#include "test_util.hpp"

namespace {

constexpr uint64_t KiB = 1024;
constexpr uint64_t MiB = 1024 * KiB;

uint64_t blocks_of(const std::filesystem::path &p) {
    struct stat st{};
    EXPECT_EQ(lstat(p.c_str(), &st), 0) << p;
    return static_cast<uint64_t>(st.st_blocks) * 512;
}

void write_file(const std::filesystem::path &p, size_t bytes) {
    int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ASSERT_GE(fd, 0) << p;
    std::string chunk(64 * KiB, 'x');
    size_t left = bytes;
    while (left > 0) {
        size_t n = std::min(left, chunk.size());
        ASSERT_EQ(write(fd, chunk.data(), n), static_cast<ssize_t>(n));
        left -= n;
    }
    ASSERT_EQ(fsync(fd), 0);
    close(fd);
}

template <typename Pred> bool eventually(Pred pred, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return pred();
}

TEST(QuotaManagerDisabled, EverythingIsUnlimitedAndUntracked) {
    QuotaManager quota;
    EXPECT_FALSE(quota.is_enabled());
    EXPECT_TRUE(quota.reserve_bytes(1ull << 40));
    EXPECT_EQ(quota.get_usage(), 0u);
    EXPECT_TRUE(quota.reserve(0, 1ull << 40));
    EXPECT_TRUE(quota.check_available(UINT64_MAX));
    quota.force_add(123);
    EXPECT_EQ(quota.get_usage(), 0u);
    quota.release_bytes(123);
    EXPECT_EQ(quota.get_usage(), 0u);
}

class QuotaManagerEnabled : public ::testing::Test {
  protected:
    static constexpr uint64_t kLimit = 10 * MiB;

    TempDir dir;
    QuotaManager quota;

    void SetUp() override {
        quota.init(dir.path().string(), kLimit, 0);
        ASSERT_TRUE(quota.is_enabled());
        ASSERT_EQ(quota.get_limit(), kLimit);
        quota.set_usage(0);
    }
};

TEST_F(QuotaManagerEnabled, ReserveWithinLimitAccumulates) {
    EXPECT_TRUE(quota.reserve_bytes(1 * MiB));
    EXPECT_TRUE(quota.reserve_bytes(2 * MiB));
    EXPECT_EQ(quota.get_usage(), 3 * MiB);
}

TEST_F(QuotaManagerEnabled, ReserveExactlyToLimitSucceeds) {
    EXPECT_TRUE(quota.reserve_bytes(kLimit));
    EXPECT_EQ(quota.get_usage(), kLimit);
    EXPECT_FALSE(quota.reserve_bytes(1));
    EXPECT_EQ(quota.get_usage(), kLimit);
}

TEST_F(QuotaManagerEnabled, ReserveBeyondLimitRollsBack) {
    EXPECT_TRUE(quota.reserve_bytes(9 * MiB));
    EXPECT_FALSE(quota.reserve_bytes(2 * MiB));
    EXPECT_EQ(quota.get_usage(), 9 * MiB);
    EXPECT_TRUE(quota.reserve_bytes(1 * MiB));
    EXPECT_EQ(quota.get_usage(), kLimit);
}

TEST_F(QuotaManagerEnabled, ReserveZeroIsNoop) {
    EXPECT_TRUE(quota.reserve_bytes(0));
    EXPECT_EQ(quota.get_usage(), 0u);
    quota.set_usage(kLimit);
    EXPECT_TRUE(quota.reserve_bytes(0));
}

TEST_F(QuotaManagerEnabled, ZeroLimitMeansUnlimited) {
    quota.set_limit(0);
    EXPECT_TRUE(quota.reserve_bytes(1ull << 40));
    EXPECT_EQ(quota.get_usage(), 1ull << 40);
    EXPECT_TRUE(quota.check_available(UINT64_MAX));
}

TEST_F(QuotaManagerEnabled, ReleaseClampsAtZero) {
    EXPECT_TRUE(quota.reserve_bytes(1 * MiB));
    quota.release_bytes(512 * KiB);
    EXPECT_EQ(quota.get_usage(), 512 * KiB);
    quota.release_bytes(5 * MiB);
    EXPECT_EQ(quota.get_usage(), 0u);
    quota.release_bytes(0);
    EXPECT_EQ(quota.get_usage(), 0u);
}

TEST_F(QuotaManagerEnabled, ReserveOnlyChargesGrowth) {
    EXPECT_TRUE(quota.reserve(1 * MiB, 3 * MiB));
    EXPECT_EQ(quota.get_usage(), 2 * MiB);
    EXPECT_TRUE(quota.reserve(3 * MiB, 3 * MiB));
    EXPECT_TRUE(quota.reserve(3 * MiB, 1 * MiB));
    EXPECT_EQ(quota.get_usage(), 2 * MiB);
    EXPECT_FALSE(quota.reserve(0, kLimit));
    EXPECT_EQ(quota.get_usage(), 2 * MiB);
}

TEST_F(QuotaManagerEnabled, ReleaseOnlyRefundsShrink) {
    quota.set_usage(5 * MiB);
    quota.release(3 * MiB, 3 * MiB);
    quota.release(1 * MiB, 3 * MiB);
    EXPECT_EQ(quota.get_usage(), 5 * MiB);
    quota.release(3 * MiB, 1 * MiB);
    EXPECT_EQ(quota.get_usage(), 3 * MiB);
}

TEST_F(QuotaManagerEnabled, CheckAvailableDoesNotReserve) {
    quota.set_usage(kLimit - 1 * MiB);
    EXPECT_TRUE(quota.check_available(1 * MiB));
    EXPECT_FALSE(quota.check_available(1 * MiB + 1));
    EXPECT_TRUE(quota.check_available(0));
    EXPECT_EQ(quota.get_usage(), kLimit - 1 * MiB);
    quota.set_usage(kLimit + 1);
    EXPECT_FALSE(quota.check_available(0));
}

TEST_F(QuotaManagerEnabled, ForceAddIgnoresLimit) {
    quota.force_add(kLimit * 2);
    EXPECT_EQ(quota.get_usage(), kLimit * 2);
    quota.force_add(0);
    EXPECT_EQ(quota.get_usage(), kLimit * 2);
    EXPECT_FALSE(quota.reserve_bytes(1));
}

TEST_F(QuotaManagerEnabled, SetLimitTakesEffectImmediately) {
    quota.set_usage(4 * MiB);
    quota.set_limit(4 * MiB);
    EXPECT_FALSE(quota.reserve_bytes(1));
    quota.set_limit(8 * MiB);
    EXPECT_TRUE(quota.reserve_bytes(4 * MiB));
    EXPECT_EQ(quota.get_usage(), 8 * MiB);
}

TEST(QuotaManagerScan, EmptyDirectoryHasNoUsage) {
    TempDir dir;
    QuotaManager quota;
    quota.init(dir.path().string(), 1 * MiB, 0);
    EXPECT_EQ(quota.get_usage(), 0u);
}

TEST(QuotaManagerScan, CountsRegularFilesDirectoriesAndSymlinks) {
    TempDir dir;
    auto sub = dir.path() / "sub";
    auto big = sub / "big";
    auto small = dir.path() / "small";
    auto link = dir.path() / "link";
    std::filesystem::create_directory(sub);
    write_file(big, 1 * MiB);
    write_file(small, 10 * KiB);
    std::filesystem::create_symlink("sub/big", link);
    ASSERT_EQ(mkfifo((dir.path() / "fifo").c_str(), 0600), 0);

    uint64_t expected = blocks_of(sub) + blocks_of(big) + blocks_of(small) + blocks_of(link);
    ASSERT_GE(expected, 1 * MiB + 10 * KiB);

    QuotaManager quota;
    quota.init(dir.path().string(), 100 * MiB, 0);
    EXPECT_EQ(quota.get_usage(), expected);
}

TEST(QuotaManagerScan, CountsHardlinkedFilesOnce) {
    TempDir dir;
    auto file = dir.path() / "file";
    write_file(file, 256 * KiB);
    std::filesystem::create_hard_link(file, dir.path() / "alias");
    std::filesystem::create_hard_link(file, dir.path() / "alias2");

    QuotaManager quota;
    quota.init(dir.path().string(), 100 * MiB, 0);
    EXPECT_EQ(quota.get_usage(), blocks_of(file));
}

TEST(QuotaManagerScan, BackgroundRescanCorrectsDriftInBothDirections) {
    TempDir dir;
    write_file(dir.path() / "file", 256 * KiB);
    uint64_t expected = blocks_of(dir.path() / "file");

    QuotaManager quota;
    quota.init(dir.path().string(), 100 * MiB, 1);
    ASSERT_EQ(quota.get_usage(), expected);

    quota.set_usage(expected + 50 * MiB);
    EXPECT_TRUE(
        eventually([&] { return quota.get_usage() == expected; }, std::chrono::milliseconds(5000)))
        << "usage stuck at " << quota.get_usage();

    quota.set_usage(0);
    EXPECT_TRUE(
        eventually([&] { return quota.get_usage() == expected; }, std::chrono::milliseconds(5000)))
        << "usage stuck at " << quota.get_usage();
}

TEST(QuotaManagerScan, RecursesDeeplyNestedDirectories) {
    TempDir dir;
    uint64_t expected = 0;
    auto cur = dir.path();
    for (int i = 0; i < 64; ++i) {
        cur /= "d";
        std::filesystem::create_directory(cur);
        expected += blocks_of(cur);
    }
    write_file(cur / "leaf", 128 * KiB);
    expected += blocks_of(cur / "leaf");

    QuotaManager quota;
    quota.init(dir.path().string(), 100 * MiB, 0);
    EXPECT_EQ(quota.get_usage(), expected);
}

TEST(QuotaManagerScan, DoesNotFollowSymlinks) {
    TempDir dir;
    TempDir outside;
    std::filesystem::create_directory(outside.path() / "sub");
    write_file(outside.path() / "sub" / "big", 1 * MiB);
    write_file(outside.path() / "file", 1 * MiB);
    std::filesystem::create_directory_symlink(outside.path() / "sub", dir.path() / "dirlink");
    std::filesystem::create_symlink(outside.path() / "file", dir.path() / "filelink");

    QuotaManager quota;
    quota.init(dir.path().string(), 100 * MiB, 0);
    EXPECT_EQ(quota.get_usage(),
              blocks_of(dir.path() / "dirlink") + blocks_of(dir.path() / "filelink"));
}

TEST(QuotaManagerScan, SparseFilesCountAllocatedBlocksOnly) {
    TempDir dir;
    auto file = dir.path() / "sparse";
    int fd = open(file.c_str(), O_WRONLY | O_CREAT, 0644);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(ftruncate(fd, static_cast<off_t>(64 * MiB)), 0);
    ASSERT_EQ(pwrite(fd, "x", 1, static_cast<off_t>(32 * MiB)), 1);
    ASSERT_EQ(fsync(fd), 0);
    close(fd);
    ASSERT_LT(blocks_of(file), 1 * MiB);

    QuotaManager quota;
    quota.init(dir.path().string(), 1 * MiB, 0);
    EXPECT_EQ(quota.get_usage(), blocks_of(file));
}

TEST(QuotaManagerScan, FailedRescanLeavesUsageUnchanged) {
    constexpr uid_t kNobody = 65534;
    TempDir dir;
    auto sub = dir.path() / "sub";
    std::filesystem::create_directory(sub);
    write_file(dir.path() / "top", 256 * KiB);
    write_file(sub / "inner", 256 * KiB);
    for (const auto &p : {dir.path(), sub, dir.path() / "top", sub / "inner"})
        ASSERT_EQ(lchown(p.c_str(), kNobody, kNobody), 0);

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        if (setgroups(0, nullptr) != 0 || setgid(kNobody) != 0 || setuid(kNobody) != 0)
            _exit(10);
        QuotaManager quota;
        quota.init(dir.path().string(), 100 * MiB, 1);
        if (quota.get_usage() < 512 * KiB)
            _exit(11);
        if (chmod(sub.c_str(), 0) != 0)
            _exit(12);
        uint64_t sentinel = 77 * MiB;
        quota.set_usage(sentinel);
        std::this_thread::sleep_for(std::chrono::milliseconds(3500));
        uint64_t after = quota.get_usage();
        chmod(sub.c_str(), 0755);
        _exit(after == sentinel ? 0 : 13);
    }
    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    chmod(sub.c_str(), 0755);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(QuotaManagerScan, DestructorStopsScannerPromptly) {
    TempDir dir;
    auto quota = std::make_unique<QuotaManager>();
    quota->init(dir.path().string(), 1 * MiB, 3600);

    auto start = std::chrono::steady_clock::now();
    quota.reset();
    auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::seconds(2));
}

} // namespace
