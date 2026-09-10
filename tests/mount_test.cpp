#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "test_util.hpp"

namespace {

constexpr uint64_t KiB = 1024;
constexpr uint64_t MiB = 1024 * KiB;
constexpr uint64_t kQuota = 8 * MiB;
constexpr uint64_t kSlack = 256 * KiB;
constexpr auto kStartupTimeout = std::chrono::seconds(10);
constexpr auto kShutdownTimeout = std::chrono::seconds(10);

bool fuse_device_usable() {
    int fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    close(fd);
    return true;
}

bool fuse_required() {
    const char *v = getenv("FUSEQUOTA_REQUIRE_FUSE");
    return v && *v && std::string_view(v) != "0";
}

class MountTest : public ::testing::Test {
  protected:
    TempDir root;
    std::filesystem::path src;
    std::filesystem::path mnt;
    std::string sock;
    pid_t child = -1;

    void SetUp() override {
        if (!fuse_device_usable()) {
            if (fuse_required())
                FAIL() << "/dev/fuse is not usable but FUSEQUOTA_REQUIRE_FUSE is set";
            GTEST_SKIP() << "/dev/fuse is not usable; skipping mount tests";
        }
        src = root.path() / "src";
        mnt = root.path() / "mnt";
        sock = (root.path() / "ctl.sock").string();
        std::filesystem::create_directory(src);
        std::filesystem::create_directory(mnt);
        ASSERT_NO_FATAL_FAILURE(launch(kQuota));
    }

    void TearDown() override {
        if (child > 0) {
            kill(child, SIGTERM);
            if (!wait_exit(kShutdownTimeout)) {
                lazy_unmount();
                kill(child, SIGKILL);
                waitpid(child, nullptr, 0);
                child = -1;
                ADD_FAILURE() << "fusequota did not exit on SIGTERM";
            }
        }
        if (is_mounted())
            lazy_unmount();
    }

    void launch(uint64_t quota) {
        std::string quota_arg = std::to_string(quota);
        child = fork();
        ASSERT_GE(child, 0) << strerror(errno);
        if (child == 0) {
            execl(FUSEQUOTA_BIN, FUSEQUOTA_BIN, "--foreground", "--nocache", "--quota",
                  quota_arg.c_str(), "--communication-socket-path", sock.c_str(), src.c_str(),
                  mnt.c_str(), static_cast<char *>(nullptr));
            _exit(127);
        }

        auto deadline = std::chrono::steady_clock::now() + kStartupTimeout;
        while (std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            if (waitpid(child, &status, WNOHANG) == child) {
                child = -1;
                FAIL() << "fusequota exited during startup with status " << status;
            }
            if (is_mounted() && std::filesystem::exists(sock))
                return;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        FAIL() << "fusequota did not mount within the startup timeout";
    }

    bool is_mounted() const {
        struct stat a{}, b{};
        if (stat(mnt.c_str(), &a) != 0 || stat(root.path().c_str(), &b) != 0)
            return false;
        return a.st_dev != b.st_dev;
    }

    void lazy_unmount() const {
        std::string cmd = "fusermount3 -u -z " + mnt.string() + " 2>/dev/null";
        [[maybe_unused]] int rc = system(cmd.c_str());
    }

    bool wait_exit(std::chrono::milliseconds timeout, int *status_out = nullptr) {
        auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            pid_t r = waitpid(child, &status, WNOHANG);
            if (r == child) {
                child = -1;
                if (status_out)
                    *status_out = status;
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    }

    std::string ctl(std::string_view cmd) {
        return unix_request(sock, cmd);
    }

    uint64_t quota_used() {
        std::string resp = ctl("get quota_used");
        EXPECT_TRUE(resp.starts_with("quota_used = ")) << resp;
        return std::stoull(resp.substr(13));
    }

    uint64_t fill(int fd, uint64_t max_bytes, int &err) {
        std::vector<char> buf(64 * KiB, 'x');
        uint64_t written = 0;
        err = 0;
        while (written < max_bytes) {
            ssize_t n = write(fd, buf.data(), buf.size());
            if (n < 0) {
                err = errno;
                break;
            }
            written += static_cast<uint64_t>(n);
        }
        return written;
    }

    int open_new(const char *name, int access_flags = O_WRONLY) {
        int fd = open((mnt / name).c_str(), access_flags | O_CREAT | O_EXCL, 0644);
        EXPECT_GE(fd, 0) << name << ": " << strerror(errno);
        return fd;
    }
};

TEST_F(MountTest, StatfsReportsQuotaAsFilesystemSize) {
    struct statvfs st{};
    ASSERT_EQ(statvfs(mnt.c_str(), &st), 0) << strerror(errno);
    ASSERT_GT(st.f_frsize, 0u);
    EXPECT_EQ(st.f_blocks, kQuota / st.f_frsize);
    EXPECT_LE(st.f_bavail, st.f_blocks);
    EXPECT_EQ(st.f_bfree, st.f_bavail);
    EXPECT_LE((st.f_blocks - st.f_bavail) * st.f_frsize, kSlack);
}

TEST_F(MountTest, WritesPassThroughToSourceAndAreCharged) {
    std::string payload(1 * MiB, 0);
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>(i * 31 + 7);

    int fd = open_new("data");
    ASSERT_EQ(write(fd, payload.data(), payload.size()), static_cast<ssize_t>(payload.size()));
    ASSERT_EQ(close(fd), 0);

    std::string on_disk(payload.size(), 0);
    int sfd = open((src / "data").c_str(), O_RDONLY);
    ASSERT_GE(sfd, 0);
    ASSERT_EQ(read(sfd, on_disk.data(), on_disk.size()), static_cast<ssize_t>(on_disk.size()));
    close(sfd);
    EXPECT_EQ(on_disk, payload);

    uint64_t used = quota_used();
    EXPECT_GE(used, 1 * MiB);
    EXPECT_LE(used, 1 * MiB + kSlack);
}

TEST_F(MountTest, WriteBeyondQuotaFailsWithEnospc) {
    int fd = open_new("big");
    int err = 0;
    uint64_t written = fill(fd, 2 * kQuota, err);
    EXPECT_EQ(err, ENOSPC) << strerror(err);
    EXPECT_LE(written, kQuota);
    EXPECT_GE(written, kQuota - 1 * MiB);
    ASSERT_EQ(close(fd), 0);

    EXPECT_EQ(std::filesystem::file_size(src / "big"), written);
    EXPECT_LE(quota_used(), kQuota);

    struct statvfs st{};
    ASSERT_EQ(statvfs(mnt.c_str(), &st), 0);
    EXPECT_LE(st.f_bavail * st.f_frsize, 1 * MiB);
}

TEST_F(MountTest, UnlinkReleasesUsageForReuse) {
    int fd = open_new("victim");
    int err = 0;
    ASSERT_EQ(fill(fd, 2 * MiB, err), 2 * MiB);
    ASSERT_EQ(close(fd), 0);
    uint64_t before = quota_used();
    ASSERT_GE(before, 2 * MiB);

    ASSERT_EQ(unlink((mnt / "victim").c_str()), 0) << strerror(errno);
    EXPECT_FALSE(std::filesystem::exists(src / "victim"));
    uint64_t after = quota_used();
    EXPECT_LE(after + 2 * MiB, before + kSlack);

    fd = open_new("refill");
    uint64_t written = fill(fd, 2 * kQuota, err);
    EXPECT_EQ(err, ENOSPC);
    EXPECT_GE(written, kQuota - 1 * MiB);
    close(fd);
}

TEST_F(MountTest, TruncateReleasesAndReservesUsage) {
    int fd = open_new("trunc", O_RDWR);
    int err = 0;
    ASSERT_EQ(fill(fd, 2 * MiB, err), 2 * MiB);
    uint64_t before = quota_used();
    ASSERT_GE(before, 2 * MiB);

    ASSERT_EQ(ftruncate(fd, 0), 0) << strerror(errno);
    uint64_t after = quota_used();
    EXPECT_LE(after + 2 * MiB, before + kSlack);

    EXPECT_EQ(ftruncate(fd, static_cast<off_t>(2 * kQuota)), -1);
    EXPECT_EQ(errno, ENOSPC);
    EXPECT_LE(quota_used(), kQuota);

    ASSERT_EQ(ftruncate(fd, static_cast<off_t>(1 * MiB)), 0) << strerror(errno);
    EXPECT_GE(quota_used(), 1 * MiB);
    close(fd);
    EXPECT_EQ(std::filesystem::file_size(src / "trunc"), 1 * MiB);
}

TEST_F(MountTest, FallocateBeyondQuotaFailsWithEnospc) {
    int fd = open_new("alloc", O_RDWR);
    EXPECT_EQ(fallocate(fd, 0, 0, static_cast<off_t>(2 * kQuota)), -1);
    EXPECT_EQ(errno, ENOSPC);
    EXPECT_LE(quota_used(), kSlack);
    close(fd);
}

TEST_F(MountTest, NewEntriesAreRefusedWhenQuotaIsExhausted) {
    ASSERT_EQ(ctl("set quota_used = " + std::to_string(kQuota + 1)), "OK\n");

    EXPECT_EQ(mkdir((mnt / "dir").c_str(), 0755), -1);
    EXPECT_EQ(errno, ENOSPC);
    EXPECT_EQ(open((mnt / "file").c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644), -1);
    EXPECT_EQ(errno, ENOSPC);
    EXPECT_EQ(symlink("target", (mnt / "link").c_str()), -1);
    EXPECT_EQ(errno, ENOSPC);
    EXPECT_FALSE(std::filesystem::exists(src / "dir"));
    EXPECT_FALSE(std::filesystem::exists(src / "file"));

    struct statvfs st{};
    ASSERT_EQ(statvfs(mnt.c_str(), &st), 0);
    EXPECT_EQ(st.f_bavail, 0u);

    ASSERT_EQ(ctl("set quota_used = 0"), "OK\n");
    EXPECT_EQ(mkdir((mnt / "dir").c_str(), 0755), 0) << strerror(errno);
    EXPECT_TRUE(std::filesystem::is_directory(src / "dir"));
    EXPECT_EQ(symlink("target", (mnt / "link").c_str()), 0) << strerror(errno);
    EXPECT_EQ(std::filesystem::read_symlink(src / "link"), "target");
}

TEST_F(MountTest, RaisingQuotaOverSocketAllowsFurtherWrites) {
    int fd = open_new("grow");
    int err = 0;
    uint64_t written = fill(fd, 2 * kQuota, err);
    ASSERT_EQ(err, ENOSPC);

    ASSERT_EQ(ctl("set quota = " + std::to_string(4 * kQuota)), "OK\n");

    std::vector<char> buf(1 * MiB, 'y');
    EXPECT_EQ(write(fd, buf.data(), buf.size()), static_cast<ssize_t>(buf.size()))
        << strerror(errno);
    ASSERT_EQ(close(fd), 0);
    EXPECT_EQ(std::filesystem::file_size(src / "grow"), written + 1 * MiB);

    struct statvfs st{};
    ASSERT_EQ(statvfs(mnt.c_str(), &st), 0);
    EXPECT_EQ(st.f_blocks, 4 * kQuota / st.f_frsize);
}

TEST_F(MountTest, DoEndUnmountsAndExitsCleanly) {
    EXPECT_EQ(ctl("do end"), "OK\n");

    int status = -1;
    ASSERT_TRUE(wait_exit(kShutdownTimeout, &status)) << "fusequota did not exit after 'do end'";
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
    EXPECT_FALSE(is_mounted());
    EXPECT_FALSE(std::filesystem::exists(sock));
}

TEST_F(MountTest, SigtermUnmountsAndExits) {
    ASSERT_EQ(kill(child, SIGTERM), 0);
    int status = -1;
    ASSERT_TRUE(wait_exit(kShutdownTimeout, &status));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_FALSE(is_mounted());
}

} // namespace
