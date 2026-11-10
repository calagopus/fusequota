#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <functional>
#include <grp.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
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
    bool nocache = true;
    std::vector<std::string> extra_args;

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
        std::vector<std::string> args = {FUSEQUOTA_BIN, "--foreground"};
        if (nocache)
            args.emplace_back("--nocache");
        args.insert(args.end(),
                    {"--quota", std::to_string(quota), "--communication-socket-path", sock});
        args.insert(args.end(), extra_args.begin(), extra_args.end());
        args.insert(args.end(), {src.string(), mnt.string()});
        std::vector<char *> argv;
        for (auto &a : args)
            argv.push_back(a.data());
        argv.push_back(nullptr);

        child = fork();
        ASSERT_GE(child, 0) << strerror(errno);
        if (child == 0) {
            execv(FUSEQUOTA_BIN, argv.data());
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

constexpr uid_t kNobody = 65534;

int run_as(uid_t id, const std::function<int()> &fn) {
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (setgroups(0, nullptr) != 0 || setgid(id) != 0 || setuid(id) != 0)
            _exit(126);
        _exit(fn());
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

mode_t mode_of(const std::filesystem::path &p) {
    struct stat st{};
    EXPECT_EQ(lstat(p.c_str(), &st), 0) << p << ": " << strerror(errno);
    return st.st_mode & 07777;
}

std::pair<uid_t, gid_t> owner_of(const std::filesystem::path &p) {
    struct stat st{};
    EXPECT_EQ(lstat(p.c_str(), &st), 0) << p << ": " << strerror(errno);
    return {st.st_uid, st.st_gid};
}

std::string read_all(const std::filesystem::path &p) {
    std::string out;
    int fd = open(p.c_str(), O_RDONLY);
    EXPECT_GE(fd, 0) << p << ": " << strerror(errno);
    if (fd < 0)
        return out;
    char buf[4096];
    for (ssize_t n; (n = read(fd, buf, sizeof(buf))) > 0;)
        out.append(buf, static_cast<size_t>(n));
    close(fd);
    return out;
}

void make_file(const std::filesystem::path &p, std::string_view data, mode_t mode) {
    int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT_GE(fd, 0) << p << ": " << strerror(errno);
    ASSERT_EQ(write(fd, data.data(), data.size()), static_cast<ssize_t>(data.size()));
    close(fd);
    ASSERT_EQ(chmod(p.c_str(), mode), 0);
}

int write_at_end(const std::filesystem::path &p, std::string_view data) {
    int fd = open(p.c_str(), O_WRONLY | O_APPEND);
    if (fd < 0)
        return errno;
    if (write(fd, data.data(), data.size()) != static_cast<ssize_t>(data.size()))
        return errno;
    return close(fd) == 0 ? 0 : errno;
}

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

// kill-priv
class MountKillPrivTest : public MountTest {
  protected:
    MountKillPrivTest() {
        extra_args = {"-o", "allow_other"};
    }

    void SetUp() override {
        MountTest::SetUp();
        if (IsSkipped() || HasFatalFailure())
            return;
        ASSERT_EQ(chmod(root.path().c_str(), 0755), 0);
        ASSERT_EQ(chmod(src.c_str(), 0777), 0);
    }

    std::filesystem::path suid_file(const char *name, mode_t mode = 06777) {
        make_file(src / name, "seed", mode);
        EXPECT_EQ(mode_of(src / name), mode);
        return mnt / name;
    }

    void expect_cleared(const char *name, mode_t expected) {
        EXPECT_EQ(mode_of(src / name), expected) << name;
        EXPECT_EQ(mode_of(mnt / name), expected) << name;
    }
};

TEST_F(MountKillPrivTest, UnprivilegedWriteClearsSuidAndExecutableSgid) {
    auto p = suid_file("f");
    ASSERT_EQ(run_as(kNobody, [&] { return write_at_end(p, "-more"); }), 0);
    expect_cleared("f", 0777);
    EXPECT_EQ(read_all(src / "f"), "seed-more");
    EXPECT_EQ(std::filesystem::file_size(src / "f"), 9u);
}

TEST_F(MountKillPrivTest, SgidWithoutGroupExecuteIsKept) {
    auto p = suid_file("f", 06766);
    ASSERT_EQ(run_as(kNobody, [&] { return write_at_end(p, "x"); }), 0);
    expect_cleared("f", 02766);
}

TEST_F(MountKillPrivTest, UnprivilegedTruncateClearsSuid) {
    auto p = suid_file("f");
    ASSERT_EQ(run_as(kNobody, [&] { return truncate(p.c_str(), 2) == 0 ? 0 : errno; }), 0);
    expect_cleared("f", 0777);
    EXPECT_EQ(read_all(src / "f"), "se");
}

TEST_F(MountKillPrivTest, UnprivilegedFtruncateClearsSuid) {
    auto p = suid_file("f");
    ASSERT_EQ(run_as(kNobody,
                     [&] {
                         int fd = open(p.c_str(), O_WRONLY);
                         if (fd < 0)
                             return errno;
                         int rc = ftruncate(fd, 100) == 0 ? 0 : errno;
                         close(fd);
                         return rc;
                     }),
              0);
    expect_cleared("f", 0777);
    EXPECT_EQ(std::filesystem::file_size(src / "f"), 100u);
}

TEST_F(MountKillPrivTest, UnprivilegedOpenTruncClearsSuid) {
    auto p = suid_file("f");
    ASSERT_EQ(run_as(kNobody,
                     [&] {
                         int fd = open(p.c_str(), O_WRONLY | O_TRUNC);
                         if (fd < 0)
                             return errno;
                         return close(fd) == 0 ? 0 : errno;
                     }),
              0);
    expect_cleared("f", 0777);
    EXPECT_EQ(std::filesystem::file_size(src / "f"), 0u);
}

TEST_F(MountKillPrivTest, UnprivilegedFallocateClearsSuid) {
    auto p = suid_file("f");
    ASSERT_EQ(run_as(kNobody,
                     [&] {
                         int fd = open(p.c_str(), O_WRONLY);
                         if (fd < 0)
                             return errno;
                         int rc = fallocate(fd, 0, 0, 64 * KiB) == 0 ? 0 : errno;
                         close(fd);
                         return rc;
                     }),
              0);
    expect_cleared("f", 0777);
    EXPECT_EQ(std::filesystem::file_size(src / "f"), 64 * KiB);
}

TEST_F(MountKillPrivTest, UnprivilegedChownClearsSuid) {
    auto p = suid_file("f", 06755);
    ASSERT_EQ(lchown((src / "f").c_str(), kNobody, kNobody), 0);
    ASSERT_EQ(chmod((src / "f").c_str(), 06755), 0);
    ASSERT_EQ(run_as(kNobody, [&] { return chown(p.c_str(), kNobody, kNobody) == 0 ? 0 : errno; }),
              0);
    expect_cleared("f", 0755);
}

TEST_F(MountKillPrivTest, DirectorySgidIsUnaffected) {
    ASSERT_EQ(mkdir((src / "d").c_str(), 0777), 0);
    ASSERT_EQ(chmod((src / "d").c_str(), 02777), 0);
    ASSERT_EQ(run_as(kNobody,
                     [&] {
                         int fd = open((mnt / "d" / "child").c_str(), O_WRONLY | O_CREAT, 0644);
                         if (fd < 0)
                             return errno;
                         return close(fd) == 0 ? 0 : errno;
                     }),
              0);
    EXPECT_EQ(mode_of(src / "d"), 02777);
    EXPECT_EQ(mode_of(mnt / "d"), 02777);
}

TEST_F(MountKillPrivTest, CreatingNewSuidFileKeepsBit) {
    ASSERT_EQ(run_as(kNobody,
                     [&] {
                         int fd = open((mnt / "new").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 04755);
                         if (fd < 0)
                             return errno;
                         return close(fd) == 0 ? 0 : errno;
                     }),
              0);
    EXPECT_EQ(mode_of(src / "new"), 04755);
    EXPECT_EQ(mode_of(mnt / "new"), 04755);
}

class MountCachedKillPrivTest : public MountKillPrivTest {
  public:
    MountCachedKillPrivTest() {
        nocache = false;
    }
};

TEST_F(MountCachedKillPrivTest, ClearedModeIsVisibleThroughCachedAttributes) {
    auto p = suid_file("f");
    ASSERT_EQ(mode_of(p), 06777);
    ASSERT_EQ(run_as(kNobody, [&] { return write_at_end(p, "-more"); }), 0);
    expect_cleared("f", 0777);
    struct stat st{};
    ASSERT_EQ(stat(p.c_str(), &st), 0);
    EXPECT_EQ(st.st_size, 9);
    EXPECT_EQ(read_all(p), "seed-more");
}

// chown
TEST_F(MountTest, ChownChangesSourceOwnership) {
    make_file(src / "f", "x", 0644);
    ASSERT_EQ(chown((mnt / "f").c_str(), 1001, 2001), 0) << strerror(errno);
    EXPECT_EQ(owner_of(src / "f"), std::make_pair(uid_t{1001}, gid_t{2001}));

    ASSERT_EQ(chown((mnt / "f").c_str(), static_cast<uid_t>(-1), 2002), 0) << strerror(errno);
    EXPECT_EQ(owner_of(src / "f"), std::make_pair(uid_t{1001}, gid_t{2002}));

    ASSERT_EQ(chown((mnt / "f").c_str(), 1002, static_cast<gid_t>(-1)), 0) << strerror(errno);
    EXPECT_EQ(owner_of(src / "f"), std::make_pair(uid_t{1002}, gid_t{2002}));
    EXPECT_EQ(owner_of(mnt / "f"), std::make_pair(uid_t{1002}, gid_t{2002}));
}

TEST_F(MountTest, LchownChangesSymlinkNotTarget) {
    make_file(src / "target", "x", 0644);
    std::filesystem::create_symlink("target", src / "link");
    ASSERT_EQ(lchown((mnt / "link").c_str(), 1001, 2001), 0) << strerror(errno);
    EXPECT_EQ(owner_of(src / "link"), std::make_pair(uid_t{1001}, gid_t{2001}));
    EXPECT_EQ(owner_of(src / "target"), std::make_pair(uid_t{0}, gid_t{0}));
}

// --uid / --gid
class MountForcedUidTest : public MountTest {
  public:
    MountForcedUidTest() {
        extra_args = {"--uid", "1234"};
    }
};

class MountForcedGidTest : public MountTest {
  public:
    MountForcedGidTest() {
        extra_args = {"--gid", "4321"};
    }
};

void create_entries(const std::filesystem::path &mnt) {
    int fd = open((mnt / "file").c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    ASSERT_GE(fd, 0) << strerror(errno);
    close(fd);
    ASSERT_EQ(mkdir((mnt / "dir").c_str(), 0755), 0) << strerror(errno);
    ASSERT_EQ(symlink("file", (mnt / "link").c_str()), 0) << strerror(errno);
}

TEST_F(MountForcedUidTest, NewEntriesGetForcedUid) {
    ASSERT_NO_FATAL_FAILURE(create_entries(mnt));
    for (const char *name : {"file", "dir", "link"})
        EXPECT_EQ(owner_of(src / name), std::make_pair(uid_t{1234}, gid_t{0})) << name;
}

TEST_F(MountForcedGidTest, NewEntriesGetForcedGid) {
    ASSERT_NO_FATAL_FAILURE(create_entries(mnt));
    for (const char *name : {"file", "dir", "link"})
        EXPECT_EQ(owner_of(src / name), std::make_pair(uid_t{0}, gid_t{4321})) << name;
}

TEST_F(MountForcedUidTest, OpeningExistingFileKeepsOwner) {
    make_file(src / "f", "x", 0666);
    ASSERT_EQ(lchown((src / "f").c_str(), 4242, 4243), 0);
    for (int flags : {O_RDONLY, O_WRONLY, O_RDWR}) {
        int fd = open((mnt / "f").c_str(), flags);
        ASSERT_GE(fd, 0) << strerror(errno);
        close(fd);
        EXPECT_EQ(owner_of(src / "f"), std::make_pair(uid_t{4242}, gid_t{4243})) << flags;
    }
}

// --noflush
class MountNoflushTest : public MountTest {
  public:
    MountNoflushTest() {
        extra_args = {"--noflush"};
    }
};

TEST_F(MountNoflushTest, DataPersistsAcrossCloseAndReopen) {
    int fd = open_new("f");
    ASSERT_EQ(write(fd, "hello", 5), 5);
    ASSERT_EQ(close(fd), 0);
    EXPECT_EQ(read_all(mnt / "f"), "hello");
    ASSERT_EQ(write_at_end(mnt / "f", " world"), 0);
    EXPECT_EQ(read_all(mnt / "f"), "hello world");
    EXPECT_EQ(read_all(src / "f"), "hello world");
}

// xattr
TEST_F(MountTest, UserXattrsReachSource) {
    make_file(src / "f", "x", 0644);
    if (setxattr((src / "f").c_str(), "user.probe", "1", 1, 0) != 0 && errno == ENOTSUP)
        GTEST_SKIP() << "backing filesystem does not support user xattrs";
    ASSERT_EQ(removexattr((src / "f").c_str(), "user.probe"), 0);

    auto p = mnt / "f";
    ASSERT_EQ(setxattr(p.c_str(), "user.k", "value", 5, 0), 0) << strerror(errno);
    char buf[64] = {};
    ASSERT_EQ(getxattr((src / "f").c_str(), "user.k", buf, sizeof(buf)), 5);
    EXPECT_EQ(std::string_view(buf, 5), "value");
    std::fill(std::begin(buf), std::end(buf), 0);
    ASSERT_EQ(getxattr(p.c_str(), "user.k", buf, sizeof(buf)), 5) << strerror(errno);
    EXPECT_EQ(std::string_view(buf, 5), "value");

    char list[256] = {};
    ssize_t n = listxattr(p.c_str(), list, sizeof(list));
    ASSERT_GE(n, 0) << strerror(errno);
    std::vector<std::string> names;
    for (ssize_t i = 0; i < n; i += static_cast<ssize_t>(strlen(list + i)) + 1)
        names.emplace_back(list + i);
    EXPECT_NE(std::find(names.begin(), names.end(), "user.k"), names.end());

    ASSERT_EQ(removexattr(p.c_str(), "user.k"), 0) << strerror(errno);
    EXPECT_EQ(getxattr((src / "f").c_str(), "user.k", buf, sizeof(buf)), -1);
    EXPECT_EQ(errno, ENODATA);
}

} // namespace
