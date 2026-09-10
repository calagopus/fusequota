#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include "fs_context.hpp"
#include "test_util.hpp"

namespace {

bool wait_for_listener(const std::string &path, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        int fd = connect_unix(path);
        if (fd >= 0) {
            close(fd);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

bool wait_for_refused(const std::string &path, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        int fd = connect_unix(path);
        if (fd < 0)
            return errno == ECONNREFUSED || errno == ENOENT;
        close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

class SocketServerTest : public ::testing::Test {
  protected:
    static inline std::unique_ptr<TempDir> dir;
    static inline std::unique_ptr<SocketServer> server;
    static inline std::string sock;

    static void SetUpTestSuite() {
        dir = std::make_unique<TempDir>();
        sock = (dir->path() / "ctl.sock").string();
        server = std::make_unique<SocketServer>();
        server->start(sock);
        ASSERT_TRUE(wait_for_listener(sock, std::chrono::milliseconds(2000)));
    }

    static void TearDownTestSuite() {
        server.reset();
        dir.reset();
    }

    void SetUp() override {
        fs.quota.set_usage(0);
        fs.quota.set_limit(0);
    }

    std::string request(std::string_view cmd) {
        return unix_request(sock, cmd);
    }
};

TEST_F(SocketServerTest, GetQuotaUsedReportsCurrentUsage) {
    EXPECT_EQ(request("get quota_used"), "quota_used = 0\nOK\n");
    fs.quota.set_usage(123456789);
    EXPECT_EQ(request("get quota_used"), "quota_used = 123456789\nOK\n");
}

TEST_F(SocketServerTest, SetQuotaUpdatesLimit) {
    EXPECT_EQ(request("set quota = 4096"), "OK\n");
    EXPECT_EQ(fs.quota.get_limit(), 4096u);
    EXPECT_EQ(request("set quota = 0"), "OK\n");
    EXPECT_EQ(fs.quota.get_limit(), 0u);
}

TEST_F(SocketServerTest, SetQuotaUsedOverridesUsage) {
    EXPECT_EQ(request("set quota_used = 777"), "OK\n");
    EXPECT_EQ(fs.quota.get_usage(), 777u);
}

TEST_F(SocketServerTest, AddQuotaUsedAccumulates) {
    fs.quota.set_usage(100);
    EXPECT_EQ(request("add quota_used = 50"), "OK\n");
    EXPECT_EQ(fs.quota.get_usage(), 150u);
}

TEST_F(SocketServerTest, RemQuotaUsedSubtractsAndClampsAtZero) {
    fs.quota.set_usage(100);
    EXPECT_EQ(request("rem quota_used = 30"), "OK\n");
    EXPECT_EQ(fs.quota.get_usage(), 70u);
    EXPECT_EQ(request("rem quota_used = 500"), "OK\n");
    EXPECT_EQ(fs.quota.get_usage(), 0u);
}

TEST_F(SocketServerTest, InvalidNumbersAreRejectedWithoutSideEffects) {
    fs.quota.set_limit(10);
    fs.quota.set_usage(20);
    EXPECT_EQ(request("set quota = abc"), "ERROR: Invalid value\n");
    EXPECT_EQ(request("set quota_used = -"), "ERROR: Invalid value\n");
    EXPECT_EQ(request("add quota_used = x1"), "ERROR: Invalid value\n");
    EXPECT_EQ(request("rem quota_used = 1 2"), "OK\n");
    EXPECT_EQ(fs.quota.get_usage(), 19u);
    EXPECT_EQ(fs.quota.get_limit(), 10u);
    EXPECT_EQ(fs.quota.get_usage(), 19u);
}

TEST_F(SocketServerTest, UnknownCommandIsReported) {
    EXPECT_EQ(request("frobnicate"), "ERROR: Unknown command\n");
    EXPECT_EQ(request("get quota"), "ERROR: Unknown command\n");
    EXPECT_EQ(request("set quota=5"), "ERROR: Unknown command\n");
    EXPECT_EQ(request("set quota = "), "ERROR: Unknown command\n");
}

TEST_F(SocketServerTest, SurroundingWhitespaceIsTrimmed) {
    EXPECT_EQ(request("  get quota_used \r\n"), "quota_used = 0\nOK\n");
    EXPECT_EQ(request("\tset quota = 42\n"), "OK\n");
    EXPECT_EQ(fs.quota.get_limit(), 42u);
}

TEST_F(SocketServerTest, EachConnectionHandlesOneRequest) {
    EXPECT_EQ(request("set quota = 1"), "OK\n");
    EXPECT_EQ(request("set quota = 2"), "OK\n");
    EXPECT_EQ(request("get quota_used"), "quota_used = 0\nOK\n");
    EXPECT_EQ(fs.quota.get_limit(), 2u);
}

TEST(SocketServerLifecycle, DoEndStopsServingAndRepliesOk) {
    TempDir dir;
    std::string sock = (dir.path() / "ctl.sock").string();
    SocketServer server;
    server.start(sock);
    ASSERT_TRUE(wait_for_listener(sock, std::chrono::milliseconds(2000)));

    EXPECT_EQ(unix_request(sock, "do end"), "OK\n");
    EXPECT_TRUE(wait_for_refused(sock, std::chrono::milliseconds(2000)));
}

TEST(SocketServerLifecycle, DestructorRemovesSocketFile) {
    TempDir dir;
    std::string sock = (dir.path() / "ctl.sock").string();
    {
        SocketServer server;
        server.start(sock);
        ASSERT_TRUE(wait_for_listener(sock, std::chrono::milliseconds(2000)));
        EXPECT_TRUE(std::filesystem::exists(sock));
    }
    EXPECT_FALSE(std::filesystem::exists(sock));
}

TEST(SocketServerLifecycle, StopBeforeStartIsHarmless) {
    SocketServer server;
    server.stop();
    server.stop();
}

TEST(SocketServerLifecycle, StartReplacesStaleSocketFile) {
    TempDir dir;
    std::string sock = (dir.path() / "ctl.sock").string();
    {
        SocketServer stale;
        stale.start(sock);
        ASSERT_TRUE(wait_for_listener(sock, std::chrono::milliseconds(2000)));
    }
    ASSERT_EQ(mknod(sock.c_str(), S_IFSOCK | 0600, 0), 0);

    SocketServer server;
    server.start(sock);
    ASSERT_TRUE(wait_for_listener(sock, std::chrono::milliseconds(2000)));
    EXPECT_EQ(unix_request(sock, "get quota_used"),
              std::format("quota_used = {}\nOK\n", fs.quota.get_usage()));
}

} // namespace
