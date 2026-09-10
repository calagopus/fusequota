#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>
#include "common.hpp"

namespace {

bool fd_is_open(int fd) {
    return fcntl(fd, F_GETFD) != -1;
}

int open_null() {
    int fd = open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return fd;
}

TEST(UniqueFd, DefaultConstructedIsInvalid) {
    UniqueFd fd;
    EXPECT_FALSE(fd.is_valid());
    EXPECT_EQ(fd.get(), -1);
    EXPECT_EQ(static_cast<int>(fd), -1);
}

TEST(UniqueFd, WrapsAndClosesOnDestruction) {
    int raw = open_null();
    {
        UniqueFd fd(raw);
        EXPECT_TRUE(fd.is_valid());
        EXPECT_EQ(fd.get(), raw);
        EXPECT_TRUE(fd_is_open(raw));
    }
    EXPECT_FALSE(fd_is_open(raw));
}

TEST(UniqueFd, MoveConstructTransfersOwnership) {
    int raw = open_null();
    UniqueFd a(raw);
    UniqueFd b(std::move(a));
    EXPECT_FALSE(a.is_valid());
    EXPECT_EQ(b.get(), raw);
    EXPECT_TRUE(fd_is_open(raw));
}

TEST(UniqueFd, MoveAssignClosesPreviousFd) {
    int first = open_null();
    int second = open_null();
    UniqueFd a(first);
    UniqueFd b(second);
    a = std::move(b);
    EXPECT_FALSE(fd_is_open(first));
    EXPECT_TRUE(fd_is_open(second));
    EXPECT_EQ(a.get(), second);
    EXPECT_FALSE(b.is_valid());
}

TEST(UniqueFd, SelfMoveAssignKeepsFd) {
    int raw = open_null();
    UniqueFd a(raw);
    UniqueFd &alias = a;
    a = std::move(alias);
    EXPECT_EQ(a.get(), raw);
    EXPECT_TRUE(fd_is_open(raw));
}

TEST(UniqueFd, ResetClosesAndReplaces) {
    int first = open_null();
    int second = open_null();
    UniqueFd fd(first);
    fd.reset(second);
    EXPECT_FALSE(fd_is_open(first));
    EXPECT_EQ(fd.get(), second);
    fd.reset();
    EXPECT_FALSE(fd_is_open(second));
    EXPECT_FALSE(fd.is_valid());
}

TEST(UniqueFd, ReleaseGivesUpOwnershipWithoutClosing) {
    int raw = open_null();
    int released;
    {
        UniqueFd fd(raw);
        released = fd.release();
        EXPECT_FALSE(fd.is_valid());
    }
    EXPECT_EQ(released, raw);
    EXPECT_TRUE(fd_is_open(raw));
    close(raw);
}

} // namespace
