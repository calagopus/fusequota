#pragma once
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

class TempDir {
  public:
    TempDir() {
        std::string tmpl =
            (std::filesystem::temp_directory_path() / "fusequota-test-XXXXXX").string();
        if (!mkdtemp(tmpl.data()))
            throw std::runtime_error("mkdtemp failed");
        path_ = tmpl;
    }
    TempDir(const TempDir &) = delete;
    TempDir &operator=(const TempDir &) = delete;
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    const std::filesystem::path &path() const {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

inline int connect_unix(const std::string &path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    path.copy(addr.sun_path, path.size());
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

inline std::string unix_request(const std::string &path, std::string_view cmd) {
    int fd = connect_unix(path);
    if (fd < 0)
        throw std::runtime_error("connect failed: " + std::string(strerror(errno)));
    if (send(fd, cmd.data(), cmd.size(), 0) != static_cast<ssize_t>(cmd.size())) {
        close(fd);
        throw std::runtime_error("send failed");
    }
    std::string response;
    char buf[1024];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        response.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    return response;
}
