#include "socket_server.hpp"
#include <algorithm>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include "fs_context.hpp"

SocketServer::~SocketServer() {
    if (!socket_path.empty()) {
        unlink(socket_path.c_str());
    }
}

void SocketServer::start(const std::string &path) {
    socket_path = path;
    server_thread = std::jthread(std::bind_front(&SocketServer::run, this));
}

bool SocketServer::handle_client(int client_fd) {
    UniqueFd fd(client_fd);
    char buffer[1024];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    if (n <= 0)
        return true;

    buffer[n] = '\0';
    std::string_view request(buffer);

    auto trim = [](std::string_view s) {
        size_t first = s.find_first_not_of(" \n\r\t");
        if (first == std::string_view::npos)
            return std::string_view{};
        size_t last = s.find_last_not_of(" \n\r\t");
        return s.substr(first, (last - first + 1));
    };

    std::string_view cmd = trim(request);
    std::string response;

    if (cmd == "get quota_used") {
        response = std::format("quota_used = {}\nOK\n", fs.quota.get_usage());
    } else if (cmd.starts_with("set quota = ")) {
        try {
            std::string val_str{cmd.substr(12)};
            uint64_t new_limit = std::stoull(val_str);
            fs.quota.set_limit(new_limit);
            response = "OK\n";
        } catch (...) {
            response = "ERROR: Invalid value\n";
        }
    } else if (cmd.starts_with("set quota_used = ")) {
        try {
            std::string val_str{cmd.substr(17)};
            uint64_t new_usage = std::stoull(val_str);

            fs.quota.set_usage(new_usage);
            response = "OK\n";
        } catch (...) {
            response = "ERROR: Invalid value\n";
        }
    } else if (cmd.starts_with("add quota_used = ")) {
        try {
            std::string val_str{cmd.substr(17)};
            uint64_t add_val = std::stoull(val_str);

            uint64_t current = fs.quota.get_usage();
            fs.quota.set_usage(current + add_val);
            response = "OK\n";
        } catch (...) {
            response = "ERROR: Invalid value\n";
        }
    } else if (cmd.starts_with("rem quota_used = ")) {
        try {
            std::string val_str{cmd.substr(17)};
            uint64_t rem_val = std::stoull(val_str);

            uint64_t current = fs.quota.get_usage();
            if (rem_val > current) {
                fs.quota.set_usage(0);
            } else {
                fs.quota.set_usage(current - rem_val);
            }
            response = "OK\n";
        } catch (...) {
            response = "ERROR: Invalid value\n";
        }
    } else if (cmd == "do end") {
        if (fs.se) {
            fuse_session_exit(fs.se);
        }

        response = "OK\n";
        send(fd, response.data(), response.size(), 0);
        return false;
    } else {
        response = "ERROR: Unknown command\n";
    }

    send(fd, response.data(), response.size(), 0);
    return true;
}

void SocketServer::run(std::stop_token st) {
    UniqueFd server_fd(socket(AF_UNIX, SOCK_STREAM, 0));
    if (!server_fd.is_valid())
        return;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    unlink(socket_path.c_str());

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        error_print("Socket bind failed at {}", socket_path);
        return;
    }

    if (listen(server_fd, 5) == -1)
        return;

    timeval tv{.tv_sec = 1, .tv_usec = 0};
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (!st.stop_requested()) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            if (!handle_client(client_fd)) {
                break;
            }
        }
    }
}
