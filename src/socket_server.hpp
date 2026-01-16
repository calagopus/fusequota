#pragma once
#include <string>
#include <thread>
#include "common.hpp"

class SocketServer {
  public:
    SocketServer() = default;
    ~SocketServer();

    void start(const std::string &path);

  private:
    void run(std::stop_token st);
    bool handle_client(int client_fd);

    std::string socket_path;
    std::jthread server_thread;
};
