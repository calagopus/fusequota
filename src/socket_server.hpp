#pragma once
#include "common.hpp"
#include <thread>
#include <string>

class SocketServer
{
public:
	SocketServer() = default;
	~SocketServer();

	void start(const std::string &path);

private:
	void run(std::stop_token st);
	void handle_client(int client_fd);

	std::string socket_path;
	std::jthread server_thread;
};