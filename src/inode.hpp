#pragma once
#include "common.hpp"
#include <unordered_map>

using SrcId = std::pair<ino_t, dev_t>;

template <>
struct std::hash<SrcId>
{
	size_t operator()(const SrcId &id) const
	{
		return std::hash<ino_t>{}(id.first) ^ std::hash<dev_t>{}(id.second);
	}
};

struct Inode
{
	int fd{-1};
	dev_t src_dev{0};
	ino_t src_ino{0};
	int generation{0};
	int backing_id{0};
	uint64_t nopen{0};
	std::atomic<uint64_t> nlookup{0};
	std::mutex m;

	std::atomic<uint64_t> known_size{0};
	int stop_timeout_secs{60};

	Inode() = default;
	Inode(const Inode &) = delete;
	Inode(Inode &&) = delete;
	~Inode()
	{
		if (fd > 0)
			close(fd);
	}
};

using InodeMap = std::unordered_map<SrcId, Inode>;