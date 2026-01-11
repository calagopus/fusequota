#include "quota.hpp"
#include "inode.hpp"
#include <unordered_set>

QuotaManager::~QuotaManager()
{
	// jthread automatically requests stop and joins on destruction
}

void QuotaManager::init(const std::string &source_path, uint64_t limit, int rescan_seconds)
{
	source_dir = source_path;
	quota_limit = limit;
	rescan_interval = std::chrono::seconds(rescan_seconds);
	enabled = true;

	calculate_usage();

	if (rescan_interval.count() > 0)
	{
		std::println("QUOTA: Starting background rescan thread (Interval: {}s)", rescan_seconds);
		scanner_thread = std::jthread(std::bind_front(&QuotaManager::background_scanner, this));
	}
}

void QuotaManager::calculate_usage()
{
	namespace fsys = std::filesystem;

	std::unordered_set<SrcId> seen_inodes;
	uint64_t total = 0;

	try
	{
		for (const auto &entry : fsys::recursive_directory_iterator(source_dir))
		{
			if (entry.is_regular_file())
			{
				struct stat st;
				if (stat(entry.path().c_str(), &st) == 0)
				{
					SrcId id{st.st_ino, st.st_dev};
					if (seen_inodes.find(id) == seen_inodes.end())
					{
						seen_inodes.insert(id);
						total += st.st_size;
					}
				}
			}
		}

		uint64_t old = used_bytes.exchange(total);
		(void)old;
	}
	catch (const std::exception &e)
	{
		std::println(stderr, "QUOTA ERROR: Failed to scan source directory: {}", e.what());
	}
}

void QuotaManager::background_scanner(std::stop_token st)
{
	while (!st.stop_requested())
	{
		if (std::this_thread::sleep_for(rescan_interval); st.stop_requested())
		{
			break;
		}

		uint64_t pre_scan = used_bytes.load();
		calculate_usage();
		uint64_t post_scan = used_bytes.load();

		if (pre_scan != post_scan)
		{
			int64_t diff = static_cast<int64_t>(post_scan) - static_cast<int64_t>(pre_scan);
			if (std::abs(diff) > 1024 * 1024)
			{
				std::println("QUOTA RESCAN: Corrected usage drift. Old: {}, New: {} (Delta: {})",
										 pre_scan, post_scan, diff);
			}
		}
	}
}

bool QuotaManager::reserve(uint64_t current_file_size, uint64_t new_file_size)
{
	if (!enabled)
		return true;
	if (new_file_size <= current_file_size)
		return true;

	uint64_t delta = new_file_size - current_file_size;
	uint64_t current_usage = used_bytes.load();
	uint64_t limit = quota_limit.load();

	if (current_usage + delta > limit && limit != 0)
	{
		return false;
	}

	while (!used_bytes.compare_exchange_weak(current_usage, current_usage + delta))
	{
		limit = quota_limit.load();
		if (current_usage + delta > limit && limit != 0)
			return false;
	}
	return true;
}

void QuotaManager::release(uint64_t current_file_size, uint64_t new_file_size)
{
	if (!enabled || new_file_size >= current_file_size)
		return;

	uint64_t delta = current_file_size - new_file_size;
	uint64_t current_usage = used_bytes.load();
	while (true)
	{
		uint64_t next_usage = (delta > current_usage) ? 0 : (current_usage - delta);
		if (used_bytes.compare_exchange_weak(current_usage, next_usage))
			break;
	}
}