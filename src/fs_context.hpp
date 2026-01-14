#pragma once
#include "common.hpp"
#include "inode.hpp"
#include "quota.hpp"
#include "socket_server.hpp"

struct Fs {
    std::mutex mutex;
    InodeMap inodes;
    Inode root;
    double timeout{0.0};

    bool debug{false};
    bool debug_fuse{false};
    bool foreground{false};

    std::string source;
    size_t blocksize{4096};
    dev_t src_dev{0};

    bool nosplice{false};
    bool nocache{false};
    int num_threads{-1};
    bool clone_fd{false};

    std::string fuse_mount_options;
    bool direct_io{false};
    bool passthrough{false};

    bool force_uid_enabled{false};
    uid_t force_uid{0};

    bool force_gid_enabled{false};
    gid_t force_gid{0};

    struct fuse_session *se = nullptr;
    std::binary_semaphore shutdown_complete{0};

    QuotaManager quota;
    SocketServer socket_server;

    bool needs_chown() const {
        return force_uid_enabled || force_gid_enabled;
    }
};

extern Fs fs;

template <typename... Args> void debug_print(std::format_string<Args...> fmt, Args &&...args) {
    if (fs.debug) {
        std::println(stderr, "DEBUG: {}", std::format(fmt, std::forward<Args>(args)...));
    }
}

inline Inode &get_inode(fuse_ino_t ino) {
    if (ino == FUSE_ROOT_ID)
        return fs.root;
    Inode *inode = reinterpret_cast<Inode *>(ino);
    if (inode->fd == -1) {
        error_print("INTERNAL ERROR: Unknown inode {}", ino);
        abort();
    }
    return *inode;
}
