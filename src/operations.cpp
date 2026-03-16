#include "operations.hpp"
#include <sys/xattr.h>
#include "fs_context.hpp"
#include "passthrough_helpers.hpp"

Fs fs{};

#define FUSE_BUF_COPY_FLAGS                                                                        \
    (fs.nosplice ? FUSE_BUF_NO_SPLICE : static_cast<fuse_buf_copy_flags>(FUSE_BUF_SPLICE_MOVE))

static int get_fs_fd(fuse_ino_t ino) {
    return get_inode(ino).fd;
}

static int with_fd_path(int fd, const std::function<int(const char *)> &f) {
#ifdef __FreeBSD__
    struct kinfo_file kf;
    kf.kf_structsize = sizeof(kf);
    if (fcntl(fd, F_KINFO, &kf) == -1)
        return -1;
    return f(kf.kf_path);
#else // Linux
    std::string procname = std::format("/proc/self/fd/{}", fd);
    return f(procname.c_str());
#endif
}

struct DirHandle {
    DIR *dp{nullptr};
    off_t offset{0};

    DirHandle() = default;
    DirHandle(const DirHandle &) = delete;
    DirHandle &operator=(const DirHandle &) = delete;
    ~DirHandle() {
        if (dp)
            closedir(dp);
    }
};

static DirHandle *get_dir_handle(fuse_file_info *fi) {
    return reinterpret_cast<DirHandle *>(fi->fh);
}

static void enforce_ownership(int dirfd, const char *name, int fd = -1) {
    if (!fs.needs_chown())
        return;

    uid_t u = fs.force_uid_enabled ? fs.force_uid : -1;
    gid_t g = fs.force_gid_enabled ? fs.force_gid : -1;

    int res = 0;
    if (fd >= 0) {
        res = fchown(fd, u, g);
    } else {
        res = fchownat(dirfd, name, u, g, AT_SYMLINK_NOFOLLOW);
    }

    if (res == -1) {
        if (name)
            error_print("WARNING: Failed to chown created file '{}': {}", name, errno);
        else
            error_print("WARNING: Failed to fchown fd {}: {}", fd, errno);
    }
}

static void forget_one(fuse_ino_t ino, uint64_t n) {
    Inode &inode = get_inode(ino);
    std::unique_lock<std::mutex> l{inode.m};

    if (std::cmp_greater(n, inode.nlookup.load())) {
        error_print("INTERNAL ERROR: Negative lookup count for inode {}", inode.src_ino);
        abort();
    }
    inode.nlookup -= n;

    debug_print("forget: inode {} count now {}", inode.src_ino, inode.nlookup.load());

    if (!inode.nlookup) {
        l.unlock();
        std::lock_guard<std::mutex> g_fs{fs.mutex};

        if (!inode.nlookup) {
            debug_print("forget: cleaning up inode {}", inode.src_ino);
            fs.inodes.erase({inode.src_ino, inode.src_dev});
        }
    }
}

static int do_lookup(fuse_ino_t parent, const char *name, fuse_entry_param *e) {
    debug_print("lookup(): name={}, parent={}", name, parent);

    memset(e, 0, sizeof(*e));
    e->attr_timeout = fs.timeout;
    e->entry_timeout = fs.timeout;

    UniqueFd newfd(openat(get_fs_fd(parent), name, O_PATH | O_NOFOLLOW));
    if (!newfd.is_valid())
        return errno;

    if (fstatat(newfd.get(), "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) == -1) {
        int saveerr = errno;
        debug_print("lookup(): fstatat failed");
        return saveerr;
    }

    if (e->attr.st_dev != fs.src_dev) {
        std::println(stderr, "WARNING: Mountpoints in the source directory tree will be hidden.");
        return ENOTSUP;
    } else if (e->attr.st_ino == FUSE_ROOT_ID) {
        error_print("Source directory tree must not include inode {}", FUSE_ROOT_ID);
        return EIO;
    }

    SrcId id{e->attr.st_ino, e->attr.st_dev};
    std::unique_lock<std::mutex> fs_lock{fs.mutex};

    Inode *inode_p;
    try {
        inode_p = &fs.inodes[id];
    } catch (const std::bad_alloc &) {
        return ENOMEM;
    }

    e->ino = reinterpret_cast<fuse_ino_t>(inode_p);
    Inode &inode{*inode_p};
    e->generation = inode.generation;

    inode.known_size = e->attr.st_size;

    if (inode.fd == -ENOENT) {
        debug_print("lookup(): inode {} recycled; generation={}", e->attr.st_ino, inode.generation);
    }

    if (inode.fd > 0) {
        debug_print("lookup(): inode {} (userspace) already known; fd = {}", e->attr.st_ino,
                    inode.fd);
        inode.nlookup++;
        fs_lock.unlock();
    } else {
        std::lock_guard<std::mutex> g{inode.m};
        inode.src_ino = e->attr.st_ino;
        inode.src_dev = e->attr.st_dev;
        inode.nlookup++;
        inode.fd = newfd.release();
        fs_lock.unlock();
        debug_print("lookup(): created userspace inode {}; fd = {}", e->attr.st_ino, inode.fd);
    }

    return 0;
}

static void sfs_init(void *userdata, fuse_conn_info *conn) {
    (void)userdata;

    if (!fuse_set_feature_flag(conn, FUSE_CAP_PASSTHROUGH))
        fs.passthrough = false;

    if (fs.timeout)
        fuse_set_feature_flag(conn, FUSE_CAP_WRITEBACK_CACHE);

    fuse_set_feature_flag(conn, FUSE_CAP_FLOCK_LOCKS);

    if (fs.nosplice) {
        fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_READ);
        fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_WRITE);
        fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_MOVE);
    } else {
        fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_WRITE);
        fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_READ);
        fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_MOVE);
    }

    fuse_set_feature_flag(conn, FUSE_CAP_NO_EXPORT_SUPPORT);
    conn->no_interrupt = 1;
    conn->max_readahead = 4 * 1024 * 1024;
    conn->max_write = 4 * 1024 * 1024;
    conn->max_background = 64;
    conn->congestion_threshold = 48;
}

static void sfs_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
    struct stat attr;
    int fd = fi ? fi->fh : get_inode(ino).fd;

    if (fstatat(fd, "", &attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) == -1) {
        fuse_reply_err(req, errno);
        return;
    }
    fuse_reply_attr(req, &attr, fs.timeout);
}

static void sfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int valid,
                        struct fuse_file_info *fi) {
    Inode &inode = get_inode(ino);
    int ifd = inode.fd;
    int res = 0;

    if (valid & FUSE_SET_ATTR_MODE) {
        res = with_fd_path(ifd,
                           [attr](const char *procname) { return chmod(procname, attr->st_mode); });
        if (res == -1) {
            fuse_reply_err(req, errno);
            return;
        }
    }

    if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
        uid_t u = (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : static_cast<uid_t>(-1);
        gid_t g = (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : static_cast<gid_t>(-1);

        res = with_fd_path(ifd, [u, g](const char *procname) { return lchown(procname, u, g); });
        if (res == -1) {
            fuse_reply_err(req, errno);
            return;
        }
    }

    if (valid & FUSE_SET_ATTR_SIZE) {
        std::unique_lock<std::mutex> g{inode.m};

        uint64_t old_size = inode.known_size;
        uint64_t new_size = attr->st_size;
        bool quota_changed = false;

        if (new_size > old_size) {
            if (!fs.quota.reserve(old_size, new_size)) {
                fuse_reply_err(req, ENOSPC);
                return;
            }
            quota_changed = true;
        }

        if (fi) {
            res = ftruncate(fi->fh, attr->st_size);
        } else {
            res = with_fd_path(
                ifd, [attr](const char *procname) { return truncate(procname, attr->st_size); });
        }

        if (res == -1) {
            if (quota_changed)
                fs.quota.release(new_size, old_size);
            fuse_reply_err(req, errno);
            return;
        }

        if (new_size < old_size)
            fs.quota.release(old_size, new_size);

        inode.known_size = new_size;
        g.unlock();
    }

    if (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
        struct timespec tv[2];

        tv[0].tv_sec = 0;
        tv[0].tv_nsec = UTIME_OMIT;
        tv[1].tv_sec = 0;
        tv[1].tv_nsec = UTIME_OMIT;

        if (valid & FUSE_SET_ATTR_ATIME) {
            if (valid & FUSE_SET_ATTR_ATIME_NOW) {
                tv[0].tv_nsec = UTIME_NOW;
            } else {
                tv[0] = attr->st_atim;
            }
        }

        if (valid & FUSE_SET_ATTR_MTIME) {
            if (valid & FUSE_SET_ATTR_MTIME_NOW) {
                tv[1].tv_nsec = UTIME_NOW;
            } else {
                tv[1] = attr->st_mtim;
            }
        }

        if (fi) {
            res = futimens(fi->fh, tv);
        } else {
            std::string procname = std::format("/proc/self/fd/{}", ifd);
            res = utimensat(AT_FDCWD, procname.c_str(), tv, 0);
        }

        if (res == -1) {
            fuse_reply_err(req, errno);
            return;
        }
    }

    return sfs_getattr(req, ino, fi);
}

static void sfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    fuse_entry_param e{};
    auto err = do_lookup(parent, name, &e);
    if (err == ENOENT) {
        e.attr_timeout = fs.timeout;
        e.entry_timeout = fs.timeout;
        e.ino = e.attr.st_ino = 0;
        fuse_reply_entry(req, &e);
    } else if (err) {
        if (err == ENFILE || err == EMFILE)
            error_print("Reached maximum number of file descriptors.");
        fuse_reply_err(req, err);
    } else {
        fuse_reply_entry(req, &e);
    }
}

static void mknod_symlink(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
                          dev_t rdev, const char *link) {
    Inode &inode_p = get_inode(parent);

    if (fs.quota.is_enabled()) {
        if (S_ISDIR(mode)) {
            if (!fs.quota.reserve(0, fs.blocksize)) {
                fuse_reply_err(req, ENOSPC);
                return;
            }
        } else if (S_ISLNK(mode) && link) {
            uint64_t link_size = strlen(link);
            if (!fs.quota.reserve(0, link_size)) {
                fuse_reply_err(req, ENOSPC);
                return;
            }
        } else if (S_ISREG(mode)) {
            if (!fs.quota.check_available(0)) {
                fuse_reply_err(req, ENOSPC);
                return;
            }
        }
    }

    int res;
    if (S_ISDIR(mode))
        res = mkdirat(inode_p.fd, name, mode);
    else if (S_ISLNK(mode))
        res = symlinkat(link, inode_p.fd, name);
    else
        res = mknodat(inode_p.fd, name, mode, rdev);

    int saverr = errno;
    if (res == -1) {
        if (fs.quota.is_enabled()) {
            if (S_ISDIR(mode)) {
                fs.quota.release(fs.blocksize, 0);
            } else if (S_ISLNK(mode) && link) {
                fs.quota.release(strlen(link), 0);
            }
        }

        if (saverr == ENFILE || saverr == EMFILE)
            error_print("Reached maximum number of file descriptors.");
        fuse_reply_err(req, saverr);
        return;
    }

    enforce_ownership(inode_p.fd, name, -1);

    fuse_entry_param e;
    saverr = do_lookup(parent, name, &e);
    if (saverr) {
        fuse_reply_err(req, saverr);
        return;
    }
    fuse_reply_entry(req, &e);
}

static void sfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
                      dev_t rdev) {
    mknod_symlink(req, parent, name, mode, rdev, nullptr);
}

static void sfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
    mknod_symlink(req, parent, name, S_IFDIR | mode, 0, nullptr);
}

static void sfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
    mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}

static void sfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent, const char *name) {
    Inode &inode = get_inode(ino);
    Inode &inode_p = get_inode(parent);
    fuse_entry_param e{};

    e.attr_timeout = fs.timeout;
    e.entry_timeout = fs.timeout;

    std::string procname = std::format("/proc/self/fd/{}", inode.fd);

    if (linkat(AT_FDCWD, procname.c_str(), inode_p.fd, name, AT_SYMLINK_FOLLOW) == -1) {
        fuse_reply_err(req, errno);
        return;
    }

    if (fstatat(inode.fd, "", &e.attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) == -1) {
        fuse_reply_err(req, errno);
        return;
    }

    e.ino = reinterpret_cast<fuse_ino_t>(&inode);
    inode.nlookup++;
    fuse_reply_entry(req, &e);
}

static void sfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    Inode &inode_p = get_inode(parent);

    uint64_t dir_size = 0;
    if (fs.quota.is_enabled()) {
        struct stat st;
        if (fstatat(inode_p.fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            dir_size = st.st_size;
        }
    }

    std::lock_guard<std::mutex> g{inode_p.m};
    auto res = unlinkat(inode_p.fd, name, AT_REMOVEDIR);
    if (res == -1) {
        fuse_reply_err(req, errno);
    } else {
        if (dir_size > 0)
            fs.quota.release(dir_size, 0);
        fuse_reply_err(req, 0);
    }
}

static void sfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent,
                       const char *newname, unsigned int flags) {
    Inode &inode_p = get_inode(parent);
    Inode &inode_np = get_inode(newparent);
    if (flags) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    uint64_t victim_size = 0;
    nlink_t victim_nlink = 0;
    if (fs.quota.is_enabled()) {
        struct stat st;
        if (fstatat(inode_np.fd, newname, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            victim_size = st.st_size;
            victim_nlink = st.st_nlink;
        }
    }

    auto res = renameat(inode_p.fd, name, inode_np.fd, newname);
    if (res == -1) {
        fuse_reply_err(req, errno);
    } else {
        if (victim_size > 0 && victim_nlink == 1)
            fs.quota.release(victim_size, 0);
        fuse_reply_err(req, 0);
    }
}

static void sfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
    Inode &inode_p = get_inode(parent);

    fuse_entry_param e;
    auto err = do_lookup(parent, name, &e);
    if (err) {
        fuse_reply_err(req, err);
        return;
    }

    auto res = unlinkat(inode_p.fd, name, 0);
    if (res == -1) {
        forget_one(e.ino, 1);
        fuse_reply_err(req, errno);
        return;
    }

    if (fs.quota.is_enabled() && e.attr.st_nlink == 1) {
        Inode &inode = get_inode(e.ino);
        std::lock_guard<std::mutex> g{inode.m};
        uint64_t size = inode.known_size;
        if (S_ISLNK(e.attr.st_mode)) {
            size = e.attr.st_size;
        }
        fs.quota.release(size, 0);
        debug_print("QUOTA: Reclaimed {} bytes from unlink", size);
    }

    if (!fs.timeout) {
        if (e.attr.st_nlink == 1) {
            Inode &inode = get_inode(e.ino);
            std::lock_guard<std::mutex> g{inode.m};
            if (inode.fd > 0 && !inode.nopen) {
                std::lock_guard<std::mutex> g_fs{fs.mutex};
                close(inode.fd);
                inode.fd = -ENOENT;
                inode.generation++;
            }
        }
    }

    forget_one(e.ino, 1);

    fuse_reply_err(req, 0);
}

static void sfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    forget_one(ino, nlookup);
    fuse_reply_none(req);
}

static void sfs_forget_multi(fuse_req_t req, size_t count, fuse_forget_data *forgets) {
    for (size_t i = 0; i < count; i++)
        forget_one(forgets[i].ino, forgets[i].nlookup);
    fuse_reply_none(req);
}

static void sfs_readlink(fuse_req_t req, fuse_ino_t ino) {
    Inode &inode = get_inode(ino);
    char buf[PATH_MAX + 1];
    auto res = readlinkat(inode.fd, "", buf, sizeof(buf));
    if (res == -1)
        fuse_reply_err(req, errno);
    else if (res == sizeof(buf))
        fuse_reply_err(req, ENAMETOOLONG);
    else {
        buf[res] = '\0';
        fuse_reply_readlink(req, buf);
    }
}

static void sfs_opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
    Inode &inode = get_inode(ino);
    auto d = std::make_unique<DirHandle>();

    std::lock_guard<std::mutex> g{inode.m};

    int fd = openat(inode.fd, ".", O_RDONLY);
    if (fd == -1) {
        fuse_reply_err(req, errno);
        return;
    }

    d->dp = fdopendir(fd);
    if (d->dp == nullptr) {
        close(fd);
        fuse_reply_err(req, errno);
        return;
    }

    d->offset = 0;
    fi->fh = reinterpret_cast<uint64_t>(d.release());

    if (fs.timeout) {
        fi->keep_cache = 1;
        fi->cache_readdir = 1;
    }
    fuse_reply_open(req, fi);
}

static bool is_dot_or_dotdot(std::string_view name) {
    return name == "." || name == "..";
}

static void do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                       fuse_file_info *fi, const int plus) {
    auto d = get_dir_handle(fi);
    Inode &inode = get_inode(ino);
    std::lock_guard<std::mutex> g{inode.m};

    std::vector<char> buf(size);
    char *p = buf.data();
    auto rem = size;
    int err = 0;

    if (offset != d->offset) {
        seekdir(d->dp, offset);
        d->offset = offset;
    }

    while (true) {
        bool did_lookup = false;
        errno = 0;
        struct dirent *entry = readdir(d->dp);
        if (!entry) {
            if (errno) {
                err = errno;
                goto error;
            }
            break;
        }
        d->offset = entry->d_off;

        fuse_entry_param e{};
        size_t entsize;

        if (plus) {
            if (is_dot_or_dotdot(entry->d_name)) {
                e.attr.st_ino = entry->d_ino;
                e.attr.st_mode = entry->d_type << 12;
            } else {
                err = do_lookup(ino, entry->d_name, &e);
                if (err)
                    goto error;
                did_lookup = true;
            }
            entsize = fuse_add_direntry_plus(req, p, rem, entry->d_name, &e, entry->d_off);
        } else {
            e.attr.st_ino = entry->d_ino;
            e.attr.st_mode = entry->d_type << 12;
            entsize = fuse_add_direntry(req, p, rem, entry->d_name, &e.attr, entry->d_off);
        }

        if (entsize > rem) {
            if (did_lookup)
                forget_one(e.ino, 1);
            break;
        }

        p += entsize;
        rem -= entsize;
    }
    err = 0;

error:
    if (err && rem == size) {
        fuse_reply_err(req, err);
    } else {
        fuse_reply_buf(req, buf.data(), size - rem);
    }
}

static void sfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                        fuse_file_info *fi) {
    do_readdir(req, ino, size, offset, fi, 0);
}

static void sfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                            fuse_file_info *fi) {
    do_readdir(req, ino, size, offset, fi, 1);
}

static void sfs_releasedir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
    (void)ino;
    auto d = get_dir_handle(fi);
    delete d;
    fuse_reply_err(req, 0);
}

static void sfs_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, fuse_file_info *fi) {
    (void)ino;
    int res;
    int fd = dirfd(get_dir_handle(fi)->dp);
    if (datasync)
        res = fdatasync(fd);
    else
        res = fsync(fd);
    fuse_reply_err(req, res == -1 ? errno : 0);
}

static void do_passthrough_open(fuse_req_t req, fuse_ino_t ino, int fd, fuse_file_info *fi) {
    bool is_write = (fi->flags & O_WRONLY) || (fi->flags & O_RDWR);

    debug_print("is_write: {}, flags: {}", is_write, fi->flags);

    Inode &inode = get_inode(ino);
    if (inode.backing_id) {
        fi->backing_id = inode.backing_id;
        debug_print("reusing existing backing_id for inode {}", ino);
    } else if (is_write) {
        debug_print("not handling fuse_passthrough due to writing.");
    } else if (!(inode.backing_id = fuse_passthrough_open(req, fd))) {
        debug_print("fuse_passthrough_open failed for inode {}, disabling rw passthrough.", ino);
    } else {
        fi->backing_id = inode.backing_id;
        debug_print("assigned new backing_id for inode {}", ino);
    }
    fi->keep_cache = false;
}

static void sfs_create_open_flags(fuse_file_info *fi) {
    if (fs.direct_io)
        fi->direct_io = 1;
    if (!fs.passthrough && (fi->flags & O_DIRECT))
        fi->direct_io = 1;
    fi->parallel_direct_writes = 1;
    fi->keep_cache = (fs.timeout != 0);
    fi->noflush = (fs.timeout == 0 && (fi->flags & O_ACCMODE) == O_RDONLY);
}

static void sfs_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
                       fuse_file_info *fi) {
    Inode &inode_p = get_inode(parent);

    debug_print("sfs_create: parent ino {}, name '{}', mode {:o}, flags {:o}", parent, name, mode,
                fi->flags);

    uint64_t old_file_size = 0;
    bool truncating_existing = false;

    if (fs.quota.is_enabled()) {
        if (fi->flags & O_TRUNC) {
            struct stat st;
            if (fstatat(inode_p.fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode)) {
                old_file_size = st.st_size;
                truncating_existing = true;
            }
        }

        if (!truncating_existing && !fs.quota.check_available(0)) {
            fuse_reply_err(req, ENOSPC);
            return;
        }
    }

    int fd = openat(inode_p.fd, name, (fi->flags | O_CREAT) & ~O_NOFOLLOW, mode);
    if (fd == -1) {
        fuse_reply_err(req, errno);
        return;
    }

    if (truncating_existing && old_file_size > 0) {
        fs.quota.release(old_file_size, 0);
        debug_print("QUOTA: Released {} bytes from O_TRUNC in create", old_file_size);
    }

    enforce_ownership(inode_p.fd, name, fd);

    fi->fh = fd;
    fuse_entry_param e;
    auto err = do_lookup(parent, name, &e);
    if (err) {
        close(fd);
        fuse_reply_err(req, err);
        return;
    }

    Inode &inode = get_inode(e.ino);
    std::lock_guard<std::mutex> g{inode.m};
    inode.nopen++;

    if (truncating_existing) {
        inode.known_size = 0;
    }

    sfs_create_open_flags(fi);

    fuse_reply_create(req, &e, fi);
}

static void sfs_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
    Inode &inode = get_inode(ino);

    uint64_t trunc_release = 0;
    if (fs.quota.is_enabled() && (fi->flags & O_TRUNC)) {
        std::lock_guard<std::mutex> g{inode.m};
        trunc_release = inode.known_size;
    }

    if (fs.timeout && (fi->flags & O_ACCMODE) == O_WRONLY) {
        fi->flags &= ~O_ACCMODE;
        fi->flags |= O_RDWR;
    }
    if (fs.timeout && fi->flags & O_APPEND)
        fi->flags &= ~O_APPEND;

    int fd = with_fd_path(inode.fd,
                          [fi](const char *buf) { return open(buf, fi->flags & ~O_NOFOLLOW); });

    if (fd == -1) {
        fuse_reply_err(req, errno);
        return;
    }

    if (trunc_release > 0) {
        fs.quota.release(trunc_release, 0);
        debug_print("QUOTA: Released {} bytes from O_TRUNC in open", trunc_release);
    }

    enforce_ownership(-1, nullptr, fd);

    std::lock_guard<std::mutex> g{inode.m};
    inode.nopen++;

    if (trunc_release > 0)
        inode.known_size = 0;

    sfs_create_open_flags(fi);
    fi->fh = fd;

    if (fs.passthrough)
        do_passthrough_open(req, ino, fd, fi);
    fuse_reply_open(req, fi);
}

static void sfs_release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
    Inode &inode = get_inode(ino);
    std::lock_guard<std::mutex> g{inode.m};
    inode.nopen--;

    if (inode.backing_id && !inode.nopen) {
        fuse_passthrough_close(req, inode.backing_id);
        inode.backing_id = 0;
    }

    close(fi->fh);
    fuse_reply_err(req, 0);
}

static void sfs_flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
    (void)ino;
    UniqueFd fd_dup(dup(fi->fh));
    fuse_reply_err(req, fd_dup.get() == -1 ? errno : 0);
}

static void sfs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, fuse_file_info *fi) {
    (void)ino;
    int res = datasync ? fdatasync(fi->fh) : fsync(fi->fh);
    fuse_reply_err(req, res == -1 ? errno : 0);
}

static void sfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi) {
    (void)ino;

    fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
    char *payload = nullptr;
    size_t payload_size = 0;
    int res = fuse_req_get_payload(req, &payload, &payload_size, NULL);

    if (res == 0 && payload_size >= size) {
        buf.buf[0].mem = payload;
        buf.buf[0].size = payload_size;
        res = pread(fi->fh, payload, size, off);
        if (res < 0) {
            fuse_reply_err(req, errno);
            return;
        }
        buf.buf[0].size = res;
    } else {
        buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
        buf.buf[0].fd = fi->fh;
        buf.buf[0].pos = off;
    }
    fuse_reply_data(req, &buf, FUSE_BUF_COPY_FLAGS);
}

static void sfs_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *in_buf, off_t off,
                          fuse_file_info *fi) {
    Inode &inode = get_inode(ino);

    size_t size = fuse_buf_size(in_buf);
    uint64_t write_end = off + size;

    bool reserved = false;
    uint64_t amount_reserved = 0;
    uint64_t pre_write_size = 0;

    {
        std::lock_guard<std::mutex> g{inode.m};
        pre_write_size = inode.known_size;

        if (write_end > pre_write_size) {
            if (!fs.quota.reserve(pre_write_size, write_end)) {
                fuse_reply_err(req, ENOSPC);
                return;
            }
            reserved = true;
            amount_reserved = write_end - pre_write_size;
            inode.known_size = write_end;
        }
    }

    fuse_bufvec out_buf = FUSE_BUFVEC_INIT(size);
    out_buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
    out_buf.buf[0].fd = fi->fh;
    out_buf.buf[0].pos = off;

    auto res = fuse_buf_copy(&out_buf, in_buf, FUSE_BUF_COPY_FLAGS);

    if (res < 0) {
        if (reserved) {
            std::lock_guard<std::mutex> g{inode.m};
            inode.known_size = pre_write_size;
            fs.quota.release(pre_write_size + amount_reserved, pre_write_size);
        }
        fuse_reply_err(req, -res);
    } else {
        if (reserved) {
            uint64_t actual_end = off + static_cast<uint64_t>(res);
            if (actual_end < write_end) {
                std::lock_guard<std::mutex> g{inode.m};

                if (inode.known_size == write_end) {
                    uint64_t corrected = std::max(pre_write_size, actual_end);
                    if (corrected < write_end) {
                        fs.quota.release(write_end, corrected);
                        inode.known_size = corrected;
                    }
                }
            }
        }
        fuse_reply_write(req, (size_t)res);
    }
}

static void sfs_statfs(fuse_req_t req, fuse_ino_t ino) {
    struct statvfs stbuf;
    if (fstatvfs(get_fs_fd(ino), &stbuf) == -1) {
        fuse_reply_err(req, errno);
        return;
    }

    if (fs.quota.is_enabled()) {
        uint64_t bs = stbuf.f_frsize > 0 ? stbuf.f_frsize : 4096;
        stbuf.f_blocks = fs.quota.get_limit() / bs;
        uint64_t used_blocks = (fs.quota.get_usage() + bs - 1) / bs;

        if (used_blocks >= stbuf.f_blocks) {
            stbuf.f_bfree = 0;
            stbuf.f_bavail = 0;
        } else {
            stbuf.f_bfree = stbuf.f_blocks - used_blocks;
            stbuf.f_bavail = stbuf.f_bfree;
        }
    }

    fuse_reply_statfs(req, &stbuf);
}

static void sfs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset, off_t length,
                          fuse_file_info *fi) {
    Inode &inode = get_inode(ino);
    uint64_t end = offset + length;

    std::unique_lock<std::mutex> g{inode.m};

    uint64_t current = inode.known_size;
    bool changing_size = !(mode & FALLOC_FL_KEEP_SIZE);
    bool reserved = false;

    if (changing_size && end > current) {
        if (!fs.quota.reserve(current, end)) {
            fuse_reply_err(req, ENOSPC);
            return;
        }
        reserved = true;
        inode.known_size = end;
    }
    g.unlock();

    int err = 0;
    if (fallocate(fi->fh, mode, offset, length) == -1)
        err = errno;

    if (err != 0) {
        if (reserved) {
            std::lock_guard<std::mutex> g2{inode.m};
            if (inode.known_size == end)
                inode.known_size = current;
            fs.quota.release(end, current);
        }
        fuse_reply_err(req, err);
    } else {
        fuse_reply_err(req, 0);
    }
}

static void sfs_flock(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi, int op) {
    (void)ino;
    auto res = flock(fi->fh, op);
    fuse_reply_err(req, res == -1 ? errno : 0);
}

static void sfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size) {
    Inode &inode = get_inode(ino);
    std::string procname = std::format("/proc/self/fd/{}", inode.fd);

    if (size) {
        std::vector<char> value(size);
        ssize_t ret = getxattr(procname.c_str(), name, value.data(), size);
        if (ret == -1)
            fuse_reply_err(req, errno);
        else
            fuse_reply_buf(req, value.data(), ret);
    } else {
        ssize_t ret = getxattr(procname.c_str(), name, nullptr, 0);
        if (ret == -1)
            fuse_reply_err(req, errno);
        else
            fuse_reply_xattr(req, ret);
    }
}

static void sfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {
    Inode &inode = get_inode(ino);
    std::string procname = std::format("/proc/self/fd/{}", inode.fd);

    if (size) {
        std::vector<char> value(size);
        ssize_t ret = listxattr(procname.c_str(), value.data(), size);
        if (ret == -1)
            fuse_reply_err(req, errno);
        else
            fuse_reply_buf(req, value.data(), ret);
    } else {
        ssize_t ret = listxattr(procname.c_str(), nullptr, 0);
        if (ret == -1)
            fuse_reply_err(req, errno);
        else
            fuse_reply_xattr(req, ret);
    }
}

static void sfs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value,
                         size_t size, int flags) {
    Inode &inode = get_inode(ino);
    std::string procname = std::format("/proc/self/fd/{}", inode.fd);
    int ret = setxattr(procname.c_str(), name, value, size, flags);
    fuse_reply_err(req, ret == -1 ? errno : 0);
}

static void sfs_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
    Inode &inode = get_inode(ino);
    std::string procname = std::format("/proc/self/fd/{}", inode.fd);
    int ret = removexattr(procname.c_str(), name);
    fuse_reply_err(req, ret == -1 ? errno : 0);
}

void assign_operations(fuse_lowlevel_ops &sfs_oper) {
    sfs_oper.init = sfs_init;
    sfs_oper.lookup = sfs_lookup;
    sfs_oper.mkdir = sfs_mkdir;
    sfs_oper.mknod = sfs_mknod;
    sfs_oper.symlink = sfs_symlink;
    sfs_oper.link = sfs_link;
    sfs_oper.unlink = sfs_unlink;
    sfs_oper.rmdir = sfs_rmdir;
    sfs_oper.rename = sfs_rename;
    sfs_oper.forget = sfs_forget;
    sfs_oper.forget_multi = sfs_forget_multi;
    sfs_oper.getattr = sfs_getattr;
    sfs_oper.setattr = sfs_setattr;
    sfs_oper.readlink = sfs_readlink;
    sfs_oper.opendir = sfs_opendir;
    sfs_oper.readdir = sfs_readdir;
    sfs_oper.readdirplus = sfs_readdirplus;
    sfs_oper.releasedir = sfs_releasedir;
    sfs_oper.fsyncdir = sfs_fsyncdir;
    sfs_oper.create = sfs_create;
    sfs_oper.open = sfs_open;
    sfs_oper.release = sfs_release;
    sfs_oper.flush = sfs_flush;
    sfs_oper.fsync = sfs_fsync;
    sfs_oper.read = sfs_read;
    sfs_oper.write_buf = sfs_write_buf;
    sfs_oper.statfs = sfs_statfs;
    sfs_oper.fallocate = sfs_fallocate;
    sfs_oper.flock = sfs_flock;
    sfs_oper.setxattr = sfs_setxattr;
    sfs_oper.getxattr = sfs_getxattr;
    sfs_oper.listxattr = sfs_listxattr;
    sfs_oper.removexattr = sfs_removexattr;
}
