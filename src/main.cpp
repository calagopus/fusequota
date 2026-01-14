#include <sys/stat.h>
#include "common.hpp"
#include "cxxopts.hpp"
#include "fs_context.hpp"
#include "operations.hpp"

int main(int argc, char *argv[]) {
    cxxopts::Options opt_parser(argv[0]);
    std::vector<std::string> mount_options;
    std::vector<std::string> positional_args;

    opt_parser.add_options()("debug", "Enable filesystem debug messages")(
        "debug-fuse", "Enable libfuse debug messages")("foreground", "Run in foreground")(
        "help", "Print help")("nocache", "Disable attribute all caching")(
        "nosplice", "Do not use splice(2)")("nopassthrough", "Disable passthrough")(
        "single", "Run single-threaded")("o", "Mount options", cxxopts::value(mount_options))(
        "num-threads", "Number of threads", cxxopts::value<int>()->default_value("-1"))(
        "clone-fd", "Separate fuse device fd per thread")("direct-io", "Enable internal direct-io")(
        "quota", "Global quota limit in bytes", cxxopts::value<uint64_t>())(
        "quota-rescan-interval", "Quota background rescan interval (seconds, 0=off)",
        cxxopts::value<int>()->default_value("0"))(
        "communication-socket-path", "Path for the control socket", cxxopts::value<std::string>())(
        "uid", "Force ownership of created files to this UID", cxxopts::value<uid_t>())(
        "gid", "Force ownership of created files to this GID",
        cxxopts::value<gid_t>())("filenames", "Positional arguments",
                                 cxxopts::value<std::vector<std::string>>(positional_args));

    opt_parser.parse_positional({"filenames"});
    auto options = opt_parser.parse(argc, argv);

    if (options.count("help")) {
        std::println("Usage: {} [options] <source> <mountpoint>", argv[0]);
        std::println("{}", opt_parser.help());
        exit(0);
    }

    if (positional_args.empty()) {
        error_print("Missing source directory");
        exit(2);
    }
    fs.source = positional_args[0];

    fs.debug = options.count("debug");
    fs.debug_fuse = options.count("debug-fuse");
    fs.foreground = options.count("foreground") || fs.debug || fs.debug_fuse;
    fs.nosplice = options.count("nosplice");
    fs.passthrough = options.count("nopassthrough") == 0;
    fs.num_threads = options["num-threads"].as<int>();
    fs.clone_fd = options.count("clone-fd");
    fs.direct_io = options.count("direct-io");
    fs.timeout = options.count("nocache") ? 0.0 : 86400.0;

    bool start_quota = false;
    uint64_t quota_limit = 0;
    int quota_interval = 0;

    if (options.count("quota")) {
        start_quota = true;
        quota_limit = options["quota"].as<uint64_t>();
        quota_interval = options["quota-rescan-interval"].as<int>();
    }

    bool start_socket = false;
    std::string socket_path;

    if (options.count("communication-socket-path")) {
        std::string raw_path = options["communication-socket-path"].as<std::string>();

        std::error_code ec;
        std::filesystem::path p = std::filesystem::absolute(raw_path, ec);
        if (ec) {
            error_print("Invalid socket path: {}", raw_path);
            exit(1);
        }

        if (!std::filesystem::exists(p.parent_path())) {
            error_print("Socket parent directory does not exist: {}", p.parent_path().string());
            exit(1);
        }

        socket_path = p.string();
        start_socket = true;
    }

    if (options.count("uid")) {
        fs.force_uid = options["uid"].as<uid_t>();
        fs.force_uid_enabled = true;
    }
    if (options.count("gid")) {
        fs.force_gid = options["gid"].as<gid_t>();
        fs.force_gid_enabled = true;
    }

    std::unique_ptr<char, decltype(&free)> resolved_path(realpath(fs.source.c_str(), NULL), &free);
    if (resolved_path)
        fs.source = std::string{resolved_path.get()};

    struct stat statbuf;
    if (lstat(fs.source.c_str(), &statbuf) == -1)
        err(1, "ERROR: failed to stat source (\"%s\")", fs.source.c_str());
    if (!S_ISDIR(statbuf.st_mode))
        errx(1, "ERROR: source is not a directory");
    fs.src_dev = statbuf.st_dev;

    fs.root.fd = open(fs.source.c_str(), O_PATH);
    if (fs.root.fd == -1)
        err(1, "ERROR: open source");

    std::string final_opts;
    for (const auto &opt : mount_options)
        final_opts += opt + ",";
    final_opts += "fsname=" + fs.source + ",default_permissions";
    fs.fuse_mount_options = final_opts;

    fuse_args args = FUSE_ARGS_INIT(0, nullptr);
    fuse_opt_add_arg(&args, argv[0]);
    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args, fs.fuse_mount_options.c_str());
    if (fs.debug_fuse)
        fuse_opt_add_arg(&args, "-odebug");

    fuse_lowlevel_ops sfs_oper{};
    assign_operations(sfs_oper);

    const char *mountpoint =
        positional_args.size() > 1 ? positional_args[1].c_str() : argv[argc - 1];

    struct fuse_session *se = fuse_session_new(&args, &sfs_oper, sizeof(sfs_oper), &fs);
    if (!se)
        return 1;

    fs.se = se;

    auto se_guard =
        std::unique_ptr<fuse_session, decltype(&fuse_session_destroy)>(se, &fuse_session_destroy);

    if (fuse_set_signal_handlers(se) != 0)
        return 1;
    if (fuse_set_fail_signal_handlers(se) != 0) {
        fuse_remove_signal_handlers(se);
        return 1;
    }

    if (fuse_session_mount(se, mountpoint) != 0) {
        fuse_remove_signal_handlers(se);
        return 1;
    }

    if (fuse_daemonize(fs.foreground) != 0) {
        error_print("Failed to daemonize process");
        fuse_remove_signal_handlers(se);
        return 1;
    }

    if (start_quota) {
        fs.quota.init(fs.source, quota_limit, quota_interval);
    }

    if (start_socket) {
        fs.socket_server.start(socket_path);
        if (fs.foreground) {
            std::println("Control socket started at {}", socket_path);
        }
    }

    struct fuse_loop_config *loop_config = fuse_loop_cfg_create();
    auto loop_guard = std::unique_ptr<fuse_loop_config, decltype(&fuse_loop_cfg_destroy)>(
        loop_config, &fuse_loop_cfg_destroy);

    if (fs.num_threads != -1)
        fuse_loop_cfg_set_max_threads(loop_config, fs.num_threads);
    fuse_loop_cfg_set_clone_fd(loop_config, fs.clone_fd);

    int ret =
        options.count("single") ? fuse_session_loop(se) : fuse_session_loop_mt(se, loop_config);

    fuse_session_unmount(se);
    fuse_remove_signal_handlers(se);

    fs.shutdown_complete.release();

    fuse_opt_free_args(&args);

    return ret;
}
