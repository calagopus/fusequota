![Calagopus Logo](https://calagopus.com/fulllogo.svg)

# fusequota

FuseQuota is a small program that uses FUSE to mount a virtual filesystem which enforces a disk quota on files created within it. It is designed for usage in [Calagopus Wings](https://github.com/calagopus/wings) to limit the disk usage of servers on systems that do not support native quotas.

## Features

- Enforces a maximum disk usage quota on files created within the mounted filesystem.
- Transparent integration with existing applications using standard file operations.
- Configurable quota size via socket communication.
- Built using FUSE for cross-platform compatibility.
- Using Modern Passthrough FUSE API for better read performance.
- Supports dynamic quota adjustments without unmounting the filesystem.
- Written in C++ for performance and efficiency.

## Requirements

- C++ compiler with C++23 support
- CMake 3.24 or higher
- Ninja build system

## Building

```bash
make
```

## Testing

The test suite uses [GoogleTest](https://github.com/google/googletest). It is
picked up from the system when `libgtest-dev` (or equivalent) is installed and
downloaded by CMake otherwise.

```bash
make test
```

Unit tests cover the quota accounting and the control socket protocol.
Integration tests mount a real filesystem with the built binary and therefore
need access to `/dev/fuse`; they are skipped when it is unavailable. Set
`FUSEQUOTA_REQUIRE_FUSE=1` to turn that skip into a failure, or run only one
half with `ctest --test-dir build -L unit` / `-L integration`.
