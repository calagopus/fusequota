# fusequota

FuseQuota is a small program that uses FUSE to mount a virtual filesystem which enforces a disk quota on files created within it. It is designed for usage in [Calagopus Wings](https://github.com/calagopus/wings) to limit the disk usage of servers on systems that do not support native quotas.

## Features

- Enforces a maximum disk usage quota on files created within the mounted filesystem.
- Transparent integration with existing applications using standard file operations.
- Configurable quota size via socket communication.
- Built using FUSE for cross-platform compatibility.
- Written in C++ for performance and efficiency.

## Requirements

- C++ compiler with C++23 support
- CMake 3.20 or higher
- Ninja build system

## Building

```bash
make
```
