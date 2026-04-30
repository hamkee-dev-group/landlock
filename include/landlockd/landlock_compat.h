#ifndef LANDLOCKD_LANDLOCK_COMPAT_H
#define LANDLOCKD_LANDLOCK_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#if defined(__has_include)
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#define LANDLOCKD_HAVE_LINUX_LANDLOCK_H 1
#if defined(LANDLOCK_ACCESS_NET_BIND_TCP) || \
    defined(LANDLOCK_ACCESS_NET_CONNECT_TCP)
#define LANDLOCKD_HAVE_LINUX_LANDLOCK_NET_PORT 1
#endif
#if defined(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET) || \
    defined(LANDLOCK_SCOPE_SIGNAL)
#define LANDLOCKD_HAVE_LINUX_LANDLOCK_SCOPE 1
#endif
#endif
#endif

#if defined(LANDLOCKD_HAVE_LINUX_LANDLOCK_H)
#if defined(LANDLOCKD_HAVE_LINUX_LANDLOCK_NET_PORT)
#define LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET 1
#else
#define LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET 0
#endif
#if defined(LANDLOCKD_HAVE_LINUX_LANDLOCK_SCOPE)
#define LANDLOCKD_RULESET_ATTR_HAS_SCOPED 1
#else
#define LANDLOCKD_RULESET_ATTR_HAS_SCOPED 0
#endif
#else
#define LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET 1
#define LANDLOCKD_RULESET_ATTR_HAS_SCOPED 1
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif
#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#endif
#ifndef LANDLOCK_ACCESS_FS_REMOVE_DIR
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#endif
#ifndef LANDLOCK_ACCESS_FS_REMOVE_FILE
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_CHAR
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_DIR
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_REG
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_SOCK
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_FIFO
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_BLOCK
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_SYM
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

struct landlock_ruleset_attr_compat {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;
  uint64_t scoped;
};

#define LANDLOCKD_RULESET_ATTR_FS_SIZE \
  offsetof(struct landlock_ruleset_attr_compat, handled_access_net)
#define LANDLOCKD_RULESET_ATTR_NET_SIZE \
  offsetof(struct landlock_ruleset_attr_compat, scoped)

#ifndef LANDLOCKD_HAVE_LINUX_LANDLOCK_H
struct landlock_ruleset_attr {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;
  uint64_t scoped;
};

struct landlock_path_beneath_attr {
  uint64_t allowed_access;
  int32_t parent_fd;
} __attribute__((packed));
#endif

#if !defined(LANDLOCKD_HAVE_LINUX_LANDLOCK_H) || \
    !defined(LANDLOCKD_HAVE_LINUX_LANDLOCK_NET_PORT)
struct landlock_net_port_attr {
  uint64_t allowed_access;
  uint64_t port;
};
#endif

#endif
