#define _GNU_SOURCE

#include "landlockd/landlock.h"
#include "landlock_compat.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int landlockd_restrict_self_e2big_warned;

__attribute__((weak)) long landlock_create_ruleset_syscall(const void *attr,
                                                           size_t size,
                                                           unsigned int flags) {
  return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

__attribute__((weak)) long landlock_add_rule_syscall(int ruleset_fd,
                                                     int rule_type,
                                                     const void *rule_attr,
                                                     unsigned int flags) {
  return syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
                 flags);
}

__attribute__((weak)) long landlock_restrict_self_syscall(int ruleset_fd,
                                                          uint32_t flags) {
  return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

__attribute__((weak)) int landlock_abi_version(void) {
  int abi_version;

  if (landlock_probe_abi(&abi_version) == 0) {
    return abi_version;
  }
  if (errno == ENOSYS || errno == EOPNOTSUPP) {
    return 0;
  }
  return -1;
}

int landlock_probe_abi(int *abi_version) {
  long probed_abi;
  int saved_errno;

  if (abi_version == NULL) {
    errno = EINVAL;
    return -1;
  }

  saved_errno = errno;
  probed_abi =
      landlock_create_ruleset_syscall(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (probed_abi < 0) {
    return -1;
  }

  *abi_version = (int)probed_abi;
  errno = saved_errno;
  return 0;
}

int landlock_create_ruleset_for_abi(int abi_version,
                                    const struct landlock_ruleset_attr *attr,
                                    unsigned int flags) {
  int saved_errno;
  long fd;
  size_t size;
  const void *sys_attr;
  struct landlock_ruleset_attr_compat compat_attr;

  if (abi_version <= 0) {
    errno = ENOSYS;
    return -1;
  }

  if (flags & LANDLOCK_CREATE_RULESET_VERSION) {
    errno = EINVAL;
    return -1;
  }

  if (abi_version <= 3) {
    size = LANDLOCKD_RULESET_ATTR_FS_SIZE;
  } else if (abi_version <= 5) {
    size = LANDLOCKD_RULESET_ATTR_NET_SIZE;
  } else {
    size = sizeof(compat_attr);
  }

  sys_attr = attr;
  if (attr != NULL) {
    memset(&compat_attr, 0, sizeof(compat_attr));
    compat_attr.handled_access_fs = attr->handled_access_fs;
#if LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET
    compat_attr.handled_access_net = attr->handled_access_net;
#endif
#if LANDLOCKD_RULESET_ATTR_HAS_SCOPED
    compat_attr.scoped = attr->scoped;
#endif
    sys_attr = &compat_attr;
  }

  saved_errno = errno;
  fd = landlock_create_ruleset_syscall(sys_attr, size, flags);
  if (fd < 0) {
    return -1;
  }
  errno = saved_errno;
  return (int)fd;
}

int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                            size_t size, unsigned int flags) {
  int saved_errno;
  long fd;

  if (flags & LANDLOCK_CREATE_RULESET_VERSION) {
    errno = EINVAL;
    return -1;
  }

  saved_errno = errno;
  fd = landlock_create_ruleset_syscall(attr, size, flags);
  if (fd < 0) {
    return -1;
  }
  errno = saved_errno;
  return (int)fd;
}

int landlock_add_fs_rule(int ruleset_fd,
                         const struct landlock_path_beneath_attr *attr,
                         unsigned int flags) {
  if (ruleset_fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (attr == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (attr->parent_fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (attr->allowed_access == 0ULL) {
    errno = EINVAL;
    return -1;
  }

  return landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, attr, flags);
}

int landlock_add_net_rule(int ruleset_fd,
                          const struct landlock_net_port_attr *attr,
                          unsigned int flags) {
  if (attr == NULL) {
    errno = EINVAL;
    return -1;
  }

  return landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, attr, flags);
}

int landlock_add_rule(int ruleset_fd, int rule_type, const void *rule_attr,
                      unsigned int flags) {
  long rc;
  int saved_errno;
  const struct landlock_net_port_attr *net_port_attr;

  if (ruleset_fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (rule_attr == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (rule_type == LANDLOCK_RULE_NET_PORT) {
    net_port_attr = rule_attr;
    if (net_port_attr->allowed_access == 0ULL) {
      errno = EINVAL;
      return -1;
    }
  }

  saved_errno = errno;
  rc = landlock_add_rule_syscall(ruleset_fd, rule_type, rule_attr, flags);
  if (rc < 0) {
    return -1;
  }
  errno = saved_errno;
  return 0;
}

int landlock_restrict_self(int ruleset_fd, unsigned int flags) {
  long rc;
  int saved_errno;

  if (flags != 0) {
    errno = EINVAL;
    return -1;
  }

  saved_errno = errno;
  rc = landlock_restrict_self_syscall(ruleset_fd, flags);
  if (rc < 0) {
    saved_errno = errno;
    if (saved_errno == E2BIG && !landlockd_restrict_self_e2big_warned) {
      landlockd_restrict_self_e2big_warned = 1;
      fprintf(stderr,
              "landlock_restrict_self failed with E2BIG; check no_new_privs\n");
    }
    errno = saved_errno;
    return -1;
  }
  errno = saved_errno;
  return 0;
}
