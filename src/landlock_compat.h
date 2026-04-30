#ifndef LANDLOCK_COMPAT_H
#define LANDLOCK_COMPAT_H

#include <stdint.h>
#include <sys/syscall.h>

#if defined(__has_include)
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#define LANDLOCKD_SRC_HAVE_LINUX_LANDLOCK_H 1
#if defined(LANDLOCK_RULE_NET_PORT)
#define LANDLOCKD_SRC_HAVE_LINUX_LANDLOCK_NET_PORT 1
#endif
#endif
#endif

#include "landlockd/landlock_compat.h"

#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__) && defined(__ILP32__)
#define __NR_landlock_create_ruleset (0x40000000 + 444)
#define __NR_landlock_add_rule (0x40000000 + 445)
#define __NR_landlock_restrict_self (0x40000000 + 446)
#elif defined(__mips__)
#define __NR_landlock_create_ruleset (__NR_Linux + 444)
#define __NR_landlock_add_rule (__NR_Linux + 445)
#define __NR_landlock_restrict_self (__NR_Linux + 446)
#else
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#endif

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset __NR_landlock_create_ruleset
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule __NR_landlock_add_rule
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self __NR_landlock_restrict_self
#endif

#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

#if defined(LANDLOCKD_SRC_HAVE_LINUX_LANDLOCK_H) && \
    !defined(LANDLOCKD_SRC_HAVE_LINUX_LANDLOCK_NET_PORT)
struct landlock_net_port_attr {
  uint64_t allowed_access;
  uint64_t port;
};
#endif

#endif
