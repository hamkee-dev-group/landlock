#ifndef LANDLOCKD_SECCOMP_NOTIFY_PROBE_H
#define LANDLOCKD_SECCOMP_NOTIFY_PROBE_H

#include <linux/types.h>

#if defined(__has_include)
#if __has_include(<linux/seccomp.h>)
#include <linux/seccomp.h>
#endif
#if __has_include(<sys/syscall.h>)
#include <sys/syscall.h>
#endif
#endif

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif

#ifndef SYS_seccomp
#ifdef __NR_seccomp
#define SYS_seccomp __NR_seccomp
#endif
#endif

struct landlockd_seccomp_notif_sizes {
  __u16 seccomp_notif;
  __u16 seccomp_notif_resp;
  __u16 seccomp_data;
};

int landlockd_seccomp_probe_notif_sizes(
    struct landlockd_seccomp_notif_sizes *out);

#endif
