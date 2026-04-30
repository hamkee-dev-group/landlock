#define _GNU_SOURCE

#include "landlockd/preflight.h"

#include <errno.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((weak)) long landlockd_seccomp_get_action_avail_syscall(
    unsigned int *action) {
  return syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0U, action);
}

int landlockd_preflight_probe_seccomp_user_notif(
    struct landlockd_preflight_report *out) {
  unsigned int action;
  int saved_errno;
  int probe_errno;

  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }

  saved_errno = errno;
  out->seccomp_user_notif_supported = 0;
  out->seccomp_probe_errno = 0;

  action = SECCOMP_RET_USER_NOTIF;
  errno = 0;
  if (landlockd_seccomp_get_action_avail_syscall(&action) < 0) {
    probe_errno = errno;
    if (probe_errno == ENOSYS || probe_errno == EOPNOTSUPP ||
        probe_errno == EINVAL) {
      out->seccomp_probe_errno = probe_errno;
      errno = saved_errno;
      return 0;
    }
    errno = probe_errno;
    return -1;
  }

  out->seccomp_user_notif_supported = 1;
  errno = saved_errno;
  return 0;
}
