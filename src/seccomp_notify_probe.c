#define _GNU_SOURCE

#include "landlockd/seccomp.h"
#include "seccomp_notify_probe.h"

#include <errno.h>
#include <linux/seccomp.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((weak)) long landlockd_seccomp_get_notif_sizes_syscall(
    struct seccomp_notif_sizes *sizes) {
  return syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0U, sizes);
}

int landlockd_seccomp_probe_user_notif(void) {
  struct seccomp_notif_sizes sizes;
  int saved_errno;

  saved_errno = errno;
  memset(&sizes, 0, sizeof(sizes));
  if (landlockd_seccomp_get_notif_sizes_syscall(&sizes) < 0) {
    if (errno == EINVAL) {
      errno = ENOSYS;
    }
    return -1;
  }

  errno = saved_errno;
  return 0;
}

int landlockd_seccomp_probe_notif_sizes(
    struct landlockd_seccomp_notif_sizes *out) {
  struct seccomp_notif_sizes sizes;
  int saved_errno;

  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }

  saved_errno = errno;
  memset(&sizes, 0, sizeof(sizes));
  if (landlockd_seccomp_get_notif_sizes_syscall(&sizes) < 0) {
    return -1;
  }

  out->seccomp_notif = sizes.seccomp_notif;
  out->seccomp_notif_resp = sizes.seccomp_notif_resp;
  out->seccomp_data = sizes.seccomp_data;
  errno = saved_errno;
  return 0;
}
