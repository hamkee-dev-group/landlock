#include "landlockd/landlock.h"
#include "landlockd/seccomp.h"

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

int landlockd_apply_sandbox_with_seccomp(
    int ruleset_fd, const struct landlockd_seccomp_plan *plan,
    int *listener_fd_out) {
  int fd;
  int rc;
  int saved_errno;

  if (ruleset_fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (listener_fd_out != NULL) {
    *listener_fd_out = -1;
  }

  if (plan != NULL && plan->count > 0 && listener_fd_out == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (landlockd_set_no_new_privs() < 0) {
    return -1;
  }

  fd = -1;
  if (plan != NULL && plan->count > 0) {
    fd = landlockd_seccomp_install(plan);
    if (fd < 0) {
      return -1;
    }
    if (listener_fd_out != NULL) {
      *listener_fd_out = fd;
    }
  }

  rc = landlockd_apply_sandbox(ruleset_fd, 0);
  if (rc < 0 && fd >= 0) {
    saved_errno = errno;
    close(fd);
    if (listener_fd_out != NULL) {
      *listener_fd_out = -1;
    }
    errno = saved_errno;
  }
  return rc;
}
