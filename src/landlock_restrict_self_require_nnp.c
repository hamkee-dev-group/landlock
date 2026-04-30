#include "landlockd/landlock.h"

#include <errno.h>
#include <sys/prctl.h>

__attribute__((weak)) long landlockd_prctl_get_no_new_privs_syscall(void) {
  return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
}

int landlockd_restrict_self_require_nnp(int ruleset_fd, unsigned int flags) {
  long rc;
  int saved_errno;

  if (flags != 0) {
    errno = EINVAL;
    return -1;
  }

  saved_errno = errno;
  rc = landlockd_prctl_get_no_new_privs_syscall();
  if (rc < 0) {
    saved_errno = errno;
    errno = saved_errno;
    return -1;
  }
  if (rc == 0) {
    errno = EPERM;
    return -1;
  }
  errno = saved_errno;
  return landlock_restrict_self(ruleset_fd, flags);
}
