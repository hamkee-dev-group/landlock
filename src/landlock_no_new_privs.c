#include "landlockd/landlock.h"

#include <errno.h>
#include <sys/prctl.h>

__attribute__((weak)) long landlockd_prctl_shim(int option, unsigned long arg2,
                                                unsigned long arg3,
                                                unsigned long arg4,
                                                unsigned long arg5) {
  return prctl(option, arg2, arg3, arg4, arg5);
}

int landlockd_set_no_new_privs(void) {
  long rc;
  int saved_errno;

  saved_errno = errno;
  rc = landlockd_prctl_shim(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  if (rc < 0) {
    return -1;
  }
  errno = saved_errno;
  return 0;
}
