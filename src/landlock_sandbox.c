#include "landlockd/landlock.h"

#include <errno.h>

int landlock_restrict_self_with_no_new_privs(int ruleset_fd,
                                             unsigned int flags) {
  if (flags != 0) {
    errno = EINVAL;
    return -1;
  }

  if (landlockd_set_no_new_privs() < 0) {
    return -1;
  }

  return landlock_restrict_self(ruleset_fd, flags);
}

int landlockd_apply_sandbox(int ruleset_fd, unsigned int flags) {
  if (ruleset_fd < 0) {
    errno = EBADF;
    return -1;
  }

  return landlock_restrict_self_with_no_new_privs(ruleset_fd, flags);
}
