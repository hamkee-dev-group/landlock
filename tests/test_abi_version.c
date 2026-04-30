#include <errno.h>
#include <stddef.h>

#include "landlockd/landlock.h"
#include "tap.h"

static long fake_return_value;
static int fake_errno_value;
static int saw_unexpected_arguments;

long landlock_create_ruleset_syscall(const void *attr, size_t size,
                                     unsigned int flags) {
  if (attr != NULL || size != 0 || flags != LANDLOCK_CREATE_RULESET_VERSION) {
    saw_unexpected_arguments = 1;
    errno = EINVAL;
    return -1;
  }

  errno = fake_errno_value;
  return fake_return_value;
}

int main(void) {
  plan(6);

  fake_return_value = 4;
  fake_errno_value = 0;
  errno = 0;
  ok(landlock_abi_version() == 4, "returns the probed ABI version");

  fake_return_value = -1;
  fake_errno_value = ENOSYS;
  errno = 0;
  ok(landlock_abi_version() == 0 && errno == ENOSYS,
     "maps ENOSYS to an unavailable ABI");

  fake_return_value = -1;
  fake_errno_value = EOPNOTSUPP;
  errno = 0;
  ok(landlock_abi_version() == 0 && errno == EOPNOTSUPP,
     "maps EOPNOTSUPP to an unavailable ABI");

  fake_return_value = -1;
  fake_errno_value = EINVAL;
  errno = 0;
  ok(landlock_abi_version() == -1 && errno == EINVAL &&
         !saw_unexpected_arguments,
     "returns -1 for unexpected syscall failures");

  fake_return_value = 0;
  fake_errno_value = 0;
  errno = 0;
  ok(landlock_abi_version() == 0,
     "negative-return boundary: ABI 0 is a valid non-negative return");

  fake_return_value = -1;
  fake_errno_value = EPERM;
  errno = 0;
  ok(landlock_abi_version() == -1 && errno == EPERM &&
         !saw_unexpected_arguments,
     "preserves EPERM errno on landlock_abi_version failure");

  done_testing();
}
