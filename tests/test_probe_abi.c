#include <errno.h>
#include <stddef.h>

#include "landlockd/landlock.h"
#include "tap.h"

static long fake_return_value;
static int fake_errno_value;
static int syscall_invoked;
static int saw_unexpected_arguments;

long landlock_create_ruleset_syscall(const void *attr, size_t size,
                                     unsigned int flags) {
  syscall_invoked++;

  if (attr != NULL || size != 0 || flags != LANDLOCK_CREATE_RULESET_VERSION) {
    saw_unexpected_arguments = 1;
    errno = EINVAL;
    return -1;
  }

  errno = fake_errno_value;
  return fake_return_value;
}

int main(void) {
  int abi_version;

  plan(10);

  fake_errno_value = 0;
  saw_unexpected_arguments = 0;

  fake_return_value = 1;
  syscall_invoked = 0;
  abi_version = 0;
  errno = 0;
  ok(landlock_probe_abi(&abi_version) == 0 && abi_version == 1 &&
         syscall_invoked && !saw_unexpected_arguments,
     "stores ABI version 1");

  fake_return_value = 2;
  syscall_invoked = 0;
  abi_version = 0;
  errno = 0;
  ok(landlock_probe_abi(&abi_version) == 0 && abi_version == 2 &&
         syscall_invoked && !saw_unexpected_arguments,
     "stores ABI version 2");

  fake_return_value = 3;
  syscall_invoked = 0;
  abi_version = 0;
  errno = 0;
  ok(landlock_probe_abi(&abi_version) == 0 && abi_version == 3 &&
         syscall_invoked && !saw_unexpected_arguments,
     "stores ABI version 3");

  fake_return_value = 4;
  syscall_invoked = 0;
  abi_version = 0;
  errno = 0;
  ok(landlock_probe_abi(&abi_version) == 0 && abi_version == 4 &&
         syscall_invoked && !saw_unexpected_arguments,
     "stores ABI version 4");

  fake_return_value = -1;
  fake_errno_value = ENOSYS;
  syscall_invoked = 0;
  abi_version = 0;
  errno = 0;
  ok(landlock_probe_abi(&abi_version) == -1 && errno == ENOSYS &&
         syscall_invoked,
     "returns ENOSYS when the syscall is unavailable");

  fake_errno_value = EOPNOTSUPP;
  syscall_invoked = 0;
  abi_version = 0;
  errno = 0;
  ok(landlock_probe_abi(&abi_version) == -1 && errno == EOPNOTSUPP &&
         syscall_invoked,
     "returns EOPNOTSUPP when Landlock is disabled");

  fake_return_value = -1;
  fake_errno_value = EIO;
  syscall_invoked = 0;
  abi_version = 0x5A5A5A5A;
  errno = 0;
  ok(landlock_probe_abi(&abi_version) == -1 && errno == EIO &&
         syscall_invoked && abi_version == 0x5A5A5A5A,
     "preserves a non-availability errno and leaves abi_version untouched");

  fake_errno_value = 0;
  fake_return_value = 4;
  syscall_invoked = 0;
  errno = 0;
  ok(landlock_probe_abi(NULL) == -1 && errno == EINVAL && !syscall_invoked,
     "rejects a NULL ABI output without probing");

  fake_return_value = 5;
  fake_errno_value = EIO;
  syscall_invoked = 0;
  saw_unexpected_arguments = 0;
  abi_version = 0x1234;
  errno = 0xBEEF;
  ok(landlock_probe_abi(&abi_version) == 0 && abi_version == 5 &&
         syscall_invoked == 1 && !saw_unexpected_arguments &&
         errno == 0xBEEF,
     "preserves caller errno on successful probe");

  fake_return_value = 4;
  fake_errno_value = EIO;
  syscall_invoked = 0;
  saw_unexpected_arguments = 0;
  abi_version = -1;
  errno = ERANGE;
  ok(landlock_probe_abi(&abi_version) == 0 && abi_version == 4 &&
         syscall_invoked == 1 && !saw_unexpected_arguments &&
         errno == ERANGE,
     "preserves ERANGE caller sentinel across a successful ABI 4 probe");

  done_testing();
}
