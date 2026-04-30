#include <errno.h>

#include <linux/seccomp.h>

#include "landlockd/seccomp.h"
#include "tap.h"

static long fake_return_value;
static int fake_errno_value;
static int syscall_invoked;
static int saw_unexpected_arguments;

long landlockd_seccomp_get_notif_sizes_syscall(struct seccomp_notif_sizes *sizes) {
  syscall_invoked++;

  if (sizes == NULL) {
    saw_unexpected_arguments = 1;
    errno = EINVAL;
    return -1;
  }

  errno = fake_errno_value;
  return fake_return_value;
}

int main(void) {
  plan(6);

  fake_errno_value = 0;
  saw_unexpected_arguments = 0;

  fake_return_value = 0;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_user_notif() == 0 && syscall_invoked == 1 &&
         !saw_unexpected_arguments,
     "reports success when seccomp user-notify is available");

  fake_return_value = -1;
  fake_errno_value = ENOSYS;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_user_notif() == -1 && errno == ENOSYS &&
         syscall_invoked == 1,
     "returns ENOSYS when the seccomp syscall is unavailable");

  fake_return_value = -1;
  fake_errno_value = EINVAL;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_user_notif() == -1 && errno == ENOSYS &&
         syscall_invoked == 1,
     "maps an unsupported seccomp user-notify probe to ENOSYS");

  fake_errno_value = EFAULT;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_user_notif() == -1 && errno == EFAULT &&
         syscall_invoked == 1,
     "preserves EFAULT from the seccomp probe");

  fake_errno_value = EPERM;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_user_notif() == -1 && errno == EPERM &&
         syscall_invoked == 1,
     "preserves EPERM from the seccomp probe");

  fake_return_value = 0;
  fake_errno_value = EPERM;
  syscall_invoked = 0;
  saw_unexpected_arguments = 0;
  errno = ERANGE;
  ok(landlockd_seccomp_probe_user_notif() == 0 && syscall_invoked == 1 &&
         !saw_unexpected_arguments && errno == ERANGE,
     "preserves caller errno on successful seccomp user-notify probe");

  done_testing();
}
