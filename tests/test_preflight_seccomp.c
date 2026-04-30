#include <errno.h>
#include <stddef.h>

#include <linux/seccomp.h>

#include "landlockd/preflight.h"
#include "tap.h"

static long fake_return_value;
static int fake_errno_value;
static int syscall_invoked;
static unsigned int last_action;
static int saw_unexpected_arguments;

long landlockd_seccomp_get_action_avail_syscall(unsigned int *action) {
  syscall_invoked++;

  if (action == NULL) {
    saw_unexpected_arguments = 1;
    errno = EFAULT;
    return -1;
  }
  last_action = *action;

  errno = fake_errno_value;
  return fake_return_value;
}

int main(void) {
  struct landlockd_preflight_report report;

  plan(9);

  fake_errno_value = 0;
  saw_unexpected_arguments = 0;

  fake_return_value = 0;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == 0 &&
         report.seccomp_user_notif_supported == 1 &&
         report.seccomp_probe_errno == 0 && syscall_invoked == 1 &&
         last_action == SECCOMP_RET_USER_NOTIF && !saw_unexpected_arguments,
     "reports user-notify support and probes SECCOMP_RET_USER_NOTIF");

  fake_return_value = -1;
  fake_errno_value = EOPNOTSUPP;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == 0 &&
         report.seccomp_user_notif_supported == 0 &&
         report.seccomp_probe_errno == EOPNOTSUPP && syscall_invoked == 1,
     "EOPNOTSUPP reports user-notify unavailable without failing");

  fake_return_value = -1;
  fake_errno_value = ENOSYS;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == 0 &&
         report.seccomp_user_notif_supported == 0 &&
         report.seccomp_probe_errno == ENOSYS && syscall_invoked == 1,
     "ENOSYS reports user-notify unavailable without failing");

  fake_return_value = -1;
  fake_errno_value = EINVAL;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == 0 &&
         report.seccomp_user_notif_supported == 0 &&
         report.seccomp_probe_errno == EINVAL && syscall_invoked == 1,
     "EINVAL reports user-notify unavailable without failing");

  fake_return_value = -1;
  fake_errno_value = EPERM;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == -1 &&
         errno == EPERM && syscall_invoked == 1,
     "unexpected probe errno is surfaced to the caller");

  fake_return_value = -1;
  fake_errno_value = EFAULT;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == -1 &&
         errno == EFAULT && syscall_invoked == 1,
     "EFAULT from the seccomp probe is surfaced verbatim");

  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(NULL) == -1 &&
         errno == EINVAL && syscall_invoked == 0,
     "NULL report argument rejected without probing");

  fake_return_value = 0;
  fake_errno_value = 0;
  syscall_invoked = 0;
  errno = ERANGE;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == 0 &&
         report.seccomp_user_notif_supported == 1 &&
         report.seccomp_probe_errno == 0 && errno == ERANGE &&
         syscall_invoked == 1,
     "preserves caller errno on successful seccomp preflight");

  report.seccomp_user_notif_supported = 1;
  report.seccomp_probe_errno = 0;
  fake_return_value = -1;
  fake_errno_value = EOPNOTSUPP;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_probe_seccomp_user_notif(&report) == 0 &&
         report.seccomp_user_notif_supported == 0 &&
         report.seccomp_probe_errno == EOPNOTSUPP,
     "failure path resets seccomp_user_notif_supported to 0");

  done_testing();
}
