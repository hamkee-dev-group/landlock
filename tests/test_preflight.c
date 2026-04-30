#include <errno.h>
#include <stddef.h>

#include "landlockd/landlock.h"
#include "landlockd/preflight.h"
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
  struct landlockd_preflight_report report;

  plan(9);

  fake_errno_value = 0;
  saw_unexpected_arguments = 0;

  fake_return_value = 1;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &report) == 0 &&
         report.abi_version == 1 &&
         report.required_abi_floor == LANDLOCKD_PREFLIGHT_ABI_FLOOR &&
         report.meets_abi_floor == 1 && report.stacking_supported == 1 &&
         report.probe_errno == 0 && syscall_invoked == 1 &&
         !saw_unexpected_arguments,
     "abi 1 at default floor meets requirements and reports stacking");

  fake_return_value = 4;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(2, &report) == 0 && report.abi_version == 4 &&
         report.required_abi_floor == 2 && report.meets_abi_floor == 1 &&
         report.stacking_supported == 1 && report.probe_errno == 0 &&
         syscall_invoked == 1,
     "abi 4 clears floor 2 and reports stacking");

  fake_return_value = 1;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(3, &report) == 0 && report.abi_version == 1 &&
         report.required_abi_floor == 3 && report.meets_abi_floor == 0 &&
         report.stacking_supported == 1 && report.probe_errno == 0 &&
         syscall_invoked == 1,
     "abi 1 is below floor 3 yet stacking assumption still holds");

  fake_return_value = -1;
  fake_errno_value = ENOSYS;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &report) == 0 &&
         report.abi_version == 0 && report.meets_abi_floor == 0 &&
         report.stacking_supported == 0 && report.probe_errno == ENOSYS &&
         syscall_invoked == 1,
     "ENOSYS reports unsupported kernel without failing preflight");

  fake_errno_value = EOPNOTSUPP;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &report) == 0 &&
         report.abi_version == 0 && report.meets_abi_floor == 0 &&
         report.stacking_supported == 0 &&
         report.probe_errno == EOPNOTSUPP && syscall_invoked == 1,
     "EOPNOTSUPP reports unsupported kernel without failing preflight");

  fake_errno_value = EIO;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &report) == -1 &&
         errno == EIO && syscall_invoked == 1,
     "unexpected probe errno is surfaced to the caller");

  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, NULL) == -1 &&
         errno == EINVAL && syscall_invoked == 0,
     "NULL report argument rejected without probing");

  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_preflight_run(-1, &report) == -1 && errno == EINVAL &&
         syscall_invoked == 0,
     "negative floor rejected without probing");

  fake_return_value = 2;
  fake_errno_value = EIO;
  syscall_invoked = 0;
  errno = ERANGE;
  ok(landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &report) == 0 &&
         report.abi_version == 2 && report.meets_abi_floor == 1 &&
         report.stacking_supported == 1 && report.probe_errno == 0 &&
         errno == ERANGE && syscall_invoked == 1,
     "preserves caller errno on successful preflight");

  done_testing();
}
