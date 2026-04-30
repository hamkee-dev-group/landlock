#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <linux/seccomp.h>

#include "seccomp_notify_probe.h"
#include "tap.h"

static int syscall_invoked;
static struct seccomp_notif_sizes *last_arg;
static long fake_return_value;
static int fake_errno_value;
static int fake_fill_sizes;
static __u16 fake_seccomp_notif;
static __u16 fake_seccomp_notif_resp;
static __u16 fake_seccomp_data;

long landlockd_seccomp_get_notif_sizes_syscall(
    struct seccomp_notif_sizes *sizes) {
  syscall_invoked++;
  last_arg = sizes;

  if (fake_fill_sizes && sizes != NULL) {
    sizes->seccomp_notif = fake_seccomp_notif;
    sizes->seccomp_notif_resp = fake_seccomp_notif_resp;
    sizes->seccomp_data = fake_seccomp_data;
  }

  errno = fake_errno_value;
  return fake_return_value;
}

int main(void) {
  struct landlockd_seccomp_notif_sizes out;

  plan(5);

  memset(&out, 0, sizeof(out));
  syscall_invoked = 0;
  last_arg = NULL;
  fake_fill_sizes = 1;
  fake_seccomp_notif = 80;
  fake_seccomp_notif_resp = 24;
  fake_seccomp_data = 64;
  fake_return_value = 0;
  fake_errno_value = 0;
  errno = ERANGE;
  ok(landlockd_seccomp_probe_notif_sizes(&out) == 0 && syscall_invoked == 1 &&
         last_arg != NULL && out.seccomp_notif == 80 &&
         out.seccomp_notif_resp == 24 && out.seccomp_data == 64 &&
         errno == ERANGE,
     "returns sizes from SECCOMP_GET_NOTIF_SIZES and preserves caller errno");

  fake_fill_sizes = 0;
  fake_return_value = -1;
  fake_errno_value = ENOSYS;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_notif_sizes(&out) == -1 && errno == ENOSYS &&
         syscall_invoked == 1,
     "returns ENOSYS when seccomp user-notify is unavailable");

  fake_return_value = -1;
  fake_errno_value = EINVAL;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_notif_sizes(&out) == -1 && errno == EINVAL &&
         syscall_invoked == 1,
     "preserves EINVAL verbatim from the seccomp probe");

  fake_return_value = -1;
  fake_errno_value = EOPNOTSUPP;
  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_notif_sizes(&out) == -1 && errno == EOPNOTSUPP &&
         syscall_invoked == 1,
     "preserves EOPNOTSUPP verbatim from the seccomp probe");

  syscall_invoked = 0;
  errno = 0;
  ok(landlockd_seccomp_probe_notif_sizes(NULL) == -1 && errno == EINVAL &&
         syscall_invoked == 0,
     "rejects a NULL out-pointer with EINVAL and no syscall");

  done_testing();
}
