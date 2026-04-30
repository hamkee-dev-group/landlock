#define _GNU_SOURCE

#include "landlockd/preflight.h"
#include "landlockd/landlock.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

int landlockd_preflight_run(int required_abi_floor,
                            struct landlockd_preflight_report *out) {
  int abi_version;
  int probe_rc;
  int probe_errno;
  int saved_errno;

  if (out == NULL || required_abi_floor < 0) {
    errno = EINVAL;
    return -1;
  }

  saved_errno = errno;
  memset(out, 0, sizeof(*out));
  out->required_abi_floor = required_abi_floor;

  abi_version = 0;
  errno = 0;
  probe_rc = landlock_probe_abi(&abi_version);
  probe_errno = errno;
  if (probe_rc < 0) {
    if (probe_errno == ENOSYS || probe_errno == EOPNOTSUPP) {
      out->probe_errno = probe_errno;
      errno = saved_errno;
      return 0;
    }
    errno = probe_errno;
    return -1;
  }

  out->abi_version = abi_version;
  out->meets_abi_floor = abi_version >= required_abi_floor;
  out->stacking_supported =
      abi_version >= LANDLOCKD_PREFLIGHT_STACKING_MIN_ABI;
  errno = saved_errno;
  return 0;
}
