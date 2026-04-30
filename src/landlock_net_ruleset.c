#include "landlockd/landlock.h"
#include "landlock_compat.h"

#include <errno.h>
#include <stddef.h>

static uint64_t landlockd_net_access_mask_for_abi(int abi) {
  if (abi >= 4) {
    return LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
  }
  return 0;
}

int landlock_create_net_ruleset(uint64_t requested_access_net,
                                uint64_t *granted_access_net) {
  struct landlock_ruleset_attr attr = {0};
  uint64_t abi_mask;
  uint64_t effective;
  int saved_errno;
  int fd;
  int abi;

  saved_errno = errno;
  abi = landlock_abi_version();
  if (abi == 0) {
    errno = ENOSYS;
    return -1;
  }
  if (abi < 0) {
    return -1;
  }

  abi_mask = landlockd_net_access_mask_for_abi(abi);
  if (abi_mask == 0) {
    errno = EOPNOTSUPP;
    return -1;
  }

  effective = requested_access_net & abi_mask;
  if (effective == 0) {
    errno = EINVAL;
    return -1;
  }
  attr.handled_access_net = effective;

  fd = landlock_create_ruleset(&attr, LANDLOCKD_RULESET_ATTR_NET_SIZE, 0);
  if (fd < 0) {
    return -1;
  }
  if (granted_access_net != NULL) {
    *granted_access_net = effective;
  }
  errno = saved_errno;
  return fd;
}
