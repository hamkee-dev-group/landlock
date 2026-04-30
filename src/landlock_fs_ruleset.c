#include "landlockd/landlock.h"
#include "landlock_compat.h"

#include <errno.h>
#include <stddef.h>

static uint64_t landlockd_fs_access_mask_for_abi(int abi) {
  uint64_t abi_mask;

  abi_mask = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
             LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
             LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
             LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
             LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
             LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
             LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2) {
    abi_mask |= LANDLOCK_ACCESS_FS_REFER;
  }
  if (abi >= 3) {
    abi_mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  if (abi >= 5) {
    abi_mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  }
  return abi_mask;
}

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs) {
  struct landlock_ruleset_attr attr = {0};
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

  effective = requested_access_fs & landlockd_fs_access_mask_for_abi(abi);
  if (effective == 0) {
    errno = EINVAL;
    return -1;
  }
  attr.handled_access_fs = effective;

  fd = landlock_create_ruleset(&attr, LANDLOCKD_RULESET_ATTR_FS_SIZE, 0);
  if (fd < 0) {
    return -1;
  }
  if (granted_access_fs != NULL) {
    *granted_access_fs = effective;
  }
  errno = saved_errno;
  return (int)fd;
}
