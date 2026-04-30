#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int fake_abi_value;
static int fake_abi_errno;
static int probe_call_count;
static int create_call_count;
static size_t captured_size;
static unsigned int captured_flags;
static struct landlock_ruleset_attr captured_attr_copy;
static long fake_create_fd;
static int fake_create_errno;

int landlock_abi_version(void)
{
    probe_call_count++;
    errno = fake_abi_errno;
    return fake_abi_value;
}

long landlock_create_ruleset_syscall(const void *attr, size_t size,
                                     unsigned int flags)
{
    create_call_count++;
    captured_size = size;
    captured_flags = flags;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    if (attr != NULL && size <= sizeof(captured_attr_copy)) {
        memcpy(&captured_attr_copy, attr, size);
    }
    errno = fake_create_errno;
    return fake_create_fd;
}

int main(void)
{
    const uint64_t requested_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                                         LANDLOCK_ACCESS_FS_REFER |
                                         LANDLOCK_ACCESS_FS_TRUNCATE |
                                         LANDLOCK_ACCESS_FS_IOCTL_DEV |
                                         (1ULL << 63);
    const uint64_t abi_v1_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    const uint64_t abi_v2_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                                      LANDLOCK_ACCESS_FS_REFER;
    const uint64_t abi_v3_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                                      LANDLOCK_ACCESS_FS_REFER |
                                      LANDLOCK_ACCESS_FS_TRUNCATE;
    const uint64_t abi_v4_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                                      LANDLOCK_ACCESS_FS_REFER |
                                      LANDLOCK_ACCESS_FS_TRUNCATE;
    const uint64_t abi_v5_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                                      LANDLOCK_ACCESS_FS_REFER |
                                      LANDLOCK_ACCESS_FS_TRUNCATE |
                                      LANDLOCK_ACCESS_FS_IOCTL_DEV;
    const uint64_t saturated_requested_access_fs =
        ((1ULL << 16) - 1) | (1ULL << 16) | (1ULL << 63);
    const uint64_t saturated_granted_access_fs = (1ULL << 16) - 1;
    const uint64_t granted_sentinel = 0xDEADBEEFULL;
    uint64_t granted_access_fs;

    plan(12);

    fake_abi_value = 1;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 7;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               7 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v1_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == abi_v1_access_fs,
       "abi v1 keeps only the filesystem bits supported by the public helper");

    fake_abi_value = 2;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 13;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               13 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v2_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == abi_v2_access_fs,
       "abi v2 keeps refer but still masks out truncate");

    fake_abi_value = 3;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 17;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               17 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v3_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == abi_v3_access_fs,
       "abi v3 keeps truncate but still masks out ioctl");

    fake_abi_value = 4;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 19;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               19 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v4_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == abi_v4_access_fs,
       "abi v4 still masks out ioctl while returning the created ruleset fd");

    fake_abi_value = 5;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 11;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               11 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v5_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == abi_v5_access_fs,
       "abi v5 keeps the ioctl bit and returns the created ruleset fd");

    fake_abi_value = 5;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = -1;
    fake_create_errno = EPERM;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               -1 &&
           errno == EPERM &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v5_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == granted_sentinel,
       "syscall failure preserves errno and leaves granted_access_fs unchanged");

    fake_abi_value = 5;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 29;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(saturated_requested_access_fs,
                                  &granted_access_fs) == 29 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == saturated_granted_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == saturated_granted_access_fs,
       "abi v5 saturates to the known filesystem access mask");

    fake_abi_value = 6;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 31;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(saturated_requested_access_fs,
                                  &granted_access_fs) == 31 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == saturated_granted_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == saturated_granted_access_fs,
       "abi v6 saturates to the known filesystem access mask");

    fake_abi_value = -1;
    fake_abi_errno = EIO;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 0;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               -1 &&
           errno == EIO &&
           probe_call_count == 1 &&
           create_call_count == 0 &&
           granted_access_fs == granted_sentinel,
       "probe failure preserves errno and skips ruleset creation");

    fake_abi_value = -1;
    fake_abi_errno = EACCES;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 0;
    fake_create_errno = 0;
    granted_access_fs = granted_sentinel;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               -1 &&
           errno == EACCES &&
           probe_call_count == 1 &&
           create_call_count == 0 &&
           granted_access_fs == granted_sentinel,
       "probe failure preserves a non-availability errno other than EIO");

    fake_abi_value = 5;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 23;
    fake_create_errno = 0;
    errno = 0;
    ok(landlock_create_fs_ruleset(requested_access_fs, NULL) == 23 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v5_access_fs,
       "NULL granted_access_fs still returns the created ruleset fd");

    fake_abi_value = 5;
    fake_abi_errno = EBUSY;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 41;
    fake_create_errno = EAGAIN;
    granted_access_fs = granted_sentinel;
    errno = ENOTTY;
    ok(landlock_create_fs_ruleset(requested_access_fs, &granted_access_fs) ==
               41 &&
           errno == ENOTTY &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == abi_v5_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0 &&
           granted_access_fs == abi_v5_access_fs,
       "success path preserves the caller errno across probe and syscall errno");

    done_testing();
}
