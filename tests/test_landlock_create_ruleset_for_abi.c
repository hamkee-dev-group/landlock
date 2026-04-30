#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "landlockd/landlock.h"
#include "landlockd/landlock_compat.h"
#include "tap.h"

struct captured_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

static int syscall_call_count;
static const void *captured_attr;
static size_t captured_size;
static unsigned int captured_flags;
static struct captured_ruleset_attr captured_attr_copy;
static long fake_return_value;
static int fake_errno_value;

long landlock_create_ruleset_syscall(const void *attr, size_t size,
                                     unsigned int flags)
{
    syscall_call_count++;
    captured_attr = attr;
    captured_size = size;
    captured_flags = flags;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    if (attr != NULL && size <= sizeof(captured_attr_copy)) {
        memcpy(&captured_attr_copy, attr, size);
    }
    errno = fake_errno_value;
    return fake_return_value;
}

int main(void)
{
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
    };
    uint64_t expected_handled_access_net;
    uint64_t expected_scoped;
    int rc;

#if LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET
    attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP;
#endif
#if LANDLOCKD_RULESET_ATTR_HAS_SCOPED
    attr.scoped = 0x1234;
#endif

    expected_handled_access_net = 0;
#if LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET
    expected_handled_access_net = attr.handled_access_net;
#endif
    expected_scoped = 0;
#if LANDLOCKD_RULESET_ATTR_HAS_SCOPED
    expected_scoped = attr.scoped;
#endif

    plan(15);

    syscall_call_count = 0;
    errno = 0;
    ok(landlock_create_ruleset_for_abi(0, &attr, 2) == -1 &&
           errno == ENOSYS &&
           syscall_call_count == 0,
       "rejects abi version 0 without invoking the syscall");

    syscall_call_count = 0;
    errno = 0;
    ok(landlock_create_ruleset_for_abi(-1, &attr, 2) == -1 &&
           errno == ENOSYS &&
           syscall_call_count == 0,
       "rejects negative abi versions without invoking the syscall");

    syscall_call_count = 0;
    errno = 0;
    ok(landlock_create_ruleset_for_abi(6, &attr,
                                       LANDLOCK_CREATE_RULESET_VERSION) == -1 &&
           errno == EINVAL &&
           syscall_call_count == 0,
       "rejects the version probe flag without invoking the syscall");

    fake_return_value = 11;
    fake_errno_value = 0;
    rc = landlock_create_ruleset_for_abi(1, &attr, 2);
    ok(rc == 11 &&
           syscall_call_count == 1 &&
           captured_attr != &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 2,
       "uses the filesystem-only ruleset size for abi v1");

    fake_return_value = 12;
    fake_errno_value = 0;
    rc = landlock_create_ruleset_for_abi(2, &attr, 4);
    ok(rc == 12 &&
           syscall_call_count == 2 &&
           captured_attr != &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 4,
       "uses the filesystem-only ruleset size for abi v2");

    fake_return_value = 13;
    fake_errno_value = 0;
    rc = landlock_create_ruleset_for_abi(3, &attr, 6);
    ok(rc == 13 &&
           syscall_call_count == 3 &&
           captured_attr != &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 6,
       "uses the filesystem-only ruleset size for abi v3");

    fake_return_value = 14;
    fake_errno_value = 0;
    rc = landlock_create_ruleset_for_abi(4, &attr, 8);
    ok(rc == 14, "returns the fake fd for abi v4");
    ok(syscall_call_count == 4 &&
           captured_attr != &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 8 &&
           captured_attr_copy.handled_access_fs == attr.handled_access_fs &&
           captured_attr_copy.handled_access_net == expected_handled_access_net &&
           captured_attr_copy.scoped == 0,
       "uses the network-capable ruleset size for abi v4");

    fake_return_value = 15;
    fake_errno_value = 0;
    rc = landlock_create_ruleset_for_abi(5, &attr, 16);
    ok(rc == 15, "returns the fake fd for abi v5");
    ok(syscall_call_count == 5 &&
           captured_attr != &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 16 &&
           captured_attr_copy.handled_access_fs == attr.handled_access_fs &&
           captured_attr_copy.handled_access_net == expected_handled_access_net &&
           captured_attr_copy.scoped == 0,
       "uses the network-capable ruleset size for abi v5");

    fake_return_value = 16;
    fake_errno_value = 0;
    rc = landlock_create_ruleset_for_abi(6, &attr, 32);
    ok(rc == 16, "returns the fake fd for abi v6");
    ok(syscall_call_count == 6 &&
           captured_attr != &attr &&
           captured_size == sizeof(struct landlock_ruleset_attr_compat) &&
           captured_flags == 32 &&
           captured_attr_copy.handled_access_fs == attr.handled_access_fs &&
           captured_attr_copy.handled_access_net == expected_handled_access_net &&
           captured_attr_copy.scoped == expected_scoped,
       "uses the full ruleset size once scoped is part of the abi");

    fake_return_value = -1;
    fake_errno_value = EPERM;
    errno = 0;
    rc = landlock_create_ruleset_for_abi(6, &attr, 64);
    ok(rc == -1 &&
           errno == EPERM &&
           syscall_call_count == 7 &&
           captured_attr != &attr &&
           captured_size == sizeof(struct landlock_ruleset_attr_compat) &&
           captured_flags == 64,
       "preserves syscall errno on failure");

    fake_return_value = 42;
    fake_errno_value = EIO;
    errno = EDOM;
    rc = landlock_create_ruleset_for_abi(4, NULL, 128);
    ok(rc == 42 &&
           syscall_call_count == 8 &&
           captured_attr == NULL &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 128 &&
           errno == EDOM,
       "forwards a NULL attr for abi v4 and preserves errno on success");

    syscall_call_count = 0;
    captured_attr = &attr;
    captured_size = 0;
    captured_flags = 0;
    fake_return_value = 77;
    fake_errno_value = EIO;
    errno = 0x4242;
    rc = landlock_create_ruleset_for_abi(6, NULL, 32);
    ok(rc == 77 &&
           syscall_call_count == 1 &&
           captured_attr == NULL &&
           captured_size == sizeof(struct landlock_ruleset_attr_compat) &&
           captured_flags == 32 &&
           errno == 0x4242,
       "forwards a NULL attr for abi v6 and preserves caller errno on success");

    done_testing();
}
