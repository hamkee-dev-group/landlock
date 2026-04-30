#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "landlockd/landlock.h"
#include "landlock_compat.h"
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
    const uint64_t supported_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
                                          LANDLOCK_ACCESS_NET_CONNECT_TCP;
    const uint64_t requested_access_net = supported_access_net | (1ULL << 63);
    const uint64_t granted_sentinel = 0xDEADBEEFULL;
    uint64_t granted_access_net;

    plan(8);

    fake_abi_value = 0;
    fake_abi_errno = ENOSYS;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 0;
    fake_create_errno = 0;
    granted_access_net = granted_sentinel;
    errno = 0;
    ok(landlock_create_net_ruleset(requested_access_net, &granted_access_net) ==
           -1 &&
           errno == ENOSYS &&
           probe_call_count == 1 &&
           create_call_count == 0 &&
           captured_size == 0 &&
           captured_flags == 0 &&
           granted_access_net == granted_sentinel,
       "ABI version 0 fails without invoking the create syscall");

    fake_abi_value = 3;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 0;
    fake_create_errno = 0;
    granted_access_net = granted_sentinel;
    errno = 0;
    ok(landlock_create_net_ruleset(requested_access_net, &granted_access_net) ==
           -1 &&
           errno == EOPNOTSUPP &&
           probe_call_count == 1 &&
           create_call_count == 0 &&
           captured_size == 0 &&
           captured_flags == 0 &&
           granted_access_net == granted_sentinel,
       "ABI versions below 4 fail without invoking the create syscall");

    fake_abi_value = 4;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 7;
    fake_create_errno = 0;
    granted_access_net = granted_sentinel;
    errno = 0;
    ok(landlock_create_net_ruleset(requested_access_net, &granted_access_net) ==
               7 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == 0 &&
           captured_attr_copy.handled_access_net == supported_access_net &&
           captured_attr_copy.scoped == 0 &&
           granted_access_net == supported_access_net,
       "successful creation uses the expected net ruleset mask and returns the fake fd");

    fake_abi_value = 4;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 9;
    fake_create_errno = 0;
    errno = 0;
    ok(landlock_create_net_ruleset(requested_access_net, NULL) == 9 &&
           errno == 0 &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == 0 &&
           captured_attr_copy.handled_access_net == supported_access_net &&
           captured_attr_copy.scoped == 0,
       "successful creation with NULL granted pointer returns the fake fd and preserves errno");

    fake_abi_value = 4;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 0;
    fake_create_errno = 0;
    granted_access_net = granted_sentinel;
    errno = 0;
    ok(landlock_create_net_ruleset(0, &granted_access_net) == -1 &&
           errno == EINVAL &&
           probe_call_count == 1 &&
           create_call_count == 0 &&
           captured_size == 0 &&
           captured_flags == 0 &&
           granted_access_net == granted_sentinel,
       "zero requested net access fails before invoking the create syscall");

    fake_abi_value = 4;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = -1;
    fake_create_errno = EPERM;
    granted_access_net = granted_sentinel;
    errno = 0;
    ok(landlock_create_net_ruleset(requested_access_net, &granted_access_net) ==
               -1 &&
           errno == EPERM &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == 0 &&
           captured_attr_copy.handled_access_net == supported_access_net &&
           captured_attr_copy.scoped == 0 &&
           granted_access_net == granted_sentinel,
       "syscall failure preserves errno and leaves granted_access_net unchanged");

    fake_abi_value = -1;
    fake_abi_errno = EIO;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 0;
    fake_create_errno = 0;
    granted_access_net = granted_sentinel;
    errno = 0;
    ok(landlock_create_net_ruleset(requested_access_net, &granted_access_net) ==
               -1 &&
           errno == EIO &&
           probe_call_count == 1 &&
           create_call_count == 0 &&
           captured_size == 0 &&
           captured_flags == 0 &&
           granted_access_net == granted_sentinel,
       "probe failure preserves a non-availability errno and skips ruleset creation");

    fake_abi_value = 4;
    fake_abi_errno = 0;
    probe_call_count = 0;
    create_call_count = 0;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_create_fd = 11;
    fake_create_errno = EPERM;
    granted_access_net = granted_sentinel;
    errno = 0x5A5A;
    ok(landlock_create_net_ruleset(requested_access_net, &granted_access_net) ==
               11 &&
           errno == 0x5A5A &&
           probe_call_count == 1 &&
           create_call_count == 1 &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == 0 &&
           captured_attr_copy.handled_access_net == supported_access_net &&
           captured_attr_copy.scoped == 0 &&
           granted_access_net == supported_access_net,
       "success path preserves the caller errno across probe and syscall errno");

    done_testing();
}
