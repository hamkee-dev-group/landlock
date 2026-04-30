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
#if LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET
        .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP,
#endif
#if LANDLOCKD_RULESET_ATTR_HAS_SCOPED
        .scoped = 0x1234,
#endif
    };
    int attr_matches;
    int rc;

    plan(7);

    syscall_call_count = 0;
    captured_attr = NULL;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_return_value = 17;
    fake_errno_value = 0;
    errno = EDOM;
    rc = landlock_create_ruleset(&attr, sizeof(attr), 8);
    attr_matches = captured_attr_copy.handled_access_fs == attr.handled_access_fs;
#if LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET
    attr_matches = attr_matches &&
                   captured_attr_copy.handled_access_net == attr.handled_access_net;
#else
    attr_matches = attr_matches && captured_attr_copy.handled_access_net == 0;
#endif
#if LANDLOCKD_RULESET_ATTR_HAS_SCOPED
    attr_matches = attr_matches && captured_attr_copy.scoped == attr.scoped;
#else
    attr_matches = attr_matches && captured_attr_copy.scoped == 0;
#endif
    ok(rc == 17 &&
           syscall_call_count == 1 &&
           captured_attr == &attr &&
           captured_size == sizeof(attr) &&
           captured_flags == 8 &&
           attr_matches,
       "forwards the installed public ruleset payload unchanged");

    syscall_call_count = 0;
    captured_attr = NULL;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_return_value = 23;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_create_ruleset(&attr, LANDLOCKD_RULESET_ATTR_FS_SIZE, 0) == 23 &&
           syscall_call_count == 1 &&
           captured_attr == &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == attr.handled_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0,
       "forwards the portable filesystem ruleset size unchanged");

    skip(!LANDLOCKD_RULESET_ATTR_HAS_HANDLED_ACCESS_NET, 1,
         "installed headers lack handled_access_net");
    syscall_call_count = 0;
    captured_attr = NULL;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_return_value = 42;
    fake_errno_value = 0;
    errno = 0;
    rc = landlock_create_ruleset(&attr, LANDLOCKD_RULESET_ATTR_NET_SIZE, 4);
    ok(rc == 42 &&
           syscall_call_count == 1 &&
           captured_attr == &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_NET_SIZE &&
           captured_flags == 4 &&
           captured_attr_copy.handled_access_fs == attr.handled_access_fs &&
           captured_attr_copy.handled_access_net == attr.handled_access_net &&
           captured_attr_copy.scoped == 0,
       "forwards the portable network ruleset size unchanged");
    end_skip;

    syscall_call_count = 0;
    captured_attr = NULL;
    captured_size = 0;
    captured_flags = 0;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_return_value = -1;
    fake_errno_value = EPERM;
    errno = 0;
    rc = landlock_create_ruleset(&attr, LANDLOCKD_RULESET_ATTR_FS_SIZE, 0);
    ok(rc == -1 &&
           errno == EPERM &&
           syscall_call_count == 1 &&
           captured_attr == &attr &&
           captured_size == LANDLOCKD_RULESET_ATTR_FS_SIZE &&
           captured_flags == 0 &&
           captured_attr_copy.handled_access_fs == attr.handled_access_fs &&
           captured_attr_copy.handled_access_net == 0 &&
           captured_attr_copy.scoped == 0,
       "preserves errno on syscall failure");

    syscall_call_count = 0;
    fake_return_value = 99;
    fake_errno_value = 0;
    errno = 0;
    rc = landlock_create_ruleset(&attr, LANDLOCKD_RULESET_ATTR_FS_SIZE,
                                 LANDLOCK_CREATE_RULESET_VERSION);
    ok(rc == -1 &&
           errno == EINVAL &&
           syscall_call_count == 0,
       "rejects the version probe flag before invoking the syscall");

    syscall_call_count = 0;
    captured_attr = &attr;
    captured_size = 1;
    captured_flags = 1;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_return_value = 55;
    fake_errno_value = 0;
    errno = EDOM;
    rc = landlock_create_ruleset(NULL, 0, 0);
    ok(rc == 55 &&
           syscall_call_count == 1 &&
           captured_attr == NULL &&
           captured_size == 0 &&
           captured_flags == 0 &&
           errno == EDOM,
       "forwards a NULL raw-wrapper call and preserves errno on success");

    syscall_call_count = 0;
    captured_attr = &attr;
    captured_size = 2;
    captured_flags = 2;
    memset(&captured_attr_copy, 0, sizeof(captured_attr_copy));
    fake_return_value = 71;
    fake_errno_value = 0;
    errno = EDOM;
    rc = landlock_create_ruleset(NULL, 0, 0);
    ok(rc == 71 &&
           syscall_call_count == 1 &&
           captured_attr == NULL &&
           captured_size == 0 &&
           captured_flags == 0 &&
           errno == EDOM,
       "returns the raw syscall fd unchanged for a NULL probe payload");

    done_testing();
}
