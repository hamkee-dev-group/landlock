#include <errno.h>
#include <stdint.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int call_order;
static int prctl_order;
static int restrict_order;
static long prctl_return_value;
static int prctl_errno_value;
static long restrict_return_value;
static int restrict_errno_value;

long landlockd_prctl_get_no_new_privs_syscall(void)
{
    prctl_order = ++call_order;
    errno = prctl_errno_value;
    return prctl_return_value;
}

long landlock_restrict_self_syscall(int ruleset_fd, uint32_t flags)
{
    (void)ruleset_fd;
    (void)flags;
    restrict_order = ++call_order;
    errno = restrict_errno_value;
    return restrict_return_value;
}

int main(void)
{
    int rc;

    plan(7);

    call_order = 0;
    prctl_order = 0;
    restrict_order = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_restrict_self_require_nnp(11, 0);
    ok(rc == -1 && errno == EPERM && prctl_order == 1 && restrict_order == 0,
       "rejects restrict_self when no_new_privs is not set");

    call_order = 0;
    prctl_order = 0;
    restrict_order = 0;
    prctl_return_value = 1;
    prctl_errno_value = 0;
    restrict_return_value = -1;
    restrict_errno_value = ENOSYS;
    errno = 0;
    rc = landlockd_restrict_self_require_nnp(13, 0);
    ok(rc == -1 && errno == ENOSYS && prctl_order == 1 && restrict_order == 2,
       "calls restrict_self after confirming no_new_privs");

    call_order = 0;
    prctl_order = 0;
    restrict_order = 0;
    prctl_return_value = 1;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_restrict_self_require_nnp(17, 0);
    ok(rc == 0 && errno == 0 && prctl_order == 1 && restrict_order == 2,
       "returns success when no_new_privs is already set");

    call_order = 0;
    prctl_order = 0;
    restrict_order = 0;
    prctl_return_value = -1;
    prctl_errno_value = EACCES;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_restrict_self_require_nnp(19, 0);
    ok(rc == -1 && errno == EACCES && prctl_order == 1 && restrict_order == 0,
       "returns the prctl error before calling restrict_self");

    call_order = 0;
    prctl_order = 0;
    restrict_order = 0;
    prctl_return_value = 1;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_restrict_self_require_nnp(11, 1);
    ok(rc == -1 && errno == EINVAL && call_order == 0 &&
           prctl_order == 0 && restrict_order == 0,
       "rejects non-zero flags before probing no_new_privs");

    call_order = 0;
    prctl_order = 0;
    restrict_order = 0;
    prctl_return_value = 1;
    prctl_errno_value = EIO;
    restrict_return_value = 0;
    restrict_errno_value = EACCES;
    errno = 0xBEEF;
    rc = landlockd_restrict_self_require_nnp(23, 0);
    ok(rc == 0 && errno == 0xBEEF && prctl_order == 1 && restrict_order == 2,
       "preserves caller errno on successful require_nnp wrapper path");

    call_order = 0;
    prctl_order = 0;
    restrict_order = 0;
    prctl_return_value = 1;
    prctl_errno_value = ERANGE;
    restrict_return_value = 0;
    restrict_errno_value = EILSEQ;
    errno = EDOM;
    rc = landlockd_restrict_self_require_nnp(23, 0);
    ok(rc == 0 && errno == EDOM && prctl_order == 1 && restrict_order == 2,
       "preserves EDOM caller sentinel across a successful require_nnp wrapper path");

    done_testing();
}
