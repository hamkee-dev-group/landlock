#include <errno.h>
#include <stdint.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int syscall_call_count;
static int captured_ruleset_fd;
static uint32_t captured_flags;
static long fake_return_value;
static int fake_errno_value;

long landlock_restrict_self_syscall(int ruleset_fd, uint32_t flags)
{
    syscall_call_count++;
    captured_ruleset_fd = ruleset_fd;
    captured_flags = flags;
    errno = fake_errno_value;
    return fake_return_value;
}

int main(void)
{
    int rc;

    plan(6);

    syscall_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_restrict_self(-1, 0) == 0 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == -1 &&
           captured_flags == 0,
       "forwards exact syscall arguments on zero-return success");

    syscall_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    fake_return_value = 9;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_restrict_self(11, 0) == 0 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == 11 &&
           captured_flags == 0,
       "normalizes positive syscall returns to 0");

    syscall_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    fake_return_value = -7;
    fake_errno_value = EPERM;
    errno = 0;
    rc = landlock_restrict_self(15, 0);
    ok(rc == -1 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == 15 &&
           captured_flags == 0,
       "returns -1 for negative syscall results");

    syscall_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    fake_return_value = -1;
    fake_errno_value = ENOSYS;
    errno = 0;
    ok(landlock_restrict_self(21, 0) == -1 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == 21 &&
           captured_flags == 0 &&
           errno == ENOSYS,
       "preserves errno on syscall failure");

    syscall_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    fake_return_value = 0;
    fake_errno_value = EIO;
    errno = EBUSY;
    ok(landlock_restrict_self(31, 0) == 0 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == 31 &&
           captured_flags == 0 &&
           errno == EBUSY,
       "preserves caller errno on successful restrict_self");

    syscall_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    fake_return_value = 9;
    fake_errno_value = EPERM;
    errno = ENAMETOOLONG;
    ok(landlock_restrict_self(33, 0) == 0 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == 33 &&
           captured_flags == 0 &&
           errno == ENAMETOOLONG,
       "preserves caller errno when syscall returns a positive success value");

    done_testing();
}
