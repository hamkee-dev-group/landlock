#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int call_order;
static int prctl_call_order;
static int restrict_call_order;
static int prctl_call_count;
static int restrict_call_count;
static int captured_ruleset_fd;
static uint32_t captured_flags;
static int captured_prctl_option;
static unsigned long captured_prctl_arg2;
static unsigned long captured_prctl_arg3;
static unsigned long captured_prctl_arg4;
static unsigned long captured_prctl_arg5;
static long prctl_return_value;
static int prctl_errno_value;
static long restrict_return_value;
static int restrict_errno_value;

long landlockd_prctl_shim(int option, unsigned long arg2, unsigned long arg3,
                          unsigned long arg4, unsigned long arg5)
{
    prctl_call_count++;
    prctl_call_order = ++call_order;
    captured_prctl_option = option;
    captured_prctl_arg2 = arg2;
    captured_prctl_arg3 = arg3;
    captured_prctl_arg4 = arg4;
    captured_prctl_arg5 = arg5;
    errno = prctl_errno_value;
    return prctl_return_value;
}

long landlock_restrict_self_syscall(int ruleset_fd, uint32_t flags)
{
    restrict_call_count++;
    restrict_call_order = ++call_order;
    captured_ruleset_fd = ruleset_fd;
    captured_flags = flags;
    errno = restrict_errno_value;
    return restrict_return_value;
}

int main(void)
{
    char warning[256];
    int capture_pipe[2];
    int rc;
    int saved_stderr_fd;
    ssize_t warning_len;

    plan(25);

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlock_restrict_self_with_no_new_privs(27, 0);
    ok(rc == 0 && errno == 0,
       "returns success when prctl and restrict_self succeed");
    ok(prctl_call_count == 1 &&
           restrict_call_count == 1 &&
           prctl_call_order == 1 &&
           restrict_call_order == 2,
       "calls prctl before restrict_self on success");
    ok(captured_prctl_option == PR_SET_NO_NEW_PRIVS &&
           captured_prctl_arg2 == 1 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "uses the exact PR_SET_NO_NEW_PRIVS contract");
    ok(captured_ruleset_fd == 27 && captured_flags == 0,
       "forwards exact restrict_self arguments after prctl succeeds");

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = -1;
    prctl_errno_value = EPERM;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlock_restrict_self_with_no_new_privs(31, 0);
    ok(rc == -1 && errno == EPERM,
       "returns the prctl errno when prctl fails");
    ok(prctl_call_count == 1 &&
           prctl_call_order == 1 &&
           restrict_call_count == 0 &&
           restrict_call_order == 0,
       "does not call restrict_self after a prctl failure");
    ok(captured_ruleset_fd == 0 && captured_flags == 0,
       "leaves restrict_self arguments untouched when prctl fails first");

    pipe(capture_pipe);
    saved_stderr_fd = dup(STDERR_FILENO);

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = -1;
    restrict_errno_value = ENOSYS;
    errno = 0;

    dup2(capture_pipe[1], STDERR_FILENO);
    rc = landlock_restrict_self_with_no_new_privs(44, 0);
    fflush(stderr);
    dup2(saved_stderr_fd, STDERR_FILENO);
    close(saved_stderr_fd);
    close(capture_pipe[1]);

    warning_len = read(capture_pipe[0], warning, sizeof(warning) - 1);
    if (warning_len >= 0) {
        warning[warning_len] = '\0';
    } else {
        warning[0] = '\0';
    }
    close(capture_pipe[0]);

    ok(rc == -1 && errno == ENOSYS,
       "returns the restrict_self errno after prctl succeeds");
    ok(prctl_call_count == 1 &&
           restrict_call_count == 1 &&
           prctl_call_order == 1 &&
           restrict_call_order == 2,
       "still calls restrict_self after a successful prctl");
    ok(captured_ruleset_fd == 44 && captured_flags == 0,
       "forwards arguments to restrict_self on post-prctl failure");
    ok(warning_len == 0,
       "leaves restrict_self warning behavior unchanged");

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_apply_sandbox(53, 0);
    ok(rc == 0 && errno == 0,
       "apply_sandbox returns success when prctl and restrict_self succeed");
    ok(prctl_call_count == 1 &&
           restrict_call_count == 1 &&
           prctl_call_order == 1 &&
           restrict_call_order == 2,
       "apply_sandbox calls prctl before restrict_self");
    ok(captured_prctl_option == PR_SET_NO_NEW_PRIVS &&
           captured_prctl_arg2 == 1 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "apply_sandbox uses the exact PR_SET_NO_NEW_PRIVS contract");
    ok(captured_ruleset_fd == 53 && captured_flags == 0,
       "apply_sandbox forwards ruleset_fd and flags unchanged");

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_apply_sandbox(31, 0);
    ok(captured_ruleset_fd == 31 &&
           captured_flags == 0 &&
           prctl_call_order == 1 &&
           restrict_call_order == 2 &&
           rc == 0,
       "apply_sandbox forwards ruleset_fd and flags verbatim to restrict_self");

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_apply_sandbox(-1, 0);
    ok(rc == -1 && errno == EBADF,
       "apply_sandbox fails with EBADF for a negative ruleset fd");
    ok(prctl_call_count == 0 &&
           restrict_call_count == 0 &&
           prctl_call_order == 0 &&
           restrict_call_order == 0,
       "apply_sandbox skips prctl and restrict_self for a negative ruleset fd");
    ok(captured_ruleset_fd == 0 && captured_flags == 0,
       "apply_sandbox leaves restrict_self arguments untouched for a negative ruleset fd");
    ok(captured_prctl_option == 0 &&
           captured_prctl_arg2 == 0 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "apply_sandbox leaves prctl arguments untouched for a negative ruleset fd");

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlock_restrict_self_with_no_new_privs(7, 1);
    ok(rc == -1 && errno == EINVAL,
       "rejects non-zero flags with EINVAL before touching prctl");
    ok(prctl_call_count == 0 &&
           restrict_call_count == 0 &&
           prctl_call_order == 0 &&
           restrict_call_order == 0,
       "skips prctl and restrict_self when flags are invalid");
    ok(captured_ruleset_fd == 0 && captured_flags == 0,
       "leaves restrict_self arguments untouched for invalid flags");
    ok(captured_prctl_option == 0 &&
           captured_prctl_arg2 == 0 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "leaves prctl arguments untouched for invalid flags");

    call_order = 0;
    prctl_call_order = 0;
    restrict_call_order = 0;
    prctl_call_count = 0;
    restrict_call_count = 0;
    captured_ruleset_fd = 0;
    captured_flags = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    prctl_return_value = 0;
    prctl_errno_value = 0;
    restrict_return_value = 0;
    restrict_errno_value = 0;
    errno = 0;
    rc = landlockd_apply_sandbox(53, 1);
    ok(rc == -1 && errno == EINVAL &&
           prctl_call_count == 0 &&
           restrict_call_count == 0 &&
           prctl_call_order == 0 &&
           restrict_call_order == 0 &&
           captured_ruleset_fd == 0 &&
           captured_flags == 0 &&
           captured_prctl_option == 0 &&
           captured_prctl_arg2 == 0 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "apply_sandbox rejects non-zero flags with EINVAL without touching prctl or restrict_self");

    done_testing();
}
