#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int syscall_call_count;
static long fake_return_value;
static int fake_errno_value;

long landlock_restrict_self_syscall(int ruleset_fd, uint32_t flags)
{
    (void)ruleset_fd;
    (void)flags;
    syscall_call_count++;
    errno = fake_errno_value;
    return fake_return_value;
}

int main(void)
{
    char warning[256];
    int capture_pipe[2];
    int saved_stderr_fd;
    int rc;
    ssize_t warning_len;

    plan(3);

    pipe(capture_pipe);
    saved_stderr_fd = dup(STDERR_FILENO);

    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = ENOSYS;
    errno = 0;

    dup2(capture_pipe[1], STDERR_FILENO);
    rc = landlock_restrict_self(5, 1);
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

    ok(rc == -1 && errno == EINVAL,
       "rejects non-zero flags with EINVAL");
    ok(syscall_call_count == 0,
       "does not call the syscall for invalid flags");
    ok(warning_len == 0,
       "does not emit an unsupported-kernel warning for invalid flags");

    done_testing();
}
