#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/preflight.h"
#include "landlockd/seccomp.h"
#include "landlockd_cli.h"
#include "tap.h"

struct cli_state {
    int create_fs_ruleset_call_count;
    int add_fs_rule_call_count;
    int apply_sandbox_call_count;
    int apply_sandbox_with_seccomp_call_count;
    int open_call_count;
    int fork_call_count;
    int execvp_call_count;
};

static struct cli_state state;

int landlockd_preflight_run(int required_abi_floor,
                            struct landlockd_preflight_report *out)
{
    out->abi_version = 1;
    out->required_abi_floor = required_abi_floor;
    out->meets_abi_floor = 1;
    out->stacking_supported = 1;
    out->probe_errno = 0;
    out->seccomp_user_notif_supported = 0;
    out->seccomp_probe_errno = 0;
    return 0;
}

int landlockd_preflight_probe_seccomp_user_notif(
    struct landlockd_preflight_report *out)
{
    out->seccomp_user_notif_supported = 0;
    out->seccomp_probe_errno = EINVAL;
    return 0;
}

int open(const char *path, int flags, ...)
{
    (void)path;
    (void)flags;
    state.open_call_count++;
    errno = ENOENT;
    return -1;
}

pid_t fork(void)
{
    state.fork_call_count++;
    errno = ENOSYS;
    return -1;
}

int execvp(const char *file, char *const argv[])
{
    (void)file;
    (void)argv;
    state.execvp_call_count++;
    errno = ENOENT;
    return -1;
}

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs)
{
    (void)requested_access_fs;
    (void)granted_access_fs;
    state.create_fs_ruleset_call_count++;
    errno = ENOSYS;
    return -1;
}

int landlock_add_fs_rule(int ruleset_fd,
                         const struct landlock_path_beneath_attr *attr,
                         unsigned int flags)
{
    (void)ruleset_fd;
    (void)attr;
    (void)flags;
    state.add_fs_rule_call_count++;
    return 0;
}

int landlockd_apply_sandbox(int ruleset_fd, unsigned int flags)
{
    (void)ruleset_fd;
    (void)flags;
    state.apply_sandbox_call_count++;
    return 0;
}

int landlockd_apply_sandbox_with_seccomp(
    int ruleset_fd, const struct landlockd_seccomp_plan *plan,
    int *listener_fd_out)
{
    (void)ruleset_fd;
    (void)plan;
    (void)listener_fd_out;
    state.apply_sandbox_with_seccomp_call_count++;
    return 0;
}

int main(void)
{
    char *argv[] = {"landlockd", "--ro",    "/tmp",     "--notify",
                    "39",        "--",      "/bin/true", NULL};
    char stderr_buf[512];
    int pipe_fds[2];
    int saved_stderr;
    ssize_t n;
    int rc;

    plan(8);

    memset(&state, 0, sizeof(state));

    if (pipe2(pipe_fds, O_NONBLOCK) < 0) {
        BAIL_OUT("pipe2 failed");
    }
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0) {
        BAIL_OUT("dup failed");
    }
    if (dup2(pipe_fds[1], STDERR_FILENO) < 0) {
        BAIL_OUT("dup2 failed");
    }

    errno = 0;
    rc = landlockd_cli_main(7, argv);
    fflush(stderr);

    dup2(saved_stderr, STDERR_FILENO);
    n = read(pipe_fds[0], stderr_buf, sizeof(stderr_buf) - 1);
    if (n < 0) {
        n = 0;
    }
    stderr_buf[n] = '\0';
    close(saved_stderr);
    close(pipe_fds[0]);
    close(pipe_fds[1]);

    ok(rc == 1, "EINVAL: launcher returns exit status 1");
    ok(strstr(stderr_buf, "seccomp") != NULL &&
           (strstr(stderr_buf, "user-notif") != NULL ||
            strstr(stderr_buf, "user_notif") != NULL) &&
           (strstr(stderr_buf, "not supported") != NULL ||
            strstr(stderr_buf, "unsupported") != NULL),
       "EINVAL: stderr names seccomp user-notif as unsupported");
    ok(state.create_fs_ruleset_call_count == 0,
       "EINVAL: landlock_create_fs_ruleset is never called");
    ok(state.open_call_count == 0, "EINVAL: open is never called");
    ok(state.fork_call_count == 0, "EINVAL: fork is never called");
    ok(state.apply_sandbox_with_seccomp_call_count == 0,
       "EINVAL: landlockd_apply_sandbox_with_seccomp is never called");
    ok(state.execvp_call_count == 0, "EINVAL: execvp is never called");
    ok(state.apply_sandbox_call_count == 0,
       "EINVAL: landlockd_apply_sandbox is never called");

    done_testing();
}
