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
    int probe_seccomp_errno;
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
    out->seccomp_probe_errno = state.probe_seccomp_errno;
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

static int run_case(int stub_errno, char *stderr_buf, size_t bufsize)
{
    char *argv[] = {"landlockd", "--ro",    "/tmp",     "--notify",
                    "39",        "--",      "/bin/true", NULL};
    int pipe_fds[2];
    int saved_stderr;
    ssize_t n;
    int rc;

    memset(&state, 0, sizeof(state));
    state.probe_seccomp_errno = stub_errno;

    if (pipe2(pipe_fds, O_NONBLOCK) < 0) {
        return -1;
    }
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0) {
        return -1;
    }
    if (dup2(pipe_fds[1], STDERR_FILENO) < 0) {
        return -1;
    }

    errno = 0;
    rc = landlockd_cli_main(7, argv);
    fflush(stderr);

    dup2(saved_stderr, STDERR_FILENO);
    n = read(pipe_fds[0], stderr_buf, bufsize - 1);
    if (n < 0) {
        n = 0;
    }
    stderr_buf[n] = '\0';
    close(saved_stderr);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return rc;
}

static int stderr_names_seccomp_user_notif_unsupported(const char *buf)
{
    int has_seccomp = strstr(buf, "seccomp") != NULL;
    int has_user_notif = strstr(buf, "user-notif") != NULL ||
                         strstr(buf, "user_notif") != NULL ||
                         strstr(buf, "user notify") != NULL;
    int has_unsupported = strstr(buf, "not supported") != NULL ||
                          strstr(buf, "unsupported") != NULL;
    return has_seccomp && has_user_notif && has_unsupported;
}

int main(void)
{
    char stderr_buf[512];
    int rc;

    plan(16);

    rc = run_case(ENOSYS, stderr_buf, sizeof(stderr_buf));
    ok(rc == 1, "ENOSYS: launcher returns exit status 1");
    ok(stderr_names_seccomp_user_notif_unsupported(stderr_buf),
       "ENOSYS: stderr names seccomp user-notif as unsupported");
    ok(state.create_fs_ruleset_call_count == 0,
       "ENOSYS: landlock_create_fs_ruleset is never called");
    ok(state.open_call_count == 0, "ENOSYS: open is never called");
    ok(state.fork_call_count == 0, "ENOSYS: fork is never called");
    ok(state.apply_sandbox_with_seccomp_call_count == 0,
       "ENOSYS: landlockd_apply_sandbox_with_seccomp is never called");
    ok(state.execvp_call_count == 0, "ENOSYS: execvp is never called");
    ok(state.apply_sandbox_call_count == 0,
       "ENOSYS: landlockd_apply_sandbox is never called");

    rc = run_case(EOPNOTSUPP, stderr_buf, sizeof(stderr_buf));
    ok(rc == 1, "EOPNOTSUPP: launcher returns exit status 1");
    ok(stderr_names_seccomp_user_notif_unsupported(stderr_buf),
       "EOPNOTSUPP: stderr names seccomp user-notif as unsupported");
    ok(state.create_fs_ruleset_call_count == 0,
       "EOPNOTSUPP: landlock_create_fs_ruleset is never called");
    ok(state.open_call_count == 0, "EOPNOTSUPP: open is never called");
    ok(state.fork_call_count == 0, "EOPNOTSUPP: fork is never called");
    ok(state.apply_sandbox_with_seccomp_call_count == 0,
       "EOPNOTSUPP: landlockd_apply_sandbox_with_seccomp is never called");
    ok(state.execvp_call_count == 0, "EOPNOTSUPP: execvp is never called");
    ok(state.apply_sandbox_call_count == 0,
       "EOPNOTSUPP: landlockd_apply_sandbox is never called");

    done_testing();
}
