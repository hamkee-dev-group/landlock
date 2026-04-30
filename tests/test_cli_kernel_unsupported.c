#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/preflight.h"
#include "landlockd_cli.h"
#include "tap.h"

int landlockd_preflight_run(int required_abi_floor,
                            struct landlockd_preflight_report *out)
{
    out->abi_version = 1;
    out->required_abi_floor = required_abi_floor;
    out->meets_abi_floor = 1;
    out->stacking_supported = 1;
    out->probe_errno = 0;
    return 0;
}

struct cli_state {
    int create_fs_ruleset_call_count;
    int create_fs_ruleset_errno;
    int add_fs_rule_call_count;
    int apply_sandbox_call_count;
    int open_call_count;
    int execvp_call_count;
    int close_call_count;
};

static struct cli_state state;

int open(const char *path, int flags, ...)
{
    (void)path;
    (void)flags;
    state.open_call_count++;
    errno = ENOENT;
    return -1;
}

int close(int fd)
{
    (void)fd;
    state.close_call_count++;
    return 0;
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
    errno = state.create_fs_ruleset_errno;
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

static int run_case(int stub_errno, char *stderr_buf, size_t bufsize)
{
    char *argv[] = {"landlockd", "--ro", "/tmp", "--", "/bin/true", NULL};
    int pipe_fds[2];
    int saved_stderr;
    ssize_t n;
    int rc;

    memset(&state, 0, sizeof(state));
    state.create_fs_ruleset_errno = stub_errno;

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
    rc = landlockd_cli_main(5, argv);
    fflush(stderr);

    dup2(saved_stderr, STDERR_FILENO);
    n = read(pipe_fds[0], stderr_buf, bufsize - 1);
    if (n < 0) {
        n = 0;
    }
    stderr_buf[n] = '\0';
    return rc;
}

static int stderr_has_landlock_kernel_hint(const char *buf)
{
    if (buf[0] == '\0' || strstr(buf, "Landlock") == NULL) {
        return 0;
    }
    return strstr(buf, "not supported") != NULL ||
           strstr(buf, "kernel") != NULL;
}

int main(void)
{
    char stderr_buf[512];
    int rc;

    plan(12);

    rc = run_case(ENOSYS, stderr_buf, sizeof(stderr_buf));
    ok(rc == 1, "ENOSYS: launcher returns exit status 1");
    ok(stderr_has_landlock_kernel_hint(stderr_buf),
       "ENOSYS: stderr names Landlock and an unsupported-kernel hint");
    ok(state.open_call_count == 0, "ENOSYS: open is never called");
    ok(state.add_fs_rule_call_count == 0,
       "ENOSYS: landlock_add_fs_rule is never called");
    ok(state.apply_sandbox_call_count == 0,
       "ENOSYS: landlockd_apply_sandbox is never called");
    ok(state.execvp_call_count == 0, "ENOSYS: execvp is never called");

    rc = run_case(EOPNOTSUPP, stderr_buf, sizeof(stderr_buf));
    ok(rc == 1, "EOPNOTSUPP: launcher returns exit status 1");
    ok(stderr_has_landlock_kernel_hint(stderr_buf),
       "EOPNOTSUPP: stderr names Landlock and an unsupported-kernel hint");
    ok(state.open_call_count == 0, "EOPNOTSUPP: open is never called");
    ok(state.add_fs_rule_call_count == 0,
       "EOPNOTSUPP: landlock_add_fs_rule is never called");
    ok(state.apply_sandbox_call_count == 0,
       "EOPNOTSUPP: landlockd_apply_sandbox is never called");
    ok(state.execvp_call_count == 0, "EOPNOTSUPP: execvp is never called");

    done_testing();
}
