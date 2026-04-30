#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "landlock_policy_ir.h"
#include "landlock_policy_loader.h"
#include "landlockd/preflight.h"
#include "landlockd/seccomp.h"
#include "landlockd_cli.h"
#include "tap.h"

struct cli_state {
    int load_file_call_count;
    int fork_call_count;
    int create_fs_ruleset_call_count;
    int create_net_ruleset_call_count;
    int apply_sandbox_call_count;
    int apply_sandbox_with_seccomp_call_count;
    int execvp_call_count;
};

static struct cli_state state;

int landlockd_preflight_run(int required_abi_floor,
                            struct landlockd_preflight_report *out)
{
    memset(out, 0, sizeof(*out));
    out->abi_version = 1;
    out->required_abi_floor = required_abi_floor;
    out->meets_abi_floor = 1;
    out->stacking_supported = 1;
    return 0;
}

int landlockd_preflight_probe_seccomp_user_notif(
    struct landlockd_preflight_report *out)
{
    out->seccomp_user_notif_supported = 1;
    out->seccomp_probe_errno = 0;
    return 0;
}

int landlockd_policy_load_file(const char *file_path,
                               struct landlockd_policy_ir *out_ir,
                               FILE *err_stream)
{
    (void)file_path;
    (void)err_stream;
    state.load_file_call_count++;
    landlockd_policy_ir_init(out_ir);
    return landlockd_policy_ir_enable_net(out_ir, 0x3);
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

int landlock_create_net_ruleset(uint64_t requested_access_net,
                                uint64_t *granted_access_net)
{
    (void)requested_access_net;
    (void)granted_access_net;
    state.create_net_ruleset_call_count++;
    errno = ENOSYS;
    return -1;
}

int landlockd_apply_sandbox(int ruleset_fd, unsigned int flags)
{
    (void)ruleset_fd;
    (void)flags;
    state.apply_sandbox_call_count++;
    errno = ENOSYS;
    return -1;
}

int landlockd_apply_sandbox_with_seccomp(
    int ruleset_fd, const struct landlockd_seccomp_plan *plan,
    int *listener_fd_out)
{
    (void)ruleset_fd;
    (void)plan;
    (void)listener_fd_out;
    state.apply_sandbox_with_seccomp_call_count++;
    errno = ENOSYS;
    return -1;
}

static int capture_cli(int argc, char *argv[], int *rc, char *stdout_buf,
                       size_t stdout_size, char *stderr_buf,
                       size_t stderr_size)
{
    int stdout_pipe[2];
    int stderr_pipe[2];
    int saved_stdout;
    int saved_stderr;
    ssize_t n;

    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
        return -1;
    }
    saved_stdout = dup(STDOUT_FILENO);
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stdout < 0 || saved_stderr < 0) {
        return -1;
    }
    fflush(stdout);
    fflush(stderr);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    dup2(stderr_pipe[1], STDERR_FILENO);
    *rc = landlockd_cli_main(argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_stdout, STDOUT_FILENO);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stdout);
    close(saved_stderr);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    n = read(stdout_pipe[0], stdout_buf, stdout_size - 1);
    if (n < 0) {
        n = 0;
    }
    stdout_buf[n] = '\0';
    n = read(stderr_pipe[0], stderr_buf, stderr_size - 1);
    if (n < 0) {
        n = 0;
    }
    stderr_buf[n] = '\0';
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    return 0;
}

static int no_runtime_side_effects(void)
{
    return state.fork_call_count == 0 &&
           state.create_fs_ruleset_call_count == 0 &&
           state.create_net_ruleset_call_count == 0 &&
           state.apply_sandbox_call_count == 0 &&
           state.apply_sandbox_with_seccomp_call_count == 0 &&
           state.execvp_call_count == 0;
}

int main(void)
{
    char *argv[] = {"landlockd", "run", "--policy-file", "/dev/null",
                    "--dry-run", "--", "/bin/true", NULL};
    char stdout_buf[2048];
    char stderr_buf[256];
    int rc;

    plan(7);

    memset(&state, 0, sizeof(state));
    ok(capture_cli(7, argv, &rc, stdout_buf, sizeof(stdout_buf), stderr_buf,
                   sizeof(stderr_buf)) == 0,
       "dry-run net-unsupported output can be captured");
    ok(rc == 2, "dry-run exits 2 for unsupported required network ABI");
    ok(strstr(stdout_buf, "landlockd dry-run v1\n") != NULL,
       "dry-run still emits the stable header");
    ok(strstr(stdout_buf, "feature.degraded name=net") != NULL,
       "dry-run reports degraded network support");
    ok(strstr(stdout_buf, "dry-run.status=fail reason=net-unsupported") !=
           NULL,
       "dry-run reports the net-unsupported failure reason");
    ok(state.load_file_call_count == 1,
       "dry-run loads the policy exactly once before reporting degradation");
    ok(no_runtime_side_effects(),
       "dry-run net-unsupported exits before any runtime side effects");

    done_testing();
}
