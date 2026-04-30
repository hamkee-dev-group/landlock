#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "landlock_policy_ir.h"
#include "landlock_policy_loader.h"
#include "landlockd/landlock.h"
#include "landlockd/preflight.h"
#include "landlockd/seccomp.h"
#include "landlockd_cli.h"
#include "tap.h"

struct cli_state {
    int load_file_call_count;
    int fork_call_count;
    int create_fs_ruleset_call_count;
    int add_fs_rule_call_count;
    int apply_sandbox_call_count;
    int apply_sandbox_with_seccomp_call_count;
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
    if (landlockd_policy_ir_enable_net(out_ir, 0x3) < 0) {
        return -1;
    }
    return 0;
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
    errno = ENOSYS;
    return -1;
}

int landlock_add_net_rule(int ruleset_fd,
                          const struct landlock_net_port_attr *attr,
                          unsigned int flags)
{
    (void)ruleset_fd;
    (void)attr;
    (void)flags;
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

static int stderr_diagnoses_network_abi_requirement(const char *buf)
{
    return strstr(buf, "landlockd") != NULL &&
           strstr(buf, "network") != NULL &&
           strstr(buf, "ABI") != NULL &&
           strstr(buf, "4") != NULL;
}

int main(void)
{
    char *argv[] = {"landlockd", "run",      "--policy-file",
                    "/dev/null", "--",       "/bin/true",
                    NULL};
    char stderr_buf[512];
    int pipe_fds[2];
    int saved_stderr;
    ssize_t n;
    int rc;

    plan(9);

    memset(&state, 0, sizeof(state));

    if (pipe2(pipe_fds, O_NONBLOCK) < 0) {
        diag("pipe2 failed");
        return 1;
    }
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0) {
        diag("dup failed");
        return 1;
    }
    if (dup2(pipe_fds[1], STDERR_FILENO) < 0) {
        diag("dup2 failed");
        return 1;
    }

    errno = 0;
    rc = landlockd_cli_main(6, argv);
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

    ok(rc == 1,
       "network policy on ABI 1 drives run path to exit 1");
    ok(state.load_file_call_count == 1,
       "landlockd_policy_load_file is invoked exactly once");
    ok(stderr_diagnoses_network_abi_requirement(stderr_buf),
       "stderr reports the ABI requirement for network policy");
    ok(state.fork_call_count == 0, "fork is never called");
    ok(state.create_fs_ruleset_call_count == 0,
       "landlock_create_fs_ruleset is never called");
    ok(state.add_fs_rule_call_count == 0,
       "landlock_add_fs_rule is never called");
    ok(state.apply_sandbox_call_count == 0,
       "landlockd_apply_sandbox is never called");
    ok(state.apply_sandbox_with_seccomp_call_count == 0,
       "landlockd_apply_sandbox_with_seccomp is never called");
    ok(state.execvp_call_count == 0, "execvp is never called");

    done_testing();
}
