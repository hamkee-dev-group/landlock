#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/preflight.h"
#include "landlockd/seccomp.h"
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

struct cli_build_state {
    int create_fs_ruleset_call_count;
    uint64_t create_fs_ruleset_requested_access_fs;
    int add_fs_rule_call_count;
    int add_fs_rule_ruleset_fd[4];
    uint64_t add_fs_rule_allowed_access[4];
    int add_fs_rule_parent_fd[4];
    unsigned int add_fs_rule_flags[4];
    int apply_sandbox_call_count;
    int apply_sandbox_ruleset_fd;
    unsigned int apply_sandbox_flags;
    int apply_sandbox_with_seccomp_call_count;
    int apply_sandbox_with_seccomp_ruleset_fd;
    int apply_sandbox_with_seccomp_listener_fd;
    int apply_sandbox_with_seccomp_plan_count;
    int apply_sandbox_with_seccomp_syscalls[4];
    int open_call_count;
    const char *opened_paths[4];
    int open_flags[4];
    int close_call_count;
    int closed_fds[8];
    int execvp_call_count;
    const char *execvp_file;
    char *const *execvp_argv;
};

static struct cli_build_state *state;

int open(const char *path, int flags, ...)
{
    state->opened_paths[state->open_call_count] = path;
    state->open_flags[state->open_call_count] = flags;
    state->open_call_count++;
    return 40 + state->open_call_count;
}

int close(int fd)
{
    state->closed_fds[state->close_call_count] = fd;
    state->close_call_count++;
    return 0;
}

int execvp(const char *file, char *const argv[])
{
    state->execvp_call_count++;
    state->execvp_file = file;
    state->execvp_argv = argv;
    errno = ENOENT;
    return -1;
}

void perror(const char *s)
{
    (void)s;
}

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs)
{
    (void)granted_access_fs;
    state->create_fs_ruleset_call_count++;
    state->create_fs_ruleset_requested_access_fs = requested_access_fs;
    return 17;
}

int landlock_add_fs_rule(int ruleset_fd,
                         const struct landlock_path_beneath_attr *attr,
                         unsigned int flags)
{
    int i = state->add_fs_rule_call_count;
    state->add_fs_rule_ruleset_fd[i] = ruleset_fd;
    state->add_fs_rule_allowed_access[i] = attr->allowed_access;
    state->add_fs_rule_parent_fd[i] = attr->parent_fd;
    state->add_fs_rule_flags[i] = flags;
    state->add_fs_rule_call_count++;
    return 0;
}

int landlockd_apply_sandbox(int ruleset_fd, unsigned int flags)
{
    state->apply_sandbox_call_count++;
    state->apply_sandbox_ruleset_fd = ruleset_fd;
    state->apply_sandbox_flags = flags;
    return 0;
}

int landlockd_apply_sandbox_with_seccomp(
    int ruleset_fd, const struct landlockd_seccomp_plan *plan,
    int *listener_fd_out)
{
    int i;

    state->apply_sandbox_with_seccomp_call_count++;
    state->apply_sandbox_with_seccomp_ruleset_fd = ruleset_fd;
    state->apply_sandbox_with_seccomp_listener_fd = 61;
    state->apply_sandbox_with_seccomp_plan_count = plan->count;
    for (i = 0; i < plan->count; i++) {
        state->apply_sandbox_with_seccomp_syscalls[i] = plan->syscall_nrs[i];
    }
    if (listener_fd_out != NULL) {
        *listener_fd_out = state->apply_sandbox_with_seccomp_listener_fd;
    }
    return 0;
}

int main(void)
{
    char *argv[] = {"landlockd", "--ro", "/a", "--ro", "/b", "--", "/bin/echo",
                    "ok", NULL};
    char *mixed_argv[] = {"landlockd", "--notify", "39", "--ro", "/a",
                          "--notify", "102", "--ro", "/b", "--", "/bin/echo",
                          "ok", NULL};
    int rc;

    state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) {
        diag("mmap failed");
        return 1;
    }
    memset(state, 0, sizeof(*state));

    plan(14);

    errno = 0;
    rc = landlockd_cli_main(8, argv);

    ok(rc == 127,
       "exec failure in the forked child surfaces as the launcher's 127 exit status");
    ok(state->create_fs_ruleset_call_count == 1 &&
           state->create_fs_ruleset_requested_access_fs != 0,
       "creates exactly one filesystem ruleset");
    ok(state->open_call_count == 2 &&
           strcmp(state->opened_paths[0], "/a") == 0 &&
           strcmp(state->opened_paths[1], "/b") == 0 &&
           state->open_flags[0] == (O_PATH | O_CLOEXEC) &&
           state->open_flags[1] == (O_PATH | O_CLOEXEC),
       "opens each allowed path with O_PATH and O_CLOEXEC");
    ok(state->add_fs_rule_call_count == 2,
       "adds one filesystem rule per allowed path");
    ok(state->add_fs_rule_ruleset_fd[0] == 17 &&
           state->add_fs_rule_ruleset_fd[1] == 17 &&
           state->add_fs_rule_parent_fd[0] == 41 &&
           state->add_fs_rule_parent_fd[1] == 42,
       "uses the same ruleset fd and each opened parent fd");
    ok(state->add_fs_rule_allowed_access[0] ==
           (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) &&
           state->add_fs_rule_allowed_access[1] ==
               (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) &&
           state->add_fs_rule_flags[0] == 0 &&
           state->add_fs_rule_flags[1] == 0,
       "adds read-only rules with zero flags");
    ok(state->close_call_count == 3 && state->closed_fds[0] == 41 &&
           state->closed_fds[1] == 42 && state->closed_fds[2] == 17,
       "closes both parent fds and the ruleset fd");
    ok(state->apply_sandbox_call_count == 1 &&
           state->apply_sandbox_ruleset_fd == 17 &&
           state->apply_sandbox_flags == 0,
       "applies the sandbox once after adding all rules");
    ok(state->apply_sandbox_with_seccomp_call_count == 0,
       "does not use seccomp when --notify is absent");
    ok(state->execvp_call_count == 1 &&
           strcmp(state->execvp_file, "/bin/echo") == 0,
       "execs the requested command after applying the sandbox");
    ok(state->execvp_argv != NULL &&
           strcmp(state->execvp_argv[1], "ok") == 0 &&
           state->execvp_argv[2] == NULL,
       "passes the command argv through to execvp");

    memset(state, 0, sizeof(*state));
    errno = 0;
    rc = landlockd_cli_main(12, mixed_argv);
    ok(rc == 127 && state->open_call_count == 2 &&
           strcmp(state->opened_paths[0], "/a") == 0 &&
           strcmp(state->opened_paths[1], "/b") == 0,
       "opens declared --ro paths regardless of interleaved --notify options");
    ok(state->apply_sandbox_call_count == 0 &&
           state->apply_sandbox_with_seccomp_call_count == 1 &&
           state->apply_sandbox_with_seccomp_ruleset_fd == 17 &&
           state->apply_sandbox_with_seccomp_plan_count == 2 &&
           state->apply_sandbox_with_seccomp_syscalls[0] == 39 &&
           state->apply_sandbox_with_seccomp_syscalls[1] == 102,
       "uses the seccomp sandbox helper with the notify syscall plan");
    ok(state->close_call_count == 5 && state->closed_fds[0] == 41 &&
           state->closed_fds[1] == 42 && state->closed_fds[2] == 61 &&
           state->closed_fds[3] == 17 && state->closed_fds[4] == 17,
       "closes the seccomp listener and notify-path ruleset fds before exit");

    done_testing();
}
