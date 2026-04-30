#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
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
    uint64_t create_fs_ruleset_requested_access_fs;
    int add_fs_rule_call_count;
    uint64_t add_fs_rule_allowed_access;
    int add_fs_rule_parent_fd;
    unsigned int add_fs_rule_flags;
    int open_call_count;
    char opened_path[32];
    int open_flags;
    int open_returned_fd;
    int apply_sandbox_call_count;
    int apply_sandbox_with_seccomp_call_count;
    int execvp_call_count;
    char execvp_file[32];
};

static struct cli_state *state;

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
    size_t layer0;

    (void)file_path;
    (void)err_stream;

    state->load_file_call_count++;

    landlockd_policy_ir_init(out_ir);
    if (landlockd_policy_ir_add_fs_layer(
            out_ir,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            &layer0) < 0 ||
        landlockd_policy_ir_add_fs_rule(
            out_ir, layer0, "/a",
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) < 0) {
        return -1;
    }

    return 0;
}

int open(const char *path, int flags, ...)
{
    int fd;

    state->open_call_count++;
    snprintf(state->opened_path, sizeof(state->opened_path), "%s", path);
    state->open_flags = flags;
    fd = 40 + state->open_call_count;
    state->open_returned_fd = fd;
    return fd;
}

int close(int fd)
{
    (void)fd;
    return 0;
}

void perror(const char *s)
{
    (void)s;
}

pid_t fork(void)
{
    state->fork_call_count++;
    return (pid_t)syscall(SYS_fork);
}

int execvp(const char *file, char *const argv[])
{
    (void)argv;
    state->execvp_call_count++;
    snprintf(state->execvp_file, sizeof(state->execvp_file), "%s", file);
    errno = ENOENT;
    return -1;
}

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs)
{
    (void)granted_access_fs;
    state->create_fs_ruleset_call_count++;
    state->create_fs_ruleset_requested_access_fs = requested_access_fs;
    return 71;
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
    state->add_fs_rule_call_count++;
    state->add_fs_rule_allowed_access = attr->allowed_access;
    state->add_fs_rule_parent_fd = attr->parent_fd;
    state->add_fs_rule_flags = flags;
    return 0;
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
    state->apply_sandbox_call_count++;
    return 0;
}

int landlockd_apply_sandbox_with_seccomp(
    int ruleset_fd, const struct landlockd_seccomp_plan *plan,
    int *listener_fd_out)
{
    (void)ruleset_fd;
    (void)plan;
    (void)listener_fd_out;
    state->apply_sandbox_with_seccomp_call_count++;
    return 0;
}

int main(void)
{
    char *argv[] = {"landlockd", "run",        "--policy-file",
                    "/dev/null", "--",         "/bin/echo",
                    "ok",        NULL};
    char stderr_buf[1024];
    int pipe_fds[2];
    int saved_stderr;
    ssize_t n;
    int rc;

    state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) {
        diag("mmap failed");
        return 1;
    }
    memset(state, 0, sizeof(*state));

    plan(10);

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

    ok(rc == 127,
       "fs-only run --policy-file reaches exec and surfaces child exec failure as rc=127");
    ok(state->load_file_call_count == 1,
       "landlockd_policy_load_file is invoked exactly once");
    ok(state->create_fs_ruleset_call_count == 1 &&
           state->create_fs_ruleset_requested_access_fs ==
               (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR),
       "creates exactly one fs ruleset using the loaded layer's handled_access_fs");
    ok(state->open_call_count == 1 &&
           strcmp(state->opened_path, "/a") == 0 &&
           state->open_flags == (O_PATH | O_CLOEXEC),
       "opens the loaded rule path exactly once with O_PATH|O_CLOEXEC");
    ok(state->add_fs_rule_call_count == 1 &&
           state->add_fs_rule_flags == 0 &&
           state->add_fs_rule_allowed_access ==
               (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) &&
           state->add_fs_rule_parent_fd == state->open_returned_fd,
       "adds the loaded rule with flags=0, the loaded allowed_access, and the opened parent fd");
    ok(state->fork_call_count == 1, "fork is called exactly once");
    ok(state->apply_sandbox_call_count == 1,
       "landlockd_apply_sandbox is called exactly once");
    ok(state->apply_sandbox_with_seccomp_call_count == 0,
       "landlockd_apply_sandbox_with_seccomp is never called without --notify");
    ok(state->execvp_call_count == 1 &&
           strcmp(state->execvp_file, "/bin/echo") == 0,
       "execvp is called exactly once with the declared command");
    ok(strstr(stderr_buf, "run is not implemented for --policy-file") == NULL,
       "stderr does not carry the legacy 'run is not implemented for --policy-file' diagnostic");

    done_testing();
}
