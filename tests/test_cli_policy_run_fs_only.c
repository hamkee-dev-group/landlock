#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
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
    int create_fs_ruleset_call_count;
    uint64_t create_fs_ruleset_requested_access_fs[4];
    int add_fs_rule_call_count;
    int add_fs_rule_ruleset_fd[4];
    uint64_t add_fs_rule_allowed_access[4];
    int add_fs_rule_parent_fd[4];
    int open_call_count;
    char opened_paths[4][32];
    int open_flags[4];
    int apply_sandbox_call_count;
    int apply_sandbox_ruleset_fd[4];
    int apply_sandbox_with_seccomp_call_count;
    int execvp_call_count;
    const char *execvp_file;
    char *const *execvp_argv;
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
    size_t layer1;

    (void)file_path;
    (void)err_stream;

    state->load_file_call_count++;

    landlockd_policy_ir_init(out_ir);
    if (landlockd_policy_ir_add_fs_layer(
            out_ir, LANDLOCK_ACCESS_FS_READ_FILE, &layer0) < 0 ||
        landlockd_policy_ir_add_fs_rule(out_ir, layer0, "/layer0/a",
                                        LANDLOCK_ACCESS_FS_READ_FILE) < 0 ||
        landlockd_policy_ir_add_fs_rule(out_ir, layer0, "/layer0/b",
                                        LANDLOCK_ACCESS_FS_READ_FILE) < 0 ||
        landlockd_policy_ir_add_fs_layer(
            out_ir, LANDLOCK_ACCESS_FS_READ_DIR, &layer1) < 0 ||
        landlockd_policy_ir_add_fs_rule(out_ir, layer1, "/layer1/c",
                                        LANDLOCK_ACCESS_FS_READ_DIR) < 0) {
        return -1;
    }

    return 0;
}

int open(const char *path, int flags, ...)
{
    int i = state->open_call_count;

    snprintf(state->opened_paths[i], sizeof(state->opened_paths[i]), "%s",
             path);
    state->open_flags[i] = flags;
    state->open_call_count++;
    return 40 + state->open_call_count;
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

int execvp(const char *file, char *const argv[])
{
    state->execvp_call_count++;
    state->execvp_file = file;
    state->execvp_argv = argv;
    errno = ENOENT;
    return -1;
}

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs)
{
    (void)granted_access_fs;
    state->create_fs_ruleset_requested_access_fs
        [state->create_fs_ruleset_call_count] = requested_access_fs;
    state->create_fs_ruleset_call_count++;
    return 70 + state->create_fs_ruleset_call_count;
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
    int i = state->add_fs_rule_call_count;

    state->add_fs_rule_ruleset_fd[i] = ruleset_fd;
    state->add_fs_rule_allowed_access[i] = attr->allowed_access;
    state->add_fs_rule_parent_fd[i] = attr->parent_fd;
    state->add_fs_rule_call_count++;
    (void)flags;
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
    state->apply_sandbox_ruleset_fd[state->apply_sandbox_call_count] =
        ruleset_fd;
    state->apply_sandbox_call_count++;
    (void)flags;
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
    char *argv[] = {"landlockd", "run",         "--policy-file",
                    "unused.toml", "--",         "/bin/echo",
                    "ok",         NULL};
    int rc;

    state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) {
        diag("mmap failed");
        return 1;
    }
    memset(state, 0, sizeof(*state));

    plan(10);

    errno = 0;
    rc = landlockd_cli_main(7, argv);

    ok(rc == 127,
       "fs-only run --policy-file reaches exec and surfaces child exec failure");
    ok(state->load_file_call_count == 1,
       "loads the policy file exactly once");
    ok(state->create_fs_ruleset_call_count == 2 &&
           state->create_fs_ruleset_requested_access_fs[0] ==
               LANDLOCK_ACCESS_FS_READ_FILE &&
           state->create_fs_ruleset_requested_access_fs[1] ==
               LANDLOCK_ACCESS_FS_READ_DIR,
       "creates one filesystem ruleset per fs layer in input order");
    ok(state->open_call_count == 3 &&
           strcmp(state->opened_paths[0], "/layer0/a") == 0 &&
           strcmp(state->opened_paths[1], "/layer0/b") == 0 &&
           strcmp(state->opened_paths[2], "/layer1/c") == 0 &&
           state->open_flags[0] == (O_PATH | O_CLOEXEC) &&
           state->open_flags[1] == (O_PATH | O_CLOEXEC) &&
           state->open_flags[2] == (O_PATH | O_CLOEXEC),
       "opens each fs rule path in layer order with O_PATH and O_CLOEXEC");
    ok(state->add_fs_rule_call_count == 3 &&
           state->add_fs_rule_ruleset_fd[0] == 71 &&
           state->add_fs_rule_ruleset_fd[1] == 71 &&
           state->add_fs_rule_ruleset_fd[2] == 72,
       "adds each rule to its own layer's ruleset instead of flattening layers");
    ok(state->add_fs_rule_allowed_access[0] == LANDLOCK_ACCESS_FS_READ_FILE &&
           state->add_fs_rule_allowed_access[1] == LANDLOCK_ACCESS_FS_READ_FILE &&
           state->add_fs_rule_allowed_access[2] == LANDLOCK_ACCESS_FS_READ_DIR &&
           state->add_fs_rule_parent_fd[0] == 41 &&
           state->add_fs_rule_parent_fd[1] == 42 &&
           state->add_fs_rule_parent_fd[2] == 43,
       "preserves each rule's access mask and opened parent fd");
    ok(state->apply_sandbox_call_count == 2 &&
           state->apply_sandbox_ruleset_fd[0] == 71 &&
           state->apply_sandbox_ruleset_fd[1] == 72,
       "applies the compiled fs rulesets in layer order before execvp");
    ok(state->apply_sandbox_with_seccomp_call_count == 0,
       "does not route through the seccomp sandbox helper without --notify");
    ok(state->execvp_call_count == 1 &&
           strcmp(state->execvp_file, "/bin/echo") == 0,
       "execs the requested command after applying all fs layers");
    ok(state->execvp_argv != NULL &&
           strcmp(state->execvp_argv[1], "ok") == 0 &&
           state->execvp_argv[2] == NULL,
       "passes the command argv through unchanged");

    done_testing();
}
