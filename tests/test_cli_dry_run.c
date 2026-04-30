#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    int preflight_abi;
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
    out->abi_version = state.preflight_abi;
    out->required_abi_floor = required_abi_floor;
    out->meets_abi_floor = state.preflight_abi >= required_abi_floor;
    out->stacking_supported = state.preflight_abi >= 1;
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
    size_t layer0;

    (void)file_path;
    (void)err_stream;
    state.load_file_call_count++;
    landlockd_policy_ir_init(out_ir);

    if (landlockd_policy_ir_add_fs_layer(
            out_ir,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            &layer0) < 0 ||
        landlockd_policy_ir_add_fs_rule(
            out_ir, layer0, "/src",
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) < 0 ||
        landlockd_policy_ir_enable_net(
            out_ir,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP) <
            0 ||
        landlockd_policy_ir_add_net_rule(
            out_ir, 443, LANDLOCK_ACCESS_NET_CONNECT_TCP) < 0 ||
        landlockd_policy_ir_add_broker_open_read_rule(out_ir, "/host/in") < 0 ||
        landlockd_policy_ir_add_broker_open_write_rule(out_ir, "/host/out") <
            0 ||
        landlockd_policy_ir_add_broker_scratch_rule(out_ir, "/scratch") < 0 ||
        landlockd_policy_ir_add_broker_export_rule(out_ir, "/export") < 0 ||
        landlockd_policy_ir_add_broker_mount_tmpfs_rule(out_ir, "/mnt/tmp") <
            0 ||
        landlockd_policy_ir_add_broker_mount_bind_rule(
            out_ir, "/host/bind", "/mnt/bind", 1) < 0 ||
        landlockd_policy_ir_add_mount_tmpfs_rule(out_ir, "/run") < 0 ||
        landlockd_policy_ir_add_mount_bind_rule(out_ir, "/host/etc", "/etc",
                                                1) < 0 ||
        landlockd_policy_ir_add_mount_proc_rule(out_ir, "/proc") < 0 ||
        landlockd_policy_ir_set_runtime_root(out_ir, "/newroot") < 0 ||
        landlockd_policy_ir_set_runtime_cwd(out_ir, "/work") < 0 ||
        landlockd_policy_ir_enable_seccomp(out_ir, 13) < 0 ||
        landlockd_policy_ir_add_seccomp_deny_rule(out_ir, 39) < 0) {
        return -1;
    }
#ifdef MOUNT_ATTR_RDONLY
    {
        const char *attach_paths[] = {"/proc"};

        if (landlockd_policy_ir_add_broker_mount_object_rule(
                out_ir, "proc", "proc", attach_paths, 1,
                (uint64_t)MOUNT_ATTR_RDONLY) < 0) {
            return -1;
        }
    }
#endif
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

static int write_empty_file(const char *path)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    return fclose(fp);
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
    char tempdir[] = "/tmp/landlockd-dry-run-XXXXXX";
    char policy_path[256];
    char *file_argv[] = {"landlockd", "run", "--policy-file", policy_path,
                         "--dry-run", "--", "/bin/true", NULL};
    char *name_argv[] = {"landlockd", "run", "--policy", "strict",
                         "--dry-run", "--", "/bin/true", NULL};
    char stdout_a[8192];
    char stdout_b[8192];
    char stderr_buf[512];
    int rc_a;
    int rc_b;

    plan(8);

    if (mkdtemp(tempdir) == NULL ||
        snprintf(policy_path, sizeof(policy_path), "%s/strict.toml", tempdir) >=
            (int)sizeof(policy_path) ||
        write_empty_file(policy_path) < 0 ||
        setenv("LANDLOCKD_POLICY_PATH", tempdir, 1) < 0) {
        diag("fixture setup failed: %s", strerror(errno));
        return 1;
    }

    memset(&state, 0, sizeof(state));
    state.preflight_abi = 5;
    ok(capture_cli(8, file_argv, &rc_a, stdout_a, sizeof(stdout_a),
                   stderr_buf, sizeof(stderr_buf)) == 0 &&
           capture_cli(8, file_argv, &rc_b, stdout_b, sizeof(stdout_b),
                       stderr_buf, sizeof(stderr_buf)) == 0,
       "dry-run can be captured twice");
    ok(rc_a == 0 && rc_b == 0, "dry-run succeeds when required ABI is present");
    ok(strcmp(stdout_a, stdout_b) == 0,
       "dry-run stdout is byte-stable across identical runs");
    ok(strstr(stdout_a, "landlockd dry-run v1\n") != NULL &&
           strstr(stdout_a, "fs.layer[0] handled=0xc") != NULL &&
           strstr(stdout_a, "net.rule port=443 allowed=0x2") != NULL &&
           strstr(stdout_a, "broker.open_read path=/host/in") != NULL &&
           strstr(stdout_a, "mount.bind source=/host/etc target=/etc ro=1") !=
               NULL &&
           strstr(stdout_a, "seccomp.deny syscall=39") != NULL,
       "dry-run output includes compiled policy lines");
    ok(strstr(stdout_a, "runtime.root=/newroot") != NULL &&
           strstr(stdout_a, "runtime.cwd=/work") != NULL,
       "dry-run output includes runtime root and cwd");

    memset(&state, 0, sizeof(state));
    state.preflight_abi = 5;
    ok(capture_cli(8, name_argv, &rc_a, stdout_b, sizeof(stdout_b),
                   stderr_buf, sizeof(stderr_buf)) == 0 &&
           rc_a == 0 && state.load_file_call_count == 1,
       "run --policy NAME --dry-run resolves and loads a named policy");

    memset(&state, 0, sizeof(state));
    state.preflight_abi = 1;
    ok(capture_cli(8, file_argv, &rc_a, stdout_b, sizeof(stdout_b),
                   stderr_buf, sizeof(stderr_buf)) == 0 &&
           rc_a == 2 && strstr(stdout_b, "landlockd dry-run v1\n") != NULL &&
           strstr(stdout_b, "feature.degraded name=net") != NULL &&
           strstr(stdout_b, "dry-run.status=fail reason=net-unsupported") !=
               NULL,
       "dry-run exits 2 when the policy requires unsupported network ABI");
    ok(no_runtime_side_effects(),
       "dry-run does not fork, create rulesets, apply sandbox, or exec");

    done_testing();
}
