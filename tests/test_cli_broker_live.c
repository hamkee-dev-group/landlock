#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/seccomp.h"
#include "tap.h"

static int run_landlockd(const char *binary, char *const argv[], int *status)
{
    pid_t pid;
    int devnull;

    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(binary, argv);
        _exit(127);
    }
    if (waitpid(pid, status, 0) < 0) {
        return -1;
    }
    return 0;
}

static int probe_user_notif_available(void)
{
    unsigned int action = SECCOMP_RET_USER_NOTIF;

    return syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0U, &action) == 0;
}

static int probe_user_notif_installable(void)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        return 0;
    }
    if (pid == 0) {
        struct landlockd_seccomp_plan plan;
        int listener_fd;

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            _exit(1);
        }
        if (landlockd_seccomp_plan_init(&plan) < 0) {
            _exit(1);
        }
        if (landlockd_seccomp_plan_add(&plan, (int)SYS_openat) < 0) {
            _exit(1);
        }
        listener_fd = landlockd_seccomp_install(&plan);
        if (listener_fd < 0) {
            _exit(1);
        }
        close(listener_fd);
        _exit(0);
    }

    if (waitpid(pid, &status, 0) < 0) {
        return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int parent_dir_of(const char *path, char *buf, size_t buf_size)
{
    const char *slash;
    size_t len;

    slash = strrchr(path, '/');
    if (slash == NULL) {
        errno = EINVAL;
        return -1;
    }
    len = (size_t)(slash - path);
    if (len == 0 || len >= buf_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, path, len);
    buf[len] = '\0';
    return 0;
}

static int emit_rule(FILE *fp, const char *path, const char *access_list)
{
    return fprintf(fp,
                   "  [[fs_layer.rule]]\n"
                   "  path = \"%s\"\n"
                   "  allowed_access = %s\n",
                   path, access_list) < 0
               ? -1
               : 0;
}

static int maybe_emit_rule(FILE *fp, const char *path, const char *access_list)
{
    if (access(path, F_OK) == 0) {
        return emit_rule(fp, path, access_list);
    }
    return 0;
}

static int write_policy(const char *policy_path, const char *helper_dir,
                        const char *read_target, const char *write_target,
                        int allow_read, int allow_write)
{
    FILE *fp;

    fp = fopen(policy_path, "w");
    if (fp == NULL) {
        return -1;
    }

    if (fprintf(fp,
                "version = 1\n\n"
                "[[fs_layer]]\n"
                "handled_access_fs = [\"execute\", \"read_file\", \"read_dir\"]\n") <
        0) {
        fclose(fp);
        return -1;
    }
    if (emit_rule(fp, helper_dir,
                  "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/lib",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/lib64",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/usr/lib",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/usr/lib64",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0) {
        fclose(fp);
        return -1;
    }

    if (allow_read || allow_write) {
        if (fprintf(fp, "\n[broker]\n") < 0) {
            fclose(fp);
            return -1;
        }
        if (allow_read &&
            fprintf(fp, "allow_read = [\"%s\"]\n", read_target) < 0) {
            fclose(fp);
            return -1;
        }
        if (allow_write &&
            fprintf(fp, "allow_write = [\"%s\"]\n", write_target) < 0) {
            fclose(fp);
            return -1;
        }
    }

    if (fclose(fp) < 0) {
        return -1;
    }
    return 0;
}

static int wait_for_socket(const char *path)
{
    int i;
    struct stat st;

    for (i = 0; i < 100; i++) {
        if (stat(path, &st) == 0) {
            return 0;
        }
        usleep(10000);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int file_contains_exactly(const char *path, const char *expected)
{
    char buf[128];
    size_t expected_len;
    FILE *fp;
    size_t nread;

    expected_len = strlen(expected);
    if (expected_len >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    nread = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[nread] = '\0';
    return nread == expected_len && strcmp(buf, expected) == 0 ? 0 : -1;
}

static int symlink_target_equals(const char *path, const char *expected)
{
    char buf[128];
    ssize_t nread;
    size_t expected_len;

    expected_len = strlen(expected);
    if (expected_len >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    nread = readlink(path, buf, sizeof(buf) - 1);
    if (nread < 0) {
        return -1;
    }
    buf[nread] = '\0';
    return (size_t)nread == expected_len && strcmp(buf, expected) == 0 ? 0 : -1;
}

int main(int argc, char *argv[])
{
    char tempdir[] = "/tmp/landlockd-broker-XXXXXX";
    char helper_dir[PATH_MAX];
    char read_target[PATH_MAX];
    char write_target[PATH_MAX];
    char scratch_root[PATH_MAX];
    char scratch_dir[PATH_MAX];
    char scratch_empty_dir[PATH_MAX];
    char scratch_file[PATH_MAX];
    char scratch_renamed_file[PATH_MAX];
    char scratch_symlink[PATH_MAX];
    char scratch_hardlink[PATH_MAX];
    char scratch_daemon_symlink[PATH_MAX];
    char export_root[PATH_MAX];
    char export_file[PATH_MAX];
    char export_hardlink[PATH_MAX];
    char export_daemon_file[PATH_MAX];
    char policy_with_read_broker[PATH_MAX];
    char policy_with_write_broker[PATH_MAX];
    char policy_with_scratch_broker[PATH_MAX];
    char policy_with_export_broker[PATH_MAX];
    char policy_without_broker[PATH_MAX];
    char socket_path[PATH_MAX];
    char *direct_ok_argv[8];
    char *direct_fail_argv[8];
    char *direct_write_ok_argv[9];
    char *direct_write_fail_argv[9];
    char *direct_scratch_mkdir_argv[9];
    char *direct_scratch_rmdir_argv[9];
    char *direct_scratch_create_argv[9];
    char *direct_scratch_rename_argv[10];
    char *direct_scratch_unlink_argv[9];
    char *direct_scratch_symlink_argv[10];
    char *direct_scratch_link_argv[11];
    char *direct_export_fail_argv[10];
    char *direct_export_rename_argv[10];
    char *direct_export_link_argv[10];
    char *serve_argv[5];
    char *daemon_run_argv[10];
    char *daemon_write_argv[11];
    char *daemon_scratch_create_argv[11];
    char *daemon_scratch_rename_argv[12];
    char *daemon_scratch_symlink_argv[12];
    char *daemon_export_rename_argv[12];
    char *stop_argv[5];
    pid_t daemon_pid;
    int direct_status;
    int daemon_status;
    int stop_status;

    if (argc < 3) {
        diag("usage: %s <landlockd> <broker-helper>", argv[0]);
        return 1;
    }

    if (landlock_abi_version() == 0 || !probe_user_notif_available() ||
        !probe_user_notif_installable()) {
        plan(SKIP_ALL,
             "Landlock or seccomp user-notify broker path is unavailable");
        done_testing();
    }

    if (mkdtemp(tempdir) == NULL) {
        diag("mkdtemp failed: %s", strerror(errno));
        return 1;
    }
    if (parent_dir_of(argv[2], helper_dir, sizeof(helper_dir)) < 0) {
        diag("cannot derive helper directory: %s", strerror(errno));
        return 1;
    }

    snprintf(read_target, sizeof(read_target), "%s/brokered-read.txt", tempdir);
    snprintf(write_target, sizeof(write_target), "%s/brokered-write.txt", tempdir);
    if (snprintf(scratch_root, sizeof(scratch_root), "%s/scratch-root", tempdir) >=
            (int)sizeof(scratch_root) ||
        snprintf(scratch_dir, sizeof(scratch_dir), "%s/nested", scratch_root) >=
            (int)sizeof(scratch_dir) ||
        snprintf(scratch_empty_dir, sizeof(scratch_empty_dir), "%s/empty",
                 scratch_root) >= (int)sizeof(scratch_empty_dir) ||
        snprintf(scratch_file, sizeof(scratch_file), "%s/out.txt", scratch_dir) >=
            (int)sizeof(scratch_file) ||
        snprintf(scratch_renamed_file, sizeof(scratch_renamed_file),
                 "%s/renamed.txt", scratch_dir) >=
            (int)sizeof(scratch_file) ||
        snprintf(scratch_symlink, sizeof(scratch_symlink), "%s/link.txt",
                 scratch_dir) >= (int)sizeof(scratch_symlink) ||
        snprintf(scratch_hardlink, sizeof(scratch_hardlink), "%s/hard.txt",
                 scratch_dir) >= (int)sizeof(scratch_hardlink) ||
        snprintf(scratch_daemon_symlink, sizeof(scratch_daemon_symlink),
                 "%s/daemon-link.txt", scratch_dir) >=
            (int)sizeof(scratch_daemon_symlink) ||
        snprintf(export_root, sizeof(export_root), "%s/export-root", tempdir) >=
            (int)sizeof(export_root) ||
        snprintf(export_file, sizeof(export_file), "%s/published.txt", export_root) >=
            (int)sizeof(export_file) ||
        snprintf(export_hardlink, sizeof(export_hardlink), "%s/hard.txt", export_root) >=
            (int)sizeof(export_hardlink) ||
        snprintf(export_daemon_file, sizeof(export_daemon_file),
                 "%s/daemon.txt", export_root) >= (int)sizeof(export_daemon_file)) {
        diag("scratch path too long");
        return 1;
    }
    snprintf(policy_with_read_broker, sizeof(policy_with_read_broker),
             "%s/with-read-broker.toml", tempdir);
    snprintf(policy_with_write_broker, sizeof(policy_with_write_broker),
             "%s/with-write-broker.toml", tempdir);
    snprintf(policy_with_scratch_broker, sizeof(policy_with_scratch_broker),
             "%s/with-scratch-broker.toml", tempdir);
    snprintf(policy_with_export_broker, sizeof(policy_with_export_broker),
             "%s/with-export-broker.toml", tempdir);
    snprintf(policy_without_broker, sizeof(policy_without_broker),
             "%s/without-broker.toml", tempdir);
    snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir);

    {
        FILE *fp = fopen(read_target, "w");
        if (fp == NULL) {
            diag("fopen read target failed: %s", strerror(errno));
            return 1;
        }
        fputs("brokered\n", fp);
        fclose(fp);
    }
    {
        FILE *fp = fopen(write_target, "w");
        if (fp == NULL) {
            diag("fopen write target failed: %s", strerror(errno));
            return 1;
        }
        fputs("seed", fp);
        fclose(fp);
    }
    if (mkdir(scratch_root, 0700) < 0) {
        diag("mkdir scratch_root failed: %s", strerror(errno));
        return 1;
    }
    if (mkdir(export_root, 0700) < 0) {
        diag("mkdir export_root failed: %s", strerror(errno));
        return 1;
    }

    if (write_policy(policy_with_read_broker, helper_dir, read_target,
                     write_target, 1, 0) < 0 ||
        write_policy(policy_with_write_broker, helper_dir, read_target,
                     write_target, 0, 1) < 0 ||
        write_policy(policy_with_scratch_broker, helper_dir, read_target,
                     write_target, 0, 0) < 0 ||
        write_policy(policy_with_export_broker, helper_dir, read_target,
                     write_target, 0, 0) < 0 ||
        write_policy(policy_without_broker, helper_dir, read_target,
                     write_target, 0, 0) < 0) {
        diag("writing policy failed: %s", strerror(errno));
        return 1;
    }
    {
        FILE *fp = fopen(policy_with_scratch_broker, "a");
        if (fp == NULL ||
            fprintf(fp, "\n[broker]\n"
                        "scratch = [\"%s\"]\n",
                        scratch_root) < 0) {
            diag("writing scratch policy failed: %s", strerror(errno));
            if (fp != NULL) {
                fclose(fp);
            }
            return 1;
        }
        fclose(fp);
    }
    {
        FILE *fp = fopen(policy_with_export_broker, "a");
        if (fp == NULL ||
            fprintf(fp, "\n[broker]\n"
                        "scratch = [\"%s\"]\n"
                        "export = [\"%s\"]\n",
                        scratch_root, export_root) < 0) {
            diag("writing export policy failed: %s", strerror(errno));
            if (fp != NULL) {
                fclose(fp);
            }
            return 1;
        }
        fclose(fp);
    }

    plan(28);

    direct_ok_argv[0] = argv[1];
    direct_ok_argv[1] = "run";
    direct_ok_argv[2] = "--policy-file";
    direct_ok_argv[3] = policy_with_read_broker;
    direct_ok_argv[4] = "--";
    direct_ok_argv[5] = argv[2];
    direct_ok_argv[6] = read_target;
    direct_ok_argv[7] = NULL;
    ok(run_landlockd(argv[1], direct_ok_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0,
       "direct run uses the broker to satisfy a denied host-file open");

    direct_fail_argv[0] = argv[1];
    direct_fail_argv[1] = "run";
    direct_fail_argv[2] = "--policy-file";
    direct_fail_argv[3] = policy_without_broker;
    direct_fail_argv[4] = "--";
    direct_fail_argv[5] = argv[2];
    direct_fail_argv[6] = read_target;
    direct_fail_argv[7] = NULL;
    ok(run_landlockd(argv[1], direct_fail_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) != 0,
       "without a broker allowlist the same host-file open stays denied");

    direct_write_ok_argv[0] = argv[1];
    direct_write_ok_argv[1] = "run";
    direct_write_ok_argv[2] = "--policy-file";
    direct_write_ok_argv[3] = policy_with_write_broker;
    direct_write_ok_argv[4] = "--";
    direct_write_ok_argv[5] = argv[2];
    direct_write_ok_argv[6] = write_target;
    direct_write_ok_argv[7] = "append";
    direct_write_ok_argv[8] = NULL;
    ok(run_landlockd(argv[1], direct_write_ok_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           file_contains_exactly(write_target, "seed!") == 0,
       "direct run uses broker addfd for an explicit write exception");

    direct_write_fail_argv[0] = argv[1];
    direct_write_fail_argv[1] = "run";
    direct_write_fail_argv[2] = "--policy-file";
    direct_write_fail_argv[3] = policy_with_read_broker;
    direct_write_fail_argv[4] = "--";
    direct_write_fail_argv[5] = argv[2];
    direct_write_fail_argv[6] = write_target;
    direct_write_fail_argv[7] = "append";
    direct_write_fail_argv[8] = NULL;
    ok(run_landlockd(argv[1], direct_write_fail_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) != 0 &&
           file_contains_exactly(write_target, "seed!") == 0,
       "read-only broker policy does not permit brokered writes");

    direct_scratch_mkdir_argv[0] = argv[1];
    direct_scratch_mkdir_argv[1] = "run";
    direct_scratch_mkdir_argv[2] = "--policy-file";
    direct_scratch_mkdir_argv[3] = policy_with_scratch_broker;
    direct_scratch_mkdir_argv[4] = "--";
    direct_scratch_mkdir_argv[5] = argv[2];
    direct_scratch_mkdir_argv[6] = scratch_dir;
    direct_scratch_mkdir_argv[7] = "mkdir";
    direct_scratch_mkdir_argv[8] = NULL;
    ok(run_landlockd(argv[1], direct_scratch_mkdir_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           access(scratch_dir, F_OK) == 0,
       "direct run brokers mkdirat under a scratch root");

    direct_scratch_mkdir_argv[6] = scratch_empty_dir;
    ok(run_landlockd(argv[1], direct_scratch_mkdir_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           access(scratch_empty_dir, F_OK) == 0,
       "direct run brokers creation of an empty scratch directory");

    direct_scratch_rmdir_argv[0] = argv[1];
    direct_scratch_rmdir_argv[1] = "run";
    direct_scratch_rmdir_argv[2] = "--policy-file";
    direct_scratch_rmdir_argv[3] = policy_with_scratch_broker;
    direct_scratch_rmdir_argv[4] = "--";
    direct_scratch_rmdir_argv[5] = argv[2];
    direct_scratch_rmdir_argv[6] = scratch_empty_dir;
    direct_scratch_rmdir_argv[7] = "rmdir";
    direct_scratch_rmdir_argv[8] = NULL;
    ok(run_landlockd(argv[1], direct_scratch_rmdir_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           access(scratch_empty_dir, F_OK) < 0 && errno == ENOENT,
       "direct run brokers AT_REMOVEDIR within the scratch root");

    direct_scratch_create_argv[0] = argv[1];
    direct_scratch_create_argv[1] = "run";
    direct_scratch_create_argv[2] = "--policy-file";
    direct_scratch_create_argv[3] = policy_with_scratch_broker;
    direct_scratch_create_argv[4] = "--";
    direct_scratch_create_argv[5] = argv[2];
    direct_scratch_create_argv[6] = scratch_file;
    direct_scratch_create_argv[7] = "create";
    direct_scratch_create_argv[8] = NULL;
    ok(run_landlockd(argv[1], direct_scratch_create_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           file_contains_exactly(scratch_file, "scratch") == 0,
       "direct run brokers O_CREAT under the scratch root");

    direct_scratch_rename_argv[0] = argv[1];
    direct_scratch_rename_argv[1] = "run";
    direct_scratch_rename_argv[2] = "--policy-file";
    direct_scratch_rename_argv[3] = policy_with_scratch_broker;
    direct_scratch_rename_argv[4] = "--";
    direct_scratch_rename_argv[5] = argv[2];
    direct_scratch_rename_argv[6] = scratch_file;
    direct_scratch_rename_argv[7] = scratch_renamed_file;
    direct_scratch_rename_argv[8] = "rename";
    direct_scratch_rename_argv[9] = NULL;
    ok(run_landlockd(argv[1], direct_scratch_rename_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           access(scratch_file, F_OK) < 0 && errno == ENOENT &&
           file_contains_exactly(scratch_renamed_file, "scratch") == 0,
       "direct run brokers renameat2 within the scratch root");

    direct_scratch_unlink_argv[0] = argv[1];
    direct_scratch_unlink_argv[1] = "run";
    direct_scratch_unlink_argv[2] = "--policy-file";
    direct_scratch_unlink_argv[3] = policy_with_scratch_broker;
    direct_scratch_unlink_argv[4] = "--";
    direct_scratch_unlink_argv[5] = argv[2];
    direct_scratch_unlink_argv[6] = scratch_renamed_file;
    direct_scratch_unlink_argv[7] = "unlink";
    direct_scratch_unlink_argv[8] = NULL;
    ok(run_landlockd(argv[1], direct_scratch_unlink_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           access(scratch_renamed_file, F_OK) < 0 && errno == ENOENT,
       "direct run brokers unlinkat within the scratch root");

    ok(run_landlockd(argv[1], direct_scratch_create_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           file_contains_exactly(scratch_file, "scratch") == 0,
       "direct run recreates a scratch file for link tests");

    direct_scratch_symlink_argv[0] = argv[1];
    direct_scratch_symlink_argv[1] = "run";
    direct_scratch_symlink_argv[2] = "--policy-file";
    direct_scratch_symlink_argv[3] = policy_with_scratch_broker;
    direct_scratch_symlink_argv[4] = "--";
    direct_scratch_symlink_argv[5] = argv[2];
    direct_scratch_symlink_argv[6] = "out.txt";
    direct_scratch_symlink_argv[7] = scratch_symlink;
    direct_scratch_symlink_argv[8] = "symlink";
    direct_scratch_symlink_argv[9] = NULL;
    ok(run_landlockd(argv[1], direct_scratch_symlink_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           symlink_target_equals(scratch_symlink, "out.txt") == 0,
       "direct run brokers symlinkat within the scratch root");

    direct_scratch_link_argv[0] = argv[1];
    direct_scratch_link_argv[1] = "run";
    direct_scratch_link_argv[2] = "--policy-file";
    direct_scratch_link_argv[3] = policy_with_scratch_broker;
    direct_scratch_link_argv[4] = "--";
    direct_scratch_link_argv[5] = argv[2];
    direct_scratch_link_argv[6] = scratch_file;
    direct_scratch_link_argv[7] = scratch_hardlink;
    direct_scratch_link_argv[8] = "link";
    direct_scratch_link_argv[9] = NULL;
    ok(run_landlockd(argv[1], direct_scratch_link_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           file_contains_exactly(scratch_hardlink, "scratch") == 0,
       "direct run brokers linkat within the scratch root");

    direct_export_fail_argv[0] = argv[1];
    direct_export_fail_argv[1] = "run";
    direct_export_fail_argv[2] = "--policy-file";
    direct_export_fail_argv[3] = policy_with_scratch_broker;
    direct_export_fail_argv[4] = "--";
    direct_export_fail_argv[5] = argv[2];
    direct_export_fail_argv[6] = scratch_file;
    direct_export_fail_argv[7] = export_file;
    direct_export_fail_argv[8] = "rename";
    direct_export_fail_argv[9] = NULL;
    ok(run_landlockd(argv[1], direct_export_fail_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) != 0 &&
           access(export_file, F_OK) < 0 && errno == ENOENT,
       "scratch-only policy fails closed for cross-root export rename");

    direct_export_rename_argv[0] = argv[1];
    direct_export_rename_argv[1] = "run";
    direct_export_rename_argv[2] = "--policy-file";
    direct_export_rename_argv[3] = policy_with_export_broker;
    direct_export_rename_argv[4] = "--";
    direct_export_rename_argv[5] = argv[2];
    direct_export_rename_argv[6] = scratch_file;
    direct_export_rename_argv[7] = export_file;
    direct_export_rename_argv[8] = "rename";
    direct_export_rename_argv[9] = NULL;
    ok(run_landlockd(argv[1], direct_export_rename_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           access(scratch_file, F_OK) < 0 && errno == ENOENT &&
           file_contains_exactly(export_file, "scratch") == 0,
       "export policy brokers scratch-to-export rename publication");

    ok(run_landlockd(argv[1], direct_scratch_create_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           file_contains_exactly(scratch_file, "scratch") == 0,
       "direct run recreates a scratch file for export link tests");

    direct_export_link_argv[0] = argv[1];
    direct_export_link_argv[1] = "run";
    direct_export_link_argv[2] = "--policy-file";
    direct_export_link_argv[3] = policy_with_export_broker;
    direct_export_link_argv[4] = "--";
    direct_export_link_argv[5] = argv[2];
    direct_export_link_argv[6] = scratch_file;
    direct_export_link_argv[7] = export_hardlink;
    direct_export_link_argv[8] = "link";
    direct_export_link_argv[9] = NULL;
    ok(run_landlockd(argv[1], direct_export_link_argv, &direct_status) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0 &&
           file_contains_exactly(export_hardlink, "scratch") == 0,
       "export policy brokers scratch-to-export hard-link publication");

    daemon_pid = fork();
    if (daemon_pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        serve_argv[0] = argv[1];
        serve_argv[1] = "serve";
        serve_argv[2] = "--socket";
        serve_argv[3] = socket_path;
        serve_argv[4] = NULL;
        execv(argv[1], serve_argv);
        _exit(127);
    }
    ok(daemon_pid > 0 && wait_for_socket(socket_path) == 0,
       "daemon serve creates its control socket");

    daemon_run_argv[0] = argv[1];
    daemon_run_argv[1] = "run";
    daemon_run_argv[2] = "--socket";
    daemon_run_argv[3] = socket_path;
    daemon_run_argv[4] = "--policy-file";
    daemon_run_argv[5] = policy_with_read_broker;
    daemon_run_argv[6] = "--";
    daemon_run_argv[7] = argv[2];
    daemon_run_argv[8] = read_target;
    daemon_run_argv[9] = NULL;
    ok(run_landlockd(argv[1], daemon_run_argv, &daemon_status) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
       "daemon run uses the same brokered policy path successfully");

    daemon_write_argv[0] = argv[1];
    daemon_write_argv[1] = "run";
    daemon_write_argv[2] = "--socket";
    daemon_write_argv[3] = socket_path;
    daemon_write_argv[4] = "--policy-file";
    daemon_write_argv[5] = policy_with_write_broker;
    daemon_write_argv[6] = "--";
    daemon_write_argv[7] = argv[2];
    daemon_write_argv[8] = write_target;
    daemon_write_argv[9] = "append";
    daemon_write_argv[10] = NULL;
    ok(run_landlockd(argv[1], daemon_write_argv, &daemon_status) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0 &&
           file_contains_exactly(write_target, "seed!!") == 0,
       "daemon run also brokers explicit write exceptions");

    daemon_scratch_create_argv[0] = argv[1];
    daemon_scratch_create_argv[1] = "run";
    daemon_scratch_create_argv[2] = "--socket";
    daemon_scratch_create_argv[3] = socket_path;
    daemon_scratch_create_argv[4] = "--policy-file";
    daemon_scratch_create_argv[5] = policy_with_scratch_broker;
    daemon_scratch_create_argv[6] = "--";
    daemon_scratch_create_argv[7] = argv[2];
    daemon_scratch_create_argv[8] = scratch_file;
    daemon_scratch_create_argv[9] = "create";
    daemon_scratch_create_argv[10] = NULL;
    ok(run_landlockd(argv[1], daemon_scratch_create_argv, &daemon_status) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0 &&
           file_contains_exactly(scratch_file, "scratch") == 0,
       "daemon run brokers scratch-root file creation too");

    daemon_scratch_rename_argv[0] = argv[1];
    daemon_scratch_rename_argv[1] = "run";
    daemon_scratch_rename_argv[2] = "--socket";
    daemon_scratch_rename_argv[3] = socket_path;
    daemon_scratch_rename_argv[4] = "--policy-file";
    daemon_scratch_rename_argv[5] = policy_with_scratch_broker;
    daemon_scratch_rename_argv[6] = "--";
    daemon_scratch_rename_argv[7] = argv[2];
    daemon_scratch_rename_argv[8] = scratch_file;
    daemon_scratch_rename_argv[9] = scratch_renamed_file;
    daemon_scratch_rename_argv[10] = "rename";
    daemon_scratch_rename_argv[11] = NULL;
    ok(run_landlockd(argv[1], daemon_scratch_rename_argv, &daemon_status) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0 &&
           access(scratch_file, F_OK) < 0 && errno == ENOENT &&
           file_contains_exactly(scratch_renamed_file, "scratch") == 0,
       "daemon run brokers scratch-root rename too");

    daemon_scratch_symlink_argv[0] = argv[1];
    daemon_scratch_symlink_argv[1] = "run";
    daemon_scratch_symlink_argv[2] = "--socket";
    daemon_scratch_symlink_argv[3] = socket_path;
    daemon_scratch_symlink_argv[4] = "--policy-file";
    daemon_scratch_symlink_argv[5] = policy_with_scratch_broker;
    daemon_scratch_symlink_argv[6] = "--";
    daemon_scratch_symlink_argv[7] = argv[2];
    daemon_scratch_symlink_argv[8] = "renamed.txt";
    daemon_scratch_symlink_argv[9] = scratch_daemon_symlink;
    daemon_scratch_symlink_argv[10] = "symlink";
    daemon_scratch_symlink_argv[11] = NULL;
    ok(run_landlockd(argv[1], daemon_scratch_symlink_argv, &daemon_status) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0 &&
           symlink_target_equals(scratch_daemon_symlink, "renamed.txt") == 0,
       "daemon run brokers scratch-root symlink creation too");

    ok(run_landlockd(argv[1], daemon_scratch_create_argv, &daemon_status) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0 &&
           file_contains_exactly(scratch_file, "scratch") == 0,
       "daemon run recreates a scratch file for export publication");

    daemon_export_rename_argv[0] = argv[1];
    daemon_export_rename_argv[1] = "run";
    daemon_export_rename_argv[2] = "--socket";
    daemon_export_rename_argv[3] = socket_path;
    daemon_export_rename_argv[4] = "--policy-file";
    daemon_export_rename_argv[5] = policy_with_export_broker;
    daemon_export_rename_argv[6] = "--";
    daemon_export_rename_argv[7] = argv[2];
    daemon_export_rename_argv[8] = scratch_file;
    daemon_export_rename_argv[9] = export_daemon_file;
    daemon_export_rename_argv[10] = "rename";
    daemon_export_rename_argv[11] = NULL;
    ok(run_landlockd(argv[1], daemon_export_rename_argv, &daemon_status) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0 &&
           access(scratch_file, F_OK) < 0 && errno == ENOENT &&
           file_contains_exactly(export_daemon_file, "scratch") == 0,
       "daemon run brokers scratch-to-export rename publication too");

    stop_argv[0] = argv[1];
    stop_argv[1] = "stop";
    stop_argv[2] = "--socket";
    stop_argv[3] = socket_path;
    stop_argv[4] = NULL;
    ok(run_landlockd(argv[1], stop_argv, &stop_status) == 0 &&
           WIFEXITED(stop_status) && WEXITSTATUS(stop_status) == 0,
       "daemon stop exits successfully");

    ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
       "daemon exits cleanly after stop");

    ok(access(socket_path, F_OK) < 0 && errno == ENOENT,
       "daemon stop removes the control socket");

    done_testing();
}
