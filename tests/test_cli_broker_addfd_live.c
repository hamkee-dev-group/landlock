#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/seccomp.h>
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

static int write_base_policy(FILE *fp, const char *helper_dir)
{
    if (fprintf(fp,
                "version = 1\n\n"
                "[[fs_layer]]\n"
                "handled_access_fs = [\"execute\", \"read_file\", \"read_dir\"]\n") <
        0) {
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
        return -1;
    }
    return 0;
}

static int write_read_policy(const char *policy_path, const char *helper_dir,
                             const char *read_target, int with_addfd)
{
    FILE *fp;

    fp = fopen(policy_path, "w");
    if (fp == NULL) {
        return -1;
    }
    if (write_base_policy(fp, helper_dir) < 0 ||
        fprintf(fp, "\n[broker]\nallow_read = [\"%s\"]\n", read_target) < 0) {
        fclose(fp);
        return -1;
    }
    if (with_addfd &&
        fprintf(fp,
                "[[broker.addfd]]\n"
                "action = \"open\"\n"
                "target = \"%s\"\n"
                "mode = \"read\"\n",
                read_target) < 0) {
        fclose(fp);
        return -1;
    }
    return fclose(fp) < 0 ? -1 : 0;
}

static int write_write_policy(const char *policy_path, const char *helper_dir,
                              const char *write_target, int with_addfd)
{
    FILE *fp;

    fp = fopen(policy_path, "w");
    if (fp == NULL) {
        return -1;
    }
    if (write_base_policy(fp, helper_dir) < 0 ||
        fprintf(fp, "\n[broker]\nallow_write = [\"%s\"]\n", write_target) < 0) {
        fclose(fp);
        return -1;
    }
    if (with_addfd &&
        fprintf(fp,
                "[[broker.addfd]]\n"
                "action = \"open\"\n"
                "target = \"%s\"\n"
                "mode = \"write\"\n",
                write_target) < 0) {
        fclose(fp);
        return -1;
    }
    return fclose(fp) < 0 ? -1 : 0;
}

static int write_rw_read_only_addfd_policy(const char *policy_path,
                                           const char *helper_dir,
                                           const char *rw_target)
{
    FILE *fp;

    fp = fopen(policy_path, "w");
    if (fp == NULL) {
        return -1;
    }
    if (write_base_policy(fp, helper_dir) < 0 ||
        fprintf(fp,
                "\n[broker]\nallow_read = [\"%s\"]\nallow_write = [\"%s\"]\n"
                "[[broker.addfd]]\n"
                "action = \"open\"\n"
                "target = \"%s\"\n"
                "mode = \"read\"\n",
                rw_target, rw_target, rw_target) < 0) {
        fclose(fp);
        return -1;
    }
    return fclose(fp) < 0 ? -1 : 0;
}

static int write_scratch_policy(const char *policy_path, const char *helper_dir,
                                const char *scratch_root, int with_addfd)
{
    FILE *fp;

    fp = fopen(policy_path, "w");
    if (fp == NULL) {
        return -1;
    }
    if (write_base_policy(fp, helper_dir) < 0 ||
        fprintf(fp, "\n[broker]\nscratch = [\"%s\"]\n", scratch_root) < 0) {
        fclose(fp);
        return -1;
    }
    if (with_addfd &&
        fprintf(fp,
                "[[broker.addfd]]\n"
                "action = \"scratch_open\"\n"
                "target = \"%s\"\n"
                "mode = \"write\"\n",
                scratch_root) < 0) {
        fclose(fp);
        return -1;
    }
    return fclose(fp) < 0 ? -1 : 0;
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

int main(int argc, char *argv[])
{
    char tempdir[] = "/tmp/landlockd-broker-addfd-XXXXXX";
    char helper_dir[PATH_MAX];
    char read_target[PATH_MAX];
    char write_target[PATH_MAX];
    char scratch_root[PATH_MAX];
    char scratch_file[PATH_MAX];
    char policy_read_no_addfd[PATH_MAX];
    char policy_read_with_addfd[PATH_MAX];
    char policy_write_no_addfd[PATH_MAX];
    char policy_write_with_addfd[PATH_MAX];
    char policy_scratch_no_addfd[PATH_MAX];
    char policy_scratch_with_addfd[PATH_MAX];
    char policy_rw_read_only_addfd[PATH_MAX];
    char rw_target[PATH_MAX];
    char *read_fail_argv[8];
    char *read_ok_argv[8];
    char *write_fail_argv[9];
    char *write_ok_argv[9];
    char *scratch_fail_argv[9];
    char *scratch_ok_argv[9];
    char *mode_mismatch_argv[9];
    int status;

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
    snprintf(write_target, sizeof(write_target), "%s/brokered-write.txt",
             tempdir);
    snprintf(scratch_root, sizeof(scratch_root), "%s/scratch-root", tempdir);
    snprintf(scratch_file, sizeof(scratch_file), "%s/out.txt", scratch_root);
    snprintf(policy_read_no_addfd, sizeof(policy_read_no_addfd),
             "%s/read-no-addfd.toml", tempdir);
    snprintf(policy_read_with_addfd, sizeof(policy_read_with_addfd),
             "%s/read-with-addfd.toml", tempdir);
    snprintf(policy_write_no_addfd, sizeof(policy_write_no_addfd),
             "%s/write-no-addfd.toml", tempdir);
    snprintf(policy_write_with_addfd, sizeof(policy_write_with_addfd),
             "%s/write-with-addfd.toml", tempdir);
    snprintf(policy_scratch_no_addfd, sizeof(policy_scratch_no_addfd),
             "%s/scratch-no-addfd.toml", tempdir);
    snprintf(policy_scratch_with_addfd, sizeof(policy_scratch_with_addfd),
             "%s/scratch-with-addfd.toml", tempdir);
    snprintf(rw_target, sizeof(rw_target), "%s/brokered-rw.txt", tempdir);
    snprintf(policy_rw_read_only_addfd, sizeof(policy_rw_read_only_addfd),
             "%s/rw-read-only-addfd.toml", tempdir);

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
    {
        FILE *fp = fopen(rw_target, "w");
        if (fp == NULL) {
            diag("fopen rw target failed: %s", strerror(errno));
            return 1;
        }
        fputs("seed", fp);
        fclose(fp);
    }
    if (mkdir(scratch_root, 0700) < 0) {
        diag("mkdir scratch_root failed: %s", strerror(errno));
        return 1;
    }

    if (write_read_policy(policy_read_no_addfd, helper_dir, read_target, 0) <
            0 ||
        write_read_policy(policy_read_with_addfd, helper_dir, read_target, 1) <
            0 ||
        write_write_policy(policy_write_no_addfd, helper_dir, write_target,
                           0) < 0 ||
        write_write_policy(policy_write_with_addfd, helper_dir, write_target,
                           1) < 0 ||
        write_scratch_policy(policy_scratch_no_addfd, helper_dir, scratch_root,
                             0) < 0 ||
        write_scratch_policy(policy_scratch_with_addfd, helper_dir,
                             scratch_root, 1) < 0 ||
        write_rw_read_only_addfd_policy(policy_rw_read_only_addfd, helper_dir,
                                        rw_target) < 0) {
        diag("writing policy failed: %s", strerror(errno));
        return 1;
    }

    plan(7);

    read_fail_argv[0] = argv[1];
    read_fail_argv[1] = "run";
    read_fail_argv[2] = "--policy-file";
    read_fail_argv[3] = policy_read_no_addfd;
    read_fail_argv[4] = "--";
    read_fail_argv[5] = argv[2];
    read_fail_argv[6] = read_target;
    read_fail_argv[7] = NULL;
    ok(run_landlockd(argv[1], read_fail_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) != 0,
       "allow_read alone no longer permits broker fd injection");

    read_ok_argv[0] = argv[1];
    read_ok_argv[1] = "run";
    read_ok_argv[2] = "--policy-file";
    read_ok_argv[3] = policy_read_with_addfd;
    read_ok_argv[4] = "--";
    read_ok_argv[5] = argv[2];
    read_ok_argv[6] = read_target;
    read_ok_argv[7] = NULL;
    ok(run_landlockd(argv[1], read_ok_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "matching broker.addfd rule restores brokered read");

    write_fail_argv[0] = argv[1];
    write_fail_argv[1] = "run";
    write_fail_argv[2] = "--policy-file";
    write_fail_argv[3] = policy_write_no_addfd;
    write_fail_argv[4] = "--";
    write_fail_argv[5] = argv[2];
    write_fail_argv[6] = write_target;
    write_fail_argv[7] = "append";
    write_fail_argv[8] = NULL;
    ok(run_landlockd(argv[1], write_fail_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) != 0 &&
           file_contains_exactly(write_target, "seed") == 0,
       "allow_write alone no longer permits brokered writes and target stays unmodified");

    write_ok_argv[0] = argv[1];
    write_ok_argv[1] = "run";
    write_ok_argv[2] = "--policy-file";
    write_ok_argv[3] = policy_write_with_addfd;
    write_ok_argv[4] = "--";
    write_ok_argv[5] = argv[2];
    write_ok_argv[6] = write_target;
    write_ok_argv[7] = "append";
    write_ok_argv[8] = NULL;
    ok(run_landlockd(argv[1], write_ok_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           file_contains_exactly(write_target, "seed!") == 0,
       "matching broker.addfd rule restores brokered append");

    scratch_fail_argv[0] = argv[1];
    scratch_fail_argv[1] = "run";
    scratch_fail_argv[2] = "--policy-file";
    scratch_fail_argv[3] = policy_scratch_no_addfd;
    scratch_fail_argv[4] = "--";
    scratch_fail_argv[5] = argv[2];
    scratch_fail_argv[6] = scratch_file;
    scratch_fail_argv[7] = "create";
    scratch_fail_argv[8] = NULL;
    ok(run_landlockd(argv[1], scratch_fail_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) != 0 &&
           access(scratch_file, F_OK) < 0 && errno == ENOENT,
       "scratch alone no longer permits brokered O_CREAT and target file is not created");

    scratch_ok_argv[0] = argv[1];
    scratch_ok_argv[1] = "run";
    scratch_ok_argv[2] = "--policy-file";
    scratch_ok_argv[3] = policy_scratch_with_addfd;
    scratch_ok_argv[4] = "--";
    scratch_ok_argv[5] = argv[2];
    scratch_ok_argv[6] = scratch_file;
    scratch_ok_argv[7] = "create";
    scratch_ok_argv[8] = NULL;
    ok(run_landlockd(argv[1], scratch_ok_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           file_contains_exactly(scratch_file, "scratch") == 0,
       "matching broker.addfd rule restores brokered scratch creation");

    mode_mismatch_argv[0] = argv[1];
    mode_mismatch_argv[1] = "run";
    mode_mismatch_argv[2] = "--policy-file";
    mode_mismatch_argv[3] = policy_rw_read_only_addfd;
    mode_mismatch_argv[4] = "--";
    mode_mismatch_argv[5] = argv[2];
    mode_mismatch_argv[6] = rw_target;
    mode_mismatch_argv[7] = "append";
    mode_mismatch_argv[8] = NULL;
    ok(run_landlockd(argv[1], mode_mismatch_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) != 0 &&
           file_contains_exactly(rw_target, "seed") == 0,
       "broker.addfd mode=\"read\" rule does not authorize a write fd injection even when allow_write covers the path");

    done_testing();
}
