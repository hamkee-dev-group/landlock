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

#define HELPER_DST_PATH "/tmp/landlockd-addfd-helper"
#define ADDFD_TARGET_PATH "/tmp/landlockd-addfd-allow"

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

static int copy_helper(const char *src, const char *dst)
{
    int in_fd;
    int out_fd;
    char buf[4096];
    ssize_t nread;

    in_fd = open(src, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        return -1;
    }
    unlink(dst);
    out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }
    while ((nread = read(in_fd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < nread) {
            ssize_t n = write(out_fd, buf + written, nread - written);
            if (n < 0) {
                close(in_fd);
                close(out_fd);
                return -1;
            }
            written += n;
        }
    }
    close(in_fd);
    if (close(out_fd) < 0) {
        return -1;
    }
    return nread < 0 ? -1 : 0;
}

static int probe_helper_executable(const char *path)
{
    pid_t pid;
    int status;
    int devnull;

    pid = fork();
    if (pid < 0) {
        return 0;
    }
    if (pid == 0) {
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(path, path, NULL);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) {
        return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) != 127;
}

int main(int argc, char *argv[])
{
    char *allow_argv[8];
    char *deny_argv[8];
    int status;
    FILE *fp;

    if (argc < 5) {
        diag("usage: %s <landlockd> <broker-helper> <allow-policy> <deny-policy>",
             argv[0]);
        return 1;
    }

    if (landlock_abi_version() == 0 || !probe_user_notif_available() ||
        !probe_user_notif_installable()) {
        plan(SKIP_ALL,
             "Landlock or seccomp user-notify broker path is unavailable");
        done_testing();
    }

    if (copy_helper(argv[2], HELPER_DST_PATH) < 0) {
        plan(SKIP_ALL, "cannot stage broker helper at " HELPER_DST_PATH);
        done_testing();
    }
    if (!probe_helper_executable(HELPER_DST_PATH)) {
        unlink(HELPER_DST_PATH);
        plan(SKIP_ALL, HELPER_DST_PATH " is not executable (noexec mount?)");
        done_testing();
    }

    unlink(ADDFD_TARGET_PATH);
    fp = fopen(ADDFD_TARGET_PATH, "w");
    if (fp == NULL) {
        unlink(HELPER_DST_PATH);
        diag("fopen " ADDFD_TARGET_PATH " failed: %s", strerror(errno));
        return 1;
    }
    fputs("ok\n", fp);
    fclose(fp);

    plan(2);

    allow_argv[0] = argv[1];
    allow_argv[1] = "run";
    allow_argv[2] = "--policy-file";
    allow_argv[3] = argv[3];
    allow_argv[4] = "--";
    allow_argv[5] = HELPER_DST_PATH;
    allow_argv[6] = ADDFD_TARGET_PATH;
    allow_argv[7] = NULL;
    ok(run_landlockd(argv[1], allow_argv, &status) == 0 && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0,
       "fixture broker.addfd open rule permits brokered read of declared target");

    deny_argv[0] = argv[1];
    deny_argv[1] = "run";
    deny_argv[2] = "--policy-file";
    deny_argv[3] = argv[4];
    deny_argv[4] = "--";
    deny_argv[5] = HELPER_DST_PATH;
    deny_argv[6] = ADDFD_TARGET_PATH;
    deny_argv[7] = NULL;
    ok(run_landlockd(argv[1], deny_argv, &status) == 0 && WIFEXITED(status) &&
           WEXITSTATUS(status) != 0,
       "fixture without broker.addfd entry denies brokered read of declared target");

    unlink(ADDFD_TARGET_PATH);
    unlink(HELPER_DST_PATH);
    done_testing();
}
