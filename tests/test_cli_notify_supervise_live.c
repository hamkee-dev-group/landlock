#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <stdio.h>
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
        if (landlockd_seccomp_plan_add(&plan, (int)SYS_getppid) < 0) {
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

int main(int argc, char *argv[])
{
    char *notify_argv[8];
    char nr_buf[16];
    int status;

    if (argc < 3) {
        diag("missing landlockd or helper binary path argument");
        return 1;
    }

    if (landlock_abi_version() == 0 || !probe_user_notif_available() ||
        !probe_user_notif_installable()) {
        plan(SKIP_ALL,
             "Landlock or seccomp user-notify launch path is unavailable");
        done_testing();
    }

    plan(2);

    snprintf(nr_buf, sizeof(nr_buf), "%d", (int)SYS_getppid);

    notify_argv[0] = argv[1];
    notify_argv[1] = "--ro";
    notify_argv[2] = "/";
    notify_argv[3] = "--notify";
    notify_argv[4] = nr_buf;
    notify_argv[5] = "--";
    notify_argv[6] = argv[2];
    notify_argv[7] = NULL;

    ok(run_landlockd(argv[1], notify_argv, &status) == 0,
       "landlockd with --notify completes without hanging");
    ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "supervised child execs without inheriting seccomp or landlock fds");

    done_testing();
}
