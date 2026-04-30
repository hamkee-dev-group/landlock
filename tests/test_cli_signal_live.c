#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int run_landlockd_status(const char *binary, char *const argv[],
                                int *status_out)
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
    if (waitpid(pid, status_out, 0) < 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char *legacy_argv[8];
    char *policy_argv[9];
    int abi;
    int status;

    if (argc < 3) {
        diag("usage: %s <landlockd> <policy>", argv[0]);
        return 1;
    }

    abi = landlock_abi_version();
    if (abi == 0) {
        plan(SKIP_ALL, "Landlock is not supported");
        done_testing();
    }

    plan(4);

    legacy_argv[0] = argv[1];
    legacy_argv[1] = "--ro";
    legacy_argv[2] = "/";
    legacy_argv[3] = "--";
    legacy_argv[4] = "/bin/sh";
    legacy_argv[5] = "-c";
    legacy_argv[6] = "kill -TERM $$";
    legacy_argv[7] = NULL;
    status = 0;
    if (run_landlockd_status(argv[1], legacy_argv, &status) < 0) {
        diag("waitpid failed");
        ok(0, "legacy mode preserves SIGTERM termination from supervised child");
        ok(0, "legacy mode does not report a normal exit when the child is killed");
        ok(0, "policy mode preserves SIGTERM termination from supervised child");
        ok(0, "policy mode does not report a normal exit when the child is killed");
        done_testing();
    }
    ok(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM,
       "legacy mode preserves SIGTERM termination from supervised child");
    ok(!WIFEXITED(status),
       "legacy mode does not report a normal exit when the child is killed");

    policy_argv[0] = argv[1];
    policy_argv[1] = "run";
    policy_argv[2] = "--policy-file";
    policy_argv[3] = argv[2];
    policy_argv[4] = "--";
    policy_argv[5] = "/bin/sh";
    policy_argv[6] = "-c";
    policy_argv[7] = "kill -TERM $$";
    policy_argv[8] = NULL;
    status = 0;
    ok(run_landlockd_status(argv[1], policy_argv, &status) == 0 &&
           WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM,
       "policy mode preserves SIGTERM termination from supervised child");
    ok(!WIFEXITED(status),
       "policy mode does not report a normal exit when the child is killed");

    done_testing();
}
