#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tap.h"

static int run_landlockd(const char *binary, char *const argv[])
{
    pid_t pid;
    int status;
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
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

int main(int argc, char *argv[])
{
    char *lint_argv[5];
    int rc;

    if (argc < 3) {
        diag("usage: %s <landlockd> <prepared-root-policy>", argv[0]);
        return 1;
    }

    plan(1);

    lint_argv[0] = argv[1];
    lint_argv[1] = "lint";
    lint_argv[2] = "--policy-file";
    lint_argv[3] = argv[2];
    lint_argv[4] = NULL;
    rc = run_landlockd(argv[1], lint_argv);
    ok(rc == 0, "prepared-root fixture lints successfully");

    done_testing();
}
