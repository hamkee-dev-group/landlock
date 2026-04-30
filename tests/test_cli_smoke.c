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
    char *help_argv[3];
    char *lint_argv[5];
    char *no_argv[2];
    int i;
    int help_rc;
    int lint_rc;
    int no_args_rc;

    if (argc < 3) {
        diag("usage: %s <landlockd> <policy> [policy...]", argv[0]);
        return 1;
    }

    plan(2 + argc - 2);

    help_argv[0] = argv[1];
    help_argv[1] = "--help";
    help_argv[2] = NULL;
    help_rc = run_landlockd(argv[1], help_argv);
    ok(help_rc == 0, "landlockd --help exits 0");

    no_argv[0] = argv[1];
    no_argv[1] = NULL;
    no_args_rc = run_landlockd(argv[1], no_argv);
    ok(no_args_rc == 1, "landlockd with no arguments exits 1");

    lint_argv[0] = argv[1];
    lint_argv[1] = "lint";
    lint_argv[2] = "--policy-file";
    lint_argv[4] = NULL;
    for (i = 2; i < argc; i++) {
        lint_argv[3] = argv[i];
        lint_rc = run_landlockd(argv[1], lint_argv);
        ok(lint_rc == 0, "landlockd lint --policy-file exits 0");
    }

    done_testing();
}
