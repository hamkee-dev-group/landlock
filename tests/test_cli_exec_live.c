#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
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
    char *exec_argv[6];
    int abi;
    int rc;

    if (argc < 2) {
        diag("missing landlockd binary path argument");
        return 1;
    }

    abi = landlock_abi_version();
    if (abi == 0) {
        plan(SKIP_ALL, "Landlock is not supported");
        done_testing();
    }

    plan(2);

    exec_argv[0] = argv[1];
    exec_argv[1] = "--ro";
    exec_argv[2] = "/";
    exec_argv[3] = "--";
    exec_argv[4] = "/bin/true";
    exec_argv[5] = NULL;
    rc = run_landlockd(argv[1], exec_argv);
    ok(rc == 0,
       "landlockd execs /bin/true after applying the sandbox and inherits its exit");

    exec_argv[4] = "/no/such/landlockd-test-cmd";
    rc = run_landlockd(argv[1], exec_argv);
    ok(rc != 0,
       "landlockd exits nonzero when the exec target does not exist");

    done_testing();
}
