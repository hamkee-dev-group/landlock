#define _GNU_SOURCE

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int run_and_capture(const char *binary, char *const argv[],
                           int capture_fd, char *buf, size_t bufsize)
{
    pid_t pid;
    int status;
    int pipe_fds[2];
    ssize_t n;
    size_t total;

    if (pipe(pipe_fds) < 0) {
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        close(pipe_fds[0]);
        dup2(pipe_fds[1], capture_fd);
        close(pipe_fds[1]);
        execv(binary, argv);
        _exit(127);
    }
    close(pipe_fds[1]);
    total = 0;
    while (total + 1 < bufsize &&
           (n = read(pipe_fds[0], buf + total, bufsize - 1 - total)) > 0) {
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(pipe_fds[0]);

    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

int main(int argc, char *argv[])
{
    char *help_argv[3];
    char *bad_argv[3];
    char *live_argv[7];
    char buf[512];
    int rc;

    plan(3);

    if (argc < 2) {
        diag("missing landlockd binary path argument");
        return 1;
    }

    help_argv[0] = argv[1];
    help_argv[1] = "--help";
    help_argv[2] = NULL;
    rc = run_and_capture(argv[1], help_argv, STDOUT_FILENO, buf, sizeof(buf));
    ok(rc == 0 && strstr(buf, "Usage:") != NULL,
       "landlockd --help exits 0 and prints a Usage: fragment to stdout");

    bad_argv[0] = argv[1];
    bad_argv[1] = "--bogus";
    bad_argv[2] = NULL;
    rc = run_and_capture(argv[1], bad_argv, STDERR_FILENO, buf, sizeof(buf));
    ok(rc == 1 && strstr(buf, "Usage:") != NULL,
       "landlockd --bogus exits 1 and prints a Usage: fragment to stderr");

    skip(landlock_abi_version() == 0, 1, "Landlock is not supported");
        live_argv[0] = argv[1];
        live_argv[1] = "--ro";
        live_argv[2] = "/";
        live_argv[3] = "--";
        live_argv[4] = "/bin/echo";
        live_argv[5] = "landlockd-e2e-ok";
        live_argv[6] = NULL;
        rc = run_and_capture(argv[1], live_argv, STDOUT_FILENO, buf, sizeof(buf));
        ok(rc == 0 && strstr(buf, "landlockd-e2e-ok") != NULL,
           "landlockd execs /bin/echo under the sandbox and inherits its stdout");
    end_skip;

    done_testing();
}
