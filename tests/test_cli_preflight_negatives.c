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
    char *missing_path_argv[6];
    char buf[512];
    int rc;

    if (argc < 2) {
        diag("missing landlockd binary path argument");
        return 1;
    }

    if (landlock_abi_version() == 0) {
        plan(SKIP_ALL, "Landlock is not supported on this kernel");
        done_testing();
    }

    plan(2);

    missing_path_argv[0] = argv[1];
    missing_path_argv[1] = "--ro";
    missing_path_argv[2] = "/no/such/landlockd-preflight-path";
    missing_path_argv[3] = "--";
    missing_path_argv[4] = "/bin/true";
    missing_path_argv[5] = NULL;
    rc = run_and_capture(argv[1], missing_path_argv, STDERR_FILENO, buf,
                         sizeof(buf));
    ok(rc == 1, "preflight exits 1 when --ro path does not exist");
    ok(strstr(buf, "open") != NULL,
       "preflight error names the failing open syscall");

    done_testing();
}
