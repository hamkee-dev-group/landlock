#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int run_landlockd_raw(const char *binary, char *const argv[],
                             int *raw_status, char *stderr_buf,
                             size_t bufsize)
{
    pid_t pid;
    int devnull;
    int pipe_fds[2];
    ssize_t n;
    size_t total;

    if (pipe(pipe_fds) < 0) {
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        close(pipe_fds[0]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
        dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[1]);
        execv(binary, argv);
        _exit(127);
    }
    close(pipe_fds[1]);
    total = 0;
    while (total + 1 < bufsize &&
           (n = read(pipe_fds[0], stderr_buf + total, bufsize - 1 - total)) >
               0) {
        total += (size_t)n;
    }
    stderr_buf[total] = '\0';
    close(pipe_fds[0]);

    if (waitpid(pid, raw_status, 0) < 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char *exit_argv[6];
    char *sh_script_argv[8];
    char stderr_buf[1024];
    int status;

    if (argc < 2) {
        diag("missing landlockd binary path argument");
        return 1;
    }

    if (landlock_abi_version() == 0) {
        plan(SKIP_ALL, "Landlock is not supported on this kernel");
        done_testing();
    }

    plan(6);

    exit_argv[0] = argv[1];
    exit_argv[1] = "--ro";
    exit_argv[2] = "/";
    exit_argv[3] = "--";
    exit_argv[4] = "/bin/false";
    exit_argv[5] = NULL;
    ok(run_landlockd_raw(argv[1], exit_argv, &status, stderr_buf,
                         sizeof(stderr_buf)) == 0,
       "launcher waits for /bin/false child cleanly");
    ok(WIFEXITED(status) && WEXITSTATUS(status) == 1,
       "launcher preserves /bin/false non-zero exit status");
    ok(strstr(stderr_buf, "event child.exit status=1") != NULL,
       "launcher emits child.exit event with status=1 for /bin/false");

    sh_script_argv[0] = argv[1];
    sh_script_argv[1] = "--ro";
    sh_script_argv[2] = "/";
    sh_script_argv[3] = "--";
    sh_script_argv[4] = "/bin/sh";
    sh_script_argv[5] = "-c";
    sh_script_argv[6] = "kill -KILL $$";
    sh_script_argv[7] = NULL;
    ok(run_landlockd_raw(argv[1], sh_script_argv, &status, stderr_buf,
                         sizeof(stderr_buf)) == 0,
       "launcher waits for self-killed shell child cleanly");
    ok(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
       "launcher preserves SIGKILL termination from the sandboxed child");
    ok(strstr(stderr_buf, "event child.signal signal=9") != NULL,
       "launcher emits child.signal event with signal=9 for SIGKILL");

    done_testing();
}
