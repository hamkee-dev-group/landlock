#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tap.h"

static int run_dry_run(const char *binary, const char *policy, char *stdout_buf,
                       size_t stdout_size)
{
    char *const argv[] = {(char *)binary, "run", "--policy-file",
                          (char *)policy, "--dry-run", NULL};
    int stdout_pipe[2];
    pid_t pid;
    int status;
    int devnull;
    ssize_t n;

    if (pipe(stdout_pipe) < 0) {
        return -1;
    }
    pid = fork();
    if (pid == 0) {
        close(stdout_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(binary, argv);
        _exit(127);
    }
    close(stdout_pipe[1]);
    if (pid < 0) {
        close(stdout_pipe[0]);
        return -1;
    }
    n = read(stdout_pipe[0], stdout_buf, stdout_size - 1);
    if (n < 0) {
        n = 0;
    }
    stdout_buf[n] = '\0';
    close(stdout_pipe[0]);
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

int main(int argc, char *argv[])
{
    char stdout_a[8192];
    char stdout_b[8192];
    int rc_a;
    int rc_b;

    plan(4);

    if (argc != 3) {
        diag("usage: %s LANDLOCKD POLICY", argv[0]);
        return 1;
    }

    rc_a = run_dry_run(argv[1], argv[2], stdout_a, sizeof(stdout_a));
    rc_b = run_dry_run(argv[1], argv[2], stdout_b, sizeof(stdout_b));
    ok(rc_a == 0 && rc_b == 0, "dry-run fixture exits 0 twice");
    ok(strcmp(stdout_a, stdout_b) == 0,
       "dry-run fixture stdout is byte-for-byte stable");
    ok(strstr(stdout_a, "landlockd dry-run v1\n") != NULL,
       "dry-run fixture includes the version header");
    ok(strstr(stdout_a, "fs.layer[") != NULL,
       "dry-run fixture includes at least one fs.layer line");

    done_testing();
}
