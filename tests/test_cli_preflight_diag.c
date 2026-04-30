#define _GNU_SOURCE

#ifdef LANDLOCKD_TEST_PRELOAD

#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>

long syscall(long number, ...)
{
    static long (*real_syscall)(long number, ...);
    unsigned long args[6];
    va_list ap;
    int i;

    if (number == SYS_landlock_create_ruleset) {
        errno = ENOSYS;
        return -1;
    }

    if (real_syscall == NULL) {
        real_syscall = dlsym(RTLD_NEXT, "syscall");
    }

    va_start(ap, number);
    for (i = 0; i < 6; i++) {
        args[i] = va_arg(ap, unsigned long);
    }
    va_end(ap);

    return real_syscall(number, args[0], args[1], args[2], args[3], args[4],
                        args[5]);
}

#else

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tap.h"

static int run_and_capture(const char *binary, const char *preload,
                           char *const argv[], int capture_fd, char *buf,
                           size_t bufsize)
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
        if (setenv("LD_PRELOAD", preload, 1) < 0) {
            _exit(126);
        }
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
    char *unsupported_argv[6];
    char buf[512];
    int rc;

    if (argc < 3) {
        diag("missing landlockd binary or preload path argument");
        return 1;
    }

    plan(3);

    unsupported_argv[0] = argv[1];
    unsupported_argv[1] = "--ro";
    unsupported_argv[2] = "/";
    unsupported_argv[3] = "--";
    unsupported_argv[4] = "/bin/true";
    unsupported_argv[5] = NULL;

    rc = run_and_capture(argv[1], argv[2], unsupported_argv, STDERR_FILENO,
                         buf, sizeof(buf));
    ok(rc == 1, "preflight exits 1 when Landlock ruleset creation is unavailable");
    ok(strstr(buf, "preflight") != NULL && strstr(buf, "Landlock") != NULL,
       "preflight error names the missing Landlock capability");
    ok(strstr(buf, "Function not implemented") != NULL,
       "preflight reports the unsupported-kernel ENOSYS diagnostic");

    done_testing();
}

#endif
