#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int captured_ruleset_fd;
static uint32_t captured_flags;

static size_t count_lines(const char *text)
{
    size_t count = 0;

    while (*text != '\0') {
        if (*text == '\n') {
            count++;
        }
        text++;
    }

    return count;
}

long landlock_restrict_self_syscall(int ruleset_fd, uint32_t flags)
{
    captured_ruleset_fd = ruleset_fd;
    captured_flags = flags;
    errno = E2BIG;
    return -1;
}

int main(void)
{
    char warning[256];
    FILE *capture;
    int first_errno;
    int first_rc;
    int saved_stderr_fd;
    int second_errno;
    int second_rc;
    size_t warning_len;

    plan(7);

    capture = tmpfile();
    saved_stderr_fd = dup(STDERR_FILENO);

    captured_ruleset_fd = 0;
    captured_flags = 0;
    errno = 0;

    dup2(fileno(capture), STDERR_FILENO);
    first_rc = landlock_restrict_self(15, 0);
    first_errno = errno;
    second_rc = landlock_restrict_self(15, 0);
    second_errno = errno;
    fflush(stderr);
    dup2(saved_stderr_fd, STDERR_FILENO);
    close(saved_stderr_fd);

    rewind(capture);
    warning_len = fread(warning, 1, sizeof(warning) - 1, capture);
    warning[warning_len] = '\0';
    fclose(capture);

    ok(first_rc == -1 && first_errno == E2BIG,
       "first call returns E2BIG");
    ok(second_rc == -1 && second_errno == E2BIG,
       "second call returns E2BIG");
    ok(captured_ruleset_fd == 15,
       "forwards the ruleset fd");
    ok(captured_flags == 0,
       "forwards the flags");
    ok(strstr(warning, "E2BIG") != NULL,
       "warning includes the errno label");
    ok(strstr(warning, "NO_NEW_PRIVS") != NULL ||
           strstr(warning, "no_new_privs") != NULL,
       "warning explains the no_new_privs requirement");
    ok(count_lines(warning) == 1,
       "warns only once");

    done_testing();
}
