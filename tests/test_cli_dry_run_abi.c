#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "landlockd/preflight.h"
#include "landlockd_cli.h"
#include "tap.h"

int landlockd_preflight_run(int required_abi_floor,
                            struct landlockd_preflight_report *out)
{
    memset(out, 0, sizeof(*out));
    out->abi_version = 1;
    out->required_abi_floor = required_abi_floor;
    out->meets_abi_floor = 1;
    out->stacking_supported = 1;
    return 0;
}

static int capture_cli(int argc, char *argv[], int *rc, char *stdout_buf,
                       size_t stdout_size, char *stderr_buf,
                       size_t stderr_size)
{
    int stdout_pipe[2];
    int stderr_pipe[2];
    int saved_stdout;
    int saved_stderr;
    ssize_t n;

    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
        return -1;
    }
    saved_stdout = dup(STDOUT_FILENO);
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stdout < 0 || saved_stderr < 0) {
        return -1;
    }
    fflush(stdout);
    fflush(stderr);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    dup2(stderr_pipe[1], STDERR_FILENO);
    *rc = landlockd_cli_main(argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_stdout, STDOUT_FILENO);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stdout);
    close(saved_stderr);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    n = read(stdout_pipe[0], stdout_buf, stdout_size - 1);
    if (n < 0) {
        n = 0;
    }
    stdout_buf[n] = '\0';
    n = read(stderr_pipe[0], stderr_buf, stderr_size - 1);
    if (n < 0) {
        n = 0;
    }
    stderr_buf[n] = '\0';
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    return 0;
}

int main(int argc, char *argv[])
{
    char *cli_argv[] = {"landlockd", "run", "--policy-file", NULL,
                        "--dry-run", "--", "/bin/true", NULL};
    char stdout_buf[4096];
    char stderr_buf[512];
    int rc;

    plan(4);

    if (argc != 2) {
        diag("usage: %s POLICY", argv[0]);
        return 1;
    }

    cli_argv[3] = argv[1];
    ok(capture_cli(7, cli_argv, &rc, stdout_buf, sizeof(stdout_buf),
                   stderr_buf, sizeof(stderr_buf)) == 0,
       "dry-run output can be captured");
    ok(rc == 2, "dry-run exits 2 when compiled policy requires unsupported net ABI");
    ok(strstr(stdout_buf, "landlockd dry-run v1\n") != NULL &&
           strstr(stdout_buf, "fs.layer[0] handled=0xc") != NULL,
       "dry-run reports compiled filesystem IR");
    ok(strstr(stdout_buf, "abi.") == NULL &&
           strstr(stdout_buf, "feature.degraded name=net") != NULL &&
           strstr(stdout_buf, "dry-run.status=fail reason=net-unsupported") !=
               NULL,
       "dry-run reports degraded net support without printing a full preflight report");

    done_testing();
}
