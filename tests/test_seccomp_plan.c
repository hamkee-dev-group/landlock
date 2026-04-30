#include <errno.h>

#include "landlockd/seccomp.h"
#include "landlockd_cli.h"
#include "tap.h"

int main(void)
{
    struct landlockd_seccomp_plan p;
    struct landlockd_cli_options options;
    char *argv[] = {"landlockd",  "--ro", "/tmp",    "--notify", "39",
                    "--notify",   "102",  "--",      "/bin/true", NULL};
    char *bad_nr_argv[] = {"landlockd", "--ro",     "/tmp", "--notify",
                           "abc",       "--",       "/bin/true", NULL};
    char *overflow_nr_argv[] = {"landlockd",   "--ro",        "/tmp",
                                "--notify",    "99999999999", "--",
                                "/bin/true",   NULL};
    int i;
    int rc;

    plan(14);

    errno = 0;
    ok(landlockd_seccomp_plan_init(&p) == 0 && p.count == 0,
       "plan_init zeros the plan count");
    ok(errno == 0, "plan_init leaves errno unchanged");

    errno = 0;
    ok(landlockd_seccomp_plan_init(NULL) == -1 && errno == EINVAL,
       "plan_init rejects NULL plan with EINVAL");

    errno = 0;
    ok(landlockd_seccomp_plan_add(&p, 39) == 0 && p.count == 1 &&
           p.syscall_nrs[0] == 39,
       "plan_add appends the syscall number");

    errno = 0;
    ok(landlockd_seccomp_plan_add(&p, -1) == -1 && errno == EINVAL,
       "plan_add rejects a negative syscall number");

    landlockd_seccomp_plan_init(&p);
    for (i = 0; i < LANDLOCKD_SECCOMP_MAX_EXCEPTIONS; i++) {
        landlockd_seccomp_plan_add(&p, 100 + i);
    }
    errno = 0;
    ok(landlockd_seccomp_plan_add(&p, 200) == -1 && errno == ENOSPC &&
           p.count == LANDLOCKD_SECCOMP_MAX_EXCEPTIONS,
       "plan_add fails with ENOSPC at capacity");

    errno = 0;
    ok(landlockd_seccomp_install(NULL) == -1 && errno == EINVAL,
       "install rejects NULL plan with EINVAL");

    landlockd_seccomp_plan_init(&p);
    errno = 0;
    ok(landlockd_seccomp_install(&p) == -1 && errno == EINVAL,
       "install rejects an empty plan with EINVAL");

    rc = landlockd_cli_parse(9, argv, &options);
    ok(rc == 0 && options.notify_count == 2 &&
           options.notify_syscalls[0] == 39 &&
           options.notify_syscalls[1] == 102,
       "parser captures --notify syscall numbers in order");

    errno = 0;
    rc = landlockd_cli_build_seccomp_plan(&options, &p);
    ok(rc == 0 && p.count == 2 && p.syscall_nrs[0] == 39 &&
           p.syscall_nrs[1] == 102,
       "build_seccomp_plan copies IR into the plan");

    errno = 0;
    ok(landlockd_cli_build_seccomp_plan(NULL, &p) == -1 && errno == EINVAL,
       "build_seccomp_plan rejects NULL options with EINVAL");

    errno = 0;
    ok(landlockd_cli_build_seccomp_plan(&options, NULL) == -1 &&
           errno == EINVAL,
       "build_seccomp_plan rejects NULL plan with EINVAL");

    errno = 0;
    rc = landlockd_cli_parse(7, bad_nr_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "parser rejects --notify with non-numeric argument");

    errno = 0;
    rc = landlockd_cli_parse(7, overflow_nr_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "parser rejects --notify with a syscall number above INT_MAX");

    done_testing();
}
