#include <errno.h>

#include "landlockd/landlock.h"
#include "landlockd/seccomp.h"
#include "tap.h"

#define FAKE_LISTENER_FD 4242

static int set_no_new_privs_call_count;
static int seccomp_install_call_count;
static int apply_sandbox_call_count;
static int apply_sandbox_fake_rc;
static int apply_sandbox_fake_errno;
static int close_call_count;
static int close_last_fd;

int landlockd_set_no_new_privs(void)
{
    set_no_new_privs_call_count++;
    return 0;
}

int landlockd_seccomp_install(const struct landlockd_seccomp_plan *plan)
{
    (void)plan;
    seccomp_install_call_count++;
    return FAKE_LISTENER_FD;
}

int landlockd_apply_sandbox(int ruleset_fd, unsigned int flags)
{
    (void)ruleset_fd;
    (void)flags;
    apply_sandbox_call_count++;
    if (apply_sandbox_fake_rc < 0) {
        errno = apply_sandbox_fake_errno;
    }
    return apply_sandbox_fake_rc;
}

int close(int fd)
{
    close_call_count++;
    close_last_fd = fd;
    return 0;
}

int main(void)
{
    struct landlockd_seccomp_plan plan_state;
    int listener_fd;
    int rc;

    plan(6);

    plan_state.count = 1;
    errno = 0;
    rc = landlockd_apply_sandbox_with_seccomp(42, &plan_state, NULL);
    ok(rc == -1 && errno == EINVAL,
       "rejects a non-empty seccomp plan without a listener sink");
    ok(set_no_new_privs_call_count == 0 &&
           seccomp_install_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "fails before no_new_privs, seccomp install, or sandbox apply");

    set_no_new_privs_call_count = 0;
    seccomp_install_call_count = 0;
    apply_sandbox_call_count = 0;
    close_call_count = 0;
    close_last_fd = -1;
    apply_sandbox_fake_rc = -1;
    apply_sandbox_fake_errno = EPERM;
    listener_fd = -1;
    errno = 0;
    rc = landlockd_apply_sandbox_with_seccomp(42, &plan_state, &listener_fd);
    ok(rc == -1 && errno == EPERM,
       "propagates EPERM from landlockd_apply_sandbox failure after seccomp install");
    ok(close_call_count == 1 && close_last_fd == FAKE_LISTENER_FD,
       "closes the installed listener fd exactly once on sandbox apply failure");
    ok(listener_fd == -1,
       "resets *listener_fd_out to -1 on sandbox apply failure");
    ok(seccomp_install_call_count == 1 && apply_sandbox_call_count == 1,
       "invokes seccomp install and sandbox apply exactly once on the failure path");

    done_testing();
}
