#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>

#include "landlockd/seccomp.h"
#include "tap.h"

static int set_no_new_privs_call_count;
static int seccomp_syscall_call_count;
static unsigned int seccomp_syscall_last_op;
static unsigned int seccomp_syscall_last_flags;

int landlockd_set_no_new_privs(void)
{
    set_no_new_privs_call_count++;
    return 0;
}

long landlockd_seccomp_syscall(unsigned int op, unsigned int flags, void *args)
{
    struct sock_fprog *prog = args;

    seccomp_syscall_call_count++;
    seccomp_syscall_last_op = op;
    seccomp_syscall_last_flags = flags;
    if (prog == NULL || prog->len == 0 || prog->filter == NULL) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int main(void)
{
    struct landlockd_seccomp_plan state;

    plan(6);

    ok(landlockd_seccomp_install_denylist(NULL, EPERM) == -1 &&
           errno == EINVAL,
       "denylist install rejects NULL plans");

    landlockd_seccomp_plan_init(&state);
    ok(landlockd_seccomp_install_denylist(&state, EPERM) == -1 &&
           errno == EINVAL,
       "denylist install rejects empty plans");

    landlockd_seccomp_plan_init(&state);
    ok(landlockd_seccomp_plan_add(&state, 39) == 0 &&
           landlockd_seccomp_install_denylist(&state, EPERM) == 0 &&
           seccomp_syscall_call_count == 1 &&
           seccomp_syscall_last_op == SECCOMP_SET_MODE_FILTER &&
           seccomp_syscall_last_flags == 0U,
       "denylist install uses seccomp filter mode without listener flags");

    set_no_new_privs_call_count = 0;
    seccomp_syscall_call_count = 0;
    seccomp_syscall_last_op = 0;
    seccomp_syscall_last_flags = 0;
    ok(landlockd_seccomp_apply_hardening() == 0,
       "process hardening applies successfully");
    ok(set_no_new_privs_call_count == 1,
       "process hardening sets no_new_privs exactly once");
    ok(seccomp_syscall_call_count == 1 &&
           seccomp_syscall_last_op == SECCOMP_SET_MODE_FILTER &&
           seccomp_syscall_last_flags == 0U,
       "process hardening installs one seccomp filter without listener flags");

    done_testing();
}
