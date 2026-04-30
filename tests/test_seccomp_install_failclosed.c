#include <errno.h>

#include "landlockd/seccomp.h"
#include "tap.h"

static int seccomp_syscall_call_count;
static unsigned int seccomp_syscall_last_op;
static unsigned int seccomp_syscall_last_flags;

long landlockd_seccomp_syscall(unsigned int op, unsigned int flags, void *args)
{
    (void)args;
    seccomp_syscall_call_count++;
    seccomp_syscall_last_op = op;
    seccomp_syscall_last_flags = flags;
    errno = ENOSYS;
    return -1;
}

int main(void)
{
    struct landlockd_seccomp_plan p;
    int rc;

    plan(4);

    landlockd_seccomp_plan_init(&p);
    landlockd_seccomp_plan_add(&p, 39);

    seccomp_syscall_call_count = 0;
    errno = 0;
    rc = landlockd_seccomp_install(&p);
    ok(rc == -1 && errno == ENOSYS,
       "install fails closed when the seccomp syscall reports ENOSYS");
    ok(seccomp_syscall_call_count == 1,
       "install invokes the seccomp syscall exactly once before failing");
    ok(seccomp_syscall_last_op == 1U  ,
       "install uses SECCOMP_SET_MODE_FILTER");
    ok((seccomp_syscall_last_flags & (1U << 3)) != 0  ,
       "install requests SECCOMP_FILTER_FLAG_NEW_LISTENER");

    done_testing();
}
