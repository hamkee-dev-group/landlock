#include <errno.h>
#include <sys/prctl.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int prctl_call_count;
static int captured_prctl_option;
static unsigned long captured_prctl_arg2;
static unsigned long captured_prctl_arg3;
static unsigned long captured_prctl_arg4;
static unsigned long captured_prctl_arg5;
static long fake_return_value;
static int fake_errno_value;

long landlockd_prctl_shim(int option, unsigned long arg2, unsigned long arg3,
                          unsigned long arg4, unsigned long arg5)
{
    prctl_call_count++;
    captured_prctl_option = option;
    captured_prctl_arg2 = arg2;
    captured_prctl_arg3 = arg3;
    captured_prctl_arg4 = arg4;
    captured_prctl_arg5 = arg5;
    errno = fake_errno_value;
    return fake_return_value;
}

int main(void)
{
    int rc;

    plan(8);

    prctl_call_count = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlockd_set_no_new_privs() == 0 &&
           prctl_call_count == 1 &&
           errno == 0,
       "returns success when prctl returns 0");
    ok(captured_prctl_option == PR_SET_NO_NEW_PRIVS &&
           captured_prctl_arg2 == 1 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "uses the exact PR_SET_NO_NEW_PRIVS contract");

    prctl_call_count = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    fake_return_value = 7;
    fake_errno_value = 0;
    errno = 0;
    ok(landlockd_set_no_new_privs() == 0 &&
           prctl_call_count == 1 &&
           errno == 0,
       "normalizes a positive prctl return to success");
    ok(captured_prctl_option == PR_SET_NO_NEW_PRIVS &&
           captured_prctl_arg2 == 1 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "reuses the exact PR_SET_NO_NEW_PRIVS arguments on positive returns");

    prctl_call_count = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    fake_return_value = -1;
    fake_errno_value = EPERM;
    errno = 0;
    rc = landlockd_set_no_new_privs();
    ok(rc == -1 &&
           prctl_call_count == 1 &&
           errno == EPERM,
       "returns -1 and preserves errno when prctl fails");
    ok(captured_prctl_option == PR_SET_NO_NEW_PRIVS &&
           captured_prctl_arg2 == 1 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0,
       "uses the same PR_SET_NO_NEW_PRIVS contract on failure");

    prctl_call_count = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    fake_return_value = 0;
    fake_errno_value = EIO;
    errno = 0xBEEF;
    rc = landlockd_set_no_new_privs();
    ok(rc == 0 &&
           prctl_call_count == 1 &&
           captured_prctl_option == PR_SET_NO_NEW_PRIVS &&
           captured_prctl_arg2 == 1 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0 &&
           errno == 0xBEEF,
       "preserves caller errno on successful landlockd_set_no_new_privs");

    prctl_call_count = 0;
    captured_prctl_option = 0;
    captured_prctl_arg2 = 0;
    captured_prctl_arg3 = 0;
    captured_prctl_arg4 = 0;
    captured_prctl_arg5 = 0;
    fake_return_value = 7;
    fake_errno_value = EINTR;
    errno = ENOSYS;
    rc = landlockd_set_no_new_privs();
    ok(rc == 0 &&
           prctl_call_count == 1 &&
           captured_prctl_option == PR_SET_NO_NEW_PRIVS &&
           captured_prctl_arg2 == 1 &&
           captured_prctl_arg3 == 0 &&
           captured_prctl_arg4 == 0 &&
           captured_prctl_arg5 == 0 &&
           errno == ENOSYS,
       "preserves ENOSYS caller sentinel across a positive prctl return");

    done_testing();
}
