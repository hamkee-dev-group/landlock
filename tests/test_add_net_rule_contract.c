#include <errno.h>
#include <stdint.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int captured_ruleset_fd;
static int captured_rule_type;
static unsigned int captured_flags;
static struct landlock_net_port_attr captured_attr;
static int captured_attr_valid;
static int syscall_call_count;
static long fake_return_value;
static int fake_errno_value;

long landlock_add_rule_syscall(int ruleset_fd, int rule_type,
                               const void *rule_attr, unsigned int flags)
{
    syscall_call_count++;
    captured_ruleset_fd = ruleset_fd;
    captured_rule_type = rule_type;
    captured_flags = flags;
    captured_attr_valid = 0;
    if (rule_attr != NULL) {
        captured_attr = *(const struct landlock_net_port_attr *)rule_attr;
        captured_attr_valid = 1;
    }
    errno = fake_errno_value;
    return fake_return_value;
}

int main(void)
{
    struct landlock_net_port_attr attr = {
        .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP |
                          LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .port = 8443,
    };

    plan(17);

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    captured_attr.allowed_access = 0;
    captured_attr.port = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_net_rule(7, NULL, 3) == -1 &&
           errno == EINVAL &&
           captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "rejects null net rules before the syscall");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_net_rule(-1, &attr, 3) == -1 &&
           errno == EBADF &&
           captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "rejects negative ruleset_fd before the syscall");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_net_rule(-1, &attr, 0) == -1 &&
           errno == EBADF &&
           captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "rejects negative ruleset_fd before the syscall regardless of flags");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    attr.allowed_access = 0;
    errno = 0;
    ok(landlock_add_net_rule(7, &attr, 3) == -1 &&
           errno == EINVAL &&
           captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "rejects zero requested net access before the syscall");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    attr.allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP |
                          LANDLOCK_ACCESS_NET_CONNECT_TCP;
    errno = 0;
    ok(landlock_add_net_rule(7, &attr, 3) == 0 &&
           captured_ruleset_fd == 7 &&
           captured_rule_type == LANDLOCK_RULE_NET_PORT &&
           captured_flags == 3 &&
           captured_attr_valid &&
           captured_attr.allowed_access == attr.allowed_access &&
           captured_attr.port == attr.port,
       "forwards net rule arguments on success");
    cmp_ok(errno, "==", 0, "success path: errno unchanged on success");

    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = EBADF;
    errno = 0;
    ok(landlock_add_net_rule(7, &attr, 3) == -1 &&
           errno == EBADF &&
           syscall_call_count == 1,
       "propagates EBADF when the kernel rejects the net rule");

    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = EINVAL;
    errno = 0;
    ok(landlock_add_net_rule(7, &attr, 3) == -1 &&
           errno == EINVAL &&
           syscall_call_count == 1,
       "propagates EINVAL when the kernel rejects the net rule");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = EFAULT;
    errno = 0;
    ok(landlock_add_rule(5, LANDLOCK_RULE_NET_PORT, NULL, 0) == -1 &&
           errno == EINVAL &&
           captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "rejects null net rule attributes before the syscall");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    captured_attr.allowed_access = 0;
    captured_attr.port = 0;
    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = ENOSYS;
    errno = 0;
    cmp_ok(landlock_add_rule(5, LANDLOCK_RULE_NET_PORT, &attr, 0), "==", -1,
           "propagates ENOSYS return value for net rules");
    cmp_ok(captured_ruleset_fd, "==", 5,
           "passes ruleset fd through for ENOSYS net rules");
    cmp_ok(captured_rule_type, "==", LANDLOCK_RULE_NET_PORT,
           "passes net rule type through for ENOSYS");
    cmp_ok(captured_flags, "==", 0,
           "passes flags through for ENOSYS net rules");
    ok(captured_attr_valid, "passes net rule attributes through for ENOSYS");
    cmp_ok(captured_attr.allowed_access, "==", attr.allowed_access,
           "passes allowed_access through for ENOSYS");
    cmp_ok(captured_attr.port, "==", attr.port,
           "passes port through for ENOSYS");
    cmp_ok(errno, "==", ENOSYS, "preserves ENOSYS from the syscall");

    done_testing();
}
