#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int captured_ruleset_fd;
static int captured_rule_type;
static unsigned int captured_flags;
static struct landlock_path_beneath_attr captured_attr;
static int captured_attr_valid;
static int syscall_call_count;
static long fake_return_value;
static int fake_errno_value;

long landlock_add_rule_syscall(int ruleset_fd, int rule_type, const void *rule_attr, unsigned int flags)
{
    syscall_call_count++;
    captured_ruleset_fd = ruleset_fd;
    captured_rule_type = rule_type;
    captured_flags = flags;
    captured_attr_valid = 0;
    if (rule_attr != NULL) {
        captured_attr = *(const struct landlock_path_beneath_attr *)rule_attr;
        captured_attr_valid = 1;
    }
    errno = fake_errno_value;
    return fake_return_value;
}

int main(void)
{
    struct landlock_path_beneath_attr attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
        .parent_fd = 11,
    };

    plan(15);

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    captured_attr.parent_fd = -1;
    captured_attr.allowed_access = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_rule(5, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) == 0 &&
           captured_ruleset_fd == 5 &&
           captured_rule_type == LANDLOCK_RULE_PATH_BENEATH &&
           captured_flags == 0 &&
           captured_attr_valid &&
           captured_attr.parent_fd == attr.parent_fd &&
           captured_attr.allowed_access == attr.allowed_access,
       "forwards rule arguments on success");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_fs_rule(-1, &attr, 0) == -1,
       "rejects -1 ruleset_fd for fs rules");
    ok(errno == EBADF,
       "sets errno to EBADF for -1 fs ruleset_fd");
    ok(captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "does not invoke the syscall for -1 fs ruleset_fd");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_fs_rule(INT_MIN, &attr, 0) == -1,
       "rejects INT_MIN ruleset_fd for fs rules");
    ok(errno == EBADF,
       "sets errno to EBADF for INT_MIN fs ruleset_fd");
    ok(captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "does not invoke the syscall for INT_MIN fs ruleset_fd");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    struct landlock_path_beneath_attr bad = {
        .parent_fd = -1,
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
    };
    ok(landlock_add_fs_rule(7, &bad, 0) == -1,
       "rejects negative parent_fd for fs rules");
    ok(errno == EBADF,
       "sets errno to EBADF for negative parent_fd");
    ok(captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "does not invoke the syscall for negative parent_fd");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_rule(-1, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) == -1 &&
           errno == EBADF &&
           captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "rejects negative ruleset fd before the syscall");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = 0;
    errno = 0;
    ok(landlock_add_rule(5, LANDLOCK_RULE_PATH_BENEATH, NULL, 0) == -1 &&
           errno == EINVAL &&
           captured_ruleset_fd == -1 &&
           captured_rule_type == -1 &&
           captured_flags == 0xffffffffu &&
           syscall_call_count == 0 &&
           !captured_attr_valid,
       "rejects null rule attributes before the syscall");

    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = EBADF;
    errno = 0;
    ok(landlock_add_rule(5, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) == -1 &&
           errno == EBADF &&
           syscall_call_count == 1,
       "propagates EBADF when the kernel rejects the rule");

    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = EINVAL;
    errno = 0;
    ok(landlock_add_rule(5, LANDLOCK_RULE_PATH_BENEATH, &attr, 3) == -1 &&
           errno == EINVAL &&
           syscall_call_count == 1,
       "propagates EINVAL on invalid rule arguments");

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_flags = 0xffffffffu;
    captured_attr_valid = 0;
    syscall_call_count = 0;
    fake_return_value = 0;
    fake_errno_value = EIO;
    errno = EBUSY;
    ok(landlock_add_rule(7, LANDLOCK_RULE_PATH_BENEATH, &attr, 2) == 0 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == 7 &&
           captured_rule_type == LANDLOCK_RULE_PATH_BENEATH &&
           captured_flags == 2 &&
           captured_attr_valid &&
           captured_attr.parent_fd == attr.parent_fd &&
           captured_attr.allowed_access == attr.allowed_access &&
           errno == EBUSY,
       "preserves caller errno on successful add_rule");

    done_testing();
}
