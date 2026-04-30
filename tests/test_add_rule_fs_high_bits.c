#include <errno.h>
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

long landlock_add_rule_syscall(int ruleset_fd, int rule_type,
                               const void *rule_attr, unsigned int flags)
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
        .allowed_access = LANDLOCK_ACCESS_FS_REFER |
                          LANDLOCK_ACCESS_FS_TRUNCATE |
                          LANDLOCK_ACCESS_FS_IOCTL_DEV,
        .parent_fd = 0x5a5a5a5a,
    };

    plan(2);

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
    ok(landlock_add_fs_rule(17, &attr, 9) == 0 &&
           syscall_call_count == 1 &&
           captured_ruleset_fd == 17 &&
           captured_rule_type == LANDLOCK_RULE_PATH_BENEATH &&
           captured_flags == 9 &&
           captured_attr_valid &&
           captured_attr.parent_fd == attr.parent_fd &&
           captured_attr.allowed_access == attr.allowed_access,
       "forwards high-bit fs access masks and sentinel parent_fd unchanged");

    syscall_call_count = 0;
    fake_return_value = -1;
    fake_errno_value = EOVERFLOW;
    errno = 0;
    ok(landlock_add_fs_rule(17, &attr, 9) == -1 &&
           errno == EOVERFLOW &&
           syscall_call_count == 1,
       "propagates errno for high-bit fs rule failures");

    done_testing();
}
