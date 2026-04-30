#include <errno.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int syscall_call_count;
static int captured_ruleset_fd;
static int captured_rule_type;
static const void *captured_rule_attr;
static unsigned int captured_flags;

long landlock_add_rule_syscall(int ruleset_fd, int rule_type,
                               const void *rule_attr, unsigned int flags)
{
    syscall_call_count++;
    captured_ruleset_fd = ruleset_fd;
    captured_rule_type = rule_type;
    captured_rule_attr = rule_attr;
    captured_flags = flags;
    errno = EPERM;
    return -1;
}

int main(void)
{
    struct landlock_path_beneath_attr attr = {
        .parent_fd = 5,
        .allowed_access = 0,
    };

    plan(16);

    syscall_call_count = 0;
    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_rule_attr = &attr;
    captured_flags = 1;
    errno = 0;

    ok(landlock_add_fs_rule(7, &attr, 0) == -1,
       "returns -1 for fs rules with an empty access mask");
    ok(errno == EINVAL,
       "sets errno to EINVAL for fs rules with an empty access mask");
    ok(syscall_call_count == 0,
       "rejects empty fs access masks before calling the syscall shim");
    ok(captured_ruleset_fd == -1 && captured_rule_type == -1 &&
           captured_rule_attr == &attr && captured_flags == 1,
       "leaves syscall arguments untouched when validation fails");

    syscall_call_count = 0;
    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_rule_attr = &attr;
    captured_flags = 1;
    errno = 0;

    ok(landlock_add_fs_rule(7, NULL, 1) == -1,
       "returns -1 for landlock_add_fs_rule with a NULL attr");
    ok(errno == EINVAL,
       "sets errno to EINVAL for landlock_add_fs_rule with a NULL attr");
    ok(syscall_call_count == 0,
       "rejects NULL attr before calling the syscall shim in landlock_add_fs_rule");
    ok(captured_ruleset_fd == -1 && captured_rule_type == -1 &&
           captured_rule_attr == &attr && captured_flags == 1,
       "leaves syscall arguments untouched for landlock_add_fs_rule NULL attr");

    syscall_call_count = 0;
    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_rule_attr = &attr;
    captured_flags = 1;
    errno = 0;

    ok(landlock_add_fs_rule(7, NULL, 0) == -1,
       "returns -1 for landlock_add_fs_rule with a NULL attr and zero flags");
    ok(errno == EINVAL,
       "sets errno to EINVAL for landlock_add_fs_rule with a NULL attr and zero flags");
    ok(syscall_call_count == 0,
       "rejects NULL attr with zero flags before calling the syscall shim in landlock_add_fs_rule");
    ok(captured_ruleset_fd == -1 && captured_rule_type == -1 &&
           captured_rule_attr == &attr && captured_flags == 1,
       "leaves syscall arguments untouched for landlock_add_fs_rule NULL attr with zero flags");

    syscall_call_count = 0;
    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_rule_attr = &attr;
    captured_flags = 1;
    errno = 0;

    {
        struct landlock_path_beneath_attr bad_parent_attr = {
            .parent_fd = -1,
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
        };

        ok(landlock_add_fs_rule(7, &bad_parent_attr, 0) == -1,
           "returns -1 for landlock_add_fs_rule with a negative parent_fd");
        ok(errno == EBADF,
           "sets errno to EBADF for landlock_add_fs_rule with a negative parent_fd");
        ok(syscall_call_count == 0,
           "rejects negative parent_fd before calling the syscall shim in landlock_add_fs_rule");
        ok(captured_ruleset_fd == -1 && captured_rule_type == -1 &&
               captured_rule_attr == &attr && captured_flags == 1,
           "leaves syscall arguments untouched for landlock_add_fs_rule negative parent_fd");
    }

    done_testing();
}
