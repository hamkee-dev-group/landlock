#include <stdint.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int captured_rule_type;
static int captured_parent_fd;
static uint64_t captured_allowed_access;

long landlock_add_rule_syscall(int ruleset_fd, int rule_type,
                               const void *rule_attr, unsigned int flags)
{
    const struct landlock_path_beneath_attr *attr = rule_attr;

    (void)ruleset_fd;
    (void)flags;
    captured_rule_type = rule_type;
    captured_parent_fd = attr->parent_fd;
    captured_allowed_access = attr->allowed_access;
    return 0;
}

int main(void)
{
    struct landlock_path_beneath_attr attr = {
        .parent_fd = 0,
        .allowed_access = LANDLOCK_ACCESS_FS_READ_DIR,
    };

    plan(4);

    captured_rule_type = -1;
    captured_parent_fd = -1;
    captured_allowed_access = 0;

    ok(landlock_add_fs_rule(7, &attr, 0) == 0,
       "accepts parent_fd zero for fs rules");
    ok(captured_parent_fd == 0,
       "forwards parent_fd zero unchanged");
    ok(captured_allowed_access == LANDLOCK_ACCESS_FS_READ_DIR,
       "forwards allowed_access unchanged");
    ok(captured_rule_type == LANDLOCK_RULE_PATH_BENEATH,
       "uses path beneath rule type");

    done_testing();
}
