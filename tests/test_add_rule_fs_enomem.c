#include <errno.h>
#include <stdint.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int captured_parent_fd;
static uint64_t captured_allowed_access;

long landlock_add_rule_syscall(int ruleset_fd, int rule_type,
                               const void *rule_attr, unsigned int flags)
{
    const struct landlock_path_beneath_attr *attr = rule_attr;

    (void)ruleset_fd;
    (void)rule_type;
    (void)flags;
    captured_parent_fd = attr->parent_fd;
    captured_allowed_access = attr->allowed_access;
    errno = ENOMEM;
    return -1;
}

int main(void)
{
    struct landlock_path_beneath_attr attr = {
        .parent_fd = 11,
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_EXECUTE,
    };

    plan(4);

    captured_parent_fd = -1;
    captured_allowed_access = 0;
    errno = 0;

    ok(landlock_add_fs_rule(7, &attr, 0) == -1,
       "returns -1 when the kernel reports ENOMEM");
    ok(errno == ENOMEM,
       "propagates ENOMEM from the kernel");
    ok(captured_parent_fd == 11,
       "forwards parent_fd unchanged");
    ok(captured_allowed_access == (LANDLOCK_ACCESS_FS_READ_FILE |
                                   LANDLOCK_ACCESS_FS_EXECUTE),
       "forwards allowed_access unchanged");

    done_testing();
}
