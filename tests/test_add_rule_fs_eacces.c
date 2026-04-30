#include <errno.h>

#include "landlockd/landlock.h"
#include "tap.h"

static int captured_ruleset_fd;
static int captured_rule_type;
static struct landlock_path_beneath_attr captured_attr;

long landlock_add_rule_syscall(int ruleset_fd, int rule_type,
                               const void *rule_attr, unsigned int flags)
{
    (void)flags;
    captured_ruleset_fd = ruleset_fd;
    captured_rule_type = rule_type;
    captured_attr = *(const struct landlock_path_beneath_attr *)rule_attr;
    errno = EACCES;
    return -1;
}

int main(void)
{
    struct landlock_path_beneath_attr attr = {
        .parent_fd = 4,
        .allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE,
    };

    plan(5);

    captured_ruleset_fd = -1;
    captured_rule_type = -1;
    captured_attr.parent_fd = -1;
    captured_attr.allowed_access = 0;
    errno = 0;

    ok(landlock_add_fs_rule(9, &attr, 0) == -1,
       "returns -1 when the kernel rejects a post-restrict fs rule");
    ok(errno == EACCES,
       "preserves EACCES from the kernel");
    ok(captured_ruleset_fd == 9,
       "forwards ruleset fd to the syscall shim");
    ok(captured_rule_type == LANDLOCK_RULE_PATH_BENEATH,
       "uses the path-beneath rule type");
    ok(captured_attr.parent_fd == 4 &&
           captured_attr.allowed_access == LANDLOCK_ACCESS_FS_WRITE_FILE,
       "forwards the fs rule attributes unchanged");

    done_testing();
}
