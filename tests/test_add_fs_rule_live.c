#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

int main(void)
{
    struct landlock_path_beneath_attr attr;
    int abi;
    int ruleset_fd;
    int parent_fd;

    abi = landlock_abi_version();
    if (abi == 0) {
        plan(SKIP_ALL, "Landlock is not supported");
        done_testing();
    }

    plan(2);

    ruleset_fd = landlock_create_fs_ruleset(LANDLOCK_ACCESS_FS_READ_FILE, NULL);
    if (ruleset_fd < 0) {
        BAIL_OUT("landlock_create_fs_ruleset failed: %s", strerror(errno));
    }

    parent_fd = open("/tmp", O_PATH | O_CLOEXEC);
    if (parent_fd < 0) {
        close(ruleset_fd);
        BAIL_OUT("open failed: %s", strerror(errno));
    }

    attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
    attr.parent_fd = parent_fd;

    errno = E2BIG;
    ok(landlock_add_fs_rule(ruleset_fd, &attr, 0) == 0 && errno == E2BIG,
       "adds a valid fs rule without changing errno");

    errno = 0;
    ok(landlock_add_fs_rule(ruleset_fd, &attr, 0xDEADBEEF) == -1 &&
           errno == EINVAL,
       "rejects invalid add_rule flags");

    close(parent_fd);
    close(ruleset_fd);

    done_testing();
}
