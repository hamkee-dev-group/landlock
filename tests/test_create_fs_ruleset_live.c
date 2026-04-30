#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

int main(void)
{
    uint64_t granted_access_fs;
    int abi;
    int ruleset_fd;

    abi = landlock_abi_version();
    plan(2);

    granted_access_fs = 0;
    skip(abi == 0, 2, "Landlock is not supported");
    ruleset_fd = landlock_create_fs_ruleset(LANDLOCK_ACCESS_FS_READ_FILE,
                                            &granted_access_fs);
    ok(ruleset_fd >= 0, "creates a filesystem ruleset");
    ok(close(ruleset_fd) == 0, "closes the returned ruleset fd");
    end_skip;

    done_testing();
}
