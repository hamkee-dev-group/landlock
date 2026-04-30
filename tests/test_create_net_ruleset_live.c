#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

int main(void)
{
    uint64_t granted_access_net;
    int abi;
    int ruleset_fd;

    abi = landlock_abi_version();
    plan(2);

    granted_access_net = 0;
    skip(abi < 4, 2, "Landlock network rules require ABI >= 4");
    ruleset_fd = landlock_create_net_ruleset(LANDLOCK_ACCESS_NET_BIND_TCP,
                                             &granted_access_net);
    ok(ruleset_fd >= 0, "creates a network ruleset");
    ok(close(ruleset_fd) == 0, "closes the returned ruleset fd");
    end_skip;

    done_testing();
}
