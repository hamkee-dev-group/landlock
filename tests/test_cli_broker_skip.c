#include "tap.h"

int main(void)
{
    plan(SKIP_ALL, "seccomp notify broker is not implemented yet; brokered "
                   "exception integration tests are deferred to M3");
    done_testing();
}
