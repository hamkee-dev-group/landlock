#include <string.h>

#include "landlock_policy_loader.h"
#include "tap.h"

int main(int argc, char *argv[]) {
  int expect_helper;

  plan(1);

  if (argc < 2) {
    diag("missing expected policy loader mode");
    return 1;
  }

  expect_helper = strcmp(argv[1], "helper") == 0;
  ok(landlockd_policy_loader_uses_helper() == expect_helper,
     "policy loader mode matches the build configuration");

  done_testing();
}
