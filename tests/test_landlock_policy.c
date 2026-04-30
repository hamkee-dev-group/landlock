#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/landlock_policy.h"
#include "tap.h"

struct test_state {
  int create_call_count;
  uint64_t create_requested_access[4];
  int create_results[4];
  int create_errno;
  int add_call_count;
  int add_ruleset_fd[8];
  uint64_t add_allowed_access[8];
  int add_parent_fd[8];
  int add_errno;
  int add_fail_at;
  int open_call_count;
  const char *opened_paths[8];
  int open_flags[8];
  int open_results[8];
  int open_errno;
  int close_call_count;
  int closed_fds[16];
};

static struct test_state state;

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs) {
  int i;

  (void)granted_access_fs;
  i = state.create_call_count;
  state.create_requested_access[i] = requested_access_fs;
  state.create_call_count++;
  errno = state.create_errno;
  return state.create_results[i];
}

int landlock_add_fs_rule(int ruleset_fd,
                         const struct landlock_path_beneath_attr *attr,
                         unsigned int flags) {
  int i;

  (void)flags;
  i = state.add_call_count;
  state.add_ruleset_fd[i] = ruleset_fd;
  state.add_allowed_access[i] = attr->allowed_access;
  state.add_parent_fd[i] = attr->parent_fd;
  state.add_call_count++;
  if (state.add_fail_at > 0 && state.add_call_count == state.add_fail_at) {
    errno = state.add_errno;
    return -1;
  }
  return 0;
}

int open(const char *path, int flags, ...) {
  int i;

  i = state.open_call_count;
  state.opened_paths[i] = path;
  state.open_flags[i] = flags;
  state.open_call_count++;
  errno = state.open_errno;
  return state.open_results[i];
}

int close(int fd) {
  state.closed_fds[state.close_call_count] = fd;
  state.close_call_count++;
  return 0;
}

static void reset_state(void) {
  memset(&state, 0, sizeof(state));
  state.create_results[0] = 101;
  state.create_results[1] = 102;
  state.create_results[2] = 103;
  state.create_results[3] = 104;
  state.open_results[0] = 201;
  state.open_results[1] = 202;
  state.open_results[2] = 203;
  state.open_results[3] = 204;
}

int main(void) {
  struct landlockd_policy_fs_rule rule_a = {
      .path = "/a",
      .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
  };
  struct landlockd_policy_fs_rule rule_b = {
      .path = "/b",
      .allowed_access = LANDLOCK_ACCESS_FS_READ_DIR,
  };
  struct landlockd_policy_fs_rule rule_c = {
      .path = "/c",
      .allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE,
  };
  const struct landlockd_policy_fs_rule *layer_a_rules[] = {&rule_a, &rule_b};
  const struct landlockd_policy_fs_rule *layer_b_rules[] = {&rule_c};
  struct landlockd_policy_fs_layer layer_a = {
      .handled_access_fs =
          LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
      .rule_count = 2,
      .rules = layer_a_rules,
  };
  struct landlockd_policy_fs_layer layer_b = {
      .handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE,
      .rule_count = 1,
      .rules = layer_b_rules,
  };
  const struct landlockd_policy_fs_layer *layers[] = {&layer_a, &layer_b};
  struct landlockd_policy policy = {
      .fs_layer_count = 2,
      .fs_layers = layers,
  };
  struct landlockd_policy_fs_layer broken_layer;
  const struct landlockd_policy_fs_rule *broken_rules[1];
  const struct landlockd_policy_fs_layer *broken_layers[1];
  struct landlockd_policy broken_policy;
  struct landlockd_compiled_policy compiled;
  int rc;

  plan(16);

  reset_state();
  errno = 0;
  rc = landlockd_compile_fs_policy(NULL, &compiled);
  ok(rc == -1 && errno == EINVAL && state.create_call_count == 0 &&
         state.add_call_count == 0,
     "rejects a NULL policy pointer before creating rulesets");

  reset_state();
  errno = 0;
  rc = landlockd_compile_fs_policy(&policy, NULL);
  ok(rc == -1 && errno == EINVAL && state.create_call_count == 0 &&
         state.add_call_count == 0,
     "rejects a NULL output pointer before creating rulesets");

  reset_state();
  broken_layer = layer_a;
  broken_layer.rule_count = 1;
  broken_layer.rules = NULL;
  broken_layers[0] = &broken_layer;
  broken_policy.fs_layer_count = 1;
  broken_policy.fs_layers = broken_layers;
  errno = 0;
  rc = landlockd_compile_fs_policy(&broken_policy, &compiled);
  ok(rc == -1 && errno == EINVAL && state.create_call_count == 0 &&
         state.add_call_count == 0,
     "rejects a layer with rules but a NULL rules array before creating rulesets");

  reset_state();
  broken_layer = layer_a;
  broken_rules[0] = NULL;
  broken_layer.rule_count = 1;
  broken_layer.rules = broken_rules;
  broken_layers[0] = &broken_layer;
  broken_policy.fs_layer_count = 1;
  broken_policy.fs_layers = broken_layers;
  errno = 0;
  rc = landlockd_compile_fs_policy(&broken_policy, &compiled);
  ok(rc == -1 && errno == EINVAL && state.create_call_count == 0 &&
         state.add_call_count == 0,
     "rejects a NULL rule entry before creating rulesets");

  reset_state();
  broken_layer = layer_a;
  rule_a.path = NULL;
  broken_rules[0] = &rule_a;
  broken_layer.rule_count = 1;
  broken_layer.rules = broken_rules;
  broken_layers[0] = &broken_layer;
  broken_policy.fs_layer_count = 1;
  broken_policy.fs_layers = broken_layers;
  errno = 0;
  rc = landlockd_compile_fs_policy(&broken_policy, &compiled);
  ok(rc == -1 && errno == EINVAL && state.create_call_count == 0 &&
         state.add_call_count == 0,
     "rejects a rule with a NULL path before creating rulesets");
  rule_a.path = "/a";

  reset_state();
  errno = 0;
  rc = landlockd_compile_fs_policy(&policy, &compiled);
  ok(rc == 0 && errno == 0 && compiled.fs_layer_count == 2 &&
         compiled.fs_ruleset_fds != NULL && compiled.fs_ruleset_fds[0] == 101 &&
         compiled.fs_ruleset_fds[1] == 102,
     "returns filesystem ruleset fds in input layer order");
  ok(state.create_call_count == 2 &&
         state.create_requested_access[0] ==
             (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) &&
         state.create_requested_access[1] == LANDLOCK_ACCESS_FS_WRITE_FILE,
     "creates one filesystem ruleset per layer with each handled access mask");
  ok(state.open_call_count == 3 &&
         strcmp(state.opened_paths[0], "/a") == 0 &&
         strcmp(state.opened_paths[1], "/b") == 0 &&
         strcmp(state.opened_paths[2], "/c") == 0 &&
         state.open_flags[0] == (O_PATH | O_CLOEXEC) &&
         state.open_flags[1] == (O_PATH | O_CLOEXEC) &&
         state.open_flags[2] == (O_PATH | O_CLOEXEC),
     "opens each rule path with O_PATH and O_CLOEXEC");
  ok(state.add_call_count == 3 && state.add_ruleset_fd[0] == 101 &&
         state.add_ruleset_fd[1] == 101 && state.add_ruleset_fd[2] == 102 &&
         state.add_allowed_access[0] == LANDLOCK_ACCESS_FS_READ_FILE &&
         state.add_allowed_access[1] == LANDLOCK_ACCESS_FS_READ_DIR &&
         state.add_allowed_access[2] == LANDLOCK_ACCESS_FS_WRITE_FILE,
     "populates each created ruleset with the layer's filesystem rules");
  errno = 123;
  landlockd_compiled_policy_cleanup(&compiled);
  ok(errno == 123 && compiled.fs_layer_count == 0 &&
         compiled.fs_ruleset_fds == NULL && state.close_call_count == 5 &&
         state.closed_fds[0] == 201 && state.closed_fds[1] == 202 &&
         state.closed_fds[2] == 203 && state.closed_fds[3] == 101 &&
         state.closed_fds[4] == 102,
     "cleanup closes parent fds during compilation and later closes compiled rulesets");

  reset_state();
  state.add_fail_at = 2;
  state.add_errno = EPERM;
  errno = 0;
  rc = landlockd_compile_fs_policy(&policy, &compiled);
  ok(rc == -1 && errno == EPERM,
     "surfaces add-rule failure from the filesystem compiler");
  ok(compiled.fs_layer_count == 0 && compiled.fs_ruleset_fds == NULL,
     "compiler cleanup clears partially built output on failure");
  ok(state.create_call_count == 1 && state.add_call_count == 2,
     "stops building layers once a rule insert fails");
  ok(state.close_call_count == 3 && state.closed_fds[0] == 201 &&
         state.closed_fds[1] == 202 && state.closed_fds[2] == 101,
     "closes the open parent fd and already-created ruleset fds on failure");

  reset_state();
  compiled.fs_layer_count = 3;
  compiled.fs_ruleset_fds = malloc(3 * sizeof(*compiled.fs_ruleset_fds));
  if (compiled.fs_ruleset_fds == NULL) {
    bail_out(0, "malloc failed");
  }
  compiled.fs_ruleset_fds[0] = 301;
  compiled.fs_ruleset_fds[1] = -1;
  compiled.fs_ruleset_fds[2] = 303;
  errno = 77;
  landlockd_compiled_policy_cleanup(&compiled);
  ok(errno == 77 && compiled.fs_layer_count == 0 &&
         compiled.fs_ruleset_fds == NULL && state.close_call_count == 2 &&
         state.closed_fds[0] == 301 && state.closed_fds[1] == 303,
     "cleanup safely handles partially initialized compiler output");
  errno = 55;
  landlockd_compiled_policy_cleanup(NULL);
  ok(errno == 55, "cleanup accepts a NULL compiled-policy pointer");

  done_testing();
}
