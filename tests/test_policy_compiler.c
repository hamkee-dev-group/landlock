#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include "landlockd/landlock.h"
#include "landlockd/landlock_compat.h"
#include "landlockd/policy_compiler.h"
#include "landlockd/policy_ir.h"
#include "tap.h"








struct stub_state {
  int fs_create_calls;
  uint64_t fs_create_requested[4];
  int fs_create_results[4];
  int fs_create_errnos[4];

  int net_create_calls;
  uint64_t net_create_requested[4];
  int net_create_results[4];

  int fs_add_calls;
  int fs_add_ruleset_fd[8];
  uint64_t fs_add_allowed[8];
  int fs_add_parent_fd[8];

  int net_add_calls;
  int net_add_ruleset_fd[8];
  uint64_t net_add_allowed[8];
  uint64_t net_add_port[8];

  int open_calls;
  const char *open_paths[8];
  int open_flags[8];
  int open_results[8];

  int close_calls;
  int closed_fds[16];
};

static struct stub_state state;

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs) {
  int i;

  (void)granted_access_fs;
  i = state.fs_create_calls;
  state.fs_create_requested[i] = requested_access_fs;
  state.fs_create_calls++;
  if (state.fs_create_results[i] < 0) {
    errno = state.fs_create_errnos[i];
  }
  return state.fs_create_results[i];
}

int landlock_create_net_ruleset(uint64_t requested_access_net,
                                uint64_t *granted_access_net) {
  int i;

  (void)granted_access_net;
  i = state.net_create_calls;
  state.net_create_requested[i] = requested_access_net;
  state.net_create_calls++;
  return state.net_create_results[i];
}

int landlock_add_fs_rule(int ruleset_fd,
                         const struct landlock_path_beneath_attr *attr,
                         unsigned int flags) {
  int i;

  (void)flags;
  i = state.fs_add_calls;
  state.fs_add_ruleset_fd[i] = ruleset_fd;
  state.fs_add_allowed[i] = attr->allowed_access;
  state.fs_add_parent_fd[i] = attr->parent_fd;
  state.fs_add_calls++;
  return 0;
}

int landlock_add_net_rule(int ruleset_fd,
                          const struct landlock_net_port_attr *attr,
                          unsigned int flags) {
  int i;

  (void)flags;
  i = state.net_add_calls;
  state.net_add_ruleset_fd[i] = ruleset_fd;
  state.net_add_allowed[i] = attr->allowed_access;
  state.net_add_port[i] = attr->port;
  state.net_add_calls++;
  return 0;
}

int open(const char *path, int flags, ...) {
  int i;

  i = state.open_calls;
  state.open_paths[i] = path;
  state.open_flags[i] = flags;
  state.open_calls++;
  return state.open_results[i];
}

int close(int fd) {
  state.closed_fds[state.close_calls] = fd;
  state.close_calls++;
  return 0;
}

static void reset_state(void) {
  memset(&state, 0, sizeof(state));
  state.fs_create_results[0] = 101;
  state.fs_create_results[1] = 102;
  state.fs_create_results[2] = 103;
  state.net_create_results[0] = 201;
  state.net_create_results[1] = 202;
  state.net_create_results[2] = 203;
  state.open_results[0] = 301;
  state.open_results[1] = 302;
  state.open_results[2] = 303;
  state.open_results[3] = 304;
}

int main(void) {
  struct landlockd_ir_fs_rule fs_rules_a[] = {
      {.path = "/a", .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE},
      {.path = "/b", .allowed_access = LANDLOCK_ACCESS_FS_READ_DIR},
  };
  struct landlockd_ir_fs_rule fs_rules_b[] = {
      {.path = "/c", .allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE},
  };
  struct landlockd_ir_net_rule net_rules_a[] = {
      {.port = 80, .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP},
      {.port = 443, .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP},
  };
  struct landlockd_ir_net_rule net_rules_b[] = {
      {.port = 8080, .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP},
  };
  struct landlockd_ir_layer fs_layer_a = {
      .kind = LANDLOCKD_IR_LAYER_FS,
      .order = 0,
      .handled_access =
          LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
      .rule_count = 2,
      .fs_rules = fs_rules_a,
  };
  struct landlockd_ir_layer net_layer_a = {
      .kind = LANDLOCKD_IR_LAYER_NET,
      .order = 1,
      .handled_access =
          LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
      .rule_count = 2,
      .net_rules = net_rules_a,
  };
  struct landlockd_ir_layer fs_layer_b = {
      .kind = LANDLOCKD_IR_LAYER_FS,
      .order = 2,
      .handled_access = LANDLOCK_ACCESS_FS_WRITE_FILE,
      .rule_count = 1,
      .fs_rules = fs_rules_b,
  };
  struct landlockd_ir_layer net_layer_b = {
      .kind = LANDLOCKD_IR_LAYER_NET,
      .order = 3,
      .handled_access = LANDLOCK_ACCESS_NET_BIND_TCP,
      .rule_count = 1,
      .net_rules = net_rules_b,
  };
  const struct landlockd_ir_layer *mixed_layers[] = {
      &fs_layer_a, &net_layer_a, &fs_layer_b, &net_layer_b};
  struct landlockd_ir_policy policy = {
      .name = "unit",
      .layer_count = 4,
      .layers = mixed_layers,
  };
  struct landlockd_ir_policy invalid_policy = {
      .name = NULL,
      .layer_count = 4,
      .layers = mixed_layers,
  };
  struct landlockd_compiled_rulesets compiled;
  int rc;

  plan(19);

  reset_state();
  errno = 0;
  rc = landlockd_policy_compile_fs(NULL, &compiled);
  ok(rc == -1 && errno == EINVAL && state.fs_create_calls == 0 &&
         state.fs_add_calls == 0,
     "compile_fs rejects a NULL policy without calling any wrapper");

  reset_state();
  errno = 0;
  rc = landlockd_policy_compile_fs(&policy, NULL);
  ok(rc == -1 && errno == EINVAL && state.fs_create_calls == 0 &&
         state.fs_add_calls == 0,
     "compile_fs rejects a NULL output without calling any wrapper");

  reset_state();
  errno = 0;
  rc = landlockd_policy_compile_fs(&invalid_policy, &compiled);
  ok(rc == -1 && errno == EINVAL && state.fs_create_calls == 0 &&
         state.fs_add_calls == 0 && state.open_calls == 0,
     "compile_fs rejects invalid IR before any wrapper call");

  reset_state();
  errno = 0;
  rc = landlockd_policy_compile_net(&invalid_policy, &compiled);
  ok(rc == -1 && errno == EINVAL && state.net_create_calls == 0 &&
         state.net_add_calls == 0,
     "compile_net rejects invalid IR before any wrapper call");

  reset_state();
  errno = 0;
  rc = landlockd_policy_compile_fs(&policy, &compiled);
  ok(rc == 0 && compiled.count == 2 && compiled.ruleset_fds != NULL &&
         compiled.ruleset_fds[0] == 101 && compiled.ruleset_fds[1] == 102,
     "compile_fs returns one ruleset fd per fs layer in IR order");
  ok(state.fs_create_calls == 2 &&
         state.fs_create_requested[0] ==
             (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) &&
         state.fs_create_requested[1] == LANDLOCK_ACCESS_FS_WRITE_FILE,
     "compile_fs calls landlock_create_fs_ruleset with each fs layer's mask");
  ok(state.open_calls == 3 && strcmp(state.open_paths[0], "/a") == 0 &&
         strcmp(state.open_paths[1], "/b") == 0 &&
         strcmp(state.open_paths[2], "/c") == 0 &&
         state.open_flags[0] == (O_PATH | O_CLOEXEC),
     "compile_fs opens each rule path with O_PATH|O_CLOEXEC in IR order");
  ok(state.fs_add_calls == 3 && state.fs_add_ruleset_fd[0] == 101 &&
         state.fs_add_ruleset_fd[1] == 101 &&
         state.fs_add_ruleset_fd[2] == 102 &&
         state.fs_add_allowed[0] == LANDLOCK_ACCESS_FS_READ_FILE &&
         state.fs_add_allowed[1] == LANDLOCK_ACCESS_FS_READ_DIR &&
         state.fs_add_allowed[2] == LANDLOCK_ACCESS_FS_WRITE_FILE &&
         state.fs_add_parent_fd[0] == 301 &&
         state.fs_add_parent_fd[1] == 302 &&
         state.fs_add_parent_fd[2] == 303,
     "compile_fs calls landlock_add_fs_rule with each rule's mask and fd");
  ok(state.net_create_calls == 0 && state.net_add_calls == 0,
     "compile_fs leaves net wrappers untouched when compiling a mixed IR");
  landlockd_compiled_rulesets_cleanup(&compiled);

  reset_state();
  errno = 0;
  rc = landlockd_policy_compile_net(&policy, &compiled);
  ok(rc == 0 && compiled.count == 2 && compiled.ruleset_fds != NULL &&
         compiled.ruleset_fds[0] == 201 && compiled.ruleset_fds[1] == 202,
     "compile_net returns one ruleset fd per net layer in IR order");
  ok(state.net_create_calls == 2 &&
         state.net_create_requested[0] ==
             (LANDLOCK_ACCESS_NET_BIND_TCP |
              LANDLOCK_ACCESS_NET_CONNECT_TCP) &&
         state.net_create_requested[1] == LANDLOCK_ACCESS_NET_BIND_TCP,
     "compile_net calls landlock_create_net_ruleset with each net layer's mask");
  ok(state.net_add_calls == 3 && state.net_add_ruleset_fd[0] == 201 &&
         state.net_add_ruleset_fd[1] == 201 &&
         state.net_add_ruleset_fd[2] == 202 &&
         state.net_add_port[0] == 80 && state.net_add_port[1] == 443 &&
         state.net_add_port[2] == 8080 &&
         state.net_add_allowed[0] == LANDLOCK_ACCESS_NET_BIND_TCP &&
         state.net_add_allowed[1] == LANDLOCK_ACCESS_NET_CONNECT_TCP &&
         state.net_add_allowed[2] == LANDLOCK_ACCESS_NET_BIND_TCP,
     "compile_net calls landlock_add_net_rule with each rule's port and mask");
  ok(state.fs_create_calls == 0 && state.fs_add_calls == 0 &&
         state.open_calls == 0,
     "compile_net leaves fs wrappers untouched when compiling a mixed IR");
  landlockd_compiled_rulesets_cleanup(&compiled);

  {
    const struct landlockd_ir_layer *fs_only[] = {&fs_layer_a};
    struct landlockd_ir_layer fs_layer_only = fs_layer_a;
    struct landlockd_ir_policy fs_only_policy;
    fs_layer_only.order = 0;
    fs_only[0] = &fs_layer_only;
    fs_only_policy.name = "net-free";
    fs_only_policy.layer_count = 1;
    fs_only_policy.layers = fs_only;
    reset_state();
    rc = landlockd_policy_compile_net(&fs_only_policy, &compiled);
    ok(rc == 0 && compiled.count == 0 && compiled.ruleset_fds == NULL &&
           state.net_create_calls == 0 && state.net_add_calls == 0,
       "compile_net on an IR without net layers produces an empty result");
  }

  {
    reset_state();
    errno = 42;
    landlockd_compiled_rulesets_cleanup(NULL);
    ok(errno == 42 && state.close_calls == 0,
       "cleanup accepts a NULL pointer and preserves errno");
  }

  {
    reset_state();
    state.fs_create_results[1] = -1;
    state.fs_create_errnos[1] = EIO;
    errno = 0;
    rc = landlockd_policy_compile_fs(&policy, &compiled);
    ok(rc == -1 && errno == EIO,
       "compile_fs returns -1 with errno preserved when a later create_fs_ruleset fails");
    ok(compiled.count == 0 && compiled.ruleset_fds == NULL,
       "compile_fs cleanup resets count to 0 and ruleset_fds to NULL after a failing create_fs_ruleset");
    ok(state.fs_create_calls == 2 && state.open_calls == 2 &&
           state.fs_add_calls == 2,
       "compile_fs makes no open() or add_fs_rule() calls for layers after a failing create_fs_ruleset");
    ok(state.close_calls == 3 && state.closed_fds[2] == 101,
       "compile_fs closes the already-created ruleset fd via cleanup after a failing create_fs_ruleset");
  }

  done_testing();
}
