#ifndef LANDLOCKD_LANDLOCK_POLICY_H
#define LANDLOCKD_LANDLOCK_POLICY_H

#include <stddef.h>
#include <stdint.h>

struct landlockd_policy_fs_rule {
  const char *path;
  uint64_t allowed_access;
};

struct landlockd_policy_fs_layer {
  uint64_t handled_access_fs;
  size_t rule_count;
  const struct landlockd_policy_fs_rule *const *rules;
};

struct landlockd_policy {
  size_t fs_layer_count;
  const struct landlockd_policy_fs_layer *const *fs_layers;
};

struct landlockd_compiled_policy {
  size_t fs_layer_count;
  int *fs_ruleset_fds;
};

int landlockd_compile_fs_policy(const struct landlockd_policy *policy,
                                struct landlockd_compiled_policy *out);
void landlockd_compiled_policy_cleanup(
    struct landlockd_compiled_policy *compiled);

#endif
