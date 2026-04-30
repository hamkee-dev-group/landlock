#define _GNU_SOURCE

#include "landlockd/landlock_policy.h"

#include "landlockd/landlock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static int landlockd_validate_fs_policy(const struct landlockd_policy *policy) {
  const struct landlockd_policy_fs_layer *layer;
  const struct landlockd_policy_fs_rule *rule;
  size_t i;
  size_t j;

  if (policy->fs_layer_count > 0 && policy->fs_layers == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (i = 0; i < policy->fs_layer_count; i++) {
    layer = policy->fs_layers[i];
    if (layer == NULL) {
      errno = EINVAL;
      return -1;
    }
    if (layer->handled_access_fs == 0) {
      errno = EINVAL;
      return -1;
    }
    if (layer->rule_count > 0 && layer->rules == NULL) {
      errno = EINVAL;
      return -1;
    }
    for (j = 0; j < layer->rule_count; j++) {
      rule = layer->rules[j];
      if (rule == NULL || rule->path == NULL || rule->allowed_access == 0) {
        errno = EINVAL;
        return -1;
      }
    }
  }

  return 0;
}

void landlockd_compiled_policy_cleanup(
    struct landlockd_compiled_policy *compiled) {
  int saved_errno;
  size_t i;

  if (compiled == NULL) {
    return;
  }

  saved_errno = errno;
  if (compiled->fs_ruleset_fds != NULL) {
    for (i = 0; i < compiled->fs_layer_count; i++) {
      if (compiled->fs_ruleset_fds[i] >= 0) {
        close(compiled->fs_ruleset_fds[i]);
      }
    }
    free(compiled->fs_ruleset_fds);
  }
  compiled->fs_layer_count = 0;
  compiled->fs_ruleset_fds = NULL;
  errno = saved_errno;
}

int landlockd_compile_fs_policy(const struct landlockd_policy *policy,
                                struct landlockd_compiled_policy *out) {
  const struct landlockd_policy_fs_layer *layer;
  const struct landlockd_policy_fs_rule *rule;
  struct landlock_path_beneath_attr attr;
  int *fds;
  int fd;
  int parent_fd;
  int saved_errno;
  size_t i;
  size_t j;

  if (policy == NULL || out == NULL) {
    errno = EINVAL;
    return -1;
  }

  out->fs_layer_count = 0;
  out->fs_ruleset_fds = NULL;

  if (landlockd_validate_fs_policy(policy) < 0) {
    return -1;
  }

  fds = NULL;
  if (policy->fs_layer_count > 0) {
    fds = malloc(policy->fs_layer_count * sizeof(*fds));
    if (fds == NULL) {
      return -1;
    }
    for (i = 0; i < policy->fs_layer_count; i++) {
      fds[i] = -1;
    }
  }

  out->fs_layer_count = policy->fs_layer_count;
  out->fs_ruleset_fds = fds;

  for (i = 0; i < policy->fs_layer_count; i++) {
    layer = policy->fs_layers[i];
    fd = landlock_create_fs_ruleset(layer->handled_access_fs, NULL);
    if (fd < 0) {
      saved_errno = errno;
      landlockd_compiled_policy_cleanup(out);
      errno = saved_errno;
      return -1;
    }
    out->fs_ruleset_fds[i] = fd;

    for (j = 0; j < layer->rule_count; j++) {
      rule = layer->rules[j];
      parent_fd = open(rule->path, O_PATH | O_CLOEXEC);
      if (parent_fd < 0) {
        saved_errno = errno;
        landlockd_compiled_policy_cleanup(out);
        errno = saved_errno;
        return -1;
      }

      attr.allowed_access = rule->allowed_access;
      attr.parent_fd = parent_fd;
      if (landlock_add_fs_rule(fd, &attr, 0) < 0) {
        saved_errno = errno;
        close(parent_fd);
        landlockd_compiled_policy_cleanup(out);
        errno = saved_errno;
        return -1;
      }

      close(parent_fd);
    }
  }

  return 0;
}
