#define _GNU_SOURCE

#include "landlockd/policy_compiler.h"

#include "landlockd/landlock.h"
#include "landlockd/landlock_compat.h"
#include "landlockd/policy_ir.h"
#include "landlockd/seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static size_t landlockd_count_layers(const struct landlockd_ir_policy *policy,
                                     enum landlockd_ir_layer_kind kind) {
  size_t count;
  size_t i;

  count = 0;
  for (i = 0; i < policy->layer_count; i++) {
    if (policy->layers[i]->kind == kind) {
      count++;
    }
  }
  return count;
}

void landlockd_compiled_rulesets_cleanup(
    struct landlockd_compiled_rulesets *compiled) {
  int saved_errno;
  size_t i;

  if (compiled == NULL) {
    return;
  }

  saved_errno = errno;
  if (compiled->ruleset_fds != NULL) {
    for (i = 0; i < compiled->count; i++) {
      if (compiled->ruleset_fds[i] >= 0) {
        close(compiled->ruleset_fds[i]);
      }
    }
    free(compiled->ruleset_fds);
  }
  compiled->count = 0;
  compiled->ruleset_fds = NULL;
  errno = saved_errno;
}

int landlockd_policy_compile_fs(const struct landlockd_ir_policy *policy,
                                struct landlockd_compiled_rulesets *out) {
  const struct landlockd_ir_layer *layer;
  const struct landlockd_ir_fs_rule *rule;
  struct landlock_path_beneath_attr attr;
  int *fds;
  int fd;
  int parent_fd;
  int saved_errno;
  size_t fs_count;
  size_t next;
  size_t i;
  size_t j;

  if (policy == NULL || out == NULL) {
    errno = EINVAL;
    return -1;
  }

  out->count = 0;
  out->ruleset_fds = NULL;

  if (landlockd_ir_policy_validate(policy) < 0) {
    return -1;
  }

  fs_count = landlockd_count_layers(policy, LANDLOCKD_IR_LAYER_FS);
  if (fs_count == 0) {
    return 0;
  }

  fds = malloc(fs_count * sizeof(*fds));
  if (fds == NULL) {
    return -1;
  }
  for (i = 0; i < fs_count; i++) {
    fds[i] = -1;
  }
  out->count = fs_count;
  out->ruleset_fds = fds;

  next = 0;
  for (i = 0; i < policy->layer_count; i++) {
    layer = policy->layers[i];
    if (layer->kind != LANDLOCKD_IR_LAYER_FS) {
      continue;
    }
    fd = landlock_create_fs_ruleset(layer->handled_access, NULL);
    if (fd < 0) {
      saved_errno = errno;
      landlockd_compiled_rulesets_cleanup(out);
      errno = saved_errno;
      return -1;
    }
    fds[next] = fd;
    next++;

    for (j = 0; j < layer->rule_count; j++) {
      rule = &layer->fs_rules[j];
      parent_fd = open(rule->path, O_PATH | O_CLOEXEC);
      if (parent_fd < 0) {
        saved_errno = errno;
        landlockd_compiled_rulesets_cleanup(out);
        errno = saved_errno;
        return -1;
      }

      attr.allowed_access = rule->allowed_access;
      attr.parent_fd = parent_fd;
      if (landlock_add_fs_rule(fd, &attr, 0) < 0) {
        saved_errno = errno;
        close(parent_fd);
        landlockd_compiled_rulesets_cleanup(out);
        errno = saved_errno;
        return -1;
      }
      close(parent_fd);
    }
  }
  return 0;
}

int landlockd_policy_compile_net(const struct landlockd_ir_policy *policy,
                                 struct landlockd_compiled_rulesets *out) {
  const struct landlockd_ir_layer *layer;
  const struct landlockd_ir_net_rule *rule;
  struct landlock_net_port_attr attr;
  int *fds;
  int fd;
  int saved_errno;
  size_t net_count;
  size_t next;
  size_t i;
  size_t j;

  if (policy == NULL || out == NULL) {
    errno = EINVAL;
    return -1;
  }

  out->count = 0;
  out->ruleset_fds = NULL;

  if (landlockd_ir_policy_validate(policy) < 0) {
    return -1;
  }

  net_count = landlockd_count_layers(policy, LANDLOCKD_IR_LAYER_NET);
  if (net_count == 0) {
    return 0;
  }

  fds = malloc(net_count * sizeof(*fds));
  if (fds == NULL) {
    return -1;
  }
  for (i = 0; i < net_count; i++) {
    fds[i] = -1;
  }
  out->count = net_count;
  out->ruleset_fds = fds;

  next = 0;
  for (i = 0; i < policy->layer_count; i++) {
    layer = policy->layers[i];
    if (layer->kind != LANDLOCKD_IR_LAYER_NET) {
      continue;
    }
    fd = landlock_create_net_ruleset(layer->handled_access, NULL);
    if (fd < 0) {
      saved_errno = errno;
      landlockd_compiled_rulesets_cleanup(out);
      errno = saved_errno;
      return -1;
    }
    fds[next] = fd;
    next++;

    for (j = 0; j < layer->rule_count; j++) {
      rule = &layer->net_rules[j];
      attr.allowed_access = rule->allowed_access;
      attr.port = rule->port;
      if (landlock_add_net_rule(fd, &attr, 0) < 0) {
        saved_errno = errno;
        landlockd_compiled_rulesets_cleanup(out);
        errno = saved_errno;
        return -1;
      }
    }
  }
  return 0;
}

int landlockd_policy_compile_exceptions(const struct landlockd_ir_policy *policy,
                                        struct landlockd_seccomp_plan *plan) {
  const struct landlockd_ir_layer *layer;
  int saved_errno;
  size_t i;
  size_t j;

  if (policy == NULL || plan == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (landlockd_ir_policy_validate(policy) < 0) {
    return -1;
  }

  if (landlockd_seccomp_plan_init(plan) < 0) {
    return -1;
  }

  for (i = 0; i < policy->layer_count; i++) {
    layer = policy->layers[i];
    if (layer->kind != LANDLOCKD_IR_LAYER_EXCEPTION) {
      continue;
    }
    for (j = 0; j < layer->rule_count; j++) {
      if (landlockd_seccomp_plan_add(plan,
                                     layer->exception_rules[j].syscall_nr) <
          0) {
        saved_errno = errno;
        landlockd_seccomp_plan_init(plan);
        errno = saved_errno;
        return -1;
      }
    }
  }
  return 0;
}
