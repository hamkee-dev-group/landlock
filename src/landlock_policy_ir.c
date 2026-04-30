#define _GNU_SOURCE

#include "landlock_policy_ir.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void landlockd_policy_ir_init(struct landlockd_policy_ir *ir) {
  if (ir == NULL) {
    return;
  }
  memset(ir, 0, sizeof(*ir));
}

void landlockd_policy_ir_reset(struct landlockd_policy_ir *ir) {
  int saved_errno;
  size_t i;
  size_t j;

  if (ir == NULL) {
    return;
  }
  saved_errno = errno;
  for (i = 0; i < ir->fs_layer_count; i++) {
    for (j = 0; j < ir->fs_layers[i].rule_count; j++) {
      free(ir->fs_layers[i].rules[j].path);
    }
    free(ir->fs_layers[i].rules);
  }
  free(ir->fs_layers);
  free(ir->net_rules);
  for (i = 0; i < ir->broker_open_read_count; i++) {
    free(ir->broker_open_read_rules[i].path);
  }
  free(ir->broker_open_read_rules);
  for (i = 0; i < ir->broker_open_write_count; i++) {
    free(ir->broker_open_write_rules[i].path);
  }
  free(ir->broker_open_write_rules);
  for (i = 0; i < ir->broker_scratch_count; i++) {
    free(ir->broker_scratch_rules[i].path);
  }
  free(ir->broker_scratch_rules);
  for (i = 0; i < ir->broker_export_count; i++) {
    free(ir->broker_export_rules[i].path);
  }
  free(ir->broker_export_rules);
  for (i = 0; i < ir->broker_mount_tmpfs_count; i++) {
    free(ir->broker_mount_tmpfs_rules[i].path);
  }
  free(ir->broker_mount_tmpfs_rules);
  for (i = 0; i < ir->broker_mount_bind_count; i++) {
    free(ir->broker_mount_bind_rules[i].source);
    free(ir->broker_mount_bind_rules[i].target);
  }
  free(ir->broker_mount_bind_rules);
  for (i = 0; i < ir->broker_mount_object_count; i++) {
    free(ir->broker_mount_object_rules[i].name);
    free(ir->broker_mount_object_rules[i].fs_type);
    for (j = 0; j < ir->broker_mount_object_rules[i].attach_count; j++) {
      free(ir->broker_mount_object_rules[i].attach_paths[j]);
    }
    free(ir->broker_mount_object_rules[i].attach_paths);
  }
  free(ir->broker_mount_object_rules);
  for (i = 0; i < ir->mount_tmpfs_count; i++) {
    free(ir->mount_tmpfs_rules[i].path);
  }
  free(ir->mount_tmpfs_rules);
  for (i = 0; i < ir->mount_bind_count; i++) {
    free(ir->mount_bind_rules[i].source);
    free(ir->mount_bind_rules[i].target);
  }
  free(ir->mount_bind_rules);
  for (i = 0; i < ir->mount_proc_count; i++) {
    free(ir->mount_proc_rules[i].path);
  }
  free(ir->mount_proc_rules);
  free(ir->runtime_root);
  free(ir->runtime_cwd);
  free(ir->seccomp_deny_rules);
  memset(ir, 0, sizeof(*ir));
  errno = saved_errno;
}

int landlockd_policy_ir_add_fs_layer(struct landlockd_policy_ir *ir,
                                     uint64_t handled_access_fs,
                                     size_t *out_layer_index) {
  struct landlockd_policy_ir_fs_layer *grown;

  if (ir == NULL || handled_access_fs == 0) {
    errno = EINVAL;
    return -1;
  }
  grown = realloc(ir->fs_layers,
                  (ir->fs_layer_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    return -1;
  }
  ir->fs_layers = grown;
  grown[ir->fs_layer_count].handled_access_fs = handled_access_fs;
  grown[ir->fs_layer_count].rule_count = 0;
  grown[ir->fs_layer_count].rules = NULL;
  if (out_layer_index != NULL) {
    *out_layer_index = ir->fs_layer_count;
  }
  ir->fs_layer_count++;
  return 0;
}

int landlockd_policy_ir_add_fs_rule(struct landlockd_policy_ir *ir,
                                    size_t layer_index, const char *path,
                                    uint64_t allowed_access) {
  struct landlockd_policy_ir_fs_layer *layer;
  struct landlockd_policy_ir_fs_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || allowed_access == 0 ||
      layer_index >= ir->fs_layer_count) {
    errno = EINVAL;
    return -1;
  }
  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }
  layer = &ir->fs_layers[layer_index];
  grown = realloc(layer->rules, (layer->rule_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }
  layer->rules = grown;
  grown[layer->rule_count].path = path_copy;
  grown[layer->rule_count].allowed_access = allowed_access;
  layer->rule_count++;
  return 0;
}

int landlockd_policy_ir_enable_net(struct landlockd_policy_ir *ir,
                                   uint64_t handled_access_net) {
  if (ir == NULL || handled_access_net == 0) {
    errno = EINVAL;
    return -1;
  }
  ir->net_enabled = 1;
  ir->net_handled_access = handled_access_net;
  return 0;
}

int landlockd_policy_ir_add_net_rule(struct landlockd_policy_ir *ir,
                                     uint16_t port, uint64_t allowed_access) {
  struct landlockd_policy_ir_net_rule *grown;

  if (ir == NULL || allowed_access == 0 || !ir->net_enabled) {
    errno = EINVAL;
    return -1;
  }
  grown = realloc(ir->net_rules, (ir->net_rule_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    return -1;
  }
  ir->net_rules = grown;
  grown[ir->net_rule_count].port = port;
  grown[ir->net_rule_count].allowed_access = allowed_access;
  ir->net_rule_count++;
  return 0;
}

int landlockd_policy_ir_add_broker_open_read_rule(
    struct landlockd_policy_ir *ir, const char *path) {
  struct landlockd_policy_ir_broker_open_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  grown = realloc(ir->broker_open_read_rules,
                  (ir->broker_open_read_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }

  ir->broker_open_read_rules = grown;
  grown[ir->broker_open_read_count].path = path_copy;
  ir->broker_open_read_count++;
  return 0;
}

int landlockd_policy_ir_add_broker_open_write_rule(
    struct landlockd_policy_ir *ir, const char *path) {
  struct landlockd_policy_ir_broker_open_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  grown = realloc(ir->broker_open_write_rules,
                  (ir->broker_open_write_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }

  ir->broker_open_write_rules = grown;
  grown[ir->broker_open_write_count].path = path_copy;
  ir->broker_open_write_count++;
  return 0;
}

int landlockd_policy_ir_add_broker_scratch_rule(
    struct landlockd_policy_ir *ir, const char *path) {
  struct landlockd_policy_ir_broker_open_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  grown = realloc(ir->broker_scratch_rules,
                  (ir->broker_scratch_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }

  ir->broker_scratch_rules = grown;
  grown[ir->broker_scratch_count].path = path_copy;
  ir->broker_scratch_count++;
  return 0;
}

int landlockd_policy_ir_add_broker_export_rule(
    struct landlockd_policy_ir *ir, const char *path) {
  struct landlockd_policy_ir_broker_open_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  grown = realloc(ir->broker_export_rules,
                  (ir->broker_export_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }

  ir->broker_export_rules = grown;
  grown[ir->broker_export_count].path = path_copy;
  ir->broker_export_count++;
  return 0;
}

int landlockd_policy_ir_add_broker_mount_tmpfs_rule(
    struct landlockd_policy_ir *ir, const char *path) {
  struct landlockd_policy_ir_broker_open_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  grown = realloc(ir->broker_mount_tmpfs_rules,
                  (ir->broker_mount_tmpfs_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }

  ir->broker_mount_tmpfs_rules = grown;
  grown[ir->broker_mount_tmpfs_count].path = path_copy;
  ir->broker_mount_tmpfs_count++;
  return 0;
}

int landlockd_policy_ir_add_broker_mount_bind_rule(
    struct landlockd_policy_ir *ir, const char *source, const char *target,
    int read_only) {
  struct landlockd_policy_ir_bind_mount_rule *grown;
  char *source_copy;
  char *target_copy;

  if (ir == NULL || source == NULL || source[0] == '\0' || target == NULL ||
      target[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  source_copy = strdup(source);
  if (source_copy == NULL) {
    return -1;
  }
  target_copy = strdup(target);
  if (target_copy == NULL) {
    free(source_copy);
    return -1;
  }

  grown = realloc(ir->broker_mount_bind_rules,
                  (ir->broker_mount_bind_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(source_copy);
    free(target_copy);
    return -1;
  }

  ir->broker_mount_bind_rules = grown;
  grown[ir->broker_mount_bind_count].source = source_copy;
  grown[ir->broker_mount_bind_count].target = target_copy;
  grown[ir->broker_mount_bind_count].read_only = read_only != 0;
  ir->broker_mount_bind_count++;
  return 0;
}

int landlockd_policy_ir_add_broker_mount_object_rule(
    struct landlockd_policy_ir *ir, const char *name, const char *fs_type,
    const char *const *attach_paths, size_t attach_count,
    uint64_t allowed_attr_set) {
  struct landlockd_policy_ir_mount_object_rule *grown;
  char **attach_copies;
  char *name_copy;
  char *fs_type_copy;
  size_t i;

  if (ir == NULL || name == NULL || name[0] == '\0' || fs_type == NULL ||
      fs_type[0] == '\0' || attach_paths == NULL || attach_count == 0) {
    errno = EINVAL;
    return -1;
  }

  name_copy = strdup(name);
  if (name_copy == NULL) {
    return -1;
  }
  fs_type_copy = strdup(fs_type);
  if (fs_type_copy == NULL) {
    free(name_copy);
    return -1;
  }

  attach_copies = calloc(attach_count, sizeof(*attach_copies));
  if (attach_copies == NULL) {
    free(name_copy);
    free(fs_type_copy);
    return -1;
  }
  for (i = 0; i < attach_count; i++) {
    if (attach_paths[i] == NULL || attach_paths[i][0] == '\0') {
      errno = EINVAL;
      goto fail;
    }
    attach_copies[i] = strdup(attach_paths[i]);
    if (attach_copies[i] == NULL) {
      goto fail;
    }
  }

  grown = realloc(ir->broker_mount_object_rules,
                  (ir->broker_mount_object_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    goto fail;
  }

  ir->broker_mount_object_rules = grown;
  grown[ir->broker_mount_object_count].name = name_copy;
  grown[ir->broker_mount_object_count].fs_type = fs_type_copy;
  grown[ir->broker_mount_object_count].attach_paths = attach_copies;
  grown[ir->broker_mount_object_count].attach_count = attach_count;
  grown[ir->broker_mount_object_count].allowed_attr_set = allowed_attr_set;
  ir->broker_mount_object_count++;
  return 0;

fail:
  for (i = 0; i < attach_count; i++) {
    free(attach_copies[i]);
  }
  free(attach_copies);
  free(name_copy);
  free(fs_type_copy);
  return -1;
}

int landlockd_policy_ir_add_mount_tmpfs_rule(struct landlockd_policy_ir *ir,
                                             const char *path) {
  struct landlockd_policy_ir_mount_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  grown = realloc(ir->mount_tmpfs_rules,
                  (ir->mount_tmpfs_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }

  ir->mount_tmpfs_rules = grown;
  grown[ir->mount_tmpfs_count].path = path_copy;
  ir->mount_tmpfs_count++;
  return 0;
}

int landlockd_policy_ir_add_mount_bind_rule(struct landlockd_policy_ir *ir,
                                            const char *source,
                                            const char *target,
                                            int read_only) {
  struct landlockd_policy_ir_bind_mount_rule *grown;
  char *source_copy;
  char *target_copy;

  if (ir == NULL || source == NULL || source[0] == '\0' || target == NULL ||
      target[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  source_copy = strdup(source);
  if (source_copy == NULL) {
    return -1;
  }
  target_copy = strdup(target);
  if (target_copy == NULL) {
    free(source_copy);
    return -1;
  }

  grown = realloc(ir->mount_bind_rules,
                  (ir->mount_bind_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(source_copy);
    free(target_copy);
    return -1;
  }

  ir->mount_bind_rules = grown;
  grown[ir->mount_bind_count].source = source_copy;
  grown[ir->mount_bind_count].target = target_copy;
  grown[ir->mount_bind_count].read_only = read_only != 0;
  ir->mount_bind_count++;
  return 0;
}

int landlockd_policy_ir_add_mount_proc_rule(struct landlockd_policy_ir *ir,
                                            const char *path) {
  struct landlockd_policy_ir_mount_rule *grown;
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  grown = realloc(ir->mount_proc_rules,
                  (ir->mount_proc_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(path_copy);
    return -1;
  }

  ir->mount_proc_rules = grown;
  grown[ir->mount_proc_count].path = path_copy;
  ir->mount_proc_count++;
  return 0;
}

int landlockd_policy_ir_set_runtime_root(struct landlockd_policy_ir *ir,
                                         const char *path) {
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0' || ir->runtime_root != NULL) {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  ir->runtime_root = path_copy;
  return 0;
}

int landlockd_policy_ir_set_runtime_cwd(struct landlockd_policy_ir *ir,
                                        const char *path) {
  char *path_copy;

  if (ir == NULL || path == NULL || path[0] == '\0' || ir->runtime_cwd != NULL) {
    errno = EINVAL;
    return -1;
  }

  path_copy = strdup(path);
  if (path_copy == NULL) {
    return -1;
  }

  ir->runtime_cwd = path_copy;
  return 0;
}

int landlockd_policy_ir_enable_seccomp(struct landlockd_policy_ir *ir,
                                       unsigned short errno_ret) {
  if (ir == NULL || errno_ret == 0) {
    errno = EINVAL;
    return -1;
  }

  ir->seccomp_enabled = 1;
  ir->seccomp_errno = errno_ret;
  return 0;
}

int landlockd_policy_ir_add_seccomp_deny_rule(struct landlockd_policy_ir *ir,
                                              int syscall_nr) {
  struct landlockd_policy_ir_seccomp_rule *grown;

  if (ir == NULL || !ir->seccomp_enabled || syscall_nr < 0) {
    errno = EINVAL;
    return -1;
  }

  grown = realloc(ir->seccomp_deny_rules,
                  (ir->seccomp_deny_count + 1) * sizeof(*grown));
  if (grown == NULL) {
    return -1;
  }

  ir->seccomp_deny_rules = grown;
  grown[ir->seccomp_deny_count].syscall_nr = syscall_nr;
  ir->seccomp_deny_count++;
  return 0;
}

int landlockd_policy_ir_copy(const struct landlockd_policy_ir *src,
                             struct landlockd_policy_ir *dst) {
  size_t i;
  size_t j;
  int saved_errno;

  if (src == NULL || dst == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (dst->fs_layer_count != 0 || dst->fs_layers != NULL ||
      dst->net_enabled || dst->net_rule_count != 0 ||
      dst->net_rules != NULL || dst->broker_open_read_count != 0 ||
      dst->broker_open_read_rules != NULL ||
      dst->broker_open_write_count != 0 ||
      dst->broker_open_write_rules != NULL ||
      dst->broker_scratch_count != 0 ||
      dst->broker_scratch_rules != NULL || dst->broker_export_count != 0 ||
      dst->broker_export_rules != NULL ||
      dst->broker_mount_tmpfs_count != 0 ||
      dst->broker_mount_tmpfs_rules != NULL ||
      dst->broker_mount_bind_count != 0 ||
      dst->broker_mount_bind_rules != NULL ||
      dst->broker_mount_object_count != 0 ||
      dst->broker_mount_object_rules != NULL ||
      dst->mount_tmpfs_count != 0 ||
      dst->mount_tmpfs_rules != NULL || dst->mount_bind_count != 0 ||
      dst->mount_bind_rules != NULL || dst->mount_proc_count != 0 ||
      dst->mount_proc_rules != NULL || dst->runtime_root != NULL ||
      dst->runtime_cwd != NULL ||
      dst->seccomp_enabled ||
      dst->seccomp_errno != 0 || dst->seccomp_deny_count != 0 ||
      dst->seccomp_deny_rules != NULL) {
    errno = EINVAL;
    return -1;
  }

  if (src->fs_layer_count > 0) {
    dst->fs_layers = calloc(src->fs_layer_count, sizeof(*dst->fs_layers));
    if (dst->fs_layers == NULL) {
      return -1;
    }
    dst->fs_layer_count = src->fs_layer_count;
    for (i = 0; i < src->fs_layer_count; i++) {
      dst->fs_layers[i].handled_access_fs =
          src->fs_layers[i].handled_access_fs;
      if (src->fs_layers[i].rule_count == 0) {
        continue;
      }
      dst->fs_layers[i].rules = calloc(src->fs_layers[i].rule_count,
                                       sizeof(*dst->fs_layers[i].rules));
      if (dst->fs_layers[i].rules == NULL) {
        goto fail;
      }
      dst->fs_layers[i].rule_count = src->fs_layers[i].rule_count;
      for (j = 0; j < src->fs_layers[i].rule_count; j++) {
        dst->fs_layers[i].rules[j].allowed_access =
            src->fs_layers[i].rules[j].allowed_access;
        dst->fs_layers[i].rules[j].path =
            strdup(src->fs_layers[i].rules[j].path);
        if (dst->fs_layers[i].rules[j].path == NULL) {
          goto fail;
        }
      }
    }
  }

  if (src->net_enabled) {
    dst->net_enabled = 1;
    dst->net_handled_access = src->net_handled_access;
    if (src->net_rule_count > 0) {
      dst->net_rules = calloc(src->net_rule_count, sizeof(*dst->net_rules));
      if (dst->net_rules == NULL) {
        goto fail;
      }
      dst->net_rule_count = src->net_rule_count;
      memcpy(dst->net_rules, src->net_rules,
             src->net_rule_count * sizeof(*dst->net_rules));
    }
  }

  if (src->broker_open_read_count > 0) {
    dst->broker_open_read_rules =
        calloc(src->broker_open_read_count,
               sizeof(*dst->broker_open_read_rules));
    if (dst->broker_open_read_rules == NULL) {
      goto fail;
    }
    dst->broker_open_read_count = src->broker_open_read_count;
    for (i = 0; i < src->broker_open_read_count; i++) {
      dst->broker_open_read_rules[i].path =
          strdup(src->broker_open_read_rules[i].path);
      if (dst->broker_open_read_rules[i].path == NULL) {
        goto fail;
      }
    }
  }

  if (src->broker_open_write_count > 0) {
    dst->broker_open_write_rules =
        calloc(src->broker_open_write_count,
               sizeof(*dst->broker_open_write_rules));
    if (dst->broker_open_write_rules == NULL) {
      goto fail;
    }
    dst->broker_open_write_count = src->broker_open_write_count;
    for (i = 0; i < src->broker_open_write_count; i++) {
      dst->broker_open_write_rules[i].path =
          strdup(src->broker_open_write_rules[i].path);
      if (dst->broker_open_write_rules[i].path == NULL) {
        goto fail;
      }
    }
  }

  if (src->broker_scratch_count > 0) {
    dst->broker_scratch_rules =
        calloc(src->broker_scratch_count, sizeof(*dst->broker_scratch_rules));
    if (dst->broker_scratch_rules == NULL) {
      goto fail;
    }
    dst->broker_scratch_count = src->broker_scratch_count;
    for (i = 0; i < src->broker_scratch_count; i++) {
      dst->broker_scratch_rules[i].path =
          strdup(src->broker_scratch_rules[i].path);
      if (dst->broker_scratch_rules[i].path == NULL) {
        goto fail;
      }
    }
  }
  if (src->broker_export_count > 0) {
    dst->broker_export_rules =
        calloc(src->broker_export_count, sizeof(*dst->broker_export_rules));
    if (dst->broker_export_rules == NULL) {
      goto fail;
    }
    dst->broker_export_count = src->broker_export_count;
    for (i = 0; i < src->broker_export_count; i++) {
      dst->broker_export_rules[i].path =
          strdup(src->broker_export_rules[i].path);
      if (dst->broker_export_rules[i].path == NULL) {
        goto fail;
      }
    }
  }
  if (src->broker_mount_tmpfs_count > 0) {
    dst->broker_mount_tmpfs_rules =
        calloc(src->broker_mount_tmpfs_count,
               sizeof(*dst->broker_mount_tmpfs_rules));
    if (dst->broker_mount_tmpfs_rules == NULL) {
      goto fail;
    }
    dst->broker_mount_tmpfs_count = src->broker_mount_tmpfs_count;
    for (i = 0; i < src->broker_mount_tmpfs_count; i++) {
      dst->broker_mount_tmpfs_rules[i].path =
          strdup(src->broker_mount_tmpfs_rules[i].path);
      if (dst->broker_mount_tmpfs_rules[i].path == NULL) {
        goto fail;
      }
    }
  }
  if (src->broker_mount_bind_count > 0) {
    dst->broker_mount_bind_rules =
        calloc(src->broker_mount_bind_count,
               sizeof(*dst->broker_mount_bind_rules));
    if (dst->broker_mount_bind_rules == NULL) {
      goto fail;
    }
    dst->broker_mount_bind_count = src->broker_mount_bind_count;
    for (i = 0; i < src->broker_mount_bind_count; i++) {
      dst->broker_mount_bind_rules[i].source =
          strdup(src->broker_mount_bind_rules[i].source);
      if (dst->broker_mount_bind_rules[i].source == NULL) {
        goto fail;
      }
      dst->broker_mount_bind_rules[i].target =
          strdup(src->broker_mount_bind_rules[i].target);
      if (dst->broker_mount_bind_rules[i].target == NULL) {
        goto fail;
      }
      dst->broker_mount_bind_rules[i].read_only =
          src->broker_mount_bind_rules[i].read_only;
    }
  }
  if (src->broker_mount_object_count > 0) {
    dst->broker_mount_object_rules =
        calloc(src->broker_mount_object_count,
               sizeof(*dst->broker_mount_object_rules));
    if (dst->broker_mount_object_rules == NULL) {
      goto fail;
    }
    dst->broker_mount_object_count = src->broker_mount_object_count;
    for (i = 0; i < src->broker_mount_object_count; i++) {
      dst->broker_mount_object_rules[i].name =
          strdup(src->broker_mount_object_rules[i].name);
      if (dst->broker_mount_object_rules[i].name == NULL) {
        goto fail;
      }
      dst->broker_mount_object_rules[i].fs_type =
          strdup(src->broker_mount_object_rules[i].fs_type);
      if (dst->broker_mount_object_rules[i].fs_type == NULL) {
        goto fail;
      }
      dst->broker_mount_object_rules[i].attach_paths =
          calloc(src->broker_mount_object_rules[i].attach_count,
                 sizeof(*dst->broker_mount_object_rules[i].attach_paths));
      if (dst->broker_mount_object_rules[i].attach_paths == NULL) {
        goto fail;
      }
      dst->broker_mount_object_rules[i].attach_count =
          src->broker_mount_object_rules[i].attach_count;
      dst->broker_mount_object_rules[i].allowed_attr_set =
          src->broker_mount_object_rules[i].allowed_attr_set;
      for (j = 0; j < src->broker_mount_object_rules[i].attach_count; j++) {
        dst->broker_mount_object_rules[i].attach_paths[j] =
            strdup(src->broker_mount_object_rules[i].attach_paths[j]);
        if (dst->broker_mount_object_rules[i].attach_paths[j] == NULL) {
          goto fail;
        }
      }
    }
  }

  if (src->mount_tmpfs_count > 0) {
    dst->mount_tmpfs_rules =
        calloc(src->mount_tmpfs_count, sizeof(*dst->mount_tmpfs_rules));
    if (dst->mount_tmpfs_rules == NULL) {
      goto fail;
    }
    dst->mount_tmpfs_count = src->mount_tmpfs_count;
    for (i = 0; i < src->mount_tmpfs_count; i++) {
      dst->mount_tmpfs_rules[i].path = strdup(src->mount_tmpfs_rules[i].path);
      if (dst->mount_tmpfs_rules[i].path == NULL) {
        goto fail;
      }
    }
  }

  if (src->mount_bind_count > 0) {
    dst->mount_bind_rules =
        calloc(src->mount_bind_count, sizeof(*dst->mount_bind_rules));
    if (dst->mount_bind_rules == NULL) {
      goto fail;
    }
    dst->mount_bind_count = src->mount_bind_count;
    for (i = 0; i < src->mount_bind_count; i++) {
      dst->mount_bind_rules[i].source = strdup(src->mount_bind_rules[i].source);
      if (dst->mount_bind_rules[i].source == NULL) {
        goto fail;
      }
      dst->mount_bind_rules[i].target = strdup(src->mount_bind_rules[i].target);
      if (dst->mount_bind_rules[i].target == NULL) {
        goto fail;
      }
      dst->mount_bind_rules[i].read_only = src->mount_bind_rules[i].read_only;
    }
  }

  if (src->mount_proc_count > 0) {
    dst->mount_proc_rules =
        calloc(src->mount_proc_count, sizeof(*dst->mount_proc_rules));
    if (dst->mount_proc_rules == NULL) {
      goto fail;
    }
    dst->mount_proc_count = src->mount_proc_count;
    for (i = 0; i < src->mount_proc_count; i++) {
      dst->mount_proc_rules[i].path = strdup(src->mount_proc_rules[i].path);
      if (dst->mount_proc_rules[i].path == NULL) {
        goto fail;
      }
    }
  }

  if (src->runtime_root != NULL) {
    dst->runtime_root = strdup(src->runtime_root);
    if (dst->runtime_root == NULL) {
      goto fail;
    }
  }
  if (src->runtime_cwd != NULL) {
    dst->runtime_cwd = strdup(src->runtime_cwd);
    if (dst->runtime_cwd == NULL) {
      goto fail;
    }
  }

  if (src->seccomp_enabled) {
    if (landlockd_policy_ir_enable_seccomp(dst, src->seccomp_errno) < 0) {
      goto fail;
    }
    if (src->seccomp_deny_count > 0) {
      dst->seccomp_deny_rules =
          calloc(src->seccomp_deny_count, sizeof(*dst->seccomp_deny_rules));
      if (dst->seccomp_deny_rules == NULL) {
        goto fail;
      }
      dst->seccomp_deny_count = src->seccomp_deny_count;
      for (i = 0; i < src->seccomp_deny_count; i++) {
        dst->seccomp_deny_rules[i].syscall_nr =
            src->seccomp_deny_rules[i].syscall_nr;
      }
    }
  }
  return 0;

fail:
  saved_errno = errno;
  landlockd_policy_ir_reset(dst);
  errno = saved_errno;
  return -1;
}
