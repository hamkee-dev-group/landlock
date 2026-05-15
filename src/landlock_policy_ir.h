#ifndef LANDLOCKD_POLICY_IR_H
#define LANDLOCKD_POLICY_IR_H

#include <stddef.h>
#include <stdint.h>

struct landlockd_policy_ir_fs_rule {
  char *path;
  uint64_t allowed_access;
};

struct landlockd_policy_ir_fs_layer {
  uint64_t handled_access_fs;
  size_t rule_count;
  struct landlockd_policy_ir_fs_rule *rules;
};

struct landlockd_policy_ir_net_rule {
  uint16_t port;
  uint64_t allowed_access;
};

struct landlockd_policy_ir_broker_open_rule {
  char *path;
};

struct landlockd_policy_ir_broker_addfd_rule {
  char *action;
  char *target;
  char *mode;
};

struct landlockd_policy_ir_mount_rule {
  char *path;
};

struct landlockd_policy_ir_bind_mount_rule {
  char *source;
  char *target;
  int read_only;
};

struct landlockd_policy_ir_mount_object_rule {
  char *name;
  char *fs_type;
  char **attach_paths;
  size_t attach_count;
  uint64_t allowed_attr_set;
};

struct landlockd_policy_ir_seccomp_rule {
  int syscall_nr;
};

struct landlockd_policy_ir {
  size_t fs_layer_count;
  struct landlockd_policy_ir_fs_layer *fs_layers;
  int net_enabled;
  uint64_t net_handled_access;
  size_t net_rule_count;
  struct landlockd_policy_ir_net_rule *net_rules;
  size_t broker_open_read_count;
  struct landlockd_policy_ir_broker_open_rule *broker_open_read_rules;
  size_t broker_open_write_count;
  struct landlockd_policy_ir_broker_open_rule *broker_open_write_rules;
  size_t broker_scratch_count;
  struct landlockd_policy_ir_broker_open_rule *broker_scratch_rules;
  size_t broker_export_count;
  struct landlockd_policy_ir_broker_open_rule *broker_export_rules;
  size_t broker_mount_tmpfs_count;
  struct landlockd_policy_ir_broker_open_rule *broker_mount_tmpfs_rules;
  size_t broker_mount_bind_count;
  struct landlockd_policy_ir_bind_mount_rule *broker_mount_bind_rules;
  size_t broker_mount_object_count;
  struct landlockd_policy_ir_mount_object_rule *broker_mount_object_rules;
  size_t broker_addfd_count;
  struct landlockd_policy_ir_broker_addfd_rule *broker_addfd_rules;
  size_t mount_tmpfs_count;
  struct landlockd_policy_ir_mount_rule *mount_tmpfs_rules;
  size_t mount_bind_count;
  struct landlockd_policy_ir_bind_mount_rule *mount_bind_rules;
  size_t mount_proc_count;
  struct landlockd_policy_ir_mount_rule *mount_proc_rules;
  char *runtime_root;
  char *runtime_cwd;
  int seccomp_enabled;
  unsigned short seccomp_errno;
  size_t seccomp_deny_count;
  struct landlockd_policy_ir_seccomp_rule *seccomp_deny_rules;
};

void landlockd_policy_ir_init(struct landlockd_policy_ir *ir);
void landlockd_policy_ir_reset(struct landlockd_policy_ir *ir);
int landlockd_policy_ir_copy(const struct landlockd_policy_ir *src,
                             struct landlockd_policy_ir *dst);
int landlockd_policy_ir_add_fs_layer(struct landlockd_policy_ir *ir,
                                     uint64_t handled_access_fs,
                                     size_t *out_layer_index);
int landlockd_policy_ir_add_fs_rule(struct landlockd_policy_ir *ir,
                                    size_t layer_index, const char *path,
                                    uint64_t allowed_access);
int landlockd_policy_ir_enable_net(struct landlockd_policy_ir *ir,
                                   uint64_t handled_access_net);
int landlockd_policy_ir_add_net_rule(struct landlockd_policy_ir *ir,
                                     uint16_t port, uint64_t allowed_access);
int landlockd_policy_ir_add_broker_open_read_rule(
    struct landlockd_policy_ir *ir, const char *path);
int landlockd_policy_ir_add_broker_open_write_rule(
    struct landlockd_policy_ir *ir, const char *path);
int landlockd_policy_ir_add_broker_scratch_rule(
    struct landlockd_policy_ir *ir, const char *path);
int landlockd_policy_ir_add_broker_export_rule(
    struct landlockd_policy_ir *ir, const char *path);
int landlockd_policy_ir_add_broker_mount_tmpfs_rule(
    struct landlockd_policy_ir *ir, const char *path);
int landlockd_policy_ir_add_broker_mount_bind_rule(
    struct landlockd_policy_ir *ir, const char *source, const char *target,
    int read_only);
int landlockd_policy_ir_add_broker_mount_object_rule(
    struct landlockd_policy_ir *ir, const char *name, const char *fs_type,
    const char *const *attach_paths, size_t attach_count,
    uint64_t allowed_attr_set);
int landlockd_policy_ir_add_broker_addfd_rule(
    struct landlockd_policy_ir *ir, const char *action, const char *target,
    const char *mode);
int landlockd_policy_ir_add_mount_tmpfs_rule(struct landlockd_policy_ir *ir,
                                             const char *path);
int landlockd_policy_ir_add_mount_bind_rule(struct landlockd_policy_ir *ir,
                                            const char *source,
                                            const char *target,
                                            int read_only);
int landlockd_policy_ir_add_mount_proc_rule(struct landlockd_policy_ir *ir,
                                            const char *path);
int landlockd_policy_ir_set_runtime_root(struct landlockd_policy_ir *ir,
                                         const char *path);
int landlockd_policy_ir_set_runtime_cwd(struct landlockd_policy_ir *ir,
                                        const char *path);
int landlockd_policy_ir_enable_seccomp(struct landlockd_policy_ir *ir,
                                       unsigned short errno_ret);
int landlockd_policy_ir_add_seccomp_deny_rule(struct landlockd_policy_ir *ir,
                                              int syscall_nr);

#endif
