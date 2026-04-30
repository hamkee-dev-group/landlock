#ifndef LANDLOCKD_POLICY_IR_H
#define LANDLOCKD_POLICY_IR_H

#include <stddef.h>
#include <stdint.h>

enum landlockd_ir_layer_kind {
  LANDLOCKD_IR_LAYER_FS = 1,
  LANDLOCKD_IR_LAYER_NET,
  LANDLOCKD_IR_LAYER_EXCEPTION,
};

struct landlockd_ir_fs_rule {
  const char *path;
  uint64_t allowed_access;
};

struct landlockd_ir_net_rule {
  uint16_t port;
  uint64_t allowed_access;
};

struct landlockd_ir_exception_rule {
  int syscall_nr;
};

struct landlockd_ir_layer {
  enum landlockd_ir_layer_kind kind;
  size_t order;
  uint64_t handled_access;
  size_t rule_count;
  const struct landlockd_ir_fs_rule *fs_rules;
  const struct landlockd_ir_net_rule *net_rules;
  const struct landlockd_ir_exception_rule *exception_rules;
};

struct landlockd_ir_policy {
  const char *name;
  size_t layer_count;
  const struct landlockd_ir_layer *const *layers;
};

int landlockd_ir_policy_validate(const struct landlockd_ir_policy *policy);

#endif
