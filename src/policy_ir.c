#include "landlockd/policy_ir.h"

#include <errno.h>
#include <stddef.h>

static int validate_fs_layer(const struct landlockd_ir_layer *layer) {
  size_t i;

  if (layer->net_rules != NULL || layer->exception_rules != NULL) {
    return -1;
  }
  if (layer->handled_access == 0) {
    return -1;
  }
  if (layer->rule_count > 0 && layer->fs_rules == NULL) {
    return -1;
  }
  for (i = 0; i < layer->rule_count; i++) {
    if (layer->fs_rules[i].path == NULL ||
        layer->fs_rules[i].allowed_access == 0) {
      return -1;
    }
  }
  return 0;
}

static int validate_net_layer(const struct landlockd_ir_layer *layer) {
  size_t i;

  if (layer->fs_rules != NULL || layer->exception_rules != NULL) {
    return -1;
  }
  if (layer->handled_access == 0) {
    return -1;
  }
  if (layer->rule_count > 0 && layer->net_rules == NULL) {
    return -1;
  }
  for (i = 0; i < layer->rule_count; i++) {
    if (layer->net_rules[i].allowed_access == 0) {
      return -1;
    }
  }
  return 0;
}

static int validate_exception_layer(const struct landlockd_ir_layer *layer) {
  size_t i;

  if (layer->fs_rules != NULL || layer->net_rules != NULL) {
    return -1;
  }
  if (layer->handled_access != 0) {
    return -1;
  }
  if (layer->rule_count == 0 || layer->exception_rules == NULL) {
    return -1;
  }
  for (i = 0; i < layer->rule_count; i++) {
    if (layer->exception_rules[i].syscall_nr < 0) {
      return -1;
    }
  }
  return 0;
}

int landlockd_ir_policy_validate(const struct landlockd_ir_policy *policy) {
  const struct landlockd_ir_layer *layer;
  size_t i;
  int rc;

  if (policy == NULL || policy->name == NULL || policy->name[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  if (policy->layer_count == 0 || policy->layers == NULL) {
    errno = EINVAL;
    return -1;
  }
  for (i = 0; i < policy->layer_count; i++) {
    layer = policy->layers[i];
    if (layer == NULL || layer->order != i) {
      errno = EINVAL;
      return -1;
    }
    switch (layer->kind) {
    case LANDLOCKD_IR_LAYER_FS:
      rc = validate_fs_layer(layer);
      break;
    case LANDLOCKD_IR_LAYER_NET:
      rc = validate_net_layer(layer);
      break;
    case LANDLOCKD_IR_LAYER_EXCEPTION:
      rc = validate_exception_layer(layer);
      break;
    default:
      rc = -1;
      break;
    }
    if (rc != 0) {
      errno = EINVAL;
      return -1;
    }
  }
  return 0;
}
