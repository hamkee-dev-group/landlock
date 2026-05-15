#define _GNU_SOURCE

#include "landlock_policy_loader.h"

#include "landlockd/landlock_compat.h"
#include "landlockd/seccomp.h"
#include "toml.h"

#include <errno.h>
#include <linux/mount.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fs_access_name {
  const char *name;
  uint64_t bit;
};

static const struct fs_access_name FS_ACCESS_NAMES[] = {
    {"execute", LANDLOCK_ACCESS_FS_EXECUTE},
    {"write_file", LANDLOCK_ACCESS_FS_WRITE_FILE},
    {"read_file", LANDLOCK_ACCESS_FS_READ_FILE},
    {"read_dir", LANDLOCK_ACCESS_FS_READ_DIR},
    {"remove_dir", LANDLOCK_ACCESS_FS_REMOVE_DIR},
    {"remove_file", LANDLOCK_ACCESS_FS_REMOVE_FILE},
    {"make_char", LANDLOCK_ACCESS_FS_MAKE_CHAR},
    {"make_dir", LANDLOCK_ACCESS_FS_MAKE_DIR},
    {"make_reg", LANDLOCK_ACCESS_FS_MAKE_REG},
    {"make_sock", LANDLOCK_ACCESS_FS_MAKE_SOCK},
    {"make_fifo", LANDLOCK_ACCESS_FS_MAKE_FIFO},
    {"make_block", LANDLOCK_ACCESS_FS_MAKE_BLOCK},
    {"make_sym", LANDLOCK_ACCESS_FS_MAKE_SYM},
    {"refer", LANDLOCK_ACCESS_FS_REFER},
    {"truncate", LANDLOCK_ACCESS_FS_TRUNCATE},
    {"ioctl_dev", LANDLOCK_ACCESS_FS_IOCTL_DEV},
};

static const struct fs_access_name NET_ACCESS_NAMES[] = {
    {"bind_tcp", LANDLOCK_ACCESS_NET_BIND_TCP},
    {"connect_tcp", LANDLOCK_ACCESS_NET_CONNECT_TCP},
};

static const struct fs_access_name MOUNT_ATTR_NAMES[] = {
#ifdef MOUNT_ATTR_RDONLY
    {"readonly", MOUNT_ATTR_RDONLY},
#endif
#ifdef MOUNT_ATTR_NOSUID
    {"nosuid", MOUNT_ATTR_NOSUID},
#endif
#ifdef MOUNT_ATTR_NODEV
    {"nodev", MOUNT_ATTR_NODEV},
#endif
#ifdef MOUNT_ATTR_NOEXEC
    {"noexec", MOUNT_ATTR_NOEXEC},
#endif
};

static void report(FILE *err, const char *file_path, const char *fmt, ...) {
  va_list ap;
  if (err == NULL) {
    return;
  }
  fprintf(err, "landlockd: policy %s: ", file_path);
  va_start(ap, fmt);
  vfprintf(err, fmt, ap);
  va_end(ap);
  fputc('\n', err);
}

static int resolve_access(const struct fs_access_name *table, size_t n,
                          const char *name, uint64_t *out) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (strcmp(table[i].name, name) == 0) {
      *out = table[i].bit;
      return 0;
    }
  }
  return -1;
}

static int table_has_only_keys(const toml_table_t *tab,
                               const char *const allowed[], size_t n,
                               const char **offending) {
  const char *k;
  size_t i;
  int idx;
  int found;
  for (idx = 0;; idx++) {
    k = toml_key_in(tab, idx);
    if (k == NULL) {
      return 0;
    }
    found = 0;
    for (i = 0; i < n; i++) {
      if (strcmp(k, allowed[i]) == 0) {
        found = 1;
        break;
      }
    }
    if (!found) {
      *offending = k;
      return -1;
    }
  }
}

static int load_access_array(const toml_array_t *arr,
                             const struct fs_access_name *table, size_t table_n,
                             const char *field, const char *file_path,
                             FILE *err, uint64_t *out_mask) {
  toml_datum_t s;
  uint64_t mask;
  uint64_t bit;
  int n;
  int i;

  if (arr == NULL) {
    report(err, file_path, "%s: required array is missing", field);
    return -1;
  }
  n = toml_array_nelem(arr);
  if (n <= 0) {
    report(err, file_path, "%s: must contain at least one entry", field);
    return -1;
  }
  mask = 0;
  for (i = 0; i < n; i++) {
    s = toml_string_at(arr, i);
    if (!s.ok) {
      report(err, file_path, "%s[%d]: expected a string", field, i);
      return -1;
    }
    if (resolve_access(table, table_n, s.u.s, &bit) < 0) {
      report(err, file_path, "%s[%d]: unknown access \"%s\"", field, i, s.u.s);
      free(s.u.s);
      return -1;
    }
    free(s.u.s);
    mask |= bit;
  }
  *out_mask = mask;
  return 0;
}

static int load_fs_rule(const toml_table_t *rule_tbl, size_t layer_idx,
                        int rule_idx, struct landlockd_policy_ir *ir,
                        const char *file_path, FILE *err) {
  static const char *const allowed[] = {"path", "allowed_access"};
  char field[128];
  const char *offending;
  toml_datum_t path_d;
  toml_array_t *access_arr;
  uint64_t access_mask;

  snprintf(field, sizeof(field), "fs_layer[%zu].rule[%d]", layer_idx, rule_idx);
  if (table_has_only_keys(rule_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "%s: unknown key \"%s\"", field, offending);
    return -1;
  }

  path_d = toml_string_in(rule_tbl, "path");
  if (!path_d.ok || path_d.u.s[0] == '\0') {
    if (path_d.ok) {
      free(path_d.u.s);
    }
    report(err, file_path, "%s.path: required non-empty string is missing",
           field);
    return -1;
  }

  access_arr = toml_array_in(rule_tbl, "allowed_access");
  snprintf(field, sizeof(field), "fs_layer[%zu].rule[%d].allowed_access",
           layer_idx, rule_idx);
  if (load_access_array(access_arr, FS_ACCESS_NAMES,
                        sizeof(FS_ACCESS_NAMES) / sizeof(FS_ACCESS_NAMES[0]),
                        field, file_path, err, &access_mask) < 0) {
    free(path_d.u.s);
    return -1;
  }

  if (landlockd_policy_ir_add_fs_rule(ir, layer_idx, path_d.u.s,
                                      access_mask) < 0) {
    free(path_d.u.s);
    report(err, file_path, "fs_layer[%zu].rule[%d]: internal error: %s",
           layer_idx, rule_idx, strerror(errno));
    return -1;
  }
  free(path_d.u.s);
  return 0;
}

static int load_fs_layer(const toml_table_t *layer_tbl, size_t layer_idx,
                         struct landlockd_policy_ir *ir,
                         const char *file_path, FILE *err) {
  static const char *const allowed[] = {"handled_access_fs", "rule"};
  char field[128];
  const char *offending;
  toml_array_t *handled_arr;
  toml_array_t *rule_arr;
  uint64_t handled_mask;
  size_t emitted_idx;
  int rule_count;
  int i;

  snprintf(field, sizeof(field), "fs_layer[%zu]", layer_idx);
  if (table_has_only_keys(layer_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "%s: unknown key \"%s\"", field, offending);
    return -1;
  }

  handled_arr = toml_array_in(layer_tbl, "handled_access_fs");
  snprintf(field, sizeof(field), "fs_layer[%zu].handled_access_fs", layer_idx);
  if (load_access_array(handled_arr, FS_ACCESS_NAMES,
                        sizeof(FS_ACCESS_NAMES) / sizeof(FS_ACCESS_NAMES[0]),
                        field, file_path, err, &handled_mask) < 0) {
    return -1;
  }

  if (landlockd_policy_ir_add_fs_layer(ir, handled_mask, &emitted_idx) < 0) {
    report(err, file_path, "fs_layer[%zu]: internal error: %s", layer_idx,
           strerror(errno));
    return -1;
  }

  rule_arr = toml_array_in(layer_tbl, "rule");
  if (rule_arr == NULL) {
    return 0;
  }
  rule_count = toml_array_nelem(rule_arr);
  for (i = 0; i < rule_count; i++) {
    toml_table_t *rule_tbl = toml_table_at(rule_arr, i);
    if (rule_tbl == NULL) {
      report(err, file_path, "fs_layer[%zu].rule[%d]: expected an inline table",
             layer_idx, i);
      return -1;
    }
    if (load_fs_rule(rule_tbl, emitted_idx, i, ir, file_path, err) < 0) {
      return -1;
    }
  }
  return 0;
}

static int load_net_rule(const toml_table_t *rule_tbl, int rule_idx,
                         struct landlockd_policy_ir *ir, const char *file_path,
                         FILE *err) {
  static const char *const allowed[] = {"port", "allowed_access"};
  char field[128];
  const char *offending;
  toml_datum_t port_d;
  toml_array_t *access_arr;
  uint64_t access_mask;

  snprintf(field, sizeof(field), "net.rule[%d]", rule_idx);
  if (table_has_only_keys(rule_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "%s: unknown key \"%s\"", field, offending);
    return -1;
  }

  port_d = toml_int_in(rule_tbl, "port");
  if (!port_d.ok) {
    report(err, file_path, "%s.port: required integer is missing", field);
    return -1;
  }
  if (port_d.u.i < 0 || port_d.u.i > 65535) {
    report(err, file_path,
           "%s.port: value %lld out of range [0..65535]", field,
           (long long)port_d.u.i);
    return -1;
  }

  access_arr = toml_array_in(rule_tbl, "allowed_access");
  snprintf(field, sizeof(field), "net.rule[%d].allowed_access", rule_idx);
  if (load_access_array(access_arr, NET_ACCESS_NAMES,
                        sizeof(NET_ACCESS_NAMES) / sizeof(NET_ACCESS_NAMES[0]),
                        field, file_path, err, &access_mask) < 0) {
    return -1;
  }

  if (landlockd_policy_ir_add_net_rule(ir, (uint16_t)port_d.u.i,
                                       access_mask) < 0) {
    report(err, file_path, "net.rule[%d]: internal error: %s", rule_idx,
           strerror(errno));
    return -1;
  }
  return 0;
}

static int load_net(const toml_table_t *net_tbl,
                    struct landlockd_policy_ir *ir, const char *file_path,
                    FILE *err) {
  static const char *const allowed[] = {"handled_access_net", "rule"};
  const char *offending;
  toml_array_t *handled_arr;
  toml_array_t *rule_arr;
  uint64_t handled_mask;
  int rule_count;
  int i;

  if (table_has_only_keys(net_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "net: unknown key \"%s\"", offending);
    return -1;
  }

  handled_arr = toml_array_in(net_tbl, "handled_access_net");
  if (load_access_array(handled_arr, NET_ACCESS_NAMES,
                        sizeof(NET_ACCESS_NAMES) / sizeof(NET_ACCESS_NAMES[0]),
                        "net.handled_access_net", file_path, err,
                        &handled_mask) < 0) {
    return -1;
  }

  if (landlockd_policy_ir_enable_net(ir, handled_mask) < 0) {
    report(err, file_path, "net: internal error: %s", strerror(errno));
    return -1;
  }

  rule_arr = toml_array_in(net_tbl, "rule");
  if (rule_arr == NULL) {
    return 0;
  }
  rule_count = toml_array_nelem(rule_arr);
  for (i = 0; i < rule_count; i++) {
    toml_table_t *rule_tbl = toml_table_at(rule_arr, i);
    if (rule_tbl == NULL) {
      report(err, file_path, "net.rule[%d]: expected an inline table", i);
      return -1;
    }
    if (load_net_rule(rule_tbl, i, ir, file_path, err) < 0) {
      return -1;
    }
  }
  return 0;
}

static int load_broker_addfd_array(toml_array_t *addfd_arr,
                                   struct landlockd_policy_ir *ir,
                                   const char *file_path, FILE *err) {
  static const char *const allowed[] = {"action", "target", "mode"};
  const char *offending;
  toml_table_t *entry;
  toml_datum_t action_d;
  toml_datum_t target_d;
  toml_datum_t mode_d;
  int n;
  int i;

  if (addfd_arr == NULL) {
    return 0;
  }

  n = toml_array_nelem(addfd_arr);
  if (n <= 0) {
    report(err, file_path, "broker.addfd: must contain at least one entry");
    return -1;
  }

  for (i = 0; i < n; i++) {
    entry = toml_table_at(addfd_arr, i);
    if (entry == NULL) {
      report(err, file_path,
             "broker.addfd[%d]: expected a table with action/target/mode keys",
             i);
      return -1;
    }
    if (table_has_only_keys(entry, allowed,
                            sizeof(allowed) / sizeof(allowed[0]),
                            &offending) < 0) {
      report(err, file_path, "broker.addfd[%d]: unknown key \"%s\"", i,
             offending);
      return -1;
    }

    action_d = toml_string_in(entry, "action");
    if (!action_d.ok || action_d.u.s[0] == '\0') {
      if (action_d.ok) {
        free(action_d.u.s);
      }
      report(err, file_path,
             "broker.addfd[%d].action: expected a non-empty string", i);
      return -1;
    }

    target_d = toml_string_in(entry, "target");
    if (!target_d.ok || target_d.u.s[0] == '\0') {
      free(action_d.u.s);
      if (target_d.ok) {
        free(target_d.u.s);
      }
      report(err, file_path,
             "broker.addfd[%d].target: expected a non-empty string", i);
      return -1;
    }
    if (target_d.u.s[0] != '/') {
      free(action_d.u.s);
      report(err, file_path,
             "broker.addfd[%d].target: expected an absolute path", i);
      free(target_d.u.s);
      return -1;
    }

    mode_d = toml_string_in(entry, "mode");
    if (toml_key_exists(entry, "mode") && (!mode_d.ok || mode_d.u.s[0] == '\0')) {
      free(action_d.u.s);
      free(target_d.u.s);
      if (mode_d.ok) {
        free(mode_d.u.s);
      }
      report(err, file_path,
             "broker.addfd[%d].mode: expected a non-empty string", i);
      return -1;
    }

    if (landlockd_policy_ir_add_broker_addfd_rule(
            ir, action_d.u.s, target_d.u.s, mode_d.ok ? mode_d.u.s : NULL) <
        0) {
      report(err, file_path, "broker.addfd[%d]: internal error: %s", i,
             strerror(errno));
      free(action_d.u.s);
      free(target_d.u.s);
      if (mode_d.ok) {
        free(mode_d.u.s);
      }
      return -1;
    }
    free(action_d.u.s);
    free(target_d.u.s);
    if (mode_d.ok) {
      free(mode_d.u.s);
    }
  }
  return 0;
}

static int load_broker_path_array(
    toml_array_t *paths_arr, struct landlockd_policy_ir *ir,
    const char *field_name, const char *file_path, FILE *err,
    int absolute,
    int (*append_rule)(struct landlockd_policy_ir *ir, const char *path)) {
  toml_datum_t path_d;
  int n;
  int i;

  if (paths_arr == NULL) {
    return 0;
  }

  n = toml_array_nelem(paths_arr);
  for (i = 0; i < n; i++) {
    path_d = toml_string_at(paths_arr, i);
    if (!path_d.ok || path_d.u.s[0] == '\0') {
      if (path_d.ok) {
        free(path_d.u.s);
      }
      report(err, file_path, "broker.%s[%d]: expected a non-empty string",
             field_name, i);
      return -1;
    }
    if (absolute && path_d.u.s[0] != '/') {
      report(err, file_path, "broker.%s[%d]: expected an absolute path",
             field_name, i);
      free(path_d.u.s);
      return -1;
    }
    if (append_rule(ir, path_d.u.s) < 0) {
      report(err, file_path, "broker.%s[%d]: internal error: %s", field_name, i,
             strerror(errno));
      free(path_d.u.s);
      return -1;
    }
    free(path_d.u.s);
  }
  return 0;
}

static int load_bind_rule_array(
    toml_array_t *bind_arr, struct landlockd_policy_ir *ir,
    const char *field_name, const char *file_path, FILE *err,
    int (*append_rule)(struct landlockd_policy_ir *ir, const char *source,
                       const char *target, int read_only)) {
  static const char *const bind_allowed[] = {"source", "target", "read_only"};
  const char *offending;
  toml_table_t *bind_tbl;
  toml_datum_t source_d;
  toml_datum_t target_d;
  toml_datum_t ro_d;
  int n;
  int i;

  if (bind_arr == NULL) {
    return 0;
  }

  n = toml_array_nelem(bind_arr);
  if (n <= 0) {
    report(err, file_path, "%s: must contain at least one entry", field_name);
    return -1;
  }
  for (i = 0; i < n; i++) {
    bind_tbl = toml_table_at(bind_arr, i);
    if (bind_tbl == NULL) {
      report(err, file_path, "%s[%d]: expected a table", field_name, i);
      return -1;
    }
    if (table_has_only_keys(bind_tbl, bind_allowed,
                            sizeof(bind_allowed) / sizeof(bind_allowed[0]),
                            &offending) < 0) {
      report(err, file_path, "%s[%d]: unknown key \"%s\"", field_name, i,
             offending);
      return -1;
    }

    source_d = toml_string_in(bind_tbl, "source");
    if (!source_d.ok || source_d.u.s[0] == '\0') {
      if (source_d.ok) {
        free(source_d.u.s);
      }
      report(err, file_path, "%s[%d].source: expected a non-empty string",
             field_name, i);
      return -1;
    }
    if (source_d.u.s[0] != '/') {
      report(err, file_path, "%s[%d].source: expected an absolute path",
             field_name, i);
      free(source_d.u.s);
      return -1;
    }

    target_d = toml_string_in(bind_tbl, "target");
    if (!target_d.ok || target_d.u.s[0] == '\0') {
      free(source_d.u.s);
      if (target_d.ok) {
        free(target_d.u.s);
      }
      report(err, file_path, "%s[%d].target: expected a non-empty string",
             field_name, i);
      return -1;
    }
    if (target_d.u.s[0] != '/') {
      free(source_d.u.s);
      report(err, file_path, "%s[%d].target: expected an absolute path",
             field_name, i);
      free(target_d.u.s);
      return -1;
    }

    ro_d = toml_bool_in(bind_tbl, "read_only");
    if (toml_key_exists(bind_tbl, "read_only") && !ro_d.ok) {
      free(source_d.u.s);
      free(target_d.u.s);
      report(err, file_path, "%s[%d].read_only: expected a boolean",
             field_name, i);
      return -1;
    }

    if (append_rule(ir, source_d.u.s, target_d.u.s, ro_d.ok ? ro_d.u.b : 1) <
        0) {
      report(err, file_path, "%s[%d]: internal error: %s", field_name, i,
             strerror(errno));
      free(source_d.u.s);
      free(target_d.u.s);
      return -1;
    }
    free(source_d.u.s);
    free(target_d.u.s);
  }

  return 0;
}

static int load_mount_object_rule_array(
    toml_array_t *obj_arr, struct landlockd_policy_ir *ir,
    const char *field_name, const char *file_path, FILE *err) {
  static const char *const allowed[] = {"name", "fs_type", "attach", "attrs"};
  const char *offending;
  toml_table_t *obj_tbl;
  toml_array_t *attach_arr;
  toml_array_t *attrs_arr;
  toml_datum_t name_d;
  toml_datum_t fs_type_d;
  toml_datum_t attach_d;
  char **attach_paths;
  uint64_t allowed_attr_set;
  int n;
  int attach_n;
  int i;
  int j;

  if (obj_arr == NULL) {
    return 0;
  }

  n = toml_array_nelem(obj_arr);
  if (n <= 0) {
    report(err, file_path, "%s: must contain at least one entry", field_name);
    return -1;
  }

  for (i = 0; i < n; i++) {
    obj_tbl = toml_table_at(obj_arr, i);
    if (obj_tbl == NULL) {
      report(err, file_path, "%s[%d]: expected a table", field_name, i);
      return -1;
    }
    if (table_has_only_keys(obj_tbl, allowed,
                            sizeof(allowed) / sizeof(allowed[0]),
                            &offending) < 0) {
      report(err, file_path, "%s[%d]: unknown key \"%s\"", field_name, i,
             offending);
      return -1;
    }

    name_d = toml_string_in(obj_tbl, "name");
    if (!name_d.ok || name_d.u.s[0] == '\0') {
      if (name_d.ok) {
        free(name_d.u.s);
      }
      report(err, file_path, "%s[%d].name: expected a non-empty string",
             field_name, i);
      return -1;
    }
    if (strchr(name_d.u.s, '/') != NULL) {
      free(name_d.u.s);
      report(err, file_path, "%s[%d].name: must not contain '/'", field_name,
             i);
      return -1;
    }

    fs_type_d = toml_string_in(obj_tbl, "fs_type");
    if (!fs_type_d.ok || fs_type_d.u.s[0] == '\0') {
      free(name_d.u.s);
      if (fs_type_d.ok) {
        free(fs_type_d.u.s);
      }
      report(err, file_path, "%s[%d].fs_type: expected a non-empty string",
             field_name, i);
      return -1;
    }
    if (strcmp(fs_type_d.u.s, "tmpfs") != 0 &&
        strcmp(fs_type_d.u.s, "proc") != 0) {
      free(name_d.u.s);
      free(fs_type_d.u.s);
      report(err, file_path,
             "%s[%d].fs_type: expected one of tmpfs or proc", field_name, i);
      return -1;
    }

    attach_arr = toml_array_in(obj_tbl, "attach");
    if (attach_arr == NULL) {
      free(name_d.u.s);
      free(fs_type_d.u.s);
      report(err, file_path, "%s[%d].attach: required array is missing",
             field_name, i);
      return -1;
    }
    attach_n = toml_array_nelem(attach_arr);
    if (attach_n <= 0) {
      free(name_d.u.s);
      free(fs_type_d.u.s);
      report(err, file_path, "%s[%d].attach: must contain at least one entry",
             field_name, i);
      return -1;
    }
    attach_paths = calloc((size_t)attach_n, sizeof(*attach_paths));
    if (attach_paths == NULL) {
      free(name_d.u.s);
      free(fs_type_d.u.s);
      return -1;
    }
    for (j = 0; j < attach_n; j++) {
      attach_d = toml_string_at(attach_arr, j);
      if (!attach_d.ok || attach_d.u.s[0] == '\0') {
        if (attach_d.ok) {
          free(attach_d.u.s);
        }
        report(err, file_path,
               "%s[%d].attach[%d]: expected a non-empty string", field_name, i,
               j);
        goto fail_mount_object;
      }
      if (attach_d.u.s[0] != '/') {
        free(attach_d.u.s);
        report(err, file_path, "%s[%d].attach[%d]: expected an absolute path",
               field_name, i, j);
        goto fail_mount_object;
      }
      attach_paths[j] = attach_d.u.s;
    }

    attrs_arr = toml_array_in(obj_tbl, "attrs");
    allowed_attr_set = 0;
    if (attrs_arr != NULL &&
        load_access_array(attrs_arr, MOUNT_ATTR_NAMES,
                          sizeof(MOUNT_ATTR_NAMES) /
                              sizeof(MOUNT_ATTR_NAMES[0]),
                          "broker.mount_object.attrs", file_path, err,
                          &allowed_attr_set) < 0) {
      free(name_d.u.s);
      free(fs_type_d.u.s);
      goto fail_mount_object;
    }

    if (landlockd_policy_ir_add_broker_mount_object_rule(
            ir, name_d.u.s, fs_type_d.u.s, (const char *const *)attach_paths,
            (size_t)attach_n, allowed_attr_set) < 0) {
      report(err, file_path, "%s[%d]: internal error: %s", field_name, i,
             strerror(errno));
      free(name_d.u.s);
      free(fs_type_d.u.s);
      goto fail_mount_object;
    }

    free(name_d.u.s);
    free(fs_type_d.u.s);
    for (j = 0; j < attach_n; j++) {
      free(attach_paths[j]);
    }
    free(attach_paths);
    continue;

fail_mount_object:
    for (j = 0; j < attach_n; j++) {
      free(attach_paths[j]);
    }
    free(attach_paths);
    return -1;
  }

  return 0;
}

static int load_broker(const toml_table_t *broker_tbl,
                       struct landlockd_policy_ir *ir,
                       const char *file_path, FILE *err) {
  static const char *const allowed[] = {"allow_read", "allow_write",
                                        "scratch", "export", "mount_tmpfs",
                                        "mount_bind", "mount_object", "addfd"};
  const char *offending;
  toml_array_t *allow_read_arr;
  toml_array_t *allow_write_arr;
  toml_array_t *scratch_arr;
  toml_array_t *export_arr;
  toml_array_t *mount_tmpfs_arr;
  toml_array_t *mount_bind_arr;
  toml_array_t *mount_object_arr;
  toml_array_t *addfd_arr;

  if (table_has_only_keys(broker_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "broker: unknown key \"%s\"", offending);
    return -1;
  }

  allow_read_arr = toml_array_in(broker_tbl, "allow_read");
  if (load_broker_path_array(allow_read_arr, ir, "allow_read", file_path, err,
                             0,
                             landlockd_policy_ir_add_broker_open_read_rule) <
      0) {
    return -1;
  }

  allow_write_arr = toml_array_in(broker_tbl, "allow_write");
  if (load_broker_path_array(allow_write_arr, ir, "allow_write", file_path,
                             err, 0,
                             landlockd_policy_ir_add_broker_open_write_rule) <
      0) {
    return -1;
  }

  scratch_arr = toml_array_in(broker_tbl, "scratch");
  if (load_broker_path_array(scratch_arr, ir, "scratch", file_path, err, 0,
                             landlockd_policy_ir_add_broker_scratch_rule) <
      0) {
    return -1;
  }

  export_arr = toml_array_in(broker_tbl, "export");
  if (load_broker_path_array(export_arr, ir, "export", file_path, err, 0,
                             landlockd_policy_ir_add_broker_export_rule) < 0) {
    return -1;
  }

  mount_tmpfs_arr = toml_array_in(broker_tbl, "mount_tmpfs");
  if (load_broker_path_array(
      mount_tmpfs_arr, ir, "mount_tmpfs", file_path, err, 0,
      landlockd_policy_ir_add_broker_mount_tmpfs_rule) < 0) {
    return -1;
  }

  addfd_arr = toml_array_in(broker_tbl, "addfd");
  if (load_broker_addfd_array(addfd_arr, ir, file_path, err) < 0) {
    return -1;
  }

  mount_bind_arr = toml_array_in(broker_tbl, "mount_bind");
  if (load_bind_rule_array(mount_bind_arr, ir, "broker.mount_bind", file_path,
                           err,
                           landlockd_policy_ir_add_broker_mount_bind_rule) <
      0) {
    return -1;
  }

  mount_object_arr = toml_array_in(broker_tbl, "mount_object");
  return load_mount_object_rule_array(mount_object_arr, ir,
                                      "broker.mount_object", file_path, err);
}

static int load_mount(const toml_table_t *mount_tbl,
                      struct landlockd_policy_ir *ir,
                      const char *file_path, FILE *err) {
  static const char *const allowed[] = {"tmpfs", "bind", "proc"};
  const char *offending;
  toml_array_t *tmpfs_arr;
  toml_array_t *bind_arr;
  toml_array_t *proc_arr;
  toml_datum_t path_d;
  int n;
  int i;
  int loaded_any;

  if (table_has_only_keys(mount_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "mount: unknown key \"%s\"", offending);
    return -1;
  }

  loaded_any = 0;
  tmpfs_arr = toml_array_in(mount_tbl, "tmpfs");
  if (tmpfs_arr != NULL) {
    loaded_any = 1;
    n = toml_array_nelem(tmpfs_arr);
    if (n <= 0) {
      report(err, file_path, "mount.tmpfs: must contain at least one entry");
      return -1;
    }

    for (i = 0; i < n; i++) {
      path_d = toml_string_at(tmpfs_arr, i);
      if (!path_d.ok || path_d.u.s[0] == '\0') {
        if (path_d.ok) {
          free(path_d.u.s);
        }
        report(err, file_path, "mount.tmpfs[%d]: expected a non-empty string",
               i);
        return -1;
      }
      if (path_d.u.s[0] != '/') {
        report(err, file_path, "mount.tmpfs[%d]: expected an absolute path", i);
        free(path_d.u.s);
        return -1;
      }
      if (landlockd_policy_ir_add_mount_tmpfs_rule(ir, path_d.u.s) < 0) {
        report(err, file_path, "mount.tmpfs[%d]: internal error: %s", i,
               strerror(errno));
        free(path_d.u.s);
        return -1;
      }
      free(path_d.u.s);
    }
  }

  bind_arr = toml_array_in(mount_tbl, "bind");
  if (bind_arr != NULL) {
    loaded_any = 1;
    if (load_bind_rule_array(bind_arr, ir, "mount.bind", file_path, err,
                             landlockd_policy_ir_add_mount_bind_rule) < 0) {
      return -1;
    }
  }

  proc_arr = toml_array_in(mount_tbl, "proc");
  if (proc_arr != NULL) {
    loaded_any = 1;
    n = toml_array_nelem(proc_arr);
    if (n <= 0) {
      report(err, file_path, "mount.proc: must contain at least one entry");
      return -1;
    }
    for (i = 0; i < n; i++) {
      path_d = toml_string_at(proc_arr, i);
      if (!path_d.ok || path_d.u.s[0] == '\0') {
        if (path_d.ok) {
          free(path_d.u.s);
        }
        report(err, file_path, "mount.proc[%d]: expected a non-empty string",
               i);
        return -1;
      }
      if (path_d.u.s[0] != '/') {
        report(err, file_path, "mount.proc[%d]: expected an absolute path", i);
        free(path_d.u.s);
        return -1;
      }
      if (landlockd_policy_ir_add_mount_proc_rule(ir, path_d.u.s) < 0) {
        report(err, file_path, "mount.proc[%d]: internal error: %s", i,
               strerror(errno));
        free(path_d.u.s);
        return -1;
      }
      free(path_d.u.s);
    }
  }

  if (!loaded_any) {
    report(err, file_path,
           "mount: expected at least one of mount.tmpfs, mount.bind, or mount.proc");
    return -1;
  }

  return 0;
}

static int load_runtime(const toml_table_t *runtime_tbl,
                        struct landlockd_policy_ir *ir,
                        const char *file_path, FILE *err) {
  static const char *const allowed[] = {"root", "cwd"};
  const char *offending;
  toml_datum_t root_d;
  toml_datum_t cwd_d;
  int loaded_any;

  if (table_has_only_keys(runtime_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "runtime: unknown key \"%s\"", offending);
    return -1;
  }

  loaded_any = 0;
  root_d = toml_string_in(runtime_tbl, "root");
  if (root_d.ok) {
    loaded_any = 1;
    if (root_d.u.s[0] == '\0') {
      free(root_d.u.s);
      report(err, file_path, "runtime.root: expected a non-empty string");
      return -1;
    }
    if (root_d.u.s[0] != '/') {
      report(err, file_path, "runtime.root: expected an absolute path");
      free(root_d.u.s);
      return -1;
    }
    if (landlockd_policy_ir_set_runtime_root(ir, root_d.u.s) < 0) {
      report(err, file_path, "runtime.root: internal error: %s",
             strerror(errno));
      free(root_d.u.s);
      return -1;
    }
    free(root_d.u.s);
  }

  cwd_d = toml_string_in(runtime_tbl, "cwd");
  if (cwd_d.ok) {
    loaded_any = 1;
    if (cwd_d.u.s[0] == '\0') {
      free(cwd_d.u.s);
      report(err, file_path, "runtime.cwd: expected a non-empty string");
      return -1;
    }
    if (cwd_d.u.s[0] != '/') {
      report(err, file_path, "runtime.cwd: expected an absolute path");
      free(cwd_d.u.s);
      return -1;
    }
    if (landlockd_policy_ir_set_runtime_cwd(ir, cwd_d.u.s) < 0) {
      report(err, file_path, "runtime.cwd: internal error: %s",
             strerror(errno));
      free(cwd_d.u.s);
      return -1;
    }
    free(cwd_d.u.s);
  }
  if (!loaded_any) {
    report(err, file_path,
           "runtime: expected at least one of runtime.root or runtime.cwd");
    return -1;
  }
  return 0;
}

static int load_seccomp(const toml_table_t *seccomp_tbl,
                        struct landlockd_policy_ir *ir,
                        const char *file_path, FILE *err) {
  static const char *const allowed[] = {"deny", "errno"};
  const char *offending;
  toml_array_t *deny_arr;
  toml_datum_t errno_d;
  toml_datum_t name_d;
  unsigned short errno_ret;
  int syscall_nr;
  int n;
  int i;

  if (table_has_only_keys(seccomp_tbl, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "seccomp: unknown key \"%s\"", offending);
    return -1;
  }

  errno_d = toml_int_in(seccomp_tbl, "errno");
  errno_ret = EPERM;
  if (errno_d.ok) {
    if (errno_d.u.i <= 0 || errno_d.u.i > 4095) {
      report(err, file_path, "seccomp.errno: value %lld out of range [1..4095]",
             (long long)errno_d.u.i);
      return -1;
    }
    errno_ret = (unsigned short)errno_d.u.i;
  }

  if (landlockd_policy_ir_enable_seccomp(ir, errno_ret) < 0) {
    report(err, file_path, "seccomp: internal error: %s", strerror(errno));
    return -1;
  }

  deny_arr = toml_array_in(seccomp_tbl, "deny");
  if (deny_arr == NULL) {
    report(err, file_path, "seccomp.deny: required array is missing");
    return -1;
  }

  n = toml_array_nelem(deny_arr);
  if (n <= 0) {
    report(err, file_path, "seccomp.deny: must contain at least one entry");
    return -1;
  }

  for (i = 0; i < n; i++) {
    name_d = toml_string_at(deny_arr, i);
    if (!name_d.ok || name_d.u.s[0] == '\0') {
      if (name_d.ok) {
        free(name_d.u.s);
      }
      report(err, file_path, "seccomp.deny[%d]: expected a non-empty string",
             i);
      return -1;
    }
    if (landlockd_seccomp_syscall_by_name(name_d.u.s, &syscall_nr) < 0) {
      report(err, file_path, "seccomp.deny[%d]: unknown syscall \"%s\"", i,
             name_d.u.s);
      free(name_d.u.s);
      return -1;
    }
    if (landlockd_policy_ir_add_seccomp_deny_rule(ir, syscall_nr) < 0) {
      report(err, file_path, "seccomp.deny[%d]: internal error: %s", i,
             strerror(errno));
      free(name_d.u.s);
      return -1;
    }
    free(name_d.u.s);
  }

  return 0;
}

static int load_root(const toml_table_t *root, struct landlockd_policy_ir *ir,
                     const char *file_path, FILE *err) {
  static const char *const allowed[] = {"version", "fs_layer", "net", "broker",
                                        "mount", "runtime", "seccomp"};
  const char *offending;
  toml_datum_t version;
  toml_array_t *fs_arr;
  toml_table_t *net_tbl;
  toml_table_t *broker_tbl;
  toml_table_t *mount_tbl;
  toml_table_t *runtime_tbl;
  toml_table_t *seccomp_tbl;
  int n;
  int i;

  if (table_has_only_keys(root, allowed,
                          sizeof(allowed) / sizeof(allowed[0]),
                          &offending) < 0) {
    report(err, file_path, "unknown top-level key \"%s\"", offending);
    return -1;
  }

  version = toml_int_in(root, "version");
  if (!version.ok) {
    report(err, file_path, "version: required integer is missing");
    return -1;
  }
  if (version.u.i != 1) {
    report(err, file_path, "version: expected 1, got %lld",
           (long long)version.u.i);
    return -1;
  }

  fs_arr = toml_array_in(root, "fs_layer");
  if (fs_arr != NULL) {
    n = toml_array_nelem(fs_arr);
    for (i = 0; i < n; i++) {
      toml_table_t *layer_tbl = toml_table_at(fs_arr, i);
      if (layer_tbl == NULL) {
        report(err, file_path, "fs_layer[%d]: expected a table", i);
        return -1;
      }
      if (load_fs_layer(layer_tbl, (size_t)i, ir, file_path, err) < 0) {
        return -1;
      }
    }
  }

  net_tbl = toml_table_in(root, "net");
  if (net_tbl != NULL) {
    if (load_net(net_tbl, ir, file_path, err) < 0) {
      return -1;
    }
  }

  broker_tbl = toml_table_in(root, "broker");
  if (broker_tbl != NULL) {
    if (load_broker(broker_tbl, ir, file_path, err) < 0) {
      return -1;
    }
  }

  mount_tbl = toml_table_in(root, "mount");
  if (mount_tbl != NULL) {
    if (load_mount(mount_tbl, ir, file_path, err) < 0) {
      return -1;
    }
  }

  runtime_tbl = toml_table_in(root, "runtime");
  if (runtime_tbl != NULL) {
    if (load_runtime(runtime_tbl, ir, file_path, err) < 0) {
      return -1;
    }
  }

  seccomp_tbl = toml_table_in(root, "seccomp");
  if (seccomp_tbl != NULL) {
    if (load_seccomp(seccomp_tbl, ir, file_path, err) < 0) {
      return -1;
    }
  }
  return 0;
}

int landlockd_policy_load_file_in_process(const char *file_path,
                                          struct landlockd_policy_ir *out_ir,
                                          FILE *err_stream) {
  FILE *fp;
  toml_table_t *root;
  char errbuf[256];
  int saved_errno;

  if (file_path == NULL || out_ir == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (out_ir->fs_layer_count != 0 || out_ir->fs_layers != NULL ||
      out_ir->net_enabled || out_ir->net_rules != NULL ||
      out_ir->broker_open_read_count != 0 ||
      out_ir->broker_open_read_rules != NULL ||
      out_ir->broker_open_write_count != 0 ||
      out_ir->broker_open_write_rules != NULL ||
      out_ir->broker_scratch_count != 0 ||
      out_ir->broker_scratch_rules != NULL ||
      out_ir->broker_export_count != 0 ||
      out_ir->broker_export_rules != NULL ||
      out_ir->broker_mount_tmpfs_count != 0 ||
      out_ir->broker_mount_tmpfs_rules != NULL ||
      out_ir->broker_mount_bind_count != 0 ||
      out_ir->broker_mount_bind_rules != NULL ||
      out_ir->broker_mount_object_count != 0 ||
      out_ir->broker_mount_object_rules != NULL ||
      out_ir->broker_addfd_count != 0 ||
      out_ir->broker_addfd_rules != NULL ||
      out_ir->mount_tmpfs_count != 0 ||
      out_ir->mount_tmpfs_rules != NULL || out_ir->mount_bind_count != 0 ||
      out_ir->mount_bind_rules != NULL || out_ir->mount_proc_count != 0 ||
      out_ir->mount_proc_rules != NULL || out_ir->runtime_root != NULL ||
      out_ir->runtime_cwd != NULL ||
      out_ir->seccomp_enabled ||
      out_ir->seccomp_errno != 0 || out_ir->seccomp_deny_count != 0 ||
      out_ir->seccomp_deny_rules != NULL) {
    errno = EINVAL;
    return -1;
  }

  fp = fopen(file_path, "r");
  if (fp == NULL) {
    saved_errno = errno;
    report(err_stream, file_path, "open failed: %s", strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
  errbuf[0] = '\0';
  root = toml_parse_file(fp, errbuf, (int)sizeof(errbuf));
  fclose(fp);
  if (root == NULL) {
    report(err_stream, file_path, "%s",
           errbuf[0] != '\0' ? errbuf : "parse failed");
    errno = EINVAL;
    return -1;
  }

  if (load_root(root, out_ir, file_path, err_stream) < 0) {
    saved_errno = errno;
    toml_free(root);
    landlockd_policy_ir_reset(out_ir);
    errno = saved_errno != 0 ? saved_errno : EINVAL;
    return -1;
  }
  toml_free(root);
  return 0;
}
