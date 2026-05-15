#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <linux/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "landlock_policy_ir.h"
#include "landlock_policy_loader.h"
#include "landlockd/landlock_compat.h"
#include "tap.h"

static char *make_path(const char *dir, const char *leaf) {
  size_t n = strlen(dir) + 1 + strlen(leaf) + 1;
  char *p = malloc(n);
  snprintf(p, n, "%s/%s", dir, leaf);
  return p;
}

static int load_capturing(const char *file_path,
                          struct landlockd_policy_ir *out,
                          char *errbuf, size_t errbufsz) {
  FILE *mem;
  int rc;
  mem = fmemopen(errbuf, errbufsz, "w");
  rc = landlockd_policy_load_file(file_path, out, mem);
  fclose(mem);
  return rc;
}

static void check_invalid(const char *dir, const char *leaf,
                          const char *needle, const char *label) {
  struct landlockd_policy_ir ir;
  char err[512];
  char *path;
  int rc;

  landlockd_policy_ir_init(&ir);
  path = make_path(dir, leaf);
  memset(err, 0, sizeof(err));
  rc = load_capturing(path, &ir, err, sizeof(err));
  ok(rc == -1, "%s: loader returns -1", label);
  ok(strstr(err, path) != NULL, "%s: stderr includes the policy file path",
     label);
  ok(strstr(err, needle) != NULL,
     "%s: stderr cites a specific reason (expected %s)", label, needle);
  ok(ir.fs_layer_count == 0 && ir.fs_layers == NULL && ir.net_enabled == 0 &&
         ir.net_rules == NULL && ir.broker_open_read_count == 0 &&
         ir.broker_open_read_rules == NULL &&
         ir.broker_open_write_count == 0 &&
         ir.broker_open_write_rules == NULL &&
         ir.broker_scratch_count == 0 && ir.broker_scratch_rules == NULL &&
         ir.broker_export_count == 0 && ir.broker_export_rules == NULL &&
         ir.broker_mount_tmpfs_count == 0 &&
         ir.broker_mount_tmpfs_rules == NULL &&
         ir.broker_mount_bind_count == 0 &&
         ir.broker_mount_bind_rules == NULL &&
         ir.broker_mount_object_count == 0 &&
         ir.broker_mount_object_rules == NULL &&
         ir.broker_addfd_count == 0 && ir.broker_addfd_rules == NULL &&
         ir.mount_tmpfs_count == 0 && ir.mount_tmpfs_rules == NULL &&
         ir.mount_bind_count == 0 && ir.mount_bind_rules == NULL &&
         ir.mount_proc_count == 0 && ir.mount_proc_rules == NULL &&
         ir.runtime_root == NULL && ir.runtime_cwd == NULL &&
         ir.seccomp_enabled == 0 && ir.seccomp_errno == 0 &&
         ir.seccomp_deny_count == 0 && ir.seccomp_deny_rules == NULL,
     "%s: IR left empty — no landlock ruleset syscalls reachable", label);
  landlockd_policy_ir_reset(&ir);
  free(path);
}

int main(int argc, char *argv[]) {
  struct landlockd_policy_ir ir;
  struct landlockd_policy_ir ir2;
  const char *dir;
  char *broker_path;
  char *valid_path;
  char err[256];
  int rc;

  plan(95);

  if (argc < 2) {
    diag("usage: %s <policies-dir>", argv[0]);
    return 1;
  }
  dir = argv[1];

  valid_path = make_path(dir, "valid_minimal.toml");
  landlockd_policy_ir_init(&ir);
  memset(err, 0, sizeof(err));
  rc = load_capturing(valid_path, &ir, err, sizeof(err));
  ok(rc == 0, "valid policy loads successfully");
  ok(ir.fs_layer_count == 2, "valid policy produces two fs layers");
  ok(ir.fs_layers[0].handled_access_fs ==
         (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR),
     "fs_layer[0] handled mask is read_file|read_dir");
  ok(ir.fs_layers[0].rule_count == 2, "fs_layer[0] has two rules");
  ok(strcmp(ir.fs_layers[0].rules[0].path, "/usr") == 0,
     "fs_layer[0].rule[0].path is /usr");
  ok(ir.fs_layers[0].rules[0].allowed_access ==
         (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR),
     "fs_layer[0].rule[0] allowed_access is read_file|read_dir");
  ok(strcmp(ir.fs_layers[0].rules[1].path, "/etc") == 0,
     "fs_layer[0].rule[1].path is /etc");
  ok(ir.fs_layers[1].handled_access_fs ==
         (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE),
     "fs_layer[1] handled mask is write_file|truncate");
  ok(ir.net_enabled == 1, "net section is enabled");
  ok(ir.net_handled_access ==
         (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP),
     "net handled mask is bind_tcp|connect_tcp");
  ok(ir.net_rule_count == 2, "net has two rules");
  ok(ir.net_rules[0].port == 80 &&
         ir.net_rules[0].allowed_access == LANDLOCK_ACCESS_NET_CONNECT_TCP,
     "net.rule[0] is port 80 / connect_tcp");
  ok(ir.net_rules[1].port == 8080 &&
         ir.net_rules[1].allowed_access == LANDLOCK_ACCESS_NET_BIND_TCP,
     "net.rule[1] is port 8080 / bind_tcp");
  ok(ir.broker_open_read_count == 0 && ir.broker_open_write_count == 0 &&
         ir.broker_scratch_count == 0 && ir.broker_export_count == 0 &&
         ir.broker_mount_tmpfs_count == 0 &&
         ir.broker_mount_bind_count == 0 &&
         ir.broker_mount_object_count == 0 &&
         ir.broker_addfd_count == 0 &&
         ir.mount_tmpfs_count == 0 && ir.mount_bind_count == 0 &&
         ir.mount_proc_count == 0 && ir.runtime_root == NULL &&
         ir.runtime_cwd == NULL &&
         ir.seccomp_enabled == 0 && ir.seccomp_deny_count == 0,
     "valid minimal policy leaves broker exception lists empty");

  

  landlockd_policy_ir_init(&ir2);
  rc = load_capturing(valid_path, &ir2, err, sizeof(err));
  ok(rc == 0 && ir2.fs_layer_count == ir.fs_layer_count &&
         ir2.net_enabled == ir.net_enabled &&
         ir2.net_rule_count == ir.net_rule_count &&
         ir2.fs_layers[0].handled_access_fs ==
             ir.fs_layers[0].handled_access_fs &&
         ir2.fs_layers[0].rule_count == ir.fs_layers[0].rule_count &&
         strcmp(ir2.fs_layers[0].rules[0].path,
                ir.fs_layers[0].rules[0].path) == 0 &&
         ir2.fs_layers[1].handled_access_fs ==
             ir.fs_layers[1].handled_access_fs &&
         ir2.net_rules[0].port == ir.net_rules[0].port &&
         ir2.net_rules[1].port == ir.net_rules[1].port,
     "reloading the valid policy produces the same IR");
  landlockd_policy_ir_reset(&ir);
  landlockd_policy_ir_reset(&ir2);
  free(valid_path);

  broker_path = make_path(dir, "broker_rw.toml");
  landlockd_policy_ir_init(&ir);
  memset(err, 0, sizeof(err));
  rc = load_capturing(broker_path, &ir, err, sizeof(err));
  ok(rc == 0, "broker policy loads successfully");
  ok(ir.broker_open_read_count == 1 &&
         strcmp(ir.broker_open_read_rules[0].path, "/etc/resolv.conf") == 0,
     "broker.allow_read populates the read exception list");
  ok(ir.broker_open_write_count == 1 &&
         strcmp(ir.broker_open_write_rules[0].path,
                "/tmp/landlockd-broker-write") == 0,
     "broker.allow_write populates the write exception list");
  ok(ir.broker_scratch_count == 1 &&
         strcmp(ir.broker_scratch_rules[0].path,
                "/tmp/landlockd-scratch-root") == 0,
     "broker.scratch populates the scratch root list");
  ok(ir.broker_export_count == 1 &&
         strcmp(ir.broker_export_rules[0].path,
                "/tmp/landlockd-export-root") == 0,
     "broker.export populates the export root list");
  ok(ir.broker_mount_tmpfs_count == 1 &&
         strcmp(ir.broker_mount_tmpfs_rules[0].path,
                "/tmp/landlockd-broker-mount") == 0,
     "broker.mount_tmpfs populates the dynamic tmpfs mount list");
  ok(ir.broker_mount_bind_count == 1 &&
         strcmp(ir.broker_mount_bind_rules[0].source,
                "/tmp/landlockd-broker-bind-source") == 0 &&
         strcmp(ir.broker_mount_bind_rules[0].target,
                "/tmp/landlockd-broker-bind-target") == 0 &&
         ir.broker_mount_bind_rules[0].read_only == 1,
     "broker.mount_bind populates the dynamic bind mount list");
  landlockd_policy_ir_reset(&ir);
  free(broker_path);

  broker_path = make_path(dir, "broker_addfd.toml");
  landlockd_policy_ir_init(&ir);
  memset(err, 0, sizeof(err));
  rc = load_capturing(broker_path, &ir, err, sizeof(err));
  ok(rc == 0, "broker addfd policy loads successfully");
  ok(ir.broker_addfd_count == 1 &&
         strcmp(ir.broker_addfd_rules[0].action, "open") == 0 &&
         strcmp(ir.broker_addfd_rules[0].target, "/tmp/landlockd-addfd") == 0 &&
         ir.broker_addfd_rules[0].mode != NULL &&
         strcmp(ir.broker_addfd_rules[0].mode, "read") == 0,
     "broker.addfd populates the addfd rule list");
  landlockd_policy_ir_reset(&ir);
  free(broker_path);

  broker_path = make_path(dir, "mount_object.toml");
  landlockd_policy_ir_init(&ir);
  memset(err, 0, sizeof(err));
  rc = load_capturing(broker_path, &ir, err, sizeof(err));
  ok(rc == 0, "mount-object policy loads successfully");
  ok(ir.broker_mount_object_count == 1 &&
         strcmp(ir.broker_mount_object_rules[0].name, "scratch") == 0 &&
         strcmp(ir.broker_mount_object_rules[0].fs_type, "tmpfs") == 0,
     "broker.mount_object populates the mount object metadata");
  ok(ir.broker_mount_object_rules[0].attach_count == 1 &&
         strcmp(ir.broker_mount_object_rules[0].attach_paths[0],
                "/tmp/landlockd-mount-object") == 0,
     "broker.mount_object populates attach targets");
  ok((ir.broker_mount_object_rules[0].allowed_attr_set &
      ((uint64_t)MOUNT_ATTR_RDONLY | (uint64_t)MOUNT_ATTR_NODEV)) ==
         ((uint64_t)MOUNT_ATTR_RDONLY | (uint64_t)MOUNT_ATTR_NODEV),
     "broker.mount_object populates allowed mount attributes");
  landlockd_policy_ir_reset(&ir);
  free(broker_path);

  broker_path = make_path(dir, "mount_tmpfs.toml");
  landlockd_policy_ir_init(&ir);
  memset(err, 0, sizeof(err));
  rc = load_capturing(broker_path, &ir, err, sizeof(err));
  ok(rc == 0, "mount policy loads successfully");
  ok(ir.mount_tmpfs_count == 1 &&
         strcmp(ir.mount_tmpfs_rules[0].path,
                "/tmp/landlockd-tmpfs-mount") == 0,
     "mount.tmpfs populates the tmpfs mount list");
  ok(ir.mount_bind_count == 1 &&
         strcmp(ir.mount_bind_rules[0].source,
                "/tmp/landlockd-bind-source") == 0 &&
         strcmp(ir.mount_bind_rules[0].target,
                "/tmp/landlockd-bind-target") == 0 &&
         ir.mount_bind_rules[0].read_only == 1,
     "mount.bind populates the bind mount list");
  ok(ir.mount_proc_count == 1 &&
         strcmp(ir.mount_proc_rules[0].path, "/tmp/landlockd-proc-mount") == 0,
     "mount.proc populates the proc mount list");
  landlockd_policy_ir_reset(&ir);
  free(broker_path);

  broker_path = make_path(dir, "runtime_root.toml");
  landlockd_policy_ir_init(&ir);
  memset(err, 0, sizeof(err));
  rc = load_capturing(broker_path, &ir, err, sizeof(err));
  ok(rc == 0, "runtime-root policy loads successfully");
  ok(ir.runtime_root != NULL &&
         strcmp(ir.runtime_root, "/tmp/landlockd-runtime-root") == 0,
     "runtime.root populates the runtime root path");
  ok(ir.runtime_cwd != NULL &&
         strcmp(ir.runtime_cwd, "/workspace") == 0,
     "runtime.cwd populates the runtime cwd path");
  landlockd_policy_ir_reset(&ir);
  free(broker_path);

  broker_path = make_path(dir, "seccomp_valid.toml");
  landlockd_policy_ir_init(&ir);
  memset(err, 0, sizeof(err));
  rc = load_capturing(broker_path, &ir, err, sizeof(err));
  ok(rc == 0, "seccomp policy loads successfully");
  ok(ir.seccomp_enabled == 1 && ir.seccomp_errno == 13,
     "seccomp.errno populates the seccomp return code");
  ok(ir.seccomp_deny_count == 2, "seccomp.deny populates two deny rules");
  ok(ir.seccomp_deny_rules[0].syscall_nr >= 0 &&
         ir.seccomp_deny_rules[1].syscall_nr >= 0,
     "seccomp deny rules resolve to concrete syscall numbers");
  landlockd_policy_ir_reset(&ir);
  free(broker_path);

  check_invalid(dir, "malformed.toml", "line ", "malformed TOML");
  check_invalid(dir, "schema_unknown_access.toml", "frobnicate",
                "unknown fs access name");
  check_invalid(dir, "schema_missing_version.toml", "version",
                "missing version key");
  check_invalid(dir, "schema_port_range.toml", "99999",
                "port value out of range");
  check_invalid(dir, "schema_unknown_field.toml", "nonsense",
                "unknown top-level key");
  check_invalid(dir, "mount_relative.toml", "absolute path",
                "relative tmpfs mount path");
  check_invalid(dir, "mount_bind_relative.toml", "absolute path",
                "relative bind mount path");
  check_invalid(dir, "mount_object_relative.toml", "absolute path",
                "relative mount object attach path");
  check_invalid(dir, "mount_proc_relative.toml", "absolute path",
                "relative proc mount path");
  check_invalid(dir, "runtime_root_relative.toml", "absolute path",
                "relative runtime root path");
  check_invalid(dir, "runtime_cwd_relative.toml", "absolute path",
                "relative runtime cwd path");
  check_invalid(dir, "broker_addfd_relative.toml", "absolute path",
                "relative broker.addfd path");
  check_invalid(dir, "seccomp_unknown_syscall.toml", "unknown syscall",
                "unknown seccomp syscall name");
  check_invalid(dir, "seccomp_bad_errno.toml", "out of range",
                "invalid seccomp errno value");

  done_testing();
}
