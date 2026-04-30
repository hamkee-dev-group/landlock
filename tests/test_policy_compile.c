#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <linux/mount.h>
#include <string.h>

#include "landlock_policy_ir.h"
#include "tap.h"

static int ir_is_empty(const struct landlockd_policy_ir *ir) {
  return ir->fs_layer_count == 0 && ir->fs_layers == NULL &&
         ir->net_enabled == 0 && ir->net_handled_access == 0 &&
         ir->net_rule_count == 0 && ir->net_rules == NULL &&
         ir->broker_mount_object_count == 0 &&
         ir->broker_mount_object_rules == NULL &&
         ir->mount_proc_count == 0 && ir->mount_proc_rules == NULL &&
         ir->runtime_root == NULL && ir->runtime_cwd == NULL;
}

int main(void) {
  struct landlockd_policy_ir ir;
  struct landlockd_policy_ir copy;
  size_t layer0;
  size_t layer1;
  int rc;

  plan(29);

  landlockd_policy_ir_init(&ir);
  ok(ir_is_empty(&ir),
     "init produces an empty IR with zeroed fields");

  errno = 0;
  rc = landlockd_policy_ir_add_fs_layer(&ir, 0, NULL);
  ok(rc == -1 && errno == EINVAL && ir_is_empty(&ir),
     "add_fs_layer rejects a zero handled-access mask");

  errno = 0;
  rc = landlockd_policy_ir_add_fs_layer(NULL, 0x1, NULL);
  ok(rc == -1 && errno == EINVAL,
     "add_fs_layer rejects a NULL IR pointer");

  rc = landlockd_policy_ir_add_fs_layer(&ir, 0x1, &layer0);
  ok(rc == 0 && layer0 == 0 && ir.fs_layer_count == 1 &&
         ir.fs_layers[0].handled_access_fs == 0x1 &&
         ir.fs_layers[0].rule_count == 0 && ir.fs_layers[0].rules == NULL,
     "add_fs_layer appends the first layer and reports its index");

  rc = landlockd_policy_ir_add_fs_layer(&ir, 0x6, &layer1);
  ok(rc == 0 && layer1 == 1 && ir.fs_layer_count == 2 &&
         ir.fs_layers[1].handled_access_fs == 0x6,
     "add_fs_layer preserves insertion order across calls");

  errno = 0;
  rc = landlockd_policy_ir_add_fs_rule(&ir, 5, "/x", 0x1);
  ok(rc == -1 && errno == EINVAL,
     "add_fs_rule rejects an out-of-range layer index");

  errno = 0;
  rc = landlockd_policy_ir_add_fs_rule(&ir, 0, NULL, 0x1);
  ok(rc == -1 && errno == EINVAL,
     "add_fs_rule rejects a NULL path");

  errno = 0;
  rc = landlockd_policy_ir_add_fs_rule(&ir, 0, "/x", 0);
  ok(rc == -1 && errno == EINVAL,
     "add_fs_rule rejects a zero access mask");

  rc = landlockd_policy_ir_add_fs_rule(&ir, 0, "/a", 0x1);
  ok(rc == 0 && ir.fs_layers[0].rule_count == 1 &&
         strcmp(ir.fs_layers[0].rules[0].path, "/a") == 0 &&
         ir.fs_layers[0].rules[0].allowed_access == 0x1,
     "add_fs_rule stores an independent copy of the path and the access mask");

  rc = landlockd_policy_ir_add_fs_rule(&ir, 0, "/b", 0x2);
  ok(rc == 0 && ir.fs_layers[0].rule_count == 2 &&
         strcmp(ir.fs_layers[0].rules[1].path, "/b") == 0,
     "add_fs_rule appends further rules within the same layer");

  rc = landlockd_policy_ir_add_fs_rule(&ir, 1, "/c", 0x4);
  ok(rc == 0 && ir.fs_layers[1].rule_count == 1 &&
         strcmp(ir.fs_layers[1].rules[0].path, "/c") == 0,
     "add_fs_rule appends rules to the correct layer by index");

  errno = 0;
  rc = landlockd_policy_ir_add_net_rule(&ir, 80, 0x1);
  ok(rc == -1 && errno == EINVAL,
     "add_net_rule requires net to be enabled first");

  errno = 0;
  rc = landlockd_policy_ir_enable_net(&ir, 0);
  ok(rc == -1 && errno == EINVAL && ir.net_enabled == 0,
     "enable_net rejects a zero handled-access mask");

  rc = landlockd_policy_ir_enable_net(&ir, 0x3);
  ok(rc == 0 && ir.net_enabled == 1 && ir.net_handled_access == 0x3,
     "enable_net flips the net flag and records the handled mask");

  errno = 0;
  rc = landlockd_policy_ir_add_net_rule(&ir, 80, 0);
  ok(rc == -1 && errno == EINVAL,
     "add_net_rule rejects a zero access mask");

  rc = landlockd_policy_ir_add_net_rule(&ir, 80, 0x1);
  ok(rc == 0 && ir.net_rule_count == 1 && ir.net_rules[0].port == 80 &&
         ir.net_rules[0].allowed_access == 0x1,
     "add_net_rule appends the rule after enable_net");

  errno = 0;
  rc = landlockd_policy_ir_set_runtime_root(&ir, NULL);
  ok(rc == -1 && errno == EINVAL,
     "set_runtime_root rejects a NULL path");

  rc = landlockd_policy_ir_set_runtime_root(&ir, "/sandbox");
  ok(rc == 0 && ir.runtime_root != NULL &&
         strcmp(ir.runtime_root, "/sandbox") == 0,
     "set_runtime_root stores the runtime root path");

  errno = 0;
  rc = landlockd_policy_ir_set_runtime_cwd(&ir, NULL);
  ok(rc == -1 && errno == EINVAL,
     "set_runtime_cwd rejects a NULL path");

  rc = landlockd_policy_ir_set_runtime_cwd(&ir, "/work");
  ok(rc == 0 && ir.runtime_cwd != NULL &&
         strcmp(ir.runtime_cwd, "/work") == 0,
     "set_runtime_cwd stores the runtime cwd path");

  errno = 0;
  rc = landlockd_policy_ir_add_mount_proc_rule(&ir, NULL);
  ok(rc == -1 && errno == EINVAL,
     "add_mount_proc_rule rejects a NULL path");

  rc = landlockd_policy_ir_add_mount_proc_rule(&ir, "/proc");
  ok(rc == 0 && ir.mount_proc_count == 1 && ir.mount_proc_rules != NULL &&
         strcmp(ir.mount_proc_rules[0].path, "/proc") == 0,
     "add_mount_proc_rule stores the proc mount path");

  {
    const char *attach_paths[] = {"/sandbox/mnt"};

    errno = 0;
    rc = landlockd_policy_ir_add_broker_mount_object_rule(&ir, "", "tmpfs",
                                                          attach_paths, 1,
                                                          0);
    ok(rc == -1 && errno == EINVAL,
       "add_broker_mount_object_rule rejects an empty object name");

    rc = landlockd_policy_ir_add_broker_mount_object_rule(
        &ir, "scratch", "tmpfs", attach_paths, 1,
        (uint64_t)MOUNT_ATTR_RDONLY);
    ok(rc == 0 && ir.broker_mount_object_count == 1 &&
           strcmp(ir.broker_mount_object_rules[0].name, "scratch") == 0 &&
           strcmp(ir.broker_mount_object_rules[0].fs_type, "tmpfs") == 0 &&
           ir.broker_mount_object_rules[0].attach_count == 1 &&
           strcmp(ir.broker_mount_object_rules[0].attach_paths[0],
                  "/sandbox/mnt") == 0 &&
           ir.broker_mount_object_rules[0].allowed_attr_set ==
               (uint64_t)MOUNT_ATTR_RDONLY,
       "add_broker_mount_object_rule stores object metadata and attach paths");
  }

  landlockd_policy_ir_init(&copy);
  rc = landlockd_policy_ir_copy(&ir, &copy);
  ok(rc == 0 && copy.fs_layer_count == 2 &&
         copy.fs_layers[0].handled_access_fs == 0x1 &&
         copy.fs_layers[0].rule_count == 2 &&
         strcmp(copy.fs_layers[0].rules[0].path, "/a") == 0 &&
         copy.fs_layers[0].rules[0].path != ir.fs_layers[0].rules[0].path &&
         copy.fs_layers[1].rule_count == 1 &&
         strcmp(copy.fs_layers[1].rules[0].path, "/c") == 0 &&
         copy.mount_proc_count == 1 &&
         copy.mount_proc_rules != NULL &&
         strcmp(copy.mount_proc_rules[0].path, "/proc") == 0 &&
         copy.runtime_root != NULL &&
         strcmp(copy.runtime_root, "/sandbox") == 0 &&
         copy.runtime_cwd != NULL &&
         strcmp(copy.runtime_cwd, "/work") == 0 &&
         copy.net_enabled == 1 && copy.net_handled_access == 0x3 &&
         copy.net_rule_count == 1 && copy.net_rules[0].port == 80 &&
         copy.broker_mount_object_count == 1 &&
         strcmp(copy.broker_mount_object_rules[0].name, "scratch") == 0 &&
         copy.broker_mount_object_rules[0].attach_count == 1 &&
         strcmp(copy.broker_mount_object_rules[0].attach_paths[0],
                "/sandbox/mnt") == 0,
     "copy deep-copies layers, rules, paths, and the net section");

  ok(copy.fs_layers != ir.fs_layers && copy.fs_layers[0].rules !=
         ir.fs_layers[0].rules && copy.net_rules != ir.net_rules &&
         copy.broker_mount_object_rules != ir.broker_mount_object_rules,
     "copy allocates independent backing arrays for every owned buffer");

  errno = 0;
  rc = landlockd_policy_ir_copy(&ir, &copy);
  ok(rc == -1 && errno == EINVAL,
     "copy refuses to overwrite a non-empty destination");

  errno = 42;
  landlockd_policy_ir_reset(&ir);
  ok(errno == 42 && ir_is_empty(&ir),
     "reset preserves errno and returns the IR to init state");

  landlockd_policy_ir_reset(&copy);
  ok(ir_is_empty(&copy),
     "reset on a populated copy produces the same empty state as init");

  done_testing();
}
