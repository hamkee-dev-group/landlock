#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "landlock_policy_ir.h"
#include "landlockd/policy_ir.h"
#include "tap.h"

int main(void) {
  struct landlockd_ir_fs_rule fs_rule_a = {.path = "/a", .allowed_access = 0x1};
  struct landlockd_ir_fs_rule fs_rule_b = {.path = "/b", .allowed_access = 0x2};
  struct landlockd_ir_fs_rule fs_rules[] = {{"/a", 0x1}, {"/b", 0x2}};
  struct landlockd_ir_net_rule net_rules[] = {{80, 0x1}, {443, 0x2}};
  struct landlockd_ir_exception_rule exc_rules[] = {{39}, {102}};

  struct landlockd_ir_layer fs_layer = {
      .kind = LANDLOCKD_IR_LAYER_FS,
      .order = 0,
      .handled_access = 0x3,
      .rule_count = 2,
      .fs_rules = fs_rules,
  };
  struct landlockd_ir_layer net_layer = {
      .kind = LANDLOCKD_IR_LAYER_NET,
      .order = 1,
      .handled_access = 0x3,
      .rule_count = 2,
      .net_rules = net_rules,
  };
  struct landlockd_ir_layer exc_layer = {
      .kind = LANDLOCKD_IR_LAYER_EXCEPTION,
      .order = 2,
      .handled_access = 0,
      .rule_count = 2,
      .exception_rules = exc_rules,
  };
  const struct landlockd_ir_layer *canonical_layers[] = {
      &fs_layer, &net_layer, &exc_layer};
  struct landlockd_ir_policy policy = {
      .name = "unit",
      .layer_count = 3,
      .layers = canonical_layers,
  };

  struct landlockd_ir_layer tmp_layer;
  const struct landlockd_ir_layer *one_layer_array[1];
  struct landlockd_ir_policy tmp_policy;

  plan(18);

  errno = 0;
  ok(landlockd_ir_policy_validate(&policy) == 0 && errno == 0,
     "accepts a named policy with fs, net, and exception layers in declared order");

  errno = 0;
  ok(landlockd_ir_policy_validate(NULL) == -1 && errno == EINVAL,
     "rejects a NULL policy pointer with EINVAL");

  tmp_policy = policy;
  tmp_policy.name = NULL;
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects a policy with a NULL name");

  tmp_policy = policy;
  tmp_policy.name = "";
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects a policy with an empty name");

  tmp_policy = policy;
  tmp_policy.layer_count = 0;
  tmp_policy.layers = NULL;
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects a policy with no layers");

  tmp_layer = fs_layer;
  tmp_layer.order = 7;
  one_layer_array[0] = &tmp_layer;
  tmp_policy.name = "unit";
  tmp_policy.layer_count = 1;
  tmp_policy.layers = one_layer_array;
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects a layer whose order metadata does not match its position");

  tmp_layer = fs_layer;
  tmp_layer.net_rules = net_rules;
  one_layer_array[0] = &tmp_layer;
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects an fs layer that also carries net rules (mixed rule kinds)");

  tmp_layer = fs_layer;
  tmp_layer.handled_access = 0;
  one_layer_array[0] = &tmp_layer;
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects an fs layer with an empty handled-access mask");

  tmp_layer = net_layer;
  tmp_layer.order = 0;
  tmp_layer.handled_access = 0;
  one_layer_array[0] = &tmp_layer;
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects a net layer with an empty handled-access mask");

  {
    struct landlockd_ir_fs_rule bad = {.path = "/a", .allowed_access = 0};
    tmp_layer = fs_layer;
    tmp_layer.rule_count = 1;
    tmp_layer.fs_rules = &bad;
    one_layer_array[0] = &tmp_layer;
    errno = 0;
    ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
       "rejects an fs rule with a zero allowed-access mask");
  }

  {
    struct landlockd_ir_fs_rule bad = {.path = NULL, .allowed_access = 0x1};
    tmp_layer = fs_layer;
    tmp_layer.rule_count = 1;
    tmp_layer.fs_rules = &bad;
    one_layer_array[0] = &tmp_layer;
    errno = 0;
    ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
       "rejects an fs rule with a NULL path");
  }

  {
    struct landlockd_ir_exception_rule bad = {.syscall_nr = -1};
    tmp_layer = exc_layer;
    tmp_layer.order = 0;
    tmp_layer.rule_count = 1;
    tmp_layer.exception_rules = &bad;
    one_layer_array[0] = &tmp_layer;
    errno = 0;
    ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
       "rejects an exception rule with a negative syscall number");
  }

  tmp_layer = exc_layer;
  tmp_layer.order = 0;
  tmp_layer.fs_rules = &fs_rule_a;
  one_layer_array[0] = &tmp_layer;
  errno = 0;
  ok(landlockd_ir_policy_validate(&tmp_policy) == -1 && errno == EINVAL,
     "rejects an exception layer that also carries fs rules (mixed rule kinds)");

  (void)fs_rule_b;
  {
    struct landlockd_ir_layer first_fs = fs_layer;
    struct landlockd_ir_layer second_fs = fs_layer;
    const struct landlockd_ir_layer *two[2];
    first_fs.order = 0;
    second_fs.order = 1;
    two[0] = &first_fs;
    two[1] = &second_fs;
    tmp_policy.layer_count = 2;
    tmp_policy.layers = two;
    errno = 0;
    ok(landlockd_ir_policy_validate(&tmp_policy) == 0 && errno == 0,
       "preserves declared order across multiple layers of the same kind");
  }

  {
    static const char *const addfd_actions[] = {
        "open", "open_tree", "scratch_open", "fsopen", "fsmount"};
    struct landlockd_policy_ir addfd_ir;
    struct landlockd_policy_ir addfd_copy;
    size_t k;
    int all_added = 1;
    int pairs_ok;

    landlockd_policy_ir_init(&addfd_ir);
    for (k = 0; k < sizeof(addfd_actions) / sizeof(addfd_actions[0]); k++) {
      char target[32];
      snprintf(target, sizeof(target), "/fd/%zu", k);
      if (landlockd_policy_ir_add_broker_addfd_rule(&addfd_ir, addfd_actions[k],
                                                    target, NULL) != 0) {
        all_added = 0;
      }
    }
    ok(all_added && addfd_ir.broker_addfd_count == 5,
       "stores a broker.addfd rule for each addfd action");

    errno = 0;
    ok(landlockd_policy_ir_add_broker_addfd_rule(&addfd_ir, "", "/fd/x",
                                                 NULL) == -1 &&
           errno == EINVAL,
       "rejects a broker.addfd rule with an empty action");

    landlockd_policy_ir_init(&addfd_copy);
    pairs_ok = landlockd_policy_ir_copy(&addfd_ir, &addfd_copy) == 0 &&
               addfd_copy.broker_addfd_count == addfd_ir.broker_addfd_count;
    for (k = 0; k < addfd_ir.broker_addfd_count && pairs_ok; k++) {
      if (strcmp(addfd_copy.broker_addfd_rules[k].action,
                 addfd_ir.broker_addfd_rules[k].action) != 0 ||
          strcmp(addfd_copy.broker_addfd_rules[k].target,
                 addfd_ir.broker_addfd_rules[k].target) != 0) {
        pairs_ok = 0;
      }
    }
    ok(pairs_ok,
       "copy reproduces the broker.addfd count and every (action, target) pair");

    landlockd_policy_ir_reset(&addfd_ir);
    ok(addfd_ir.broker_addfd_count == 0 && addfd_ir.broker_addfd_rules == NULL,
       "reset zeros the broker.addfd count and frees its rules");
    landlockd_policy_ir_reset(&addfd_copy);
  }

  done_testing();
}
