#include <errno.h>

#include "landlockd/policy_compiler.h"
#include "landlockd/policy_ir.h"
#include "landlockd/seccomp.h"
#include "tap.h"

int main(void) {
  struct landlockd_ir_exception_rule exc_rules_a[] = {{39}, {102}};
  struct landlockd_ir_exception_rule exc_rules_b[] = {{217}};
  struct landlockd_ir_fs_rule fs_rules[] = {
      {.path = "/a", .allowed_access = 0x1}};
  struct landlockd_ir_layer fs_layer = {
      .kind = LANDLOCKD_IR_LAYER_FS,
      .order = 0,
      .handled_access = 0x1,
      .rule_count = 1,
      .fs_rules = fs_rules,
  };
  struct landlockd_ir_layer exc_layer_a = {
      .kind = LANDLOCKD_IR_LAYER_EXCEPTION,
      .order = 1,
      .handled_access = 0,
      .rule_count = 2,
      .exception_rules = exc_rules_a,
  };
  struct landlockd_ir_layer exc_layer_b = {
      .kind = LANDLOCKD_IR_LAYER_EXCEPTION,
      .order = 2,
      .handled_access = 0,
      .rule_count = 1,
      .exception_rules = exc_rules_b,
  };
  const struct landlockd_ir_layer *mixed_layers[] = {&fs_layer, &exc_layer_a,
                                                     &exc_layer_b};
  struct landlockd_ir_policy policy = {
      .name = "unit",
      .layer_count = 3,
      .layers = mixed_layers,
  };

  const struct landlockd_ir_layer *fs_only[] = {&fs_layer};
  struct landlockd_ir_policy fs_only_policy = {
      .name = "fs-only",
      .layer_count = 1,
      .layers = fs_only,
  };

  struct landlockd_ir_exception_rule bad_rule = {.syscall_nr = -1};
  struct landlockd_ir_layer bad_exc_layer = {
      .kind = LANDLOCKD_IR_LAYER_EXCEPTION,
      .order = 0,
      .handled_access = 0,
      .rule_count = 1,
      .exception_rules = &bad_rule,
  };
  const struct landlockd_ir_layer *bad_layers[] = {&bad_exc_layer};
  struct landlockd_ir_policy bad_policy = {
      .name = "bad",
      .layer_count = 1,
      .layers = bad_layers,
  };

  struct landlockd_seccomp_plan p;
  int rc;

  plan(9);

  errno = 0;
  rc = landlockd_policy_compile_exceptions(NULL, &p);
  ok(rc == -1 && errno == EINVAL,
     "compile_exceptions rejects a NULL policy with EINVAL");

  errno = 0;
  rc = landlockd_policy_compile_exceptions(&policy, NULL);
  ok(rc == -1 && errno == EINVAL,
     "compile_exceptions rejects a NULL plan with EINVAL");

  errno = 0;
  rc = landlockd_policy_compile_exceptions(&bad_policy, &p);
  ok(rc == -1 && errno == EINVAL,
     "compile_exceptions rejects a malformed exception rule via IR validation");

  errno = 0;
  rc = landlockd_policy_compile_exceptions(&fs_only_policy, &p);
  ok(rc == 0 && p.count == 0,
     "compile_exceptions on a policy without exception layers yields an empty plan");

  errno = 0;
  rc = landlockd_policy_compile_exceptions(&policy, &p);
  ok(rc == 0 && p.count == 3,
     "compile_exceptions lowers every declared exception rule into the plan");

  ok(p.syscall_nrs[0] == 39 && p.syscall_nrs[1] == 102 &&
         p.syscall_nrs[2] == 217,
     "compile_exceptions preserves IR-declared order across layers");

  {
    struct landlockd_ir_exception_rule many[LANDLOCKD_SECCOMP_MAX_EXCEPTIONS + 1];
    struct landlockd_ir_layer overflow_layer = {
        .kind = LANDLOCKD_IR_LAYER_EXCEPTION,
        .order = 0,
        .handled_access = 0,
        .rule_count = LANDLOCKD_SECCOMP_MAX_EXCEPTIONS + 1,
        .exception_rules = many,
    };
    const struct landlockd_ir_layer *overflow_layers[] = {&overflow_layer};
    struct landlockd_ir_policy overflow_policy = {
        .name = "overflow",
        .layer_count = 1,
        .layers = overflow_layers,
    };
    int i;
    int leaked;

    for (i = 0; i < LANDLOCKD_SECCOMP_MAX_EXCEPTIONS + 1; i++) {
      many[i].syscall_nr = 10 + i;
    }

    p.count = 0xCAFE;
    for (i = 0; i < LANDLOCKD_SECCOMP_MAX_EXCEPTIONS; i++) {
      p.syscall_nrs[i] = 0x5A5A5A5A;
    }

    errno = 0;
    rc = landlockd_policy_compile_exceptions(&overflow_policy, &p);
    ok(rc == -1 && errno == ENOSPC,
       "compile_exceptions surfaces ENOSPC when the plan overflows");
    ok(p.count == 0,
       "compile_exceptions resets plan->count after overflow");

    leaked = 0;
    for (i = 0; i < LANDLOCKD_SECCOMP_MAX_EXCEPTIONS; i++) {
      if (p.syscall_nrs[i] >= 10 &&
          p.syscall_nrs[i] < 10 + LANDLOCKD_SECCOMP_MAX_EXCEPTIONS) {
        leaked = 1;
      }
    }
    ok(!leaked,
       "compile_exceptions exposes no partially compiled syscall numbers after overflow");
  }

  done_testing();
}
