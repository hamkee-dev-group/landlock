#ifndef LANDLOCKD_POLICY_COMPILER_H
#define LANDLOCKD_POLICY_COMPILER_H

#include "landlockd/policy_ir.h"
#include "landlockd/seccomp.h"

#include <stddef.h>







struct landlockd_compiled_rulesets {
  size_t count;
  int *ruleset_fds;
};

int landlockd_policy_compile_fs(const struct landlockd_ir_policy *policy,
                                struct landlockd_compiled_rulesets *out);
int landlockd_policy_compile_net(const struct landlockd_ir_policy *policy,
                                 struct landlockd_compiled_rulesets *out);
void landlockd_compiled_rulesets_cleanup(
    struct landlockd_compiled_rulesets *compiled);






int landlockd_policy_compile_exceptions(const struct landlockd_ir_policy *policy,
                                        struct landlockd_seccomp_plan *plan);

#endif
