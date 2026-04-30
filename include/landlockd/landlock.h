#ifndef LANDLOCKD_LANDLOCK_H
#define LANDLOCKD_LANDLOCK_H

#include "landlockd/landlock_compat.h"

#include <stddef.h>
#include <stdint.h>

struct landlockd_seccomp_plan;

int landlock_abi_version(void);
int landlock_probe_abi(int *abi_version);
int landlock_create_ruleset_for_abi(int abi_version,
                                    const struct landlock_ruleset_attr *attr,
                                    unsigned int flags);
int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                            size_t size, unsigned int flags);
int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs);
int landlock_create_net_ruleset(uint64_t requested_access_net,
                                uint64_t *granted_access_net);
int landlock_add_fs_rule(
    int ruleset_fd, const struct landlock_path_beneath_attr *attr,
    unsigned int flags);
int landlock_add_net_rule(int ruleset_fd,
                          const struct landlock_net_port_attr *attr,
                          unsigned int flags);
int landlock_add_rule(int ruleset_fd, int rule_type, const void *rule_attr,
                      unsigned int flags);
int landlock_restrict_self_with_no_new_privs(int ruleset_fd,
                                             unsigned int flags);
int landlock_restrict_self(int ruleset_fd, unsigned int flags);
int landlockd_set_no_new_privs(void);
int landlockd_restrict_self_require_nnp(int ruleset_fd, unsigned int flags);
int landlockd_apply_sandbox(int ruleset_fd, unsigned int flags);
int landlockd_apply_sandbox_with_seccomp(
    int ruleset_fd, const struct landlockd_seccomp_plan *plan,
    int *listener_fd_out);

#endif
