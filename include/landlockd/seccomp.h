#ifndef LANDLOCKD_SECCOMP_H
#define LANDLOCKD_SECCOMP_H

#define LANDLOCKD_SECCOMP_MAX_EXCEPTIONS 32

struct landlockd_seccomp_plan {
  int syscall_nrs[LANDLOCKD_SECCOMP_MAX_EXCEPTIONS];
  int count;
};

int landlockd_seccomp_plan_init(struct landlockd_seccomp_plan *plan);
int landlockd_seccomp_plan_add(struct landlockd_seccomp_plan *plan,
                               int syscall_nr);
int landlockd_seccomp_syscall_by_name(const char *name, int *out_nr);
int landlockd_seccomp_probe_user_notif(void);
int landlockd_seccomp_install(const struct landlockd_seccomp_plan *plan);
int landlockd_seccomp_install_denylist(
    const struct landlockd_seccomp_plan *plan, unsigned short errno_ret);
int landlockd_seccomp_apply_hardening(void);
int landlockd_seccomp_apply_broker_hardening(int allow_mount_ops);
int landlockd_seccomp_apply_daemon_hardening(void);

#endif
