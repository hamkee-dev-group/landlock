#define _GNU_SOURCE

#include "landlockd/seccomp.h"

#include "landlockd/landlock.h"

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((weak)) long landlockd_seccomp_syscall(unsigned int op,
                                                     unsigned int flags,
                                                     void *args) {
  return syscall(SYS_seccomp, op, flags, args);
}

struct landlockd_seccomp_name_map {
  const char *name;
  int nr;
};

static const struct landlockd_seccomp_name_map LANDLOCKD_SECCOMP_NAME_MAP[] = {
#ifdef SYS_getpid
    {"getpid", SYS_getpid},
#endif
#ifdef SYS_getppid
    {"getppid", SYS_getppid},
#endif
#ifdef SYS_openat
    {"openat", SYS_openat},
#endif
#ifdef SYS_openat2
    {"openat2", SYS_openat2},
#endif
#ifdef SYS_mkdirat
    {"mkdirat", SYS_mkdirat},
#endif
#ifdef SYS_unlinkat
    {"unlinkat", SYS_unlinkat},
#endif
#ifdef SYS_renameat2
    {"renameat2", SYS_renameat2},
#endif
#ifdef SYS_symlinkat
    {"symlinkat", SYS_symlinkat},
#endif
#ifdef SYS_linkat
    {"linkat", SYS_linkat},
#endif
#ifdef SYS_socket
    {"socket", SYS_socket},
#endif
#ifdef SYS_connect
    {"connect", SYS_connect},
#endif
#ifdef SYS_mount
    {"mount", SYS_mount},
#endif
#ifdef SYS_umount2
    {"umount2", SYS_umount2},
#endif
#ifdef SYS_pivot_root
    {"pivot_root", SYS_pivot_root},
#endif
#ifdef SYS_open_tree
    {"open_tree", SYS_open_tree},
#endif
#ifdef SYS_move_mount
    {"move_mount", SYS_move_mount},
#endif
#ifdef SYS_fsopen
    {"fsopen", SYS_fsopen},
#endif
#ifdef SYS_fsconfig
    {"fsconfig", SYS_fsconfig},
#endif
#ifdef SYS_fsmount
    {"fsmount", SYS_fsmount},
#endif
#ifdef SYS_mount_setattr
    {"mount_setattr", SYS_mount_setattr},
#endif
#ifdef SYS_unshare
    {"unshare", SYS_unshare},
#endif
#ifdef SYS_setns
    {"setns", SYS_setns},
#endif
#ifdef SYS_clone3
    {"clone3", SYS_clone3},
#endif
#ifdef SYS_ptrace
    {"ptrace", SYS_ptrace},
#endif
#ifdef SYS_bpf
    {"bpf", SYS_bpf},
#endif
#ifdef SYS_perf_event_open
    {"perf_event_open", SYS_perf_event_open},
#endif
#ifdef SYS_kexec_load
    {"kexec_load", SYS_kexec_load},
#endif
#ifdef SYS_init_module
    {"init_module", SYS_init_module},
#endif
#ifdef SYS_finit_module
    {"finit_module", SYS_finit_module},
#endif
#ifdef SYS_delete_module
    {"delete_module", SYS_delete_module},
#endif
#ifdef SYS_open_by_handle_at
    {"open_by_handle_at", SYS_open_by_handle_at},
#endif
#ifdef SYS_swapon
    {"swapon", SYS_swapon},
#endif
#ifdef SYS_swapoff
    {"swapoff", SYS_swapoff},
#endif
#ifdef SYS_reboot
    {"reboot", SYS_reboot},
#endif
};

int landlockd_seccomp_plan_init(struct landlockd_seccomp_plan *plan) {
  int i;

  if (plan == NULL) {
    errno = EINVAL;
    return -1;
  }

  plan->count = 0;
  for (i = 0; i < LANDLOCKD_SECCOMP_MAX_EXCEPTIONS; i++) {
    plan->syscall_nrs[i] = 0;
  }
  return 0;
}

int landlockd_seccomp_plan_add(struct landlockd_seccomp_plan *plan,
                               int syscall_nr) {
  if (plan == NULL || syscall_nr < 0) {
    errno = EINVAL;
    return -1;
  }
  if (plan->count >= LANDLOCKD_SECCOMP_MAX_EXCEPTIONS) {
    errno = ENOSPC;
    return -1;
  }
  plan->syscall_nrs[plan->count++] = syscall_nr;
  return 0;
}

int landlockd_seccomp_syscall_by_name(const char *name, int *out_nr) {
  size_t i;

  if (name == NULL || name[0] == '\0' || out_nr == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (i = 0;
       i < sizeof(LANDLOCKD_SECCOMP_NAME_MAP) /
               sizeof(LANDLOCKD_SECCOMP_NAME_MAP[0]);
       i++) {
    if (strcmp(name, LANDLOCKD_SECCOMP_NAME_MAP[i].name) == 0) {
      *out_nr = LANDLOCKD_SECCOMP_NAME_MAP[i].nr;
      return 0;
    }
  }

  errno = ENOENT;
  return -1;
}

static int landlockd_seccomp_add_hardening_syscalls(
    struct landlockd_seccomp_plan *plan, int allow_mount_ops) {
#ifdef SYS_mount
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_mount) < 0) {
    return -1;
  }
#endif
#ifdef SYS_umount2
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_umount2) < 0) {
    return -1;
  }
#endif
#ifdef SYS_pivot_root
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_pivot_root) < 0) {
    return -1;
  }
#endif
#ifdef SYS_open_tree
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_open_tree) < 0) {
    return -1;
  }
#endif
#ifdef SYS_move_mount
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_move_mount) < 0) {
    return -1;
  }
#endif
#ifdef SYS_fsopen
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_fsopen) < 0) {
    return -1;
  }
#endif
#ifdef SYS_fsconfig
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_fsconfig) < 0) {
    return -1;
  }
#endif
#ifdef SYS_fsmount
  if (!allow_mount_ops && landlockd_seccomp_plan_add(plan, SYS_fsmount) < 0) {
    return -1;
  }
#endif
#ifdef SYS_mount_setattr
  if (!allow_mount_ops &&
      landlockd_seccomp_plan_add(plan, SYS_mount_setattr) < 0) {
    return -1;
  }
#endif
#ifdef SYS_ptrace
  if (landlockd_seccomp_plan_add(plan, SYS_ptrace) < 0) {
    return -1;
  }
#endif
#ifdef SYS_bpf
  if (landlockd_seccomp_plan_add(plan, SYS_bpf) < 0) {
    return -1;
  }
#endif
#ifdef SYS_perf_event_open
  if (landlockd_seccomp_plan_add(plan, SYS_perf_event_open) < 0) {
    return -1;
  }
#endif
#ifdef SYS_kexec_load
  if (landlockd_seccomp_plan_add(plan, SYS_kexec_load) < 0) {
    return -1;
  }
#endif
#ifdef SYS_init_module
  if (landlockd_seccomp_plan_add(plan, SYS_init_module) < 0) {
    return -1;
  }
#endif
#ifdef SYS_finit_module
  if (landlockd_seccomp_plan_add(plan, SYS_finit_module) < 0) {
    return -1;
  }
#endif
#ifdef SYS_delete_module
  if (landlockd_seccomp_plan_add(plan, SYS_delete_module) < 0) {
    return -1;
  }
#endif
#ifdef SYS_open_by_handle_at
  if (landlockd_seccomp_plan_add(plan, SYS_open_by_handle_at) < 0) {
    return -1;
  }
#endif
  return 0;
}

static int landlockd_seccomp_add_daemon_hardening_syscalls(
    struct landlockd_seccomp_plan *plan) {
#ifdef SYS_ptrace
  if (landlockd_seccomp_plan_add(plan, SYS_ptrace) < 0) {
    return -1;
  }
#endif
#ifdef SYS_bpf
  if (landlockd_seccomp_plan_add(plan, SYS_bpf) < 0) {
    return -1;
  }
#endif
#ifdef SYS_perf_event_open
  if (landlockd_seccomp_plan_add(plan, SYS_perf_event_open) < 0) {
    return -1;
  }
#endif
#ifdef SYS_kexec_load
  if (landlockd_seccomp_plan_add(plan, SYS_kexec_load) < 0) {
    return -1;
  }
#endif
#ifdef SYS_init_module
  if (landlockd_seccomp_plan_add(plan, SYS_init_module) < 0) {
    return -1;
  }
#endif
#ifdef SYS_finit_module
  if (landlockd_seccomp_plan_add(plan, SYS_finit_module) < 0) {
    return -1;
  }
#endif
#ifdef SYS_delete_module
  if (landlockd_seccomp_plan_add(plan, SYS_delete_module) < 0) {
    return -1;
  }
#endif
#ifdef SYS_open_by_handle_at
  if (landlockd_seccomp_plan_add(plan, SYS_open_by_handle_at) < 0) {
    return -1;
  }
#endif
#ifdef SYS_swapon
  if (landlockd_seccomp_plan_add(plan, SYS_swapon) < 0) {
    return -1;
  }
#endif
#ifdef SYS_swapoff
  if (landlockd_seccomp_plan_add(plan, SYS_swapoff) < 0) {
    return -1;
  }
#endif
#ifdef SYS_reboot
  if (landlockd_seccomp_plan_add(plan, SYS_reboot) < 0) {
    return -1;
  }
#endif
  return 0;
}

int landlockd_seccomp_install(const struct landlockd_seccomp_plan *plan) {
  struct sock_filter filter[LANDLOCKD_SECCOMP_MAX_EXCEPTIONS + 3];
  struct sock_fprog prog;
  int n;
  int i;
  long fd;

  if (plan == NULL || plan->count <= 0 ||
      plan->count > LANDLOCKD_SECCOMP_MAX_EXCEPTIONS) {
    errno = EINVAL;
    return -1;
  }

  n = 0;
  filter[n++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
  for (i = 0; i < plan->count; i++) {
    unsigned char jt = (unsigned char)(plan->count - i);
    filter[n++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)plan->syscall_nrs[i], jt, 0);
  }
  filter[n++] =
      (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  filter[n++] =
      (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);

  prog.len = (unsigned short)n;
  prog.filter = filter;

  fd = landlockd_seccomp_syscall(SECCOMP_SET_MODE_FILTER,
                                 SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
  if (fd < 0) {
    return -1;
  }
  return (int)fd;
}

int landlockd_seccomp_install_denylist(
    const struct landlockd_seccomp_plan *plan, unsigned short errno_ret) {
  struct sock_filter filter[LANDLOCKD_SECCOMP_MAX_EXCEPTIONS * 2 + 2];
  struct sock_fprog prog;
  int n;
  int i;
  long rc;

  if (plan == NULL || plan->count <= 0 ||
      plan->count > LANDLOCKD_SECCOMP_MAX_EXCEPTIONS) {
    errno = EINVAL;
    return -1;
  }

  n = 0;
  filter[n++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
  for (i = 0; i < plan->count; i++) {
    filter[n++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)plan->syscall_nrs[i], 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned int)errno_ret);
  }
  filter[n++] =
      (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  prog.len = (unsigned short)n;
  prog.filter = filter;

  rc = landlockd_seccomp_syscall(SECCOMP_SET_MODE_FILTER, 0U, &prog);
  if (rc < 0) {
    return -1;
  }
  return 0;
}

int landlockd_seccomp_apply_hardening(void) {
  return landlockd_seccomp_apply_broker_hardening(0);
}

int landlockd_seccomp_apply_broker_hardening(int allow_mount_ops) {
  struct landlockd_seccomp_plan plan;

  if (landlockd_set_no_new_privs() < 0) {
    return -1;
  }
  if (landlockd_seccomp_plan_init(&plan) < 0) {
    return -1;
  }
  if (landlockd_seccomp_add_hardening_syscalls(&plan, allow_mount_ops) < 0) {
    return -1;
  }
  if (plan.count == 0) {
    return 0;
  }
  return landlockd_seccomp_install_denylist(&plan, EPERM);
}

int landlockd_seccomp_apply_daemon_hardening(void) {
  struct landlockd_seccomp_plan plan;

  if (landlockd_set_no_new_privs() < 0) {
    return -1;
  }
  if (landlockd_seccomp_plan_init(&plan) < 0) {
    return -1;
  }
  if (landlockd_seccomp_add_daemon_hardening_syscalls(&plan) < 0) {
    return -1;
  }
  if (plan.count == 0) {
    return 0;
  }
  return landlockd_seccomp_install_denylist(&plan, EPERM);
}
