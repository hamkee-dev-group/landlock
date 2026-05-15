#define _GNU_SOURCE

#include "landlockd_exec.h"

#include "landlock_policy_ir.h"
#include "landlock_policy_loader.h"
#include "landlockd/landlock.h"
#include "landlockd_audit.h"
#include "landlockd/preflight.h"
#include "landlockd/seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

struct landlockd_exec_compiled_fs {
  int *fds;
  size_t count;
};

struct landlockd_broker_allowlist {
  char **read_paths;
  size_t read_count;
  char **write_paths;
  size_t write_count;
  char **scratch_paths;
  size_t scratch_count;
  char **export_paths;
  size_t export_count;
  char **mount_tmpfs_paths;
  size_t mount_tmpfs_count;
  struct landlockd_policy_ir_bind_mount_rule *mount_bind_rules;
  size_t mount_bind_count;
  struct landlockd_policy_ir_mount_object_rule *mount_object_rules;
  size_t mount_object_count;
  struct landlockd_policy_ir_broker_addfd_rule *addfd_rules;
  size_t addfd_count;
};

enum landlockd_broker_mount_fd_lease_kind {
  LANDLOCKD_BROKER_MOUNT_FD_LEASE_SOURCE = 1,
  LANDLOCKD_BROKER_MOUNT_FD_LEASE_OBJECT = 2,
};

struct landlockd_broker_mount_fd_lease {
  int remote_fd;
  int kind;
  char *value;
};

struct landlockd_broker_mount_fd_leases {
  struct landlockd_broker_mount_fd_lease *entries;
  size_t count;
};

struct landlockd_broker_fsopen_lease {
  int remote_fd;
  int created;
  char *object_name;
};

struct landlockd_broker_fsopen_leases {
  struct landlockd_broker_fsopen_lease *entries;
  size_t count;
};

static int landlockd_probe_mount_features(int need_tmpfs, int need_bind,
                                          int need_bind_read_only,
                                          int need_proc,
                                          int need_pivot_root,
                                          int need_new_mount_api);
static int landlockd_setup_mount_namespace(void);

static void landlockd_diag(FILE *diag, const char *fmt, ...) {
  va_list ap;

  if (diag == NULL) {
    return;
  }

  va_start(ap, fmt);
  vfprintf(diag, fmt, ap);
  va_end(ap);
  fputc('\n', diag);
  fflush(diag);
}

static int landlockd_join_path(const char *parent_path, const char *basename,
                               char *buf, size_t buf_size) {
  int n;

  if (parent_path == NULL || basename == NULL || buf == NULL || buf_size == 0) {
    errno = EINVAL;
    return -1;
  }

  if (strcmp(parent_path, "/") == 0) {
    n = snprintf(buf, buf_size, "/%s", basename);
  } else {
    n = snprintf(buf, buf_size, "%s/%s", parent_path, basename);
  }
  if (n < 0 || (size_t)n >= buf_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static const char *landlockd_open_access_name(int access_mode) {
  switch (access_mode) {
  case O_RDONLY:
    return "read";
  case O_WRONLY:
    return "write";
  case O_RDWR:
    return "read_write";
  default:
    return "unknown";
  }
}

static const char *landlockd_syscall_name(int nr) {
  switch (nr) {
  case SYS_openat:
    return "openat";
  case SYS_openat2:
    return "openat2";
  case SYS_mkdirat:
    return "mkdirat";
  case SYS_unlinkat:
    return "unlinkat";
  case SYS_renameat2:
    return "renameat2";
  case SYS_symlinkat:
    return "symlinkat";
  case SYS_linkat:
    return "linkat";
#ifdef SYS_move_mount
  case SYS_move_mount:
    return "move_mount";
#endif
#ifdef SYS_open_tree
  case SYS_open_tree:
    return "open_tree";
#endif
#ifdef SYS_mount_setattr
  case SYS_mount_setattr:
    return "mount_setattr";
#endif
#ifdef SYS_fsopen
  case SYS_fsopen:
    return "fsopen";
#endif
#ifdef SYS_fsconfig
  case SYS_fsconfig:
    return "fsconfig";
#endif
#ifdef SYS_fsmount
  case SYS_fsmount:
    return "fsmount";
#endif
  default:
    return "unknown";
  }
}

static void landlockd_audit_run_start(FILE *diag, pid_t child_pid,
                                      const char *policy_file,
                                      const char *argv0) {
  int first_field;

  landlockd_audit_begin(diag, "run.start", &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)child_pid);
  landlockd_audit_field_string(diag, &first_field, "policy_file", policy_file);
  landlockd_audit_field_string(diag, &first_field, "argv0", argv0);
  landlockd_audit_end(diag);
}

static void landlockd_audit_run_exit(FILE *diag, pid_t child_pid, int status) {
  int first_field;

  if (WIFEXITED(status)) {
    landlockd_audit_begin(diag, "run.exit", &first_field);
    landlockd_audit_field_int(diag, &first_field, "pid", (long long)child_pid);
    landlockd_audit_field_int(diag, &first_field, "status",
                              (long long)WEXITSTATUS(status));
    landlockd_audit_end(diag);
    return;
  }

  if (WIFSIGNALED(status)) {
    landlockd_audit_begin(diag, "run.signal", &first_field);
    landlockd_audit_field_int(diag, &first_field, "pid", (long long)child_pid);
    landlockd_audit_field_int(diag, &first_field, "signal",
                              (long long)WTERMSIG(status));
    landlockd_audit_end(diag);
  }
}

static void landlockd_audit_broker_open(FILE *diag,
                                        const struct seccomp_notif *req,
                                        const char *path, const char *scope,
                                        const char *operation,
                                        const char *decision,
                                        int error_value) {
  int first_field;

  landlockd_audit_begin(diag, "broker.open", &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)req->pid);
  landlockd_audit_field_string(diag, &first_field, "syscall",
                               landlockd_syscall_name(req->data.nr));
  landlockd_audit_field_string(diag, &first_field, "scope", scope);
  landlockd_audit_field_string(diag, &first_field, "operation", operation);
  if (path != NULL) {
    landlockd_audit_field_string(diag, &first_field, "path", path);
  }
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  if (error_value != 0) {
    landlockd_audit_field_int(diag, &first_field, "errno",
                              (long long)error_value);
  }
  landlockd_audit_end(diag);
}

static const char *landlockd_audit_broker_operation(const char *event) {
  return strncmp(event, "broker.", 7) == 0 ? event + 7 : event;
}

static void landlockd_audit_broker_path(FILE *diag, const char *event,
                                        const struct seccomp_notif *req,
                                        const char *path,
                                        const char *decision,
                                        int error_value) {
  int first_field;

  landlockd_audit_begin(diag, event, &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)req->pid);
  landlockd_audit_field_string(diag, &first_field, "operation",
                               landlockd_audit_broker_operation(event));
  landlockd_audit_field_string(diag, &first_field, "path", path);
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  if (error_value != 0) {
    landlockd_audit_field_int(diag, &first_field, "errno",
                              (long long)error_value);
  }
  landlockd_audit_end(diag);
}

static void landlockd_audit_broker_paths(FILE *diag, const char *event,
                                         const struct seccomp_notif *req,
                                         const char *old_path,
                                         const char *new_path,
                                         const char *decision,
                                         int error_value) {
  int first_field;

  landlockd_audit_begin(diag, event, &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)req->pid);
  landlockd_audit_field_string(diag, &first_field, "operation",
                               landlockd_audit_broker_operation(event));
  landlockd_audit_field_string(diag, &first_field, "old_path", old_path);
  landlockd_audit_field_string(diag, &first_field, "new_path", new_path);
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  if (error_value != 0) {
    landlockd_audit_field_int(diag, &first_field, "errno",
                              (long long)error_value);
  }
  landlockd_audit_end(diag);
}

static void landlockd_audit_broker_symlink(FILE *diag,
                                           const struct seccomp_notif *req,
                                           const char *target,
                                           const char *path,
                                           const char *decision,
                                           int error_value) {
  int first_field;

  landlockd_audit_begin(diag, "broker.symlink", &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)req->pid);
  landlockd_audit_field_string(diag, &first_field, "operation", "symlink");
  landlockd_audit_field_string(diag, &first_field, "target", target);
  landlockd_audit_field_string(diag, &first_field, "path", path);
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  if (error_value != 0) {
    landlockd_audit_field_int(diag, &first_field, "errno",
                              (long long)error_value);
  }
  landlockd_audit_end(diag);
}

static void landlockd_audit_mount_event(FILE *diag, const char *event,
                                        const char *path,
                                        const char *decision,
                                        int error_value) {
  int first_field;

  landlockd_audit_begin(diag, event, &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)getpid());
  landlockd_audit_field_string(diag, &first_field, "path", path);
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  if (error_value != 0) {
    landlockd_audit_field_int(diag, &first_field, "errno",
                              (long long)error_value);
  }
  landlockd_audit_end(diag);
}

static void landlockd_audit_tmpfs_mount(FILE *diag, const char *path,
                                        const char *decision,
                                        int error_value) {
  landlockd_audit_mount_event(diag, "mount.tmpfs", path, decision,
                              error_value);
}

static void landlockd_audit_proc_mount(FILE *diag, const char *path,
                                       const char *decision,
                                       int error_value) {
  landlockd_audit_mount_event(diag, "mount.proc", path, decision, error_value);
}

static void landlockd_audit_bind_mount(FILE *diag, const char *source,
                                       const char *target, int read_only,
                                       const char *decision,
                                       int error_value) {
  int first_field;

  landlockd_audit_begin(diag, "mount.bind", &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)getpid());
  landlockd_audit_field_string(diag, &first_field, "source", source);
  landlockd_audit_field_string(diag, &first_field, "target", target);
  landlockd_audit_field_int(diag, &first_field, "read_only",
                            (long long)read_only);
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  if (error_value != 0) {
    landlockd_audit_field_int(diag, &first_field, "errno",
                              (long long)error_value);
  }
  landlockd_audit_end(diag);
}

static void landlockd_audit_broker_mount(FILE *diag, const char *event,
                                         const struct seccomp_notif *req,
                                         const char *path,
                                         const char *decision,
                                         int error_value) {
  int first_field;

  landlockd_audit_begin(diag, event, &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)req->pid);
  landlockd_audit_field_string(diag, &first_field, "operation",
                               landlockd_audit_broker_operation(event));
  landlockd_audit_field_string(diag, &first_field, "path", path);
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  if (error_value != 0) {
    landlockd_audit_field_int(diag, &first_field, "errno",
                              (long long)error_value);
  }
  landlockd_audit_end(diag);
}

static void landlockd_exec_cleanup_fs(
    struct landlockd_exec_compiled_fs *compiled) {
  size_t i;

  if (compiled == NULL) {
    return;
  }
  if (compiled->fds != NULL) {
    for (i = 0; i < compiled->count; i++) {
      if (compiled->fds[i] >= 0) {
        close(compiled->fds[i]);
      }
    }
    free(compiled->fds);
  }
  compiled->fds = NULL;
  compiled->count = 0;
}

static int landlockd_exec_compile_fs(
    const struct landlockd_policy_ir *ir,
    struct landlockd_exec_compiled_fs *compiled) {
  struct landlock_path_beneath_attr path_rule;
  int *fds;
  int ruleset_fd;
  int parent_fd;
  int saved_errno;
  size_t i;
  size_t j;

  compiled->fds = NULL;
  compiled->count = 0;

  if (ir->fs_layer_count == 0) {
    return 0;
  }

  fds = calloc(ir->fs_layer_count, sizeof(*fds));
  if (fds == NULL) {
    return -1;
  }
  for (i = 0; i < ir->fs_layer_count; i++) {
    fds[i] = -1;
  }

  for (i = 0; i < ir->fs_layer_count; i++) {
    ruleset_fd =
        landlock_create_fs_ruleset(ir->fs_layers[i].handled_access_fs, NULL);
    if (ruleset_fd < 0) {
      saved_errno = errno;
      compiled->fds = fds;
      compiled->count = ir->fs_layer_count;
      landlockd_exec_cleanup_fs(compiled);
      errno = saved_errno;
      return -1;
    }
    fds[i] = ruleset_fd;

    for (j = 0; j < ir->fs_layers[i].rule_count; j++) {
      parent_fd = open(ir->fs_layers[i].rules[j].path, O_PATH | O_CLOEXEC);
      if (parent_fd < 0) {
        saved_errno = errno;
        compiled->fds = fds;
        compiled->count = ir->fs_layer_count;
        landlockd_exec_cleanup_fs(compiled);
        errno = saved_errno;
        return -1;
      }

      path_rule.allowed_access = ir->fs_layers[i].rules[j].allowed_access;
      path_rule.parent_fd = parent_fd;
      if (landlock_add_fs_rule(ruleset_fd, &path_rule, 0) < 0) {
        saved_errno = errno;
        close(parent_fd);
        compiled->fds = fds;
        compiled->count = ir->fs_layer_count;
        landlockd_exec_cleanup_fs(compiled);
        errno = saved_errno;
        return -1;
      }
      close(parent_fd);
    }
  }

  compiled->fds = fds;
  compiled->count = ir->fs_layer_count;
  return 0;
}

static int landlockd_exec_compile_net(const struct landlockd_policy_ir *ir,
                                      int *net_ruleset_fd_out) {
  struct landlock_net_port_attr net_rule;
  int ruleset_fd;
  int saved_errno;
  size_t i;

  *net_ruleset_fd_out = -1;
  if (!ir->net_enabled) {
    return 0;
  }

  ruleset_fd = landlock_create_net_ruleset(ir->net_handled_access, NULL);
  if (ruleset_fd < 0) {
    return -1;
  }

  for (i = 0; i < ir->net_rule_count; i++) {
    net_rule.port = ir->net_rules[i].port;
    net_rule.allowed_access = ir->net_rules[i].allowed_access;
    if (landlock_add_net_rule(ruleset_fd, &net_rule, 0) < 0) {
      saved_errno = errno;
      close(ruleset_fd);
      errno = saved_errno;
      return -1;
    }
  }

  *net_ruleset_fd_out = ruleset_fd;
  return 0;
}

static void landlockd_broker_allowlist_cleanup(
    struct landlockd_broker_allowlist *allowlist) {
  size_t i;

  if (allowlist == NULL) {
    return;
  }
  if (allowlist->read_paths != NULL) {
    for (i = 0; i < allowlist->read_count; i++) {
      free(allowlist->read_paths[i]);
    }
    free(allowlist->read_paths);
  }
  if (allowlist->write_paths != NULL) {
    for (i = 0; i < allowlist->write_count; i++) {
      free(allowlist->write_paths[i]);
    }
    free(allowlist->write_paths);
  }
  if (allowlist->scratch_paths != NULL) {
    for (i = 0; i < allowlist->scratch_count; i++) {
      free(allowlist->scratch_paths[i]);
    }
    free(allowlist->scratch_paths);
  }
  if (allowlist->export_paths != NULL) {
    for (i = 0; i < allowlist->export_count; i++) {
      free(allowlist->export_paths[i]);
    }
    free(allowlist->export_paths);
  }
  if (allowlist->mount_tmpfs_paths != NULL) {
    for (i = 0; i < allowlist->mount_tmpfs_count; i++) {
      free(allowlist->mount_tmpfs_paths[i]);
    }
    free(allowlist->mount_tmpfs_paths);
  }
  if (allowlist->mount_bind_rules != NULL) {
    for (i = 0; i < allowlist->mount_bind_count; i++) {
      free(allowlist->mount_bind_rules[i].source);
      free(allowlist->mount_bind_rules[i].target);
    }
    free(allowlist->mount_bind_rules);
  }
  if (allowlist->mount_object_rules != NULL) {
    for (i = 0; i < allowlist->mount_object_count; i++) {
      size_t j;

      free(allowlist->mount_object_rules[i].name);
      free(allowlist->mount_object_rules[i].fs_type);
      for (j = 0; j < allowlist->mount_object_rules[i].attach_count; j++) {
        free(allowlist->mount_object_rules[i].attach_paths[j]);
      }
      free(allowlist->mount_object_rules[i].attach_paths);
    }
    free(allowlist->mount_object_rules);
  }
  if (allowlist->addfd_rules != NULL) {
    for (i = 0; i < allowlist->addfd_count; i++) {
      free(allowlist->addfd_rules[i].action);
      free(allowlist->addfd_rules[i].target);
      free(allowlist->addfd_rules[i].mode);
    }
    free(allowlist->addfd_rules);
  }
  allowlist->read_paths = NULL;
  allowlist->read_count = 0;
  allowlist->write_paths = NULL;
  allowlist->write_count = 0;
  allowlist->scratch_paths = NULL;
  allowlist->scratch_count = 0;
  allowlist->export_paths = NULL;
  allowlist->export_count = 0;
  allowlist->mount_tmpfs_paths = NULL;
  allowlist->mount_tmpfs_count = 0;
  allowlist->mount_bind_rules = NULL;
  allowlist->mount_bind_count = 0;
  allowlist->mount_object_rules = NULL;
  allowlist->mount_object_count = 0;
  allowlist->addfd_rules = NULL;
  allowlist->addfd_count = 0;
}

static void landlockd_broker_mount_fd_leases_cleanup(
    struct landlockd_broker_mount_fd_leases *leases) {
  size_t i;

  if (leases == NULL || leases->entries == NULL) {
    if (leases != NULL) {
      leases->count = 0;
    }
    return;
  }
  for (i = 0; i < leases->count; i++) {
    free(leases->entries[i].value);
  }
  free(leases->entries);
  leases->entries = NULL;
  leases->count = 0;
}

static void landlockd_broker_fsopen_leases_cleanup(
    struct landlockd_broker_fsopen_leases *leases) {
  size_t i;

  if (leases == NULL || leases->entries == NULL) {
    if (leases != NULL) {
      leases->count = 0;
    }
    return;
  }
  for (i = 0; i < leases->count; i++) {
    free(leases->entries[i].object_name);
  }
  free(leases->entries);
  leases->entries = NULL;
  leases->count = 0;
}

static int landlockd_broker_mount_fd_lease_add(
    struct landlockd_broker_mount_fd_leases *leases, int remote_fd,
    int kind, const char *value) {
  struct landlockd_broker_mount_fd_lease *grown;
  char *value_copy;

  if (leases == NULL || remote_fd < 0 || value == NULL || value[0] == '\0' ||
      (kind != LANDLOCKD_BROKER_MOUNT_FD_LEASE_SOURCE &&
       kind != LANDLOCKD_BROKER_MOUNT_FD_LEASE_OBJECT)) {
    errno = EINVAL;
    return -1;
  }

  value_copy = strdup(value);
  if (value_copy == NULL) {
    return -1;
  }

  grown = realloc(leases->entries, (leases->count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(value_copy);
    return -1;
  }

  leases->entries = grown;
  leases->entries[leases->count].remote_fd = remote_fd;
  leases->entries[leases->count].kind = kind;
  leases->entries[leases->count].value = value_copy;
  leases->count++;
  return 0;
}

static int landlockd_broker_mount_fd_lease_take(
    struct landlockd_broker_mount_fd_leases *leases, int remote_fd,
    int *kind_out, char **value_out) {
  size_t i;

  if (leases == NULL || kind_out == NULL || value_out == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (i = 0; i < leases->count; i++) {
    if (leases->entries[i].remote_fd == remote_fd) {
      *kind_out = leases->entries[i].kind;
      *value_out = leases->entries[i].value;
      if (i + 1 < leases->count) {
        memmove(&leases->entries[i], &leases->entries[i + 1],
                (leases->count - i - 1) * sizeof(*leases->entries));
      }
      leases->count--;
      if (leases->count == 0) {
        free(leases->entries);
        leases->entries = NULL;
      }
      return 0;
    }
  }

  errno = ENOENT;
  return -1;
}

static int landlockd_broker_fsopen_lease_add(
    struct landlockd_broker_fsopen_leases *leases, int remote_fd,
    const char *object_name) {
  struct landlockd_broker_fsopen_lease *grown;
  char *name_copy;

  if (leases == NULL || remote_fd < 0 || object_name == NULL ||
      object_name[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  name_copy = strdup(object_name);
  if (name_copy == NULL) {
    return -1;
  }
  grown = realloc(leases->entries, (leases->count + 1) * sizeof(*grown));
  if (grown == NULL) {
    free(name_copy);
    return -1;
  }
  leases->entries = grown;
  leases->entries[leases->count].remote_fd = remote_fd;
  leases->entries[leases->count].created = 0;
  leases->entries[leases->count].object_name = name_copy;
  leases->count++;
  return 0;
}

static struct landlockd_broker_fsopen_lease *
landlockd_broker_fsopen_lease_find(struct landlockd_broker_fsopen_leases *leases,
                                   int remote_fd) {
  size_t i;

  if (leases == NULL) {
    errno = EINVAL;
    return NULL;
  }
  for (i = 0; i < leases->count; i++) {
    if (leases->entries[i].remote_fd == remote_fd) {
      return &leases->entries[i];
    }
  }
  errno = ENOENT;
  return NULL;
}

static int landlockd_broker_fsopen_lease_take(
    struct landlockd_broker_fsopen_leases *leases, int remote_fd,
    char **object_name_out, int *created_out) {
  size_t i;

  if (leases == NULL || object_name_out == NULL || created_out == NULL) {
    errno = EINVAL;
    return -1;
  }
  for (i = 0; i < leases->count; i++) {
    if (leases->entries[i].remote_fd == remote_fd) {
      *object_name_out = leases->entries[i].object_name;
      *created_out = leases->entries[i].created;
      if (i + 1 < leases->count) {
        memmove(&leases->entries[i], &leases->entries[i + 1],
                (leases->count - i - 1) * sizeof(*leases->entries));
      }
      leases->count--;
      if (leases->count == 0) {
        free(leases->entries);
        leases->entries = NULL;
      }
      return 0;
    }
  }
  errno = ENOENT;
  return -1;
}

static int landlockd_broker_canonicalize_rules(
    const struct landlockd_policy_ir_broker_open_rule *rules, size_t rule_count,
    char ***paths_out, size_t *count_out) {
  char **paths;
  char *resolved;
  size_t i;

  *paths_out = NULL;
  *count_out = 0;
  if (rule_count == 0) {
    return 0;
  }

  paths = calloc(rule_count, sizeof(*paths));
  if (paths == NULL) {
    return -1;
  }

  for (i = 0; i < rule_count; i++) {
    resolved = realpath(rules[i].path, NULL);
    if (resolved == NULL) {
      size_t j;

      for (j = 0; j < i; j++) {
        free(paths[j]);
      }
      free(paths);
      return -1;
    }
    paths[i] = resolved;
  }

  *paths_out = paths;
  *count_out = rule_count;
  return 0;
}

static int landlockd_broker_canonicalize_bind_rules(
    const struct landlockd_policy_ir_bind_mount_rule *rules, size_t rule_count,
    struct landlockd_policy_ir_bind_mount_rule **rules_out,
    size_t *count_out) {
  struct landlockd_policy_ir_bind_mount_rule *resolved_rules;
  size_t i;

  *rules_out = NULL;
  *count_out = 0;
  if (rule_count == 0) {
    return 0;
  }

  resolved_rules = calloc(rule_count, sizeof(*resolved_rules));
  if (resolved_rules == NULL) {
    return -1;
  }

  for (i = 0; i < rule_count; i++) {
    resolved_rules[i].source = realpath(rules[i].source, NULL);
    if (resolved_rules[i].source == NULL) {
      goto fail;
    }
    resolved_rules[i].target = realpath(rules[i].target, NULL);
    if (resolved_rules[i].target == NULL) {
      goto fail;
    }
    resolved_rules[i].read_only = rules[i].read_only;
  }

  *rules_out = resolved_rules;
  *count_out = rule_count;
  return 0;

fail:
  for (i = 0; i < rule_count; i++) {
    free(resolved_rules[i].source);
    free(resolved_rules[i].target);
  }
  free(resolved_rules);
  return -1;
}

static int landlockd_broker_canonicalize_mount_object_rules(
    const struct landlockd_policy_ir_mount_object_rule *rules, size_t rule_count,
    struct landlockd_policy_ir_mount_object_rule **rules_out,
    size_t *count_out) {
  struct landlockd_policy_ir_mount_object_rule *resolved_rules;
  size_t i;
  size_t j;

  *rules_out = NULL;
  *count_out = 0;
  if (rule_count == 0) {
    return 0;
  }
  resolved_rules = calloc(rule_count, sizeof(*resolved_rules));
  if (resolved_rules == NULL) {
    return -1;
  }
  for (i = 0; i < rule_count; i++) {
    resolved_rules[i].name = strdup(rules[i].name);
    if (resolved_rules[i].name == NULL) {
      goto fail;
    }
    resolved_rules[i].fs_type = strdup(rules[i].fs_type);
    if (resolved_rules[i].fs_type == NULL) {
      goto fail;
    }
    resolved_rules[i].attach_paths =
        calloc(rules[i].attach_count, sizeof(*resolved_rules[i].attach_paths));
    if (resolved_rules[i].attach_paths == NULL) {
      goto fail;
    }
    resolved_rules[i].attach_count = rules[i].attach_count;
    resolved_rules[i].allowed_attr_set = rules[i].allowed_attr_set;
    for (j = 0; j < rules[i].attach_count; j++) {
      resolved_rules[i].attach_paths[j] = realpath(rules[i].attach_paths[j], NULL);
      if (resolved_rules[i].attach_paths[j] == NULL) {
        goto fail;
      }
    }
  }
  *rules_out = resolved_rules;
  *count_out = rule_count;
  return 0;

fail:
  for (i = 0; i < rule_count; i++) {
    free(resolved_rules[i].name);
    free(resolved_rules[i].fs_type);
    if (resolved_rules[i].attach_paths != NULL) {
      for (j = 0; j < resolved_rules[i].attach_count; j++) {
        free(resolved_rules[i].attach_paths[j]);
      }
    }
    free(resolved_rules[i].attach_paths);
  }
  free(resolved_rules);
  return -1;
}

static int landlockd_broker_canonicalize_addfd_rules(
    const struct landlockd_policy_ir_broker_addfd_rule *rules, size_t rule_count,
    struct landlockd_policy_ir_broker_addfd_rule **rules_out,
    size_t *count_out) {
  struct landlockd_policy_ir_broker_addfd_rule *resolved_rules;
  size_t i;

  *rules_out = NULL;
  *count_out = 0;
  if (rule_count == 0) {
    return 0;
  }

  resolved_rules = calloc(rule_count, sizeof(*resolved_rules));
  if (resolved_rules == NULL) {
    return -1;
  }

  for (i = 0; i < rule_count; i++) {
    resolved_rules[i].action = strdup(rules[i].action);
    if (resolved_rules[i].action == NULL) {
      goto fail;
    }
    resolved_rules[i].target = realpath(rules[i].target, NULL);
    if (resolved_rules[i].target == NULL) {
      goto fail;
    }
    if (rules[i].mode != NULL) {
      resolved_rules[i].mode = strdup(rules[i].mode);
      if (resolved_rules[i].mode == NULL) {
        goto fail;
      }
    }
  }

  *rules_out = resolved_rules;
  *count_out = rule_count;
  return 0;

fail:
  for (i = 0; i < rule_count; i++) {
    free(resolved_rules[i].action);
    free(resolved_rules[i].target);
    free(resolved_rules[i].mode);
  }
  free(resolved_rules);
  return -1;
}

static int landlockd_broker_addfd_allowed(
    const struct landlockd_broker_allowlist *allowlist, const char *action,
    const char *target, const char *mode) {
  size_t i;
  size_t root_len;
  const struct landlockd_policy_ir_broker_addfd_rule *rule;

  if (allowlist == NULL || action == NULL || target == NULL) {
    return 0;
  }
  for (i = 0; i < allowlist->addfd_count; i++) {
    rule = &allowlist->addfd_rules[i];
    if (strcmp(rule->action, action) != 0) {
      continue;
    }
    if (mode != NULL && rule->mode != NULL &&
        strcmp(rule->mode, mode) != 0) {
      continue;
    }
    root_len = strlen(rule->target);
    if (strncmp(rule->target, target, root_len) == 0 &&
        (target[root_len] == '\0' || target[root_len] == '/')) {
      return 1;
    }
  }
  return 0;
}

static int landlockd_broker_mount_object_addfd_covers_action(
    const struct landlockd_broker_allowlist *allowlist, const char *action,
    const struct landlockd_policy_ir_mount_object_rule *rule) {
  size_t i;

  if (rule->attach_count == 0) {
    return 0;
  }
  for (i = 0; i < rule->attach_count; i++) {
    if (!landlockd_broker_addfd_allowed(allowlist, action,
                                        rule->attach_paths[i], NULL)) {
      return 0;
    }
  }
  return 1;
}

static const char *landlockd_broker_addfd_mode_name(int access_mode) {
  if (access_mode == O_RDONLY) {
    return "read";
  }
  return "write";
}

static int landlockd_broker_allowlist_init(
    const struct landlockd_policy_ir *ir,
    struct landlockd_broker_allowlist *allowlist) {
  allowlist->read_paths = NULL;
  allowlist->read_count = 0;
  allowlist->write_paths = NULL;
  allowlist->write_count = 0;
  allowlist->scratch_paths = NULL;
  allowlist->scratch_count = 0;
  allowlist->export_paths = NULL;
  allowlist->export_count = 0;
  allowlist->mount_tmpfs_paths = NULL;
  allowlist->mount_tmpfs_count = 0;
  allowlist->mount_bind_rules = NULL;
  allowlist->mount_bind_count = 0;
  allowlist->mount_object_rules = NULL;
  allowlist->mount_object_count = 0;
  allowlist->addfd_rules = NULL;
  allowlist->addfd_count = 0;

  if (landlockd_broker_canonicalize_rules(
          ir->broker_open_read_rules, ir->broker_open_read_count,
          &allowlist->read_paths, &allowlist->read_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  if (landlockd_broker_canonicalize_rules(
          ir->broker_open_write_rules, ir->broker_open_write_count,
          &allowlist->write_paths, &allowlist->write_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  if (landlockd_broker_canonicalize_rules(
          ir->broker_scratch_rules, ir->broker_scratch_count,
          &allowlist->scratch_paths, &allowlist->scratch_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  if (landlockd_broker_canonicalize_rules(
          ir->broker_export_rules, ir->broker_export_count,
          &allowlist->export_paths, &allowlist->export_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  if (landlockd_broker_canonicalize_rules(
          ir->broker_mount_tmpfs_rules, ir->broker_mount_tmpfs_count,
          &allowlist->mount_tmpfs_paths, &allowlist->mount_tmpfs_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  if (landlockd_broker_canonicalize_bind_rules(
          ir->broker_mount_bind_rules, ir->broker_mount_bind_count,
          &allowlist->mount_bind_rules, &allowlist->mount_bind_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  if (landlockd_broker_canonicalize_mount_object_rules(
          ir->broker_mount_object_rules, ir->broker_mount_object_count,
          &allowlist->mount_object_rules, &allowlist->mount_object_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  if (landlockd_broker_canonicalize_addfd_rules(
          ir->broker_addfd_rules, ir->broker_addfd_count,
          &allowlist->addfd_rules, &allowlist->addfd_count) < 0) {
    landlockd_broker_allowlist_cleanup(allowlist);
    return -1;
  }
  return 0;
}

static int landlockd_run_preflight(const struct landlockd_policy_ir *ir,
                                   FILE *diag) {
  struct landlockd_preflight_report preflight;
  int saved_errno;

  if (landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &preflight) < 0) {
    saved_errno = errno;
    landlockd_diag(diag, "landlockd: preflight probe failed: %s",
                   strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }

  if (preflight.probe_errno == ENOSYS || preflight.probe_errno == EOPNOTSUPP) {
    errno = preflight.probe_errno;
    landlockd_diag(diag,
                   "landlockd: Landlock is unavailable on this kernel (%s)",
                   strerror(preflight.probe_errno));
    return -1;
  }

  if (!preflight.meets_abi_floor) {
    errno = ENOSYS;
    landlockd_diag(diag, "landlockd: Landlock ABI %d is below required floor %d",
                   preflight.abi_version, preflight.required_abi_floor);
    return -1;
  }

  if (ir->net_enabled && preflight.abi_version < 4) {
    errno = ENOSYS;
    landlockd_diag(diag,
                   "landlockd: network policy requires Landlock ABI 4+, got %d",
                   preflight.abi_version);
    return -1;
  }

  if (ir->broker_open_read_count > 0 || ir->broker_open_write_count > 0 ||
      ir->broker_scratch_count > 0 || ir->broker_export_count > 0 ||
      ir->broker_mount_tmpfs_count > 0 || ir->broker_mount_bind_count > 0 ||
      ir->broker_mount_object_count > 0) {
    if (landlockd_preflight_probe_seccomp_user_notif(&preflight) < 0) {
      saved_errno = errno;
      landlockd_diag(diag, "landlockd: seccomp user-notify probe failed: %s",
                     strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    if (!preflight.seccomp_user_notif_supported) {
      errno = preflight.seccomp_probe_errno;
      landlockd_diag(diag,
                     "landlockd: seccomp user-notify is unavailable (%s)",
                     strerror(preflight.seccomp_probe_errno));
      return -1;
    }
  }

  if (ir->mount_tmpfs_count > 0 || ir->mount_bind_count > 0 ||
      ir->mount_proc_count > 0 ||
      ir->broker_mount_tmpfs_count > 0 || ir->broker_mount_bind_count > 0 ||
      ir->broker_mount_object_count > 0 || ir->runtime_root != NULL) {
    int need_bind_read_only;
    int need_bind;
    int need_tmpfs;
    int need_proc;
    int need_new_mount_api;
    size_t i;

    need_bind_read_only = 0;
    need_bind = ir->mount_bind_count > 0 || ir->broker_mount_bind_count > 0 ||
                ir->runtime_root != NULL;
    need_tmpfs = ir->mount_tmpfs_count > 0 || ir->broker_mount_tmpfs_count > 0;
    need_proc = ir->mount_proc_count > 0;
    need_new_mount_api = ir->broker_mount_object_count > 0;
    for (i = 0; i < ir->mount_bind_count; i++) {
      if (ir->mount_bind_rules[i].read_only) {
        need_bind_read_only = 1;
        break;
      }
    }
    if (!need_bind_read_only) {
      for (i = 0; i < ir->broker_mount_bind_count; i++) {
        if (ir->broker_mount_bind_rules[i].read_only) {
          need_bind_read_only = 1;
          break;
        }
      }
    }
    for (i = 0; i < ir->broker_mount_object_count; i++) {
      if (strcmp(ir->broker_mount_object_rules[i].fs_type, "proc") == 0) {
        need_proc = 1;
      }
      if (strcmp(ir->broker_mount_object_rules[i].fs_type, "tmpfs") == 0) {
        need_tmpfs = 1;
      }
      if ((ir->broker_mount_object_rules[i].allowed_attr_set &
           (uint64_t)MOUNT_ATTR_RDONLY) != 0) {
        need_bind_read_only = 1;
      }
    }
    if (need_new_mount_api) {
      need_tmpfs = 1;
    }

    if (landlockd_probe_mount_features(need_tmpfs, need_bind,
                                       need_bind_read_only, need_proc,
                                       ir->runtime_root != NULL,
                                       need_new_mount_api) < 0) {
      saved_errno = errno;
      if (ir->runtime_root != NULL) {
        landlockd_diag(diag,
                       "landlockd: runtime.root requires unprivileged user namespaces, bind mounts, and pivot_root (%s)",
                       strerror(saved_errno));
      } else if (ir->broker_mount_object_count > 0) {
        landlockd_diag(diag,
                       "landlockd: mount objects require unprivileged user namespaces and the new mount API (%s)",
                       strerror(saved_errno));
      } else if (ir->mount_proc_count > 0) {
        landlockd_diag(diag,
                       "landlockd: proc mounts require unprivileged user namespaces and proc mounts (%s)",
                       strerror(saved_errno));
      } else if ((ir->mount_tmpfs_count > 0 ||
                  ir->broker_mount_tmpfs_count > 0) &&
                 (ir->mount_bind_count > 0 ||
                  ir->broker_mount_bind_count > 0)) {
        landlockd_diag(
            diag,
            "landlockd: mount rules require unprivileged user namespaces, tmpfs mounts, and bind mounts (%s)",
            strerror(saved_errno));
      } else if (ir->mount_tmpfs_count > 0 ||
                 ir->broker_mount_tmpfs_count > 0) {
        landlockd_diag(diag,
                       "landlockd: tmpfs scratch mounts require unprivileged user namespaces and tmpfs mounts (%s)",
                       strerror(saved_errno));
      } else {
        landlockd_diag(diag,
                       "landlockd: bind mounts require unprivileged user namespaces and bind mounts (%s)",
                       strerror(saved_errno));
      }
      errno = saved_errno;
      return -1;
    }
  }

  return 0;
}

static int landlockd_write_exact_file(const char *path, const char *content) {
  int fd;
  size_t len;
  ssize_t nwritten;

  fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  len = strlen(content);
  nwritten = write(fd, content, len);
  close(fd);
  if (nwritten < 0 || (size_t)nwritten != len) {
    if (nwritten >= 0) {
      errno = EIO;
    }
    return -1;
  }
  return 0;
}

static int landlockd_probe_mount_features(int need_tmpfs, int need_bind,
                                          int need_bind_read_only,
                                          int need_proc,
                                          int need_pivot_root,
                                          int need_new_mount_api) {
  char root[] = "/tmp/landlockd-mount-probe-XXXXXX";
  char bind_source[PATH_MAX];
  char bind_target[PATH_MAX];
  char tmpfs_target[PATH_MAX];
  char proc_target[PATH_MAX];
  pid_t pid;
  int status;

  if (mkdtemp(root) == NULL) {
    return -1;
  }

  if (need_bind) {
    if (snprintf(bind_source, sizeof(bind_source), "%s/source", root) >=
            (int)sizeof(bind_source) ||
        snprintf(bind_target, sizeof(bind_target), "%s/target", root) >=
            (int)sizeof(bind_target)) {
      rmdir(root);
      errno = ENAMETOOLONG;
      return -1;
    }
    if (mkdir(bind_source, 0700) < 0 || mkdir(bind_target, 0700) < 0) {
      status = errno;
      rmdir(bind_target);
      rmdir(bind_source);
      rmdir(root);
      errno = status;
      return -1;
    }
  }

  if (need_tmpfs) {
    if (snprintf(tmpfs_target, sizeof(tmpfs_target), "%s/tmpfs", root) >=
        (int)sizeof(tmpfs_target)) {
      if (need_bind) {
        rmdir(bind_target);
        rmdir(bind_source);
      }
      rmdir(root);
      errno = ENAMETOOLONG;
      return -1;
    }
    if (mkdir(tmpfs_target, 0700) < 0) {
      status = errno;
      if (need_bind) {
        rmdir(bind_target);
        rmdir(bind_source);
      }
      rmdir(root);
      errno = status;
      return -1;
    }
  }

  if (need_proc) {
    if (snprintf(proc_target, sizeof(proc_target), "%s/proc", root) >=
        (int)sizeof(proc_target)) {
      if (need_tmpfs) {
        rmdir(tmpfs_target);
      }
      if (need_bind) {
        rmdir(bind_target);
        rmdir(bind_source);
      }
      rmdir(root);
      errno = ENAMETOOLONG;
      return -1;
    }
    if (mkdir(proc_target, 0700) < 0) {
      status = errno;
      if (need_tmpfs) {
        rmdir(tmpfs_target);
      }
      if (need_bind) {
        rmdir(bind_target);
        rmdir(bind_source);
      }
      rmdir(root);
      errno = status;
      return -1;
    }
  }

  pid = fork();
  if (pid < 0) {
    status = errno;
    if (need_tmpfs) {
      rmdir(tmpfs_target);
    }
    if (need_proc) {
      rmdir(proc_target);
    }
    if (need_bind) {
      rmdir(bind_target);
      rmdir(bind_source);
    }
    rmdir(root);
    errno = status;
    return -1;
  }
  if (pid == 0) {
    if (landlockd_setup_mount_namespace() < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (need_bind) {
      if (mount(bind_source, bind_target, NULL, MS_BIND, NULL) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      if (need_bind_read_only &&
          mount(NULL, bind_target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY,
                NULL) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      if (umount2(bind_target, MNT_DETACH) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      if (need_pivot_root) {
        char old_root[PATH_MAX];

        if (mount(bind_source, bind_source, NULL, MS_BIND, NULL) < 0) {
          _exit(errno > 0 ? errno : 1);
        }
        if (landlockd_join_path(bind_source, ".landlockd-oldroot", old_root,
                                sizeof(old_root)) < 0) {
          _exit(errno > 0 ? errno : 1);
        }
        if (mkdir(old_root, 0700) < 0 || chdir(bind_source) < 0) {
          _exit(errno > 0 ? errno : 1);
        }
#ifdef SYS_pivot_root
        if (syscall(SYS_pivot_root, ".", ".landlockd-oldroot") < 0) {
          _exit(errno > 0 ? errno : 1);
        }
#else
        _exit(ENOSYS);
#endif
        if (chdir("/") < 0 || umount2("/.landlockd-oldroot", MNT_DETACH) < 0 ||
            rmdir("/.landlockd-oldroot") < 0) {
          _exit(errno > 0 ? errno : 1);
        }
      }
    }
    if (need_tmpfs) {
      if (mount("tmpfs", tmpfs_target, "tmpfs", MS_NODEV | MS_NOSUID,
                "mode=700") < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      if (umount2(tmpfs_target, MNT_DETACH) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
    }
    if (need_proc) {
      if (mount("proc", proc_target, "proc",
                MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      if (umount2(proc_target, MNT_DETACH) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
    }
    if (need_new_mount_api) {
#if defined(SYS_fsopen) && defined(SYS_fsconfig) && defined(SYS_fsmount) && \
    defined(SYS_move_mount)
      int fsfd;
      int mntfd;

      fsfd = (int)syscall(SYS_fsopen, "tmpfs", FSOPEN_CLOEXEC);
      if (fsfd < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      if (syscall(SYS_fsconfig, fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      mntfd = (int)syscall(SYS_fsmount, fsfd, FSMOUNT_CLOEXEC, 0U);
      close(fsfd);
      if (mntfd < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      if (syscall(SYS_move_mount, mntfd, "", AT_FDCWD, tmpfs_target,
                  MOVE_MOUNT_F_EMPTY_PATH) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
      close(mntfd);
#ifdef SYS_mount_setattr
      {
        struct mount_attr attr;

        memset(&attr, 0, sizeof(attr));
        attr.attr_set = MOUNT_ATTR_RDONLY;
        if (syscall(SYS_mount_setattr, AT_FDCWD, tmpfs_target, 0U, &attr,
                    sizeof(attr)) < 0) {
          _exit(errno > 0 ? errno : 1);
        }
      }
#endif
      if (umount2(tmpfs_target, MNT_DETACH) < 0) {
        _exit(errno > 0 ? errno : 1);
      }
#else
      _exit(ENOSYS);
#endif
    }
    _exit(0);
  }

  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      status = errno;
      goto out;
    }
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    errno = WIFEXITED(status) ? WEXITSTATUS(status) : EPERM;
    status = -1;
    goto out;
  }
  status = 0;

out:
  if (need_tmpfs) {
    rmdir(tmpfs_target);
  }
  if (need_proc) {
    rmdir(proc_target);
  }
  if (need_bind) {
    rmdir(bind_target);
    rmdir(bind_source);
  }
  rmdir(root);
  return status;
}

static int landlockd_setup_mount_namespace(void) {
  uid_t uid;
  gid_t gid;
  char map[64];
  int n;
  int saved_errno;

  uid = getuid();
  gid = getgid();
  if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
    return -1;
  }

  if (landlockd_write_exact_file("/proc/self/setgroups", "deny\n") < 0 &&
      errno != ENOENT) {
    return -1;
  }

  n = snprintf(map, sizeof(map), "0 %u 1\n", (unsigned int)uid);
  if (n < 0 || (size_t)n >= sizeof(map) ||
      landlockd_write_exact_file("/proc/self/uid_map", map) < 0) {
    return -1;
  }

  n = snprintf(map, sizeof(map), "0 %u 1\n", (unsigned int)gid);
  if (n < 0 || (size_t)n >= sizeof(map) ||
      landlockd_write_exact_file("/proc/self/gid_map", map) < 0) {
    return -1;
  }

  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
    saved_errno = errno;
    errno = saved_errno;
    return -1;
  }
  return 0;
}

static int landlockd_path_is_under(const char *root, const char *path) {
  size_t root_len;

  root_len = strlen(root);
  return strncmp(root, path, root_len) == 0 &&
         (path[root_len] == '\0' || path[root_len] == '/');
}

static int landlockd_path_has_prefix(const char *path, const char *prefix) {
  size_t prefix_len;

  prefix_len = strlen(prefix);
  return strncmp(path, prefix, prefix_len) == 0 &&
         (path[prefix_len] == '\0' || path[prefix_len] == '/');
}

static int landlockd_attach_mount_rules(
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled,
    const char *mount_path) {
  struct landlock_path_beneath_attr path_rule;
  int parent_fd;
  int attached;
  int saved_errno;
  size_t i;
  size_t j;

  attached = 0;
  for (i = 0; i < ir->fs_layer_count; i++) {
    for (j = 0; j < ir->fs_layers[i].rule_count; j++) {
      const char *attach_path;

      if (landlockd_path_is_under(ir->fs_layers[i].rules[j].path,
                                  mount_path)) {
        attach_path = mount_path;
      } else if (landlockd_path_has_prefix(ir->fs_layers[i].rules[j].path,
                                           mount_path)) {
        attach_path = ir->fs_layers[i].rules[j].path;
      } else {
        continue;
      }

      parent_fd = open(attach_path, O_PATH | O_CLOEXEC);
      if (parent_fd < 0) {
        return -1;
      }
      path_rule.allowed_access = ir->fs_layers[i].rules[j].allowed_access;
      path_rule.parent_fd = parent_fd;
      if (landlock_add_fs_rule(fs_compiled->fds[i], &path_rule, 0) < 0) {
        saved_errno = errno;
        close(parent_fd);
        errno = saved_errno;
        return -1;
      }
      close(parent_fd);
      attached = 1;
    }
  }

  if (!attached) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

static int landlockd_bind_mount_self(const char *path) {
  struct stat st;

  if (stat(path, &st) < 0) {
    return -1;
  }
  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }
  if (mount(path, path, NULL, MS_BIND, NULL) < 0) {
    return -1;
  }
  return 0;
}

static int landlockd_setup_tmpfs_mounts(const struct landlockd_policy_ir *ir,
                                        const struct landlockd_exec_compiled_fs *fs_compiled,
                                        FILE *diag) {
  struct stat st;
  size_t i;
  int saved_errno;

  if (ir->mount_tmpfs_count == 0) {
    return 0;
  }

  for (i = 0; i < ir->mount_tmpfs_count; i++) {
    if (stat(ir->mount_tmpfs_rules[i].path, &st) < 0) {
      saved_errno = errno;
      landlockd_audit_tmpfs_mount(diag, ir->mount_tmpfs_rules[i].path, "deny",
                                  saved_errno);
      landlockd_diag(diag, "landlockd: tmpfs mount path %s is unavailable: %s",
                     ir->mount_tmpfs_rules[i].path, strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
      errno = ENOTDIR;
      landlockd_audit_tmpfs_mount(diag, ir->mount_tmpfs_rules[i].path, "deny",
                                  ENOTDIR);
      landlockd_diag(diag, "landlockd: tmpfs mount path %s is not a directory",
                     ir->mount_tmpfs_rules[i].path);
      return -1;
    }
    if (mount("tmpfs", ir->mount_tmpfs_rules[i].path, "tmpfs",
              MS_NODEV | MS_NOSUID, "mode=700") < 0) {
      saved_errno = errno;
      landlockd_audit_tmpfs_mount(diag, ir->mount_tmpfs_rules[i].path, "deny",
                                  saved_errno);
      landlockd_diag(diag, "landlockd: tmpfs mount failed for %s: %s",
                     ir->mount_tmpfs_rules[i].path, strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    if (landlockd_attach_mount_rules(ir, fs_compiled,
                                     ir->mount_tmpfs_rules[i].path) < 0) {
      saved_errno = errno;
      landlockd_audit_tmpfs_mount(diag, ir->mount_tmpfs_rules[i].path, "deny",
                                  saved_errno);
      landlockd_diag(diag,
                     "landlockd: tmpfs mount path %s has no usable Landlock rule after mount: %s",
                     ir->mount_tmpfs_rules[i].path, strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    landlockd_audit_tmpfs_mount(diag, ir->mount_tmpfs_rules[i].path, "allow",
                                0);
  }

  return 0;
}

static int landlockd_apply_bind_mount(
    const char *source, const char *target, int read_only,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled) {
  struct stat source_st;
  struct stat target_st;

  if (stat(source, &source_st) < 0) {
    return -1;
  }
  if (stat(target, &target_st) < 0) {
    return -1;
  }
  if (S_ISDIR(source_st.st_mode) != S_ISDIR(target_st.st_mode)) {
    errno = EINVAL;
    return -1;
  }
  if (!S_ISDIR(source_st.st_mode) && !S_ISREG(source_st.st_mode)) {
    errno = EINVAL;
    return -1;
  }
  if (mount(source, target, NULL, MS_BIND, NULL) < 0) {
    return -1;
  }
  if (read_only &&
      mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
    return -1;
  }
  return landlockd_attach_mount_rules(ir, fs_compiled, target);
}

static int landlockd_setup_bind_mounts(const struct landlockd_policy_ir *ir,
                                       const struct landlockd_exec_compiled_fs *fs_compiled,
                                       FILE *diag) {
  size_t i;
  int saved_errno;

  for (i = 0; i < ir->mount_bind_count; i++) {
    if (landlockd_apply_bind_mount(ir->mount_bind_rules[i].source,
                                   ir->mount_bind_rules[i].target,
                                   ir->mount_bind_rules[i].read_only, ir,
                                   fs_compiled) < 0) {
      saved_errno = errno;
      landlockd_audit_bind_mount(diag, ir->mount_bind_rules[i].source,
                                 ir->mount_bind_rules[i].target,
                                 ir->mount_bind_rules[i].read_only, "deny",
                                 saved_errno);
      landlockd_diag(diag, "landlockd: bind mount failed for %s -> %s: %s",
                     ir->mount_bind_rules[i].source,
                     ir->mount_bind_rules[i].target, strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    landlockd_audit_bind_mount(diag, ir->mount_bind_rules[i].source,
                               ir->mount_bind_rules[i].target,
                               ir->mount_bind_rules[i].read_only, "allow", 0);
  }

  return 0;
}

static int landlockd_setup_proc_mounts(const struct landlockd_policy_ir *ir,
                                       const struct landlockd_exec_compiled_fs *fs_compiled,
                                       FILE *diag) {
  struct stat st;
  size_t i;
  int saved_errno;

  if (ir->mount_proc_count == 0) {
    return 0;
  }

  for (i = 0; i < ir->mount_proc_count; i++) {
    if (stat(ir->mount_proc_rules[i].path, &st) < 0) {
      saved_errno = errno;
      landlockd_audit_proc_mount(diag, ir->mount_proc_rules[i].path, "deny",
                                 saved_errno);
      landlockd_diag(diag, "landlockd: proc mount path %s is unavailable: %s",
                     ir->mount_proc_rules[i].path, strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
      errno = ENOTDIR;
      landlockd_audit_proc_mount(diag, ir->mount_proc_rules[i].path, "deny",
                                 ENOTDIR);
      landlockd_diag(diag, "landlockd: proc mount path %s is not a directory",
                     ir->mount_proc_rules[i].path);
      return -1;
    }
    if (mount("proc", ir->mount_proc_rules[i].path, "proc",
              MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) < 0) {
      saved_errno = errno;
      landlockd_audit_proc_mount(diag, ir->mount_proc_rules[i].path, "deny",
                                 saved_errno);
      landlockd_diag(diag, "landlockd: proc mount failed for %s: %s",
                     ir->mount_proc_rules[i].path, strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    if (landlockd_attach_mount_rules(ir, fs_compiled,
                                     ir->mount_proc_rules[i].path) < 0) {
      saved_errno = errno;
      landlockd_audit_proc_mount(diag, ir->mount_proc_rules[i].path, "deny",
                                 saved_errno);
      landlockd_diag(diag,
                     "landlockd: proc mount path %s has no usable Landlock rule after mount: %s",
                     ir->mount_proc_rules[i].path, strerror(saved_errno));
      errno = saved_errno;
      return -1;
    }
    landlockd_audit_proc_mount(diag, ir->mount_proc_rules[i].path, "allow", 0);
  }

  return 0;
}

static int landlockd_setup_runtime_root(
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled, FILE *diag) {
  char old_root[PATH_MAX];
  int saved_errno;

  if (ir->runtime_root == NULL) {
    return 0;
  }

  if (landlockd_bind_mount_self(ir->runtime_root) < 0) {
    saved_errno = errno;
    landlockd_diag(diag, "landlockd: runtime root bind mount failed for %s: %s",
                   ir->runtime_root, strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
  if (landlockd_attach_mount_rules(ir, fs_compiled, ir->runtime_root) < 0) {
    saved_errno = errno;
    landlockd_diag(
        diag,
        "landlockd: runtime root %s has no usable Landlock rule after mount: %s",
        ir->runtime_root, strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
  if (landlockd_join_path(ir->runtime_root, ".landlockd-oldroot", old_root,
                          sizeof(old_root)) < 0) {
    return -1;
  }
  if (mkdir(old_root, 0700) < 0 && errno != EEXIST) {
    saved_errno = errno;
    landlockd_diag(diag, "landlockd: runtime root oldroot setup failed: %s",
                   strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
  if (chdir(ir->runtime_root) < 0) {
    saved_errno = errno;
    landlockd_diag(diag, "landlockd: runtime root chdir failed for %s: %s",
                   ir->runtime_root, strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
#ifdef SYS_pivot_root
  if (syscall(SYS_pivot_root, ".", ".landlockd-oldroot") < 0) {
    saved_errno = errno;
    landlockd_diag(diag, "landlockd: runtime root pivot_root failed for %s: %s",
                   ir->runtime_root, strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
#else
  errno = ENOSYS;
  return -1;
#endif
  if (chdir("/") < 0 || umount2("/.landlockd-oldroot", MNT_DETACH) < 0 ||
      rmdir("/.landlockd-oldroot") < 0) {
    return -1;
  }
  return 0;
}

static int landlockd_setup_runtime_cwd(const struct landlockd_policy_ir *ir,
                                       FILE *diag) {
  int saved_errno;

  if (ir->runtime_cwd == NULL) {
    return 0;
  }
  if (chdir(ir->runtime_cwd) < 0) {
    saved_errno = errno;
    landlockd_diag(diag, "landlockd: runtime cwd chdir failed for %s: %s",
                   ir->runtime_cwd, strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
  return 0;
}

static int landlockd_setup_policy_mounts(
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled, FILE *diag) {
  int need_mount_namespace;

  need_mount_namespace =
      ir->mount_tmpfs_count > 0 || ir->mount_bind_count > 0 ||
      ir->mount_proc_count > 0 || ir->broker_mount_tmpfs_count > 0 ||
      ir->broker_mount_bind_count > 0 || ir->broker_mount_object_count > 0 ||
      ir->runtime_root != NULL;

  if (!need_mount_namespace && ir->runtime_cwd == NULL) {
    return 0;
  }
  if (need_mount_namespace && landlockd_setup_mount_namespace() < 0) {
    int saved_errno = errno;

    landlockd_diag(diag, "landlockd: mount namespace setup failed: %s",
                   strerror(saved_errno));
    errno = saved_errno;
    return -1;
  }
  if (landlockd_setup_tmpfs_mounts(ir, fs_compiled, diag) < 0) {
    return -1;
  }
  if (landlockd_setup_bind_mounts(ir, fs_compiled, diag) < 0) {
    return -1;
  }
  if (landlockd_setup_proc_mounts(ir, fs_compiled, diag) < 0) {
    return -1;
  }
  if (landlockd_setup_runtime_root(ir, fs_compiled, diag) < 0) {
    return -1;
  }
  return landlockd_setup_runtime_cwd(ir, diag);
}

static int landlockd_send_fd(int sock, int fd) {
  struct msghdr msg;
  struct iovec iov;
  char payload;
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  struct cmsghdr *cmsg;

  memset(&msg, 0, sizeof(msg));
  memset(cmsgbuf, 0, sizeof(cmsgbuf));
  payload = 'L';
  iov.iov_base = &payload;
  iov.iov_len = sizeof(payload);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

  return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int landlockd_recv_fd(int sock) {
  struct msghdr msg;
  struct iovec iov;
  char payload;
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  struct cmsghdr *cmsg;
  int fd;
  ssize_t nread;

  memset(&msg, 0, sizeof(msg));
  memset(cmsgbuf, 0, sizeof(cmsgbuf));
  payload = '\0';
  iov.iov_base = &payload;
  iov.iov_len = sizeof(payload);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);

  nread = recvmsg(sock, &msg, 0);
  if (nread <= 0) {
    errno = EPIPE;
    return -1;
  }

  cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS) {
    errno = EINVAL;
    return -1;
  }

  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  return fd;
}

static ssize_t landlockd_read_tracee_memory(pid_t pid, uint64_t remote_addr,
                                            void *buf, size_t len) {
  struct iovec local_iov;
  struct iovec remote_iov;

  local_iov.iov_base = buf;
  local_iov.iov_len = len;
  remote_iov.iov_base = (void *)(uintptr_t)remote_addr;
  remote_iov.iov_len = len;

  return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

static int landlockd_read_tracee_string(pid_t pid, uint64_t remote_addr,
                                        char *buf, size_t buf_size) {
  size_t off;
  size_t want;
  ssize_t nread;
  size_t i;

  if (buf_size == 0) {
    errno = EINVAL;
    return -1;
  }

  off = 0;
  while (off + 1 < buf_size) {
    want = buf_size - off - 1;
    if (want > 256) {
      want = 256;
    }
    nread = landlockd_read_tracee_memory(pid, remote_addr + off, buf + off, want);
    if (nread <= 0) {
      if (nread == 0) {
        errno = EFAULT;
      }
      return -1;
    }
    for (i = 0; i < (size_t)nread; i++) {
      if (buf[off + i] == '\0') {
        return 0;
      }
    }
    off += (size_t)nread;
  }

  buf[buf_size - 1] = '\0';
  errno = ENAMETOOLONG;
  return -1;
}

static int landlockd_read_proc_link(const char *path, char *buf,
                                    size_t buf_size) {
  ssize_t len;

  len = readlink(path, buf, buf_size - 1);
  if (len < 0) {
    return -1;
  }
  buf[len] = '\0';
  return 0;
}

static int landlockd_resolve_tracee_path(pid_t pid, int dirfd,
                                         const char *requested_path,
                                         char *resolved_path,
                                         size_t resolved_path_size) {
  char base_path[PATH_MAX];
  char joined_path[PATH_MAX];
  char proc_path[PATH_MAX];
  int n;

  if (requested_path[0] == '/') {
    (void)resolved_path_size;
    if (realpath(requested_path, resolved_path) == NULL) {
      return -1;
    }
    return 0;
  }

  if (dirfd == AT_FDCWD) {
    n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/cwd", (int)pid);
  } else {
    n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", (int)pid, dirfd);
  }
  if (n < 0 || (size_t)n >= sizeof(proc_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if (landlockd_read_proc_link(proc_path, base_path, sizeof(base_path)) < 0) {
    return -1;
  }

  n = snprintf(joined_path, sizeof(joined_path), "%s/%s", base_path,
               requested_path);
  if (n < 0 || (size_t)n >= sizeof(joined_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if (realpath(joined_path, resolved_path) == NULL) {
    return -1;
  }
  return 0;
}

static int landlockd_broker_send_errno(int listener_fd, uint64_t id,
                                       int error_value) {
  struct seccomp_notif_resp resp;

  memset(&resp, 0, sizeof(resp));
  resp.id = id;
  resp.error = -error_value;
  resp.val = 0;
  resp.flags = 0;

  if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
    if (errno == ENOENT || errno == ESRCH) {
      return 0;
    }
    return -1;
  }
  return 0;
}

static int landlockd_broker_reply_addfd(int listener_fd, uint64_t id,
                                        int srcfd, unsigned int newfd_flags,
                                        int *remote_fd_out) {
  struct seccomp_notif_addfd addfd;
  struct seccomp_notif_resp resp;
  int remote_fd;

  memset(&addfd, 0, sizeof(addfd));
  addfd.id = id;
  addfd.flags = SECCOMP_ADDFD_FLAG_SEND;
  addfd.srcfd = (uint32_t)srcfd;
  addfd.newfd_flags = newfd_flags;

  remote_fd = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
  if (remote_fd >= 0) {
    if (remote_fd_out != NULL) {
      *remote_fd_out = remote_fd;
    }
    return 0;
  }
  if (errno != EINVAL) {
    if (errno == ENOENT || errno == ESRCH) {
      return 0;
    }
    return -1;
  }

  memset(&addfd, 0, sizeof(addfd));
  addfd.id = id;
  addfd.srcfd = (uint32_t)srcfd;
  addfd.newfd_flags = newfd_flags;
  remote_fd = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
  if (remote_fd < 0) {
    if (errno == ENOENT || errno == ESRCH) {
      return 0;
    }
    return -1;
  }
  if (remote_fd_out != NULL) {
    *remote_fd_out = remote_fd;
  }

  memset(&resp, 0, sizeof(resp));
  resp.id = id;
  resp.val = remote_fd;
  resp.error = 0;
  resp.flags = 0;
  if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
    if (errno == ENOENT || errno == ESRCH) {
      return 0;
    }
    return -1;
  }
  return 0;
}

static int landlockd_broker_path_in_list(char *const *paths, size_t count,
                                         const char *canonical_path) {
  size_t i;

  for (i = 0; i < count; i++) {
    if (strcmp(paths[i], canonical_path) == 0) {
      return 1;
    }
  }
  return 0;
}

static const struct landlockd_policy_ir_bind_mount_rule *
landlockd_broker_find_bind_mount_rule(
    const struct landlockd_policy_ir_bind_mount_rule *rules, size_t count,
    const char *canonical_source, const char *canonical_target) {
  size_t i;

  for (i = 0; i < count; i++) {
    if (strcmp(rules[i].source, canonical_source) == 0 &&
        strcmp(rules[i].target, canonical_target) == 0) {
      return &rules[i];
    }
  }
  return NULL;
}

static const struct landlockd_policy_ir_mount_object_rule *
landlockd_broker_find_mount_object_rule(
    const struct landlockd_policy_ir_mount_object_rule *rules, size_t count,
    const char *name) {
  size_t i;

  for (i = 0; i < count; i++) {
    if (strcmp(rules[i].name, name) == 0) {
      return &rules[i];
    }
  }
  return NULL;
}

static const struct landlockd_policy_ir_mount_object_rule *
landlockd_broker_find_mount_object_rule_for_target(
    const struct landlockd_policy_ir_mount_object_rule *rules, size_t count,
    const char *canonical_target) {
  size_t i;
  size_t j;

  for (i = 0; i < count; i++) {
    for (j = 0; j < rules[i].attach_count; j++) {
      if (strcmp(rules[i].attach_paths[j], canonical_target) == 0) {
        return &rules[i];
      }
    }
  }
  return NULL;
}

static int landlockd_broker_mount_object_target_allowed(
    const struct landlockd_policy_ir_mount_object_rule *rule,
    const char *canonical_target) {
  size_t i;

  if (rule == NULL || canonical_target == NULL) {
    return 0;
  }
  for (i = 0; i < rule->attach_count; i++) {
    if (strcmp(rule->attach_paths[i], canonical_target) == 0) {
      return 1;
    }
  }
  return 0;
}

static int landlockd_broker_bind_target_in_list(
    const struct landlockd_policy_ir_bind_mount_rule *rules, size_t count,
    const char *canonical_target) {
  size_t i;

  for (i = 0; i < count; i++) {
    if (strcmp(rules[i].target, canonical_target) == 0) {
      return 1;
    }
  }
  return 0;
}

static int landlockd_broker_path_under_list(char *const *paths, size_t count,
                                            const char *canonical_path) {
  size_t i;
  size_t root_len;

  for (i = 0; i < count; i++) {
    root_len = strlen(paths[i]);
    if (strncmp(paths[i], canonical_path, root_len) == 0 &&
        (canonical_path[root_len] == '\0' ||
         canonical_path[root_len] == '/')) {
      return 1;
    }
  }
  return 0;
}

static int landlockd_broker_is_allowed(
    const struct landlockd_broker_allowlist *allowlist,
    const char *canonical_path, int access_mode) {
  if (access_mode == O_RDONLY) {
    return landlockd_broker_path_in_list(allowlist->read_paths,
                                         allowlist->read_count,
                                         canonical_path) ||
           landlockd_broker_path_in_list(allowlist->write_paths,
                                         allowlist->write_count,
                                         canonical_path);
  }
  if (access_mode == O_WRONLY || access_mode == O_RDWR) {
    return landlockd_broker_path_in_list(allowlist->write_paths,
                                         allowlist->write_count,
                                         canonical_path);
  }
  return 0;
}

static int landlockd_build_tracee_path(pid_t pid, int dirfd,
                                       const char *requested_path,
                                       char *joined_path,
                                       size_t joined_path_size) {
  char base_path[PATH_MAX];
  char proc_path[PATH_MAX];
  int n;

  if (requested_path[0] == '/') {
    if (strlen(requested_path) >= joined_path_size) {
      errno = ENAMETOOLONG;
      return -1;
    }
    strcpy(joined_path, requested_path);
    return 0;
  }

  if (dirfd == AT_FDCWD) {
    n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/cwd", (int)pid);
  } else {
    n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", (int)pid,
                 dirfd);
  }
  if (n < 0 || (size_t)n >= sizeof(proc_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (landlockd_read_proc_link(proc_path, base_path, sizeof(base_path)) < 0) {
    return -1;
  }

  n = snprintf(joined_path, joined_path_size, "%s/%s", base_path,
               requested_path);
  if (n < 0 || (size_t)n >= joined_path_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int landlockd_split_parent_basename(const char *path, char *parent_path,
                                           size_t parent_path_size,
                                           char *basename,
                                           size_t basename_size) {
  const char *slash;
  size_t parent_len;
  size_t base_len;

  slash = strrchr(path, '/');
  if (slash == NULL) {
    errno = EINVAL;
    return -1;
  }
  base_len = strlen(slash + 1);
  if (base_len == 0 || strcmp(slash + 1, ".") == 0 ||
      strcmp(slash + 1, "..") == 0 || base_len >= basename_size) {
    errno = EINVAL;
    return -1;
  }
  strcpy(basename, slash + 1);

  parent_len = (size_t)(slash - path);
  if (parent_len == 0) {
    parent_len = 1;
  }
  if (parent_len >= parent_path_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(parent_path, path, parent_len);
  parent_path[parent_len] = '\0';
  return 0;
}

static int landlockd_resolve_tracee_parent(pid_t pid, int dirfd,
                                           const char *requested_path,
                                           char *canonical_parent,
                                           size_t canonical_parent_size,
                                           char *basename,
                                           size_t basename_size) {
  char joined_path[PATH_MAX];
  char parent_path[PATH_MAX];

  if (landlockd_build_tracee_path(pid, dirfd, requested_path, joined_path,
                                  sizeof(joined_path)) < 0) {
    return -1;
  }
  if (landlockd_split_parent_basename(joined_path, parent_path,
                                      sizeof(parent_path), basename,
                                      basename_size) < 0) {
    return -1;
  }
  if (realpath(parent_path, canonical_parent) == NULL) {
    return -1;
  }
  if (strlen(canonical_parent) >= canonical_parent_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int landlockd_broker_send_success(int listener_fd, uint64_t id) {
  struct seccomp_notif_resp resp;

  memset(&resp, 0, sizeof(resp));
  resp.id = id;
  resp.error = 0;
  resp.val = 0;
  resp.flags = 0;
  if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
    if (errno == ENOENT || errno == ESRCH) {
      return 0;
    }
    return -1;
  }
  return 0;
}

static int landlockd_broker_open_tracee_namespace(pid_t pid, const char *kind) {
  char proc_path[PATH_MAX];
  int n;

  n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/ns/%s", (int)pid, kind);
  if (n < 0 || (size_t)n >= sizeof(proc_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return open(proc_path, O_RDONLY | O_CLOEXEC);
}

static int landlockd_broker_dup_tracee_fd(pid_t pid, int remote_fd) {
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_getfd)
  int pidfd;
  int local_fd;
  int saved_errno;

  pidfd = (int)syscall(SYS_pidfd_open, pid, 0U);
  if (pidfd >= 0) {
    local_fd = (int)syscall(SYS_pidfd_getfd, pidfd, remote_fd, 0U);
    saved_errno = errno;
    close(pidfd);
    if (local_fd >= 0) {
      return local_fd;
    }
    if (saved_errno != ENOSYS && saved_errno != EPERM &&
        saved_errno != EACCES && saved_errno != EINVAL) {
      errno = saved_errno;
      return -1;
    }
    errno = saved_errno;
  }
#endif
  {
    char proc_path[PATH_MAX];
    int n;

    n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", (int)pid,
                 remote_fd);
    if (n < 0 || (size_t)n >= sizeof(proc_path)) {
      errno = ENAMETOOLONG;
      return -1;
    }
    return open(proc_path, O_RDONLY | O_CLOEXEC);
  }
}

static int landlockd_broker_enter_tracee_mount_namespace(pid_t pid) {
  int user_fd;
  int mount_fd;
  int saved_errno;

  user_fd = landlockd_broker_open_tracee_namespace(pid, "user");
  if (user_fd < 0) {
    return -1;
  }
  mount_fd = landlockd_broker_open_tracee_namespace(pid, "mnt");
  if (mount_fd < 0) {
    saved_errno = errno;
    close(user_fd);
    errno = saved_errno;
    return -1;
  }
  if (setns(user_fd, CLONE_NEWUSER) < 0) {
    saved_errno = errno;
    close(user_fd);
    close(mount_fd);
    errno = saved_errno;
    return -1;
  }
  close(user_fd);
  if (setns(mount_fd, CLONE_NEWNS) < 0) {
    saved_errno = errno;
    close(mount_fd);
    errno = saved_errno;
    return -1;
  }
  close(mount_fd);
  return 0;
}

static int landlockd_broker_wait_helper(pid_t helper_pid) {
  int status;

  while (waitpid(helper_pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return -1;
    }
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) == 0) {
    return WIFEXITED(status) ? 0 : -1;
  }
  errno = WEXITSTATUS(status);
  return -1;
}

static int landlockd_broker_mount_tmpfs_in_tracee_namespace(
    pid_t pid, const char *target_path, unsigned long long flags,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled) {
  unsigned long long allowed_flags;
  unsigned long long effective_flags;
  pid_t helper_pid;

  allowed_flags = (unsigned long long)(MS_RDONLY | MS_NOEXEC | MS_NODEV |
                                       MS_NOSUID);
  if ((flags & ~allowed_flags) != 0U) {
    errno = EACCES;
    return -1;
  }
  effective_flags =
      (flags & (unsigned long long)(MS_RDONLY | MS_NOEXEC)) |
      (unsigned long long)(MS_NODEV | MS_NOSUID);

  helper_pid = fork();
  if (helper_pid < 0) {
    return -1;
  }
  if (helper_pid == 0) {
    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (mount("tmpfs", target_path, "tmpfs", (unsigned long)effective_flags,
              "mode=700") < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (landlockd_attach_mount_rules(ir, fs_compiled, target_path) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    _exit(0);
  }
  return landlockd_broker_wait_helper(helper_pid);
}

static int landlockd_broker_open_tree_in_tracee_namespace(
    pid_t pid, const char *source_path, unsigned int flags) {
#if !defined(SYS_open_tree)
  (void)pid;
  (void)source_path;
  (void)flags;
  errno = ENOSYS;
  return -1;
#else
  int fd_socks[2];
  pid_t helper_pid;
  int tree_fd;
  int status;
  int saved_errno;

  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_socks) < 0) {
    return -1;
  }

  helper_pid = fork();
  if (helper_pid < 0) {
    saved_errno = errno;
    close(fd_socks[0]);
    close(fd_socks[1]);
    errno = saved_errno;
    return -1;
  }
  if (helper_pid == 0) {
    int local_fd;

    close(fd_socks[0]);
    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    local_fd = (int)syscall(SYS_open_tree, AT_FDCWD, source_path, flags);
    if (local_fd < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (landlockd_send_fd(fd_socks[1], local_fd) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    close(local_fd);
    close(fd_socks[1]);
    _exit(0);
  }

  close(fd_socks[1]);
  tree_fd = landlockd_recv_fd(fd_socks[0]);
  saved_errno = errno;
  close(fd_socks[0]);
  while (waitpid(helper_pid, &status, 0) < 0) {
    if (errno != EINTR) {
      if (tree_fd >= 0) {
        close(tree_fd);
      }
      return -1;
    }
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    if (tree_fd >= 0) {
      close(tree_fd);
    }
    errno = WIFEXITED(status) ? WEXITSTATUS(status) : EPERM;
    return -1;
  }
  if (tree_fd < 0) {
    errno = saved_errno;
    return -1;
  }
  return tree_fd;
#endif
}

static int landlockd_broker_fsmount_in_tracee_namespace(
    pid_t pid, const char *fs_type, unsigned int fsmount_flags,
    unsigned int attr_flags) {
#if !defined(SYS_fsopen) || !defined(SYS_fsconfig) || !defined(SYS_fsmount)
  (void)pid;
  (void)fs_type;
  (void)fsmount_flags;
  (void)attr_flags;
  errno = ENOSYS;
  return -1;
#else
  int fd_socks[2];
  pid_t helper_pid;
  int mount_fd;
  int status;
  int saved_errno;

  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_socks) < 0) {
    return -1;
  }
  helper_pid = fork();
  if (helper_pid < 0) {
    saved_errno = errno;
    close(fd_socks[0]);
    close(fd_socks[1]);
    errno = saved_errno;
    return -1;
  }
  if (helper_pid == 0) {
    int fsfd;
    int local_fd;

    close(fd_socks[0]);
    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    fsfd = (int)syscall(SYS_fsopen, fs_type, FSOPEN_CLOEXEC);
    if (fsfd < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (syscall(SYS_fsconfig, fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    local_fd = (int)syscall(SYS_fsmount, fsfd, fsmount_flags, attr_flags);
    close(fsfd);
    if (local_fd < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (landlockd_send_fd(fd_socks[1], local_fd) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    close(local_fd);
    close(fd_socks[1]);
    _exit(0);
  }

  close(fd_socks[1]);
  mount_fd = landlockd_recv_fd(fd_socks[0]);
  saved_errno = errno;
  close(fd_socks[0]);
  while (waitpid(helper_pid, &status, 0) < 0) {
    if (errno != EINTR) {
      if (mount_fd >= 0) {
        close(mount_fd);
      }
      return -1;
    }
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    if (mount_fd >= 0) {
      close(mount_fd);
    }
    errno = WIFEXITED(status) ? WEXITSTATUS(status) : EPERM;
    return -1;
  }
  if (mount_fd < 0) {
    errno = saved_errno;
    return -1;
  }
  return mount_fd;
#endif
}

static int landlockd_broker_bind_mount_in_tracee_namespace(
    pid_t pid, const char *source_path, const char *target_path,
    unsigned long long flags, int read_only,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled) {
  unsigned long long allowed_flags;
  int effective_read_only;
  pid_t helper_pid;

  allowed_flags = (unsigned long long)(MS_BIND | MS_RDONLY);
  if ((flags & ~allowed_flags) != 0U || (flags & MS_BIND) == 0U) {
    errno = EACCES;
    return -1;
  }
  effective_read_only = read_only || ((flags & MS_RDONLY) != 0U);

  helper_pid = fork();
  if (helper_pid < 0) {
    return -1;
  }
  if (helper_pid == 0) {
    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (landlockd_apply_bind_mount(source_path, target_path, effective_read_only,
                                   ir, fs_compiled) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    _exit(0);
  }
  return landlockd_broker_wait_helper(helper_pid);
}

static int landlockd_broker_set_readonly_mount(const char *target_path) {
#ifdef SYS_mount_setattr
  struct mount_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.attr_set = MOUNT_ATTR_RDONLY;
  if (syscall(SYS_mount_setattr, AT_FDCWD, target_path, 0U, &attr,
              sizeof(attr)) == 0) {
    return 0;
  }
  if (errno != ENOSYS && errno != EOPNOTSUPP && errno != EINVAL) {
    return -1;
  }
#endif

  return mount(NULL, target_path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY,
               NULL);
}

static int landlockd_broker_move_mount_in_tracee_namespace(
    pid_t pid, const char *source_path, const char *target_path, int read_only,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled) {
#if !defined(SYS_open_tree) || !defined(SYS_move_mount)
  (void)pid;
  (void)source_path;
  (void)target_path;
  (void)read_only;
  (void)ir;
  (void)fs_compiled;
  errno = ENOSYS;
  return -1;
#else
  pid_t helper_pid;

  helper_pid = fork();
  if (helper_pid < 0) {
    return -1;
  }
  if (helper_pid == 0) {
    int tree_fd;

    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    tree_fd = syscall(SYS_open_tree, AT_FDCWD, source_path,
                      OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (tree_fd < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (syscall(SYS_move_mount, tree_fd, "", AT_FDCWD, target_path,
                MOVE_MOUNT_F_EMPTY_PATH) < 0) {
      int saved_errno = errno;

      close(tree_fd);
      _exit(saved_errno > 0 ? saved_errno : 1);
    }
    close(tree_fd);
    if (read_only && landlockd_broker_set_readonly_mount(target_path) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (landlockd_attach_mount_rules(ir, fs_compiled, target_path) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    _exit(0);
  }
  return landlockd_broker_wait_helper(helper_pid);
#endif
}

static int landlockd_broker_move_mount_fd_in_tracee_namespace(
    pid_t pid, int source_fd, const char *target_path, int read_only,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled) {
#if !defined(SYS_move_mount)
  (void)pid;
  (void)source_fd;
  (void)target_path;
  (void)read_only;
  (void)ir;
  (void)fs_compiled;
  errno = ENOSYS;
  return -1;
#else
  pid_t helper_pid;

  helper_pid = fork();
  if (helper_pid < 0) {
    return -1;
  }
  if (helper_pid == 0) {
    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (syscall(SYS_move_mount, source_fd, "", AT_FDCWD, target_path,
                MOVE_MOUNT_F_EMPTY_PATH) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (read_only && landlockd_broker_set_readonly_mount(target_path) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (landlockd_attach_mount_rules(ir, fs_compiled, target_path) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    _exit(0);
  }
  return landlockd_broker_wait_helper(helper_pid);
#endif
}

static int landlockd_broker_mount_setattr_in_tracee_namespace(
    pid_t pid, const char *target_path, const struct mount_attr *attr) {
#if !defined(SYS_mount_setattr)
  (void)pid;
  (void)target_path;
  (void)attr;
  errno = ENOSYS;
  return -1;
#else
  pid_t helper_pid;

  helper_pid = fork();
  if (helper_pid < 0) {
    return -1;
  }
  if (helper_pid == 0) {
    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (syscall(SYS_mount_setattr, AT_FDCWD, target_path, 0U, attr,
                sizeof(*attr)) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    _exit(0);
  }
  return landlockd_broker_wait_helper(helper_pid);
#endif
}

static int landlockd_broker_handle_fsopen_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist,
    struct landlockd_broker_fsopen_leases *leases, FILE *diag) {
#if !defined(SYS_fsopen)
  (void)listener_fd;
  (void)req;
  (void)allowlist;
  (void)leases;
  (void)diag;
  errno = ENOSYS;
  return -1;
#else
  char object_name[128];
  unsigned int flags;
  const struct landlockd_policy_ir_mount_object_rule *rule;
  int token_fd;
  int remote_fd;
  int error_value;

  object_name[0] = '\0';
  flags = (unsigned int)req->data.args[1];
  remote_fd = -1;
  if (req->data.args[0] == 0 ||
      landlockd_read_tracee_string(req->pid, req->data.args[0], object_name,
                                   sizeof(object_name)) < 0) {
    error_value = errno != 0 ? errno : EINVAL;
    landlockd_audit_broker_mount(diag, "broker.fsopen", req, NULL, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (object_name[0] == '\0' || (flags & ~FSOPEN_CLOEXEC) != 0U) {
    landlockd_audit_broker_mount(diag, "broker.fsopen", req, object_name,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  rule = landlockd_broker_find_mount_object_rule(
      allowlist->mount_object_rules, allowlist->mount_object_count, object_name);
  if (rule == NULL) {
    landlockd_audit_broker_mount(diag, "broker.fsopen", req, object_name,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (!landlockd_broker_mount_object_addfd_covers_action(allowlist, "fsopen",
                                                         rule)) {
    landlockd_audit_broker_mount(diag, "broker.fsopen", req, object_name,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  token_fd = open("/dev/null",
                  O_RDONLY | (((flags & FSOPEN_CLOEXEC) != 0U) ? O_CLOEXEC : 0));
  if (token_fd < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.fsopen", req, object_name,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_broker_reply_addfd(listener_fd, req->id, token_fd,
                                   (flags & FSOPEN_CLOEXEC) != 0U ? O_CLOEXEC
                                                                  : 0U,
                                   &remote_fd) < 0) {
    error_value = errno;
    close(token_fd);
    landlockd_audit_broker_mount(diag, "broker.fsopen", req, object_name,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(token_fd);
  if (remote_fd >= 0 &&
      landlockd_broker_fsopen_lease_add(leases, remote_fd, object_name) < 0) {
    landlockd_audit_broker_mount(diag, "broker.fsopen", req, object_name,
                                 "error", errno);
    return 0;
  }
  landlockd_audit_broker_mount(diag, "broker.fsopen", req, object_name,
                               "allow", 0);
  return 0;
#endif
}

static int landlockd_broker_handle_fsconfig_request(
    int listener_fd, const struct seccomp_notif *req,
    struct landlockd_broker_fsopen_leases *leases, FILE *diag) {
#if !defined(SYS_fsconfig)
  (void)listener_fd;
  (void)req;
  (void)leases;
  (void)diag;
  errno = ENOSYS;
  return -1;
#else
  struct landlockd_broker_fsopen_lease *lease;
  unsigned int cmd;
  int fsfd;

  fsfd = (int)req->data.args[0];
  cmd = (unsigned int)req->data.args[1];
  lease = landlockd_broker_fsopen_lease_find(leases, fsfd);
  if (lease == NULL) {
    landlockd_audit_broker_mount(diag, "broker.fsconfig", req, NULL, "deny",
                                 EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (cmd != FSCONFIG_CMD_CREATE || req->data.args[2] != 0 ||
      req->data.args[3] != 0 || req->data.args[4] != 0 || lease->created) {
    landlockd_audit_broker_mount(diag, "broker.fsconfig", req,
                                 lease->object_name, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  lease->created = 1;
  landlockd_audit_broker_mount(diag, "broker.fsconfig", req,
                               lease->object_name, "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
#endif
}

static int landlockd_broker_handle_fsmount_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist,
    struct landlockd_broker_fsopen_leases *fsopen_leases,
    struct landlockd_broker_mount_fd_leases *mount_fd_leases, FILE *diag) {
#if !defined(SYS_fsmount)
  (void)listener_fd;
  (void)req;
  (void)allowlist;
  (void)fsopen_leases;
  (void)mount_fd_leases;
  (void)diag;
  errno = ENOSYS;
  return -1;
#else
  const struct landlockd_policy_ir_mount_object_rule *rule;
  char *object_name;
  int created;
  int local_fd;
  int remote_fd;
  int error_value;
  int fsfd;
  unsigned int flags;
  unsigned int attr_flags;

  object_name = NULL;
  remote_fd = -1;
  fsfd = (int)req->data.args[0];
  flags = (unsigned int)req->data.args[1];
  attr_flags = (unsigned int)req->data.args[2];
  if ((flags & ~FSMOUNT_CLOEXEC) != 0U) {
    landlockd_audit_broker_mount(diag, "broker.fsmount", req, NULL, "deny",
                                 EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_broker_fsopen_lease_take(fsopen_leases, fsfd, &object_name,
                                         &created) < 0 ||
      !created) {
    free(object_name);
    landlockd_audit_broker_mount(diag, "broker.fsmount", req, NULL, "deny",
                                 EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  rule = landlockd_broker_find_mount_object_rule(
      allowlist->mount_object_rules, allowlist->mount_object_count, object_name);
  if (rule == NULL ||
      (attr_flags & ~(unsigned int)rule->allowed_attr_set) != 0U) {
    free(object_name);
    landlockd_audit_broker_mount(diag, "broker.fsmount", req, NULL, "deny",
                                 EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (!landlockd_broker_mount_object_addfd_covers_action(allowlist, "fsmount",
                                                         rule)) {
    free(object_name);
    landlockd_audit_broker_mount(diag, "broker.fsmount", req, rule->name,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  local_fd = landlockd_broker_fsmount_in_tracee_namespace(req->pid, rule->fs_type,
                                                          flags, attr_flags);
  if (local_fd < 0) {
    error_value = errno;
    free(object_name);
    landlockd_audit_broker_mount(diag, "broker.fsmount", req, rule->name,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_broker_reply_addfd(listener_fd, req->id, local_fd,
                                   (flags & FSMOUNT_CLOEXEC) != 0U ? O_CLOEXEC
                                                                   : 0U,
                                   &remote_fd) < 0) {
    error_value = errno;
    close(local_fd);
    free(object_name);
    landlockd_audit_broker_mount(diag, "broker.fsmount", req, rule->name,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(local_fd);
  if (remote_fd >= 0 &&
      landlockd_broker_mount_fd_lease_add(
          mount_fd_leases, remote_fd, LANDLOCKD_BROKER_MOUNT_FD_LEASE_OBJECT,
          object_name) < 0) {
    free(object_name);
    landlockd_audit_broker_mount(diag, "broker.fsmount", req, rule->name,
                                 "error", errno);
    return 0;
  }
  landlockd_audit_broker_mount(diag, "broker.fsmount", req, rule->name,
                               "allow", 0);
  free(object_name);
  return 0;
#endif
}

static int landlockd_broker_handle_mount_setattr_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
#if !defined(SYS_mount_setattr)
  (void)listener_fd;
  (void)req;
  (void)allowlist;
  (void)diag;
  errno = ENOSYS;
  return -1;
#else
  char target[PATH_MAX];
  char canonical_target[PATH_MAX];
  struct mount_attr attr;
  const struct landlockd_policy_ir_mount_object_rule *rule;
  int dirfd;
  unsigned int flags;
  unsigned long long size;
  int error_value;

  target[0] = '\0';
  dirfd = (int)req->data.args[0];
  flags = (unsigned int)req->data.args[2];
  size = req->data.args[4];
  if (req->data.args[1] == 0 ||
      landlockd_read_tracee_string(req->pid, req->data.args[1], target,
                                   sizeof(target)) < 0) {
    error_value = errno != 0 ? errno : EINVAL;
    landlockd_audit_broker_mount(diag, "broker.mount_setattr", req, NULL,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (target[0] == '\0' || flags != 0U || req->data.args[3] == 0 ||
      size != sizeof(attr) ||
      landlockd_read_tracee_memory(req->pid, req->data.args[3], &attr,
                                   sizeof(attr)) != (ssize_t)sizeof(attr)) {
    landlockd_audit_broker_mount(diag, "broker.mount_setattr", req, target,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_resolve_tracee_path(req->pid, dirfd, target, canonical_target,
                                    sizeof(canonical_target)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.mount_setattr", req, target,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  rule = landlockd_broker_find_mount_object_rule_for_target(
      allowlist->mount_object_rules, allowlist->mount_object_count,
      canonical_target);
  if (rule == NULL || attr.attr_clr != 0 || attr.propagation != 0 ||
      attr.userns_fd != 0 ||
      (attr.attr_set & ~rule->allowed_attr_set) != 0) {
    landlockd_audit_broker_mount(diag, "broker.mount_setattr", req,
                                 canonical_target, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_broker_mount_setattr_in_tracee_namespace(req->pid,
                                                         canonical_target,
                                                         &attr) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.mount_setattr", req,
                                 canonical_target, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  landlockd_audit_broker_mount(diag, "broker.mount_setattr", req,
                               canonical_target, "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
#endif
}

static int landlockd_broker_handle_open_tree_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist,
    struct landlockd_broker_mount_fd_leases *leases, FILE *diag) {
#if !defined(SYS_open_tree)
  (void)listener_fd;
  (void)req;
  (void)allowlist;
  (void)leases;
  (void)diag;
  errno = ENOSYS;
  return -1;
#else
  char requested_path[PATH_MAX];
  char canonical_source[PATH_MAX];
  unsigned int flags;
  int dirfd;
  int tree_fd;
  int remote_fd;
  int error_value;
  size_t i;

  requested_path[0] = '\0';
  flags = (unsigned int)req->data.args[2];
  dirfd = (int)req->data.args[0];
  remote_fd = -1;
  if (req->data.args[1] == 0 ||
      landlockd_read_tracee_string(req->pid, req->data.args[1], requested_path,
                                   sizeof(requested_path)) < 0) {
    error_value = errno != 0 ? errno : EINVAL;
    landlockd_audit_broker_mount(diag, "broker.open_tree", req, NULL, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (requested_path[0] == '\0' ||
      (flags & ~(unsigned int)(OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)) != 0U ||
      (flags & OPEN_TREE_CLONE) == 0U) {
    landlockd_audit_broker_mount(diag, "broker.open_tree", req, requested_path,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_resolve_tracee_path(req->pid, dirfd, requested_path,
                                    canonical_source,
                                    sizeof(canonical_source)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.open_tree", req, requested_path,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  for (i = 0; i < allowlist->mount_bind_count; i++) {
    if (strcmp(allowlist->mount_bind_rules[i].source, canonical_source) == 0) {
      break;
    }
  }
  if (i == allowlist->mount_bind_count) {
    landlockd_audit_broker_mount(diag, "broker.open_tree", req,
                                 canonical_source, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (!landlockd_broker_addfd_allowed(allowlist, "open_tree",
                                      canonical_source, NULL)) {
    landlockd_audit_broker_mount(diag, "broker.open_tree", req,
                                 canonical_source, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  tree_fd = landlockd_broker_open_tree_in_tracee_namespace(
      req->pid, canonical_source,
      (flags & OPEN_TREE_CLOEXEC) != 0 ? OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC
                                       : OPEN_TREE_CLONE);
  if (tree_fd < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.open_tree", req,
                                 canonical_source, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_broker_reply_addfd(listener_fd, req->id, tree_fd,
                                   (flags & OPEN_TREE_CLOEXEC) != 0
                                       ? O_CLOEXEC
                                       : 0U,
                                   &remote_fd) < 0) {
    error_value = errno;
    close(tree_fd);
    landlockd_audit_broker_mount(diag, "broker.open_tree", req,
                                 canonical_source, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(tree_fd);
  if (remote_fd >= 0 &&
      landlockd_broker_mount_fd_lease_add(
          leases, remote_fd, LANDLOCKD_BROKER_MOUNT_FD_LEASE_SOURCE,
          canonical_source) < 0) {
    landlockd_audit_broker_mount(diag, "broker.open_tree", req,
                                 canonical_source, "error", errno);
    return 0;
  }
  landlockd_audit_broker_mount(diag, "broker.open_tree", req, canonical_source,
                               "allow", 0);
  return 0;
#endif
}

static int landlockd_broker_umount_in_tracee_namespace(
    pid_t pid, const char *target_path, int flags) {
  pid_t helper_pid;

  if (flags != 0 && flags != MNT_DETACH) {
    errno = EACCES;
    return -1;
  }

  helper_pid = fork();
  if (helper_pid < 0) {
    return -1;
  }
  if (helper_pid == 0) {
    if (landlockd_broker_enter_tracee_mount_namespace(pid) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    if (umount2(target_path, flags) < 0) {
      _exit(errno > 0 ? errno : 1);
    }
    _exit(0);
  }
  return landlockd_broker_wait_helper(helper_pid);
}

static int landlockd_broker_handle_mount_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled, FILE *diag) {
  char source[PATH_MAX];
  char target[PATH_MAX];
  char fstype[32];
  char canonical_source[PATH_MAX];
  char canonical_target[PATH_MAX];
  char options[128];
  const struct landlockd_policy_ir_bind_mount_rule *bind_rule;
  unsigned long long flags;
  int error_value;

  source[0] = '\0';
  target[0] = '\0';
  fstype[0] = '\0';
  options[0] = '\0';
  flags = req->data.args[3];

  if (req->data.args[0] != 0 &&
      landlockd_read_tracee_string(req->pid, req->data.args[0], source,
                                   sizeof(source)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.mount", req, NULL, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_read_tracee_string(req->pid, req->data.args[1], target,
                                   sizeof(target)) < 0) {
    error_value = errno != 0 ? errno : EINVAL;
    landlockd_audit_broker_mount(diag, "broker.mount", req, target, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (req->data.args[2] != 0 &&
      landlockd_read_tracee_string(req->pid, req->data.args[2], fstype,
                                   sizeof(fstype)) < 0) {
    error_value = errno != 0 ? errno : EINVAL;
    landlockd_audit_broker_mount(diag, "broker.mount", req, target, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (req->data.args[4] != 0 &&
      landlockd_read_tracee_string(req->pid, req->data.args[4], options,
                                   sizeof(options)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.mount", req, target, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if ((flags & MS_BIND) != 0U) {
    if (source[0] == '\0' || req->data.args[2] != 0 || options[0] != '\0') {
      landlockd_audit_broker_mount(diag, "broker.mount", req, target, "deny",
                                   EACCES);
      return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
    }
    if (landlockd_resolve_tracee_path(req->pid, AT_FDCWD, source,
                                      canonical_source,
                                      sizeof(canonical_source)) < 0 ||
        landlockd_resolve_tracee_path(req->pid, AT_FDCWD, target,
                                      canonical_target,
                                      sizeof(canonical_target)) < 0) {
      error_value = errno;
      landlockd_audit_broker_mount(diag, "broker.mount", req, target, "error",
                                   error_value);
      return landlockd_broker_send_errno(listener_fd, req->id, error_value);
    }
    bind_rule = landlockd_broker_find_bind_mount_rule(
        allowlist->mount_bind_rules, allowlist->mount_bind_count,
        canonical_source, canonical_target);
    if (bind_rule == NULL) {
      landlockd_audit_broker_mount(diag, "broker.mount", req, canonical_target,
                                   "deny", EACCES);
      return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
    }
    if (landlockd_broker_bind_mount_in_tracee_namespace(
            req->pid, canonical_source, canonical_target, flags,
            bind_rule->read_only, ir, fs_compiled) < 0) {
      error_value = errno;
      landlockd_audit_broker_mount(diag, "broker.mount", req, canonical_target,
                                   "error", error_value);
      return landlockd_broker_send_errno(listener_fd, req->id, error_value);
    }
    landlockd_audit_broker_mount(diag, "broker.mount", req, canonical_target,
                                 "allow", 0);
    return landlockd_broker_send_success(listener_fd, req->id);
  }

  if ((source[0] != '\0' && strcmp(source, "tmpfs") != 0) ||
      req->data.args[2] == 0 || strcmp(fstype, "tmpfs") != 0 ||
      options[0] != '\0') {
    landlockd_audit_broker_mount(diag, "broker.mount", req, target, "deny",
                                 EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_resolve_tracee_path(req->pid, AT_FDCWD, target,
                                    canonical_target,
                                    sizeof(canonical_target)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.mount", req, target, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_in_list(allowlist->mount_tmpfs_paths,
                                     allowlist->mount_tmpfs_count,
                                     canonical_target)) {
    landlockd_audit_broker_mount(diag, "broker.mount", req, canonical_target,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_broker_mount_tmpfs_in_tracee_namespace(
          req->pid, canonical_target, flags, ir, fs_compiled) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.mount", req, canonical_target,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  landlockd_audit_broker_mount(diag, "broker.mount", req, canonical_target,
                               "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_move_mount_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist,
    struct landlockd_broker_mount_fd_leases *leases,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled, FILE *diag) {
  char source[PATH_MAX];
  char target[PATH_MAX];
  char canonical_source[PATH_MAX];
  char canonical_target[PATH_MAX];
  const struct landlockd_policy_ir_bind_mount_rule *bind_rule;
  const struct landlockd_policy_ir_mount_object_rule *object_rule;
  char *leased_value;
  int lease_kind;
  int from_dfd;
  int to_dfd;
  unsigned int flags;
  int source_fd;
  int error_value;

  source[0] = '\0';
  target[0] = '\0';
  from_dfd = (int)req->data.args[0];
  to_dfd = (int)req->data.args[2];
  flags = (unsigned int)req->data.args[4];
  leased_value = NULL;
  source_fd = -1;

  if (req->data.args[3] == 0 ||
      landlockd_read_tracee_string(req->pid, req->data.args[3], target,
                                   sizeof(target)) < 0) {
    error_value = errno != 0 ? errno : EINVAL;
    landlockd_audit_broker_mount(diag, "broker.move_mount", req, target,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (target[0] == '\0') {
    landlockd_audit_broker_mount(diag, "broker.move_mount", req, target,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_resolve_tracee_path(req->pid, to_dfd, target, canonical_target,
                                    sizeof(canonical_target)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.move_mount", req, target,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  if (req->data.args[1] != 0 &&
      landlockd_read_tracee_string(req->pid, req->data.args[1], source,
                                   sizeof(source)) < 0) {
    error_value = errno != 0 ? errno : EINVAL;
    landlockd_audit_broker_mount(diag, "broker.move_mount", req, target,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  if (req->data.args[1] == 0 || source[0] == '\0') {
    if (flags != MOVE_MOUNT_F_EMPTY_PATH ||
        landlockd_broker_mount_fd_lease_take(leases, from_dfd, &lease_kind,
                                             &leased_value) < 0) {
      landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                   canonical_target, "deny", EACCES);
      return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
    }
    bind_rule = NULL;
    object_rule = NULL;
    if (lease_kind == LANDLOCKD_BROKER_MOUNT_FD_LEASE_SOURCE) {
      bind_rule = landlockd_broker_find_bind_mount_rule(
          allowlist->mount_bind_rules, allowlist->mount_bind_count, leased_value,
          canonical_target);
      if (bind_rule == NULL) {
        free(leased_value);
        landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                     canonical_target, "deny", EACCES);
        return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
      }
    } else if (lease_kind == LANDLOCKD_BROKER_MOUNT_FD_LEASE_OBJECT) {
      object_rule = landlockd_broker_find_mount_object_rule(
          allowlist->mount_object_rules, allowlist->mount_object_count,
          leased_value);
      if (object_rule == NULL ||
          !landlockd_broker_mount_object_target_allowed(object_rule,
                                                        canonical_target)) {
        free(leased_value);
        landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                     canonical_target, "deny", EACCES);
        return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
      }
    } else {
      free(leased_value);
      landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                   canonical_target, "deny", EACCES);
      return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
    }
    source_fd = landlockd_broker_dup_tracee_fd(req->pid, from_dfd);
    if (source_fd < 0) {
      error_value = errno;
      free(leased_value);
      landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                   canonical_target, "error", error_value);
      return landlockd_broker_send_errno(listener_fd, req->id, error_value);
    }
    if (landlockd_broker_move_mount_fd_in_tracee_namespace(
            req->pid, source_fd, canonical_target,
            bind_rule != NULL ? bind_rule->read_only : 0, ir,
            fs_compiled) < 0) {
      error_value = errno;
      close(source_fd);
      free(leased_value);
      landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                   canonical_target, "error", error_value);
      return landlockd_broker_send_errno(listener_fd, req->id, error_value);
    }
    close(source_fd);
    free(leased_value);
    landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                 canonical_target, "allow", 0);
    return landlockd_broker_send_success(listener_fd, req->id);
  }
  if (source[0] == '\0' || flags != 0U ||
      landlockd_resolve_tracee_path(req->pid, from_dfd, source, canonical_source,
                                    sizeof(canonical_source)) < 0) {
    error_value = errno != 0 ? errno : EACCES;
    landlockd_audit_broker_mount(diag, "broker.move_mount", req, target,
                                 (source[0] == '\0' || flags != 0U) ? "deny"
                                                                    : "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  bind_rule = landlockd_broker_find_bind_mount_rule(
      allowlist->mount_bind_rules, allowlist->mount_bind_count,
      canonical_source, canonical_target);
  if (bind_rule == NULL) {
    landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                 canonical_target, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_broker_move_mount_in_tracee_namespace(
          req->pid, canonical_source, canonical_target, bind_rule->read_only, ir,
          fs_compiled) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.move_mount", req,
                                 canonical_target, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  landlockd_audit_broker_mount(diag, "broker.move_mount", req, canonical_target,
                               "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_umount_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
  char target[PATH_MAX];
  char canonical_target[PATH_MAX];
  int flags;
  int error_value;

  target[0] = '\0';
  flags = (int)req->data.args[1];
  if (landlockd_read_tracee_string(req->pid, req->data.args[0], target,
                                   sizeof(target)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.umount", req, NULL, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_resolve_tracee_path(req->pid, AT_FDCWD, target,
                                    canonical_target,
                                    sizeof(canonical_target)) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.umount", req, target, "error",
                                 error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_in_list(allowlist->mount_tmpfs_paths,
                                     allowlist->mount_tmpfs_count,
                                     canonical_target) &&
      !landlockd_broker_bind_target_in_list(allowlist->mount_bind_rules,
                                            allowlist->mount_bind_count,
                                            canonical_target)) {
    landlockd_audit_broker_mount(diag, "broker.umount", req, canonical_target,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (landlockd_broker_umount_in_tracee_namespace(req->pid, canonical_target,
                                                  flags) < 0) {
    error_value = errno;
    landlockd_audit_broker_mount(diag, "broker.umount", req, canonical_target,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  landlockd_audit_broker_mount(diag, "broker.umount", req, canonical_target,
                               "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_scratch_open(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, int dirfd,
    unsigned long long flags, unsigned long long mode, FILE *diag,
    unsigned long long resolve) {
  char requested_path[PATH_MAX];
  char canonical_parent[PATH_MAX];
  char canonical_path[PATH_MAX];
  char basename[NAME_MAX + 1];
  const char *operation_name;
  int access_mode;
  int parent_fd;
  int local_fd;
  int local_open_flags;
  int error_value;

  access_mode = (int)(flags & O_ACCMODE);
  operation_name = (flags & (unsigned long long)O_CREAT) != 0
                       ? "create"
                       : landlockd_open_access_name(access_mode);
  if ((access_mode != O_RDONLY && access_mode != O_WRONLY &&
       access_mode != O_RDWR) ||
      resolve != 0 ||
      (flags &
       ~(unsigned long long)(O_ACCMODE | O_CLOEXEC | O_NOFOLLOW | O_APPEND |
                             O_TRUNC | O_CREAT | O_EXCL | O_DIRECTORY)) != 0) {
    landlockd_audit_broker_open(diag, req, NULL, "scratch", operation_name,
                                "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if ((flags & (unsigned long long)O_CREAT) == 0 && mode != 0) {
    landlockd_audit_broker_open(diag, req, NULL, "scratch", operation_name,
                                "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  requested_path[0] = '\0';
  if (landlockd_read_tracee_string(req->pid, req->data.args[1], requested_path,
                                   sizeof(requested_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_open(diag, req, NULL, "scratch", operation_name,
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_resolve_tracee_parent(req->pid, dirfd, requested_path,
                                      canonical_parent,
                                      sizeof(canonical_parent), basename,
                                      sizeof(basename)) < 0) {
    error_value = errno;
    landlockd_audit_broker_open(diag, req, requested_path, "scratch",
                                operation_name, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_join_path(canonical_parent, basename, canonical_path,
                          sizeof(canonical_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_open(diag, req, requested_path, "scratch",
                                operation_name, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                        allowlist->scratch_count,
                                        canonical_parent)) {
    landlockd_audit_broker_open(diag, req, canonical_path, "scratch",
                                operation_name, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  if (!landlockd_broker_addfd_allowed(
          allowlist, "scratch_open", canonical_path,
          landlockd_broker_addfd_mode_name(access_mode))) {
    landlockd_audit_broker_open(diag, req, canonical_path, "scratch",
                                operation_name, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  parent_fd = open(canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (parent_fd < 0) {
    error_value = errno;
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  local_open_flags = (int)flags | O_CLOEXEC | O_NOFOLLOW;
  local_fd = openat(parent_fd, basename, local_open_flags, (mode_t)mode);
  error_value = errno;
  close(parent_fd);
  if (local_fd < 0) {
    landlockd_audit_broker_open(diag, req, canonical_path, "scratch",
                                operation_name, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  if (landlockd_broker_reply_addfd(listener_fd, req->id, local_fd,
                                   (flags & O_CLOEXEC) ? O_CLOEXEC : 0,
                                   NULL) < 0) {
    error_value = errno;
    close(local_fd);
    landlockd_audit_broker_open(diag, req, canonical_path, "scratch",
                                operation_name, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(local_fd);
  landlockd_audit_broker_open(diag, req, canonical_path, "scratch",
                              operation_name, "allow", 0);
  return 0;
}

static int landlockd_broker_handle_mkdir_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
  char requested_path[PATH_MAX];
  char canonical_parent[PATH_MAX];
  char canonical_path[PATH_MAX];
  char basename[NAME_MAX + 1];
  int dirfd;
  int parent_fd;
  mode_t mode;
  int error_value;

  dirfd = (int)req->data.args[0];
  mode = (mode_t)req->data.args[2];
  requested_path[0] = '\0';
  if (landlockd_read_tracee_string(req->pid, req->data.args[1], requested_path,
                                   sizeof(requested_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_path(diag, "broker.mkdir", req, requested_path,
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_resolve_tracee_parent(req->pid, dirfd, requested_path,
                                      canonical_parent,
                                      sizeof(canonical_parent), basename,
                                      sizeof(basename)) < 0) {
    error_value = errno;
    landlockd_audit_broker_path(diag, "broker.mkdir", req, requested_path,
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_join_path(canonical_parent, basename, canonical_path,
                          sizeof(canonical_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_path(diag, "broker.mkdir", req, requested_path,
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                        allowlist->scratch_count,
                                        canonical_parent)) {
    landlockd_audit_broker_path(diag, "broker.mkdir", req, canonical_path,
                                "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  parent_fd = open(canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (parent_fd < 0) {
    error_value = errno;
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (mkdirat(parent_fd, basename, mode) < 0) {
    error_value = errno;
    close(parent_fd);
    landlockd_audit_broker_path(diag, "broker.mkdir", req, canonical_path,
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(parent_fd);
  landlockd_audit_broker_path(diag, "broker.mkdir", req, canonical_path,
                              "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_unlink_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
  char requested_path[PATH_MAX];
  char canonical_parent[PATH_MAX];
  char canonical_path[PATH_MAX];
  char basename[NAME_MAX + 1];
  int dirfd;
  int parent_fd;
  int flags;
  int error_value;

  dirfd = (int)req->data.args[0];
  flags = (int)req->data.args[2];
  if (flags != 0 && flags != AT_REMOVEDIR) {
    landlockd_audit_broker_path(diag,
                                flags == AT_REMOVEDIR ? "broker.rmdir"
                                                      : "broker.unlink",
                                req, NULL, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  requested_path[0] = '\0';
  if (landlockd_read_tracee_string(req->pid, req->data.args[1], requested_path,
                                   sizeof(requested_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_path(diag,
                                flags == AT_REMOVEDIR ? "broker.rmdir"
                                                      : "broker.unlink",
                                req, requested_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_resolve_tracee_parent(req->pid, dirfd, requested_path,
                                      canonical_parent,
                                      sizeof(canonical_parent), basename,
                                      sizeof(basename)) < 0) {
    error_value = errno;
    landlockd_audit_broker_path(diag,
                                flags == AT_REMOVEDIR ? "broker.rmdir"
                                                      : "broker.unlink",
                                req, requested_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_join_path(canonical_parent, basename, canonical_path,
                          sizeof(canonical_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_path(diag,
                                flags == AT_REMOVEDIR ? "broker.rmdir"
                                                      : "broker.unlink",
                                req, requested_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                        allowlist->scratch_count,
                                        canonical_parent)) {
    landlockd_audit_broker_path(diag,
                                flags == AT_REMOVEDIR ? "broker.rmdir"
                                                      : "broker.unlink",
                                req, canonical_path, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  parent_fd = open(canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (parent_fd < 0) {
    error_value = errno;
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (unlinkat(parent_fd, basename, flags) < 0) {
    error_value = errno;
    close(parent_fd);
    landlockd_audit_broker_path(diag,
                                flags == AT_REMOVEDIR ? "broker.rmdir"
                                                      : "broker.unlink",
                                req, canonical_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(parent_fd);
  landlockd_audit_broker_path(diag,
                              flags == AT_REMOVEDIR ? "broker.rmdir"
                                                    : "broker.unlink",
                              req, canonical_path, "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_rename_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
  char old_requested_path[PATH_MAX];
  char new_requested_path[PATH_MAX];
  char old_canonical_parent[PATH_MAX];
  char new_canonical_parent[PATH_MAX];
  char old_canonical_path[PATH_MAX];
  char new_canonical_path[PATH_MAX];
  char old_basename[NAME_MAX + 1];
  char new_basename[NAME_MAX + 1];
  int olddirfd;
  int newdirfd;
  unsigned int flags;
  int old_parent_fd;
  int new_parent_fd;
  int error_value;

  olddirfd = (int)req->data.args[0];
  newdirfd = (int)req->data.args[2];
  flags = (unsigned int)req->data.args[4];
  if (flags != 0U && flags != RENAME_NOREPLACE) {
    landlockd_audit_broker_paths(diag, "broker.rename", req, NULL, NULL,
                                 "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  old_requested_path[0] = '\0';
  new_requested_path[0] = '\0';
  if (landlockd_read_tracee_string(req->pid, req->data.args[1],
                                   old_requested_path,
                                   sizeof(old_requested_path)) < 0 ||
      landlockd_read_tracee_string(req->pid, req->data.args[3],
                                   new_requested_path,
                                   sizeof(new_requested_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_paths(diag, "broker.rename", req, NULL, NULL,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_resolve_tracee_parent(req->pid, olddirfd, old_requested_path,
                                      old_canonical_parent,
                                      sizeof(old_canonical_parent),
                                      old_basename,
                                      sizeof(old_basename)) < 0 ||
      landlockd_resolve_tracee_parent(req->pid, newdirfd, new_requested_path,
                                      new_canonical_parent,
                                      sizeof(new_canonical_parent),
                                      new_basename,
                                      sizeof(new_basename)) < 0) {
    error_value = errno;
    landlockd_audit_broker_paths(diag, "broker.rename", req, old_requested_path,
                                 new_requested_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_join_path(old_canonical_parent, old_basename, old_canonical_path,
                          sizeof(old_canonical_path)) < 0 ||
      landlockd_join_path(new_canonical_parent, new_basename, new_canonical_path,
                          sizeof(new_canonical_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_paths(diag, "broker.rename", req, old_requested_path,
                                 new_requested_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                        allowlist->scratch_count,
                                        old_canonical_parent) ||
      (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                         allowlist->scratch_count,
                                         new_canonical_parent) &&
       !landlockd_broker_path_under_list(allowlist->export_paths,
                                         allowlist->export_count,
                                         new_canonical_parent))) {
    landlockd_audit_broker_paths(diag, "broker.rename", req, old_canonical_path,
                                 new_canonical_path, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  old_parent_fd = open(old_canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (old_parent_fd < 0) {
    error_value = errno;
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  new_parent_fd = open(new_canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (new_parent_fd < 0) {
    error_value = errno;
    close(old_parent_fd);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (syscall(SYS_renameat2, old_parent_fd, old_basename, new_parent_fd,
              new_basename, flags) < 0) {
    error_value = errno;
    close(old_parent_fd);
    close(new_parent_fd);
    landlockd_audit_broker_paths(diag, "broker.rename", req, old_canonical_path,
                                 new_canonical_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(old_parent_fd);
  close(new_parent_fd);
  landlockd_audit_broker_paths(diag, "broker.rename", req, old_canonical_path,
                               new_canonical_path, "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_symlink_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
  char target[PATH_MAX];
  char link_requested_path[PATH_MAX];
  char link_canonical_parent[PATH_MAX];
  char link_canonical_path[PATH_MAX];
  char link_basename[NAME_MAX + 1];
  int newdirfd;
  int parent_fd;
  int error_value;

  newdirfd = (int)req->data.args[1];
  target[0] = '\0';
  link_requested_path[0] = '\0';
  if (landlockd_read_tracee_string(req->pid, req->data.args[0], target,
                                   sizeof(target)) < 0 ||
      landlockd_read_tracee_string(req->pid, req->data.args[2],
                                   link_requested_path,
                                   sizeof(link_requested_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_symlink(diag, req, target, link_requested_path,
                                   "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_resolve_tracee_parent(req->pid, newdirfd, link_requested_path,
                                      link_canonical_parent,
                                      sizeof(link_canonical_parent),
                                      link_basename,
                                      sizeof(link_basename)) < 0) {
    error_value = errno;
    landlockd_audit_broker_symlink(diag, req, target, link_requested_path,
                                   "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_join_path(link_canonical_parent, link_basename,
                          link_canonical_path,
                          sizeof(link_canonical_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_symlink(diag, req, target, link_requested_path,
                                   "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                        allowlist->scratch_count,
                                        link_canonical_parent)) {
    landlockd_audit_broker_symlink(diag, req, target, link_canonical_path,
                                   "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  parent_fd = open(link_canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (parent_fd < 0) {
    error_value = errno;
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (syscall(SYS_symlinkat, target, parent_fd, link_basename) < 0) {
    error_value = errno;
    close(parent_fd);
    landlockd_audit_broker_symlink(diag, req, target, link_canonical_path,
                                   "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(parent_fd);
  landlockd_audit_broker_symlink(diag, req, target, link_canonical_path,
                                 "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_link_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
  char old_requested_path[PATH_MAX];
  char new_requested_path[PATH_MAX];
  char old_canonical_parent[PATH_MAX];
  char new_canonical_parent[PATH_MAX];
  char old_canonical_path[PATH_MAX];
  char new_canonical_path[PATH_MAX];
  char old_basename[NAME_MAX + 1];
  char new_basename[NAME_MAX + 1];
  int olddirfd;
  int newdirfd;
  int old_parent_fd;
  int new_parent_fd;
  int error_value;
  int flags;

  olddirfd = (int)req->data.args[0];
  newdirfd = (int)req->data.args[2];
  flags = (int)req->data.args[4];
  if (flags != 0) {
    landlockd_audit_broker_paths(diag, "broker.link", req, NULL, NULL, "deny",
                                 EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  old_requested_path[0] = '\0';
  new_requested_path[0] = '\0';
  if (landlockd_read_tracee_string(req->pid, req->data.args[1],
                                   old_requested_path,
                                   sizeof(old_requested_path)) < 0 ||
      landlockd_read_tracee_string(req->pid, req->data.args[3],
                                   new_requested_path,
                                   sizeof(new_requested_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_paths(diag, "broker.link", req, NULL, NULL,
                                 "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_resolve_tracee_parent(req->pid, olddirfd, old_requested_path,
                                      old_canonical_parent,
                                      sizeof(old_canonical_parent),
                                      old_basename,
                                      sizeof(old_basename)) < 0 ||
      landlockd_resolve_tracee_parent(req->pid, newdirfd, new_requested_path,
                                      new_canonical_parent,
                                      sizeof(new_canonical_parent),
                                      new_basename,
                                      sizeof(new_basename)) < 0) {
    error_value = errno;
    landlockd_audit_broker_paths(diag, "broker.link", req, old_requested_path,
                                 new_requested_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (landlockd_join_path(old_canonical_parent, old_basename, old_canonical_path,
                          sizeof(old_canonical_path)) < 0 ||
      landlockd_join_path(new_canonical_parent, new_basename, new_canonical_path,
                          sizeof(new_canonical_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_paths(diag, "broker.link", req, old_requested_path,
                                 new_requested_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                        allowlist->scratch_count,
                                        old_canonical_parent) ||
      (!landlockd_broker_path_under_list(allowlist->scratch_paths,
                                         allowlist->scratch_count,
                                         new_canonical_parent) &&
       !landlockd_broker_path_under_list(allowlist->export_paths,
                                         allowlist->export_count,
                                         new_canonical_parent))) {
    landlockd_audit_broker_paths(diag, "broker.link", req, old_canonical_path,
                                 new_canonical_path, "deny", EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  old_parent_fd = open(old_canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (old_parent_fd < 0) {
    error_value = errno;
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  new_parent_fd = open(new_canonical_parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (new_parent_fd < 0) {
    error_value = errno;
    close(old_parent_fd);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  if (syscall(SYS_linkat, old_parent_fd, old_basename, new_parent_fd,
              new_basename, flags) < 0) {
    error_value = errno;
    close(old_parent_fd);
    close(new_parent_fd);
    landlockd_audit_broker_paths(diag, "broker.link", req, old_canonical_path,
                                 new_canonical_path, "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }
  close(old_parent_fd);
  close(new_parent_fd);
  landlockd_audit_broker_paths(diag, "broker.link", req, old_canonical_path,
                               new_canonical_path, "allow", 0);
  return landlockd_broker_send_success(listener_fd, req->id);
}

static int landlockd_broker_handle_open_request(
    int listener_fd, const struct seccomp_notif *req,
    const struct landlockd_broker_allowlist *allowlist, FILE *diag) {
  struct open_how how;
  char requested_path[PATH_MAX];
  char canonical_path[PATH_MAX];
  int dirfd;
  int access_mode;
  int local_open_flags;
  unsigned long long flags;
  unsigned long long mode;
  unsigned long long resolve;
  int local_fd;
  int error_value;

  memset(&how, 0, sizeof(how));
  if (req->data.nr == SYS_openat) {
    dirfd = (int)req->data.args[0];
    flags = req->data.args[2];
    mode = req->data.args[3];
    resolve = 0;
  } else if (req->data.nr == SYS_openat2) {
    dirfd = (int)req->data.args[0];
    if (landlockd_read_tracee_memory(req->pid, req->data.args[2], &how,
                                     sizeof(how)) < 0) {
      landlockd_audit_broker_open(diag, req, NULL, "exception", "unknown",
                                  "error", EFAULT);
      return landlockd_broker_send_errno(listener_fd, req->id, EFAULT);
    }
    flags = how.flags;
    mode = how.mode;
    resolve = how.resolve;
  } else {
    landlockd_audit_broker_open(diag, req, NULL, "exception", "unknown",
                                "error", ENOSYS);
    return landlockd_broker_send_errno(listener_fd, req->id, ENOSYS);
  }

  access_mode = (int)(flags & O_ACCMODE);
  if ((access_mode != O_RDONLY && access_mode != O_WRONLY &&
       access_mode != O_RDWR) ||
      mode != 0 || resolve != 0 ||
      (flags &
      ~(unsigned long long)(O_ACCMODE | O_CLOEXEC | O_NOFOLLOW | O_APPEND |
                             O_TRUNC)) != 0) {
    if (allowlist->scratch_count > 0 &&
        (flags & (unsigned long long)(O_CREAT | O_EXCL)) != 0 &&
        (flags &
         ~(unsigned long long)(O_ACCMODE | O_CLOEXEC | O_NOFOLLOW |
                               O_APPEND | O_TRUNC | O_CREAT | O_EXCL |
                               O_DIRECTORY)) == 0) {
      return landlockd_broker_handle_scratch_open(listener_fd, req, allowlist,
                                                  dirfd, flags, mode, diag,
                                                  resolve);
    }
    landlockd_audit_broker_open(diag, req, NULL, "exception",
                                landlockd_open_access_name(access_mode), "deny",
                                EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }
  if (access_mode == O_RDONLY &&
      (flags & (unsigned long long)(O_APPEND | O_TRUNC)) != 0) {
    landlockd_audit_broker_open(diag, req, NULL, "exception", "read", "deny",
                                EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  requested_path[0] = '\0';
  if (landlockd_read_tracee_string(req->pid, req->data.args[1], requested_path,
                                   sizeof(requested_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_open(diag, req, NULL, "exception",
                                landlockd_open_access_name(access_mode),
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  if (landlockd_resolve_tracee_path(req->pid, dirfd, requested_path,
                                    canonical_path,
                                    sizeof(canonical_path)) < 0) {
    error_value = errno;
    landlockd_audit_broker_open(diag, req, requested_path, "exception",
                                landlockd_open_access_name(access_mode),
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  if (!landlockd_broker_is_allowed(allowlist, canonical_path, access_mode)) {
    if (allowlist->scratch_count > 0) {
      return landlockd_broker_handle_scratch_open(listener_fd, req, allowlist,
                                                  dirfd, flags, mode, diag,
                                                  resolve);
    }
    landlockd_audit_broker_open(diag, req, canonical_path, "exception",
                                landlockd_open_access_name(access_mode), "deny",
                                EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  if (!landlockd_broker_addfd_allowed(
          allowlist, "open", canonical_path,
          landlockd_broker_addfd_mode_name(access_mode))) {
    landlockd_audit_broker_open(diag, req, canonical_path, "exception",
                                landlockd_open_access_name(access_mode), "deny",
                                EACCES);
    return landlockd_broker_send_errno(listener_fd, req->id, EACCES);
  }

  local_open_flags = (int)flags | O_CLOEXEC;
  local_fd = open(canonical_path, local_open_flags);
  if (local_fd < 0) {
    error_value = errno;
    landlockd_audit_broker_open(diag, req, canonical_path, "exception",
                                landlockd_open_access_name(access_mode),
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  if (landlockd_broker_reply_addfd(listener_fd, req->id, local_fd,
                                   (flags & O_CLOEXEC) ? O_CLOEXEC : 0,
                                   NULL) < 0) {
    error_value = errno;
    close(local_fd);
    landlockd_audit_broker_open(diag, req, canonical_path, "exception",
                                landlockd_open_access_name(access_mode),
                                "error", error_value);
    return landlockd_broker_send_errno(listener_fd, req->id, error_value);
  }

  close(local_fd);
  landlockd_audit_broker_open(diag, req, canonical_path, "exception",
                              landlockd_open_access_name(access_mode), "allow",
                              0);
  return 0;
}

static int landlockd_broker_loop(
    int control_sock, const struct landlockd_broker_allowlist *allowlist,
    const struct landlockd_policy_ir *ir,
    const struct landlockd_exec_compiled_fs *fs_compiled, FILE *diag) {
  struct landlockd_broker_mount_fd_leases leases;
  struct landlockd_broker_fsopen_leases fsopen_leases;
  struct seccomp_notif req;
  int listener_fd;

  memset(&leases, 0, sizeof(leases));
  memset(&fsopen_leases, 0, sizeof(fsopen_leases));
  listener_fd = landlockd_recv_fd(control_sock);
  close(control_sock);
  if (listener_fd < 0) {
    return -1;
  }

  for (;;) {
    memset(&req, 0, sizeof(req));
    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == ENOENT || errno == ESRCH || errno == EBADF) {
        break;
      }
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }

    if ((req.data.nr == SYS_openat || req.data.nr == SYS_openat2) &&
        landlockd_broker_handle_open_request(listener_fd, &req, allowlist,
                                             diag) <
            0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
    if (req.data.nr == SYS_mkdirat &&
        landlockd_broker_handle_mkdir_request(listener_fd, &req, allowlist,
                                              diag) <
            0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
    if (req.data.nr == SYS_unlinkat &&
        landlockd_broker_handle_unlink_request(listener_fd, &req, allowlist,
                                               diag) <
            0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
    if (req.data.nr == SYS_renameat2 &&
        landlockd_broker_handle_rename_request(listener_fd, &req, allowlist,
                                               diag) <
            0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
    if (req.data.nr == SYS_symlinkat &&
        landlockd_broker_handle_symlink_request(listener_fd, &req, allowlist,
                                                diag) <
            0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
    if (req.data.nr == SYS_linkat &&
        landlockd_broker_handle_link_request(listener_fd, &req, allowlist,
                                             diag) <
            0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#ifdef SYS_mount
    if (req.data.nr == SYS_mount &&
        landlockd_broker_handle_mount_request(listener_fd, &req, allowlist, ir,
                                              fs_compiled, diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
#ifdef SYS_fsopen
    if (req.data.nr == SYS_fsopen &&
        landlockd_broker_handle_fsopen_request(listener_fd, &req, allowlist,
                                               &fsopen_leases, diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
#ifdef SYS_fsconfig
    if (req.data.nr == SYS_fsconfig &&
        landlockd_broker_handle_fsconfig_request(listener_fd, &req,
                                                 &fsopen_leases, diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
#ifdef SYS_fsmount
    if (req.data.nr == SYS_fsmount &&
        landlockd_broker_handle_fsmount_request(listener_fd, &req, allowlist,
                                                &fsopen_leases, &leases,
                                                diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
#ifdef SYS_open_tree
    if (req.data.nr == SYS_open_tree &&
        landlockd_broker_handle_open_tree_request(listener_fd, &req, allowlist,
                                                  &leases, diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
#ifdef SYS_move_mount
    if (req.data.nr == SYS_move_mount &&
        landlockd_broker_handle_move_mount_request(listener_fd, &req, allowlist,
                                                   &leases, ir, fs_compiled,
                                                   diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
#ifdef SYS_mount_setattr
    if (req.data.nr == SYS_mount_setattr &&
        landlockd_broker_handle_mount_setattr_request(listener_fd, &req,
                                                      allowlist, diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
#ifdef SYS_umount2
    if (req.data.nr == SYS_umount2 &&
        landlockd_broker_handle_umount_request(listener_fd, &req, allowlist,
                                               diag) < 0) {
      landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
      landlockd_broker_mount_fd_leases_cleanup(&leases);
      close(listener_fd);
      return -1;
    }
#endif
    if (req.data.nr != SYS_openat && req.data.nr != SYS_openat2 &&
        req.data.nr != SYS_mkdirat && req.data.nr != SYS_unlinkat &&
        req.data.nr != SYS_renameat2 && req.data.nr != SYS_symlinkat &&
        req.data.nr != SYS_linkat
#ifdef SYS_mount
        && req.data.nr != SYS_mount
#endif
#ifdef SYS_fsopen
        && req.data.nr != SYS_fsopen
#endif
#ifdef SYS_fsconfig
        && req.data.nr != SYS_fsconfig
#endif
#ifdef SYS_fsmount
        && req.data.nr != SYS_fsmount
#endif
#ifdef SYS_open_tree
        && req.data.nr != SYS_open_tree
#endif
#ifdef SYS_move_mount
        && req.data.nr != SYS_move_mount
#endif
#ifdef SYS_mount_setattr
        && req.data.nr != SYS_mount_setattr
#endif
#ifdef SYS_umount2
        && req.data.nr != SYS_umount2
#endif
    ) {
      if (landlockd_broker_send_errno(listener_fd, req.id, ENOSYS) < 0) {
        landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
        landlockd_broker_mount_fd_leases_cleanup(&leases);
        close(listener_fd);
        return -1;
      }
    }
  }

  landlockd_broker_fsopen_leases_cleanup(&fsopen_leases);
  landlockd_broker_mount_fd_leases_cleanup(&leases);
  close(listener_fd);
  return 0;
}

static int landlockd_apply_policy_in_child(
    const struct landlockd_exec_compiled_fs *fs_compiled, int net_ruleset_fd,
    const struct landlockd_seccomp_plan *notify_plan,
    const struct landlockd_seccomp_plan *deny_plan,
    unsigned short deny_errno_ret, int broker_sock_fd) {
  size_t i;
  int listener_fd;
  int net_applied;
  int seccomp_active;

  listener_fd = -1;
  net_applied = 0;
  i = 0;
  seccomp_active =
      (notify_plan != NULL && notify_plan->count > 0) ||
      (deny_plan != NULL && deny_plan->count > 0);

  if (seccomp_active) {
    if (landlockd_set_no_new_privs() < 0) {
      return -1;
    }
    if (deny_plan != NULL && deny_plan->count > 0) {
      if (landlockd_seccomp_install_denylist(deny_plan, deny_errno_ret) < 0) {
        return -1;
      }
    }
    if (notify_plan != NULL && notify_plan->count > 0) {
      listener_fd = landlockd_seccomp_install(notify_plan);
      if (listener_fd < 0) {
        return -1;
      }
    }
  }

  if (broker_sock_fd >= 0) {
    if (listener_fd < 0) {
      errno = EINVAL;
      return -1;
    }
    if (landlockd_send_fd(broker_sock_fd, listener_fd) < 0) {
      return -1;
    }
    close(listener_fd);
    listener_fd = -1;
    close(broker_sock_fd);
  }

  for (; i < fs_compiled->count; i++) {
    if (landlockd_apply_sandbox(fs_compiled->fds[i], 0) < 0) {
      return -1;
    }
  }

  if (net_ruleset_fd >= 0 && !net_applied) {
    if (landlockd_apply_sandbox(net_ruleset_fd, 0) < 0) {
      return -1;
    }
  }

  if (listener_fd >= 0) {
    close(listener_fd);
  }
  return 0;
}

static void landlockd_child_close_policy_fds(
    const struct landlockd_exec_compiled_fs *fs_compiled, int net_ruleset_fd) {
  size_t i;

  for (i = 0; i < fs_compiled->count; i++) {
    if (fs_compiled->fds[i] >= 0) {
      close(fs_compiled->fds[i]);
    }
  }
  if (net_ruleset_fd >= 0) {
    close(net_ruleset_fd);
  }
}

static int landlockd_status_to_exit_code(int status) {
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

static int landlockd_run_policy_ir(const struct landlockd_policy_ir *ir,
                                   const char *policy_label,
                                   char *const argv[], FILE *diag,
                                   int *wait_status_out) {
  struct landlockd_exec_compiled_fs fs_compiled;
  struct landlockd_broker_allowlist allowlist;
  struct landlockd_seccomp_plan notify_plan;
  struct landlockd_seccomp_plan deny_plan;
  int net_ruleset_fd;
  int broker_socks[2];
  pid_t broker_pid;
  pid_t child_pid;
  int child_status;
  int saved_errno;
  int mount_broker_active;
  int mount_namespace_active;
  int wait_failed;

  fs_compiled.fds = NULL;
  fs_compiled.count = 0;
  allowlist.read_paths = NULL;
  allowlist.read_count = 0;
  allowlist.write_paths = NULL;
  allowlist.write_count = 0;
  allowlist.scratch_paths = NULL;
  allowlist.scratch_count = 0;
  allowlist.export_paths = NULL;
  allowlist.export_count = 0;
  allowlist.mount_tmpfs_paths = NULL;
  allowlist.mount_tmpfs_count = 0;
  allowlist.mount_bind_rules = NULL;
  allowlist.mount_bind_count = 0;
  allowlist.mount_object_rules = NULL;
  allowlist.mount_object_count = 0;
  net_ruleset_fd = -1;
  broker_socks[0] = -1;
  broker_socks[1] = -1;
  broker_pid = -1;
  wait_failed = 0;
  if (landlockd_seccomp_plan_init(&notify_plan) < 0 ||
      landlockd_seccomp_plan_init(&deny_plan) < 0) {
    return 1;
  }

  if (argv == NULL || argv[0] == NULL) {
    errno = EINVAL;
    return 1;
  }

  if (landlockd_run_preflight(ir, diag) < 0) {
    return 1;
  }
  if (landlockd_exec_compile_fs(ir, &fs_compiled) < 0) {
    landlockd_diag(diag, "landlockd: failed to compile filesystem rules: %s",
                   strerror(errno));
    return 1;
  }
  if (landlockd_exec_compile_net(ir, &net_ruleset_fd) < 0) {
    saved_errno = errno;
    landlockd_exec_cleanup_fs(&fs_compiled);
    landlockd_diag(diag, "landlockd: failed to compile network rules: %s",
                   strerror(saved_errno));
    errno = saved_errno;
    return 1;
  }
  if (landlockd_broker_allowlist_init(ir, &allowlist) < 0) {
    saved_errno = errno;
    landlockd_exec_cleanup_fs(&fs_compiled);
    if (net_ruleset_fd >= 0) {
      close(net_ruleset_fd);
    }
    landlockd_diag(diag, "landlockd: invalid broker allowlist entry: %s",
                   strerror(saved_errno));
    errno = saved_errno;
    return 1;
  }

  mount_namespace_active =
      ir->mount_tmpfs_count > 0 || ir->mount_bind_count > 0 ||
      ir->mount_proc_count > 0 ||
      ir->broker_mount_tmpfs_count > 0 || ir->broker_mount_bind_count > 0 ||
      ir->broker_mount_object_count > 0 ||
      ir->runtime_root != NULL;
  mount_broker_active =
      allowlist.mount_tmpfs_count > 0 || allowlist.mount_bind_count > 0 ||
      allowlist.mount_object_count > 0;

  if (mount_namespace_active) {
#ifdef SYS_mount
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_mount)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_mount)) < 0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_umount2
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_umount2)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_umount2)) < 0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_open_tree
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_open_tree)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_open_tree)) < 0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_move_mount
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_move_mount)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_move_mount)) <
        0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_mount_setattr
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_mount_setattr)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_mount_setattr)) <
        0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_fsopen
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_fsopen)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_fsopen)) < 0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_fsconfig
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_fsconfig)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_fsconfig)) <
        0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_fsmount
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_fsmount)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_fsmount)) < 0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
#ifdef SYS_pivot_root
    if ((mount_broker_active
             ? landlockd_seccomp_plan_add(&notify_plan, (int)SYS_pivot_root)
             : landlockd_seccomp_plan_add(&deny_plan, (int)SYS_pivot_root)) <
        0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
#endif
  }

  if (allowlist.read_count > 0 || allowlist.write_count > 0 ||
      allowlist.scratch_count > 0 || allowlist.export_count > 0 ||
      allowlist.mount_tmpfs_count > 0 || allowlist.mount_bind_count > 0 ||
      allowlist.mount_object_count > 0) {
    if (landlockd_seccomp_plan_add(&notify_plan, (int)SYS_openat) < 0 ||
        landlockd_seccomp_plan_add(&notify_plan, (int)SYS_openat2) < 0 ||
        ((allowlist.scratch_count > 0 || allowlist.export_count > 0) &&
         (landlockd_seccomp_plan_add(&notify_plan, (int)SYS_mkdirat) < 0 ||
          landlockd_seccomp_plan_add(&notify_plan, (int)SYS_unlinkat) < 0 ||
          landlockd_seccomp_plan_add(&notify_plan, (int)SYS_renameat2) < 0 ||
          landlockd_seccomp_plan_add(&notify_plan, (int)SYS_symlinkat) < 0 ||
          landlockd_seccomp_plan_add(&notify_plan, (int)SYS_linkat) <
              0))
    ) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, broker_socks) < 0) {
      saved_errno = errno;
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }

    broker_pid = fork();
    if (broker_pid < 0) {
      saved_errno = errno;
      close(broker_socks[0]);
      close(broker_socks[1]);
      landlockd_exec_cleanup_fs(&fs_compiled);
      landlockd_broker_allowlist_cleanup(&allowlist);
      if (net_ruleset_fd >= 0) {
        close(net_ruleset_fd);
      }
      errno = saved_errno;
      return 1;
    }
    if (broker_pid == 0) {
      close(broker_socks[1]);
      if (landlockd_seccomp_apply_broker_hardening(
              allowlist.mount_tmpfs_count > 0 ||
              allowlist.mount_bind_count > 0 ||
              allowlist.mount_object_count > 0) < 0) {
        _exit(1);
      }
      _exit(landlockd_broker_loop(broker_socks[0], &allowlist, ir,
                                  &fs_compiled, diag) == 0
                ? 0
                : 1);
    }
    close(broker_socks[0]);
    broker_socks[0] = -1;
  }

  if (ir->seccomp_enabled) {
    size_t i;

    for (i = 0; i < ir->seccomp_deny_count; i++) {
      if (landlockd_seccomp_plan_add(&deny_plan,
                                     ir->seccomp_deny_rules[i].syscall_nr) <
          0) {
        saved_errno = errno;
        if (broker_socks[1] >= 0) {
          close(broker_socks[1]);
        }
        if (broker_pid > 0) {
          kill(broker_pid, SIGTERM);
          waitpid(broker_pid, NULL, 0);
        }
        landlockd_exec_cleanup_fs(&fs_compiled);
        landlockd_broker_allowlist_cleanup(&allowlist);
        if (net_ruleset_fd >= 0) {
          close(net_ruleset_fd);
        }
        errno = saved_errno;
        return 1;
      }
    }
  }

  child_pid = fork();
  if (child_pid < 0) {
    saved_errno = errno;
    if (broker_socks[1] >= 0) {
      close(broker_socks[1]);
    }
    if (broker_pid > 0) {
      kill(broker_pid, SIGTERM);
      waitpid(broker_pid, NULL, 0);
    }
    landlockd_exec_cleanup_fs(&fs_compiled);
    landlockd_broker_allowlist_cleanup(&allowlist);
    if (net_ruleset_fd >= 0) {
      close(net_ruleset_fd);
    }
    errno = saved_errno;
    return 1;
  }

  if (child_pid == 0) {
    if (broker_socks[0] >= 0) {
      close(broker_socks[0]);
    }
    if (landlockd_setup_policy_mounts(ir, &fs_compiled, diag) < 0) {
      perror("landlockd");
      _exit(1);
    }
    if (landlockd_apply_policy_in_child(
            &fs_compiled, net_ruleset_fd,
            notify_plan.count > 0 ? &notify_plan : NULL,
            deny_plan.count > 0 ? &deny_plan : NULL,
            ir->seccomp_enabled ? ir->seccomp_errno : EPERM,
            broker_socks[1]) < 0) {
      perror("landlockd");
      _exit(1);
    }
    landlockd_child_close_policy_fds(&fs_compiled, net_ruleset_fd);
    execvp(argv[0], argv);
    perror(argv[0]);
    _exit(127);
  }

  landlockd_audit_run_start(diag, child_pid, policy_label, argv[0]);

  if (broker_socks[1] >= 0) {
    close(broker_socks[1]);
  }

  child_status = 0;
  while (waitpid(child_pid, &child_status, 0) < 0) {
    if (errno != EINTR) {
      wait_failed = 1;
      break;
    }
  }

  if (broker_pid > 0) {
    kill(broker_pid, SIGTERM);
    waitpid(broker_pid, NULL, 0);
  }

  landlockd_exec_cleanup_fs(&fs_compiled);
  landlockd_broker_allowlist_cleanup(&allowlist);
  if (net_ruleset_fd >= 0) {
    close(net_ruleset_fd);
  }

  if (wait_failed) {
    return 1;
  }
  landlockd_audit_run_exit(diag, child_pid, child_status);
  if (wait_status_out != NULL) {
    *wait_status_out = child_status;
  }
  return landlockd_status_to_exit_code(child_status);
}

int landlockd_run_policy_ir_loaded(const struct landlockd_policy_ir *ir,
                                   const char *policy_label,
                                   char *const argv[], FILE *diag) {
  int status;

  if (ir == NULL || argv == NULL || argv[0] == NULL) {
    errno = EINVAL;
    return 1;
  }
  status = landlockd_run_policy_ir(ir, policy_label, argv, diag, NULL);
  return status;
}

int landlockd_run_policy_file(const char *policy_file, char *const argv[],
                              FILE *diag) {
  return landlockd_run_policy_file_wait_status(policy_file, argv, diag, NULL);
}

int landlockd_run_policy_file_wait_status(const char *policy_file,
                                          char *const argv[], FILE *diag,
                                          int *wait_status_out) {
  struct landlockd_policy_ir ir;
  int status;

  if (policy_file == NULL || argv == NULL || argv[0] == NULL) {
    errno = EINVAL;
    return 1;
  }

  landlockd_policy_ir_init(&ir);
  if (landlockd_policy_load_file(policy_file, &ir, diag) < 0) {
    landlockd_policy_ir_reset(&ir);
    return 1;
  }
  status = landlockd_run_policy_ir(&ir, policy_file, argv, diag,
                                   wait_status_out);
  landlockd_policy_ir_reset(&ir);
  return status;
}
