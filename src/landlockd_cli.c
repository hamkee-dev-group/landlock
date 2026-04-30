#define _GNU_SOURCE

#include "landlockd_cli.h"

#include "landlock_policy_loader.h"
#include "landlockd_daemon.h"
#include "landlockd_exec.h"
#include "landlockd/landlock.h"
#include "landlockd/preflight.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/mount.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LANDLOCKD_POLICY_SHARE_DIR
#define LANDLOCKD_POLICY_SHARE_DIR "/usr/local/share/landlockd/policies"
#endif

static int landlockd_cli_policy_name_valid(const char *name) {
  size_t i;

  if (name == NULL || name[0] == '\0' || strcmp(name, ".") == 0 ||
      strcmp(name, "..") == 0) {
    return 0;
  }
  for (i = 0; name[i] != '\0'; i++) {
    if (name[i] == '/') {
      return 0;
    }
  }
  return 1;
}

static char *landlockd_cli_join_policy_candidate(const char *dir,
                                                 const char *name) {
  size_t dir_len;
  size_t name_len;
  char *candidate;
  int n;

  if (dir == NULL || dir[0] == '\0' || name == NULL || name[0] == '\0') {
    errno = EINVAL;
    return NULL;
  }

  dir_len = strlen(dir);
  name_len = strlen(name);
  candidate = malloc(dir_len + 1 + name_len + sizeof(".toml"));
  if (candidate == NULL) {
    return NULL;
  }
  n = snprintf(candidate, dir_len + 1 + name_len + sizeof(".toml"),
               "%s/%s.toml", dir, name);
  if (n < 0 || (size_t)n >= dir_len + 1 + name_len + sizeof(".toml")) {
    free(candidate);
    errno = ENAMETOOLONG;
    return NULL;
  }
  return candidate;
}

static char *landlockd_cli_find_policy_in_search_path(const char *dirs,
                                                      const char *name) {
  const char *cursor;
  const char *sep;
  char *dir;
  char *candidate;
  size_t len;

  if (dirs == NULL || dirs[0] == '\0') {
    return NULL;
  }

  cursor = dirs;
  while (*cursor != '\0') {
    sep = strchr(cursor, ':');
    len = sep == NULL ? strlen(cursor) : (size_t)(sep - cursor);
    if (len > 0) {
      dir = malloc(len + 1);
      if (dir == NULL) {
        return NULL;
      }
      memcpy(dir, cursor, len);
      dir[len] = '\0';
      candidate = landlockd_cli_join_policy_candidate(dir, name);
      free(dir);
      if (candidate == NULL) {
        return NULL;
      }
      if (access(candidate, R_OK) == 0) {
        return candidate;
      }
      free(candidate);
    }
    if (sep == NULL) {
      break;
    }
    cursor = sep + 1;
  }
  errno = ENOENT;
  return NULL;
}

static char *landlockd_cli_resolve_named_policy(const char *name, FILE *diag) {
  const char *search_path_env;
  const char *system_policy_dir_env;
  const char *xdg_config_home;
  const char *home;
  char *dir;
  char *candidate;
  int n;

  if (!landlockd_cli_policy_name_valid(name)) {
    if (diag != NULL) {
      fprintf(diag,
              "landlockd: invalid policy name \"%s\"; use a simple name without '/'\n",
              name != NULL ? name : "");
    }
    errno = EINVAL;
    return NULL;
  }

  search_path_env = getenv("LANDLOCKD_POLICY_PATH");
  candidate = landlockd_cli_find_policy_in_search_path(search_path_env, name);
  if (candidate != NULL) {
    return candidate;
  }
  if (search_path_env != NULL && search_path_env[0] != '\0' &&
      errno != ENOENT) {
    return NULL;
  }

  xdg_config_home = getenv("XDG_CONFIG_HOME");
  if (xdg_config_home != NULL && xdg_config_home[0] != '\0') {
    dir = malloc(strlen(xdg_config_home) + strlen("/landlockd/policies") + 1);
    if (dir == NULL) {
      return NULL;
    }
    n = snprintf(dir, strlen(xdg_config_home) + strlen("/landlockd/policies") +
                          1,
                 "%s/landlockd/policies", xdg_config_home);
    if (n < 0 ||
        (size_t)n >=
            strlen(xdg_config_home) + strlen("/landlockd/policies") + 1) {
      free(dir);
      errno = ENAMETOOLONG;
      return NULL;
    }
    candidate = landlockd_cli_join_policy_candidate(dir, name);
    free(dir);
    if (candidate == NULL) {
      return NULL;
    }
    if (access(candidate, R_OK) == 0) {
      return candidate;
    }
    free(candidate);
  } else {
    home = getenv("HOME");
    if (home != NULL && home[0] != '\0') {
      dir = malloc(strlen(home) + strlen("/.config/landlockd/policies") + 1);
      if (dir == NULL) {
        return NULL;
      }
      n = snprintf(dir,
                   strlen(home) + strlen("/.config/landlockd/policies") + 1,
                   "%s/.config/landlockd/policies", home);
      if (n < 0 ||
          (size_t)n >=
              strlen(home) + strlen("/.config/landlockd/policies") + 1) {
        free(dir);
        errno = ENAMETOOLONG;
        return NULL;
      }
      candidate = landlockd_cli_join_policy_candidate(dir, name);
      free(dir);
      if (candidate == NULL) {
        return NULL;
      }
      if (access(candidate, R_OK) == 0) {
        return candidate;
      }
      free(candidate);
    }
  }

  system_policy_dir_env = getenv("LANDLOCKD_POLICY_SYSTEM_DIR");
  if (system_policy_dir_env != NULL && system_policy_dir_env[0] != '\0') {
    candidate =
        landlockd_cli_join_policy_candidate(system_policy_dir_env, name);
  } else {
    candidate = landlockd_cli_join_policy_candidate(LANDLOCKD_POLICY_SHARE_DIR,
                                                    name);
  }
  if (candidate == NULL) {
    return NULL;
  }
  if (access(candidate, R_OK) == 0) {
    return candidate;
  }
  free(candidate);

  candidate = landlockd_cli_join_policy_candidate("/etc/landlockd/policies",
                                                  name);
  if (candidate == NULL) {
    return NULL;
  }
  if (access(candidate, R_OK) == 0) {
    return candidate;
  }
  free(candidate);

  if (diag != NULL) {
    fprintf(diag,
            "landlockd: named policy \"%s\" not found in LANDLOCKD_POLICY_PATH, user config, installed policy directories, or /etc/landlockd/policies\n",
            name);
  }
  errno = ENOENT;
  return NULL;
}

static void landlockd_cli_print_usage(FILE *stream) {
  fputs("Usage: landlockd --help\n"
        "       landlockd --ro PATH [--ro PATH ...] [--notify SYSCALL_NR ...]"
        " -- command [args...]\n"
        "       landlockd lint --policy NAME\n"
        "       landlockd lint --policy-file POLICY.toml\n"
        "       landlockd serve --socket PATH\n"
        "       landlockd serve --systemd\n"
        "       landlockd status --socket PATH\n"
        "       landlockd stop --socket PATH\n"
        "       landlockd run --policy NAME [--preflight] -- command [args...]\n"
        "       landlockd run --policy NAME --dry-run -- command [args...]\n"
        "       landlockd run --policy-file POLICY.toml [--preflight|--dry-run]\n"
        "       landlockd run --socket PATH --policy-file POLICY.toml --"
        " command [args...]\n"
        "       landlockd run --socket PATH --policy NAME -- command [args...]\n"
        "       landlockd run --policy-file POLICY.toml [--preflight|--dry-run] --"
        " command [args...]\n"
        "\n"
        "Notes:\n"
        "  --policy NAME resolves through LANDLOCKD_POLICY_PATH, then user"
        " config, then the installed policy set, then /etc.\n"
        "  LANDLOCKD_POLICY_SYSTEM_DIR overrides the installed policy"
        " directory.\n"
        "  serve --systemd consumes one inherited Unix listener from socket"
        " activation.\n"
        "  status --socket PATH prints daemon protocol and policy-cache"
        " counters.\n"
        "  Policy-driven run supports Landlock filesystem rules, Landlock"
        " network rules,\n"
        "  declarative seccomp deny/errno filters, per-run tmpfs/bind/proc"
        " mounts,\n"
        "  runtime root/cwd control, and brokered host-file and mount"
        " operations.\n"
        "  The legacy --ro/--notify path remains available for direct"
        " one-shot use.\n",
        stream);
}

static void landlockd_cli_emit_event(const char *fmt, ...) {
  va_list ap;

  fputs("event ", stderr);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  fflush(stderr);
}

static uint64_t landlockd_cli_handled_access_fs(void) {
  return LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
         LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
         LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
         LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
         LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
         LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
         LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE |
         LANDLOCK_ACCESS_FS_IOCTL_DEV;
}

static void landlockd_cli_dry_run_string(FILE *out, const char *value) {
  const unsigned char *p;

  if (value != NULL) {
    for (p = (const unsigned char *)value; *p != '\0'; p++) {
      if (*p == '\\') {
        fputc('\\', out);
        fputc(*p, out);
      } else if (*p == '\n') {
        fputs("\\n", out);
      } else if (*p == '\r') {
        fputs("\\r", out);
      } else if (*p == '\t') {
        fputs("\\t", out);
      } else if (*p < 0x20) {
        fprintf(out, "\\u%04x", (unsigned int)*p);
      } else {
        fputc(*p, out);
      }
    }
  }
}

static int landlockd_cli_cmp_u64(uint64_t a, uint64_t b) {
  return (a > b) - (a < b);
}

static int landlockd_cli_cmp_str(const char *a, const char *b) {
  if (a == NULL && b == NULL) {
    return 0;
  }
  if (a == NULL) {
    return -1;
  }
  if (b == NULL) {
    return 1;
  }
  return strcmp(a, b);
}

static int landlockd_cli_dry_run_fs_rule_cmp(const void *a, const void *b) {
  const struct landlockd_policy_ir_fs_rule *ra = a;
  const struct landlockd_policy_ir_fs_rule *rb = b;
  int cmp;

  cmp = landlockd_cli_cmp_str(ra->path, rb->path);
  if (cmp != 0) {
    return cmp;
  }
  return landlockd_cli_cmp_u64(ra->allowed_access, rb->allowed_access);
}

static int landlockd_cli_dry_run_net_rule_cmp(const void *a, const void *b) {
  const struct landlockd_policy_ir_net_rule *ra = a;
  const struct landlockd_policy_ir_net_rule *rb = b;
  int cmp;

  cmp = (ra->port > rb->port) - (ra->port < rb->port);
  if (cmp != 0) {
    return cmp;
  }
  return landlockd_cli_cmp_u64(ra->allowed_access, rb->allowed_access);
}

static int landlockd_cli_dry_run_open_rule_cmp(const void *a, const void *b) {
  const struct landlockd_policy_ir_broker_open_rule *ra = a;
  const struct landlockd_policy_ir_broker_open_rule *rb = b;

  return landlockd_cli_cmp_str(ra->path, rb->path);
}

static int landlockd_cli_dry_run_mount_rule_cmp(const void *a, const void *b) {
  const struct landlockd_policy_ir_mount_rule *ra = a;
  const struct landlockd_policy_ir_mount_rule *rb = b;

  return landlockd_cli_cmp_str(ra->path, rb->path);
}

static int landlockd_cli_dry_run_bind_rule_cmp(const void *a, const void *b) {
  const struct landlockd_policy_ir_bind_mount_rule *ra = a;
  const struct landlockd_policy_ir_bind_mount_rule *rb = b;
  int cmp;

  cmp = landlockd_cli_cmp_str(ra->source, rb->source);
  if (cmp != 0) {
    return cmp;
  }
  cmp = landlockd_cli_cmp_str(ra->target, rb->target);
  if (cmp != 0) {
    return cmp;
  }
  return (ra->read_only > rb->read_only) - (ra->read_only < rb->read_only);
}

static int landlockd_cli_dry_run_mount_object_cmp(const void *a,
                                                  const void *b) {
  const struct landlockd_policy_ir_mount_object_rule *ra = a;
  const struct landlockd_policy_ir_mount_object_rule *rb = b;
  int cmp;
  size_t i;
  size_t n;

  cmp = landlockd_cli_cmp_str(ra->name, rb->name);
  if (cmp != 0) {
    return cmp;
  }
  cmp = landlockd_cli_cmp_str(ra->fs_type, rb->fs_type);
  if (cmp != 0) {
    return cmp;
  }
  cmp = landlockd_cli_cmp_u64(ra->allowed_attr_set, rb->allowed_attr_set);
  if (cmp != 0) {
    return cmp;
  }
  n = ra->attach_count < rb->attach_count ? ra->attach_count : rb->attach_count;
  for (i = 0; i < n; i++) {
    cmp = landlockd_cli_cmp_str(ra->attach_paths[i], rb->attach_paths[i]);
    if (cmp != 0) {
      return cmp;
    }
  }
  return (ra->attach_count > rb->attach_count) -
         (ra->attach_count < rb->attach_count);
}

static int landlockd_cli_dry_run_string_cmp(const void *a, const void *b) {
  const char *const *sa = a;
  const char *const *sb = b;

  return landlockd_cli_cmp_str(*sa, *sb);
}

static int landlockd_cli_dry_run_seccomp_cmp(const void *a, const void *b) {
  const struct landlockd_policy_ir_seccomp_rule *ra = a;
  const struct landlockd_policy_ir_seccomp_rule *rb = b;

  return (ra->syscall_nr > rb->syscall_nr) -
         (ra->syscall_nr < rb->syscall_nr);
}

static void landlockd_cli_dry_run_emit_open_rules(
    FILE *out, const char *name,
    const struct landlockd_policy_ir_broker_open_rule *rules,
    size_t rule_count) {
  size_t i;

  for (i = 0; i < rule_count; i++) {
    fprintf(out, "broker.%s path=", name);
    landlockd_cli_dry_run_string(out, rules[i].path);
    fputc('\n', out);
  }
}

static void landlockd_cli_dry_run_emit_mount_rules(
    FILE *out, const char *name,
    const struct landlockd_policy_ir_mount_rule *rules, size_t rule_count) {
  size_t i;

  for (i = 0; i < rule_count; i++) {
    fprintf(out, "mount.%s path=", name);
    landlockd_cli_dry_run_string(out, rules[i].path);
    fputc('\n', out);
  }
}

static void landlockd_cli_dry_run_emit_bind_rules(
    FILE *out, const char *prefix,
    const struct landlockd_policy_ir_bind_mount_rule *rules,
    size_t rule_count) {
  size_t i;

  for (i = 0; i < rule_count; i++) {
    fprintf(out, "%s source=", prefix);
    landlockd_cli_dry_run_string(out, rules[i].source);
    fputs(" target=", out);
    landlockd_cli_dry_run_string(out, rules[i].target);
    fprintf(out, " ro=%d\n", rules[i].read_only ? 1 : 0);
  }
}

static int landlockd_cli_dry_run(struct landlockd_policy_ir *ir, FILE *out) {
  size_t i;
  size_t j;

  for (i = 0; i < ir->fs_layer_count; i++) {
    qsort(ir->fs_layers[i].rules, ir->fs_layers[i].rule_count,
          sizeof(*ir->fs_layers[i].rules), landlockd_cli_dry_run_fs_rule_cmp);
  }
  qsort(ir->net_rules, ir->net_rule_count, sizeof(*ir->net_rules),
        landlockd_cli_dry_run_net_rule_cmp);
  qsort(ir->broker_open_read_rules, ir->broker_open_read_count,
        sizeof(*ir->broker_open_read_rules),
        landlockd_cli_dry_run_open_rule_cmp);
  qsort(ir->broker_open_write_rules, ir->broker_open_write_count,
        sizeof(*ir->broker_open_write_rules),
        landlockd_cli_dry_run_open_rule_cmp);
  qsort(ir->broker_scratch_rules, ir->broker_scratch_count,
        sizeof(*ir->broker_scratch_rules), landlockd_cli_dry_run_open_rule_cmp);
  qsort(ir->broker_export_rules, ir->broker_export_count,
        sizeof(*ir->broker_export_rules), landlockd_cli_dry_run_open_rule_cmp);
  qsort(ir->broker_mount_tmpfs_rules, ir->broker_mount_tmpfs_count,
        sizeof(*ir->broker_mount_tmpfs_rules),
        landlockd_cli_dry_run_open_rule_cmp);
  qsort(ir->broker_mount_bind_rules, ir->broker_mount_bind_count,
        sizeof(*ir->broker_mount_bind_rules),
        landlockd_cli_dry_run_bind_rule_cmp);
  for (i = 0; i < ir->broker_mount_object_count; i++) {
    qsort(ir->broker_mount_object_rules[i].attach_paths,
          ir->broker_mount_object_rules[i].attach_count,
          sizeof(*ir->broker_mount_object_rules[i].attach_paths),
          landlockd_cli_dry_run_string_cmp);
  }
  qsort(ir->broker_mount_object_rules, ir->broker_mount_object_count,
        sizeof(*ir->broker_mount_object_rules),
        landlockd_cli_dry_run_mount_object_cmp);
  qsort(ir->mount_tmpfs_rules, ir->mount_tmpfs_count,
        sizeof(*ir->mount_tmpfs_rules), landlockd_cli_dry_run_mount_rule_cmp);
  qsort(ir->mount_bind_rules, ir->mount_bind_count,
        sizeof(*ir->mount_bind_rules), landlockd_cli_dry_run_bind_rule_cmp);
  qsort(ir->mount_proc_rules, ir->mount_proc_count,
        sizeof(*ir->mount_proc_rules), landlockd_cli_dry_run_mount_rule_cmp);
  qsort(ir->seccomp_deny_rules, ir->seccomp_deny_count,
        sizeof(*ir->seccomp_deny_rules), landlockd_cli_dry_run_seccomp_cmp);

  fputs("landlockd dry-run v1\n", out);
  for (i = 0; i < ir->fs_layer_count; i++) {
    fprintf(out, "fs.layer[%zu] handled=0x%" PRIx64 "\n", i,
            ir->fs_layers[i].handled_access_fs);
    for (j = 0; j < ir->fs_layers[i].rule_count; j++) {
      fputs("fs.rule path=", out);
      landlockd_cli_dry_run_string(out, ir->fs_layers[i].rules[j].path);
      fprintf(out, " allowed=0x%" PRIx64 "\n",
              ir->fs_layers[i].rules[j].allowed_access);
    }
  }

  fprintf(out, "net.handled=0x%" PRIx64 "\n", ir->net_handled_access);
  for (i = 0; i < ir->net_rule_count; i++) {
    fprintf(out, "net.rule port=%u allowed=0x%" PRIx64 "\n",
            (unsigned int)ir->net_rules[i].port,
            ir->net_rules[i].allowed_access);
  }

  landlockd_cli_dry_run_emit_open_rules(
      out, "open_read", ir->broker_open_read_rules,
      ir->broker_open_read_count);
  landlockd_cli_dry_run_emit_open_rules(
      out, "open_write", ir->broker_open_write_rules,
      ir->broker_open_write_count);
  landlockd_cli_dry_run_emit_open_rules(out, "scratch",
                                        ir->broker_scratch_rules,
                                        ir->broker_scratch_count);
  landlockd_cli_dry_run_emit_open_rules(out, "export",
                                        ir->broker_export_rules,
                                        ir->broker_export_count);
  landlockd_cli_dry_run_emit_open_rules(
      out, "mount_tmpfs", ir->broker_mount_tmpfs_rules,
      ir->broker_mount_tmpfs_count);
  landlockd_cli_dry_run_emit_bind_rules(
      out, "broker.mount_bind", ir->broker_mount_bind_rules,
      ir->broker_mount_bind_count);
  for (i = 0; i < ir->broker_mount_object_count; i++) {
    for (j = 0; j < ir->broker_mount_object_rules[i].attach_count; j++) {
      fputs("broker.mount_object name=", out);
      landlockd_cli_dry_run_string(out, ir->broker_mount_object_rules[i].name);
      fputs(" fs_type=", out);
      landlockd_cli_dry_run_string(out,
                                   ir->broker_mount_object_rules[i].fs_type);
      fputs(" attach=", out);
      landlockd_cli_dry_run_string(
          out, ir->broker_mount_object_rules[i].attach_paths[j]);
      fprintf(out, " attrs=0x%" PRIx64 "\n",
              ir->broker_mount_object_rules[i].allowed_attr_set);
    }
  }

  landlockd_cli_dry_run_emit_mount_rules(out, "tmpfs", ir->mount_tmpfs_rules,
                                         ir->mount_tmpfs_count);
  landlockd_cli_dry_run_emit_bind_rules(out, "mount.bind",
                                        ir->mount_bind_rules,
                                        ir->mount_bind_count);
  landlockd_cli_dry_run_emit_mount_rules(out, "proc", ir->mount_proc_rules,
                                         ir->mount_proc_count);

  if (ir->runtime_root != NULL) {
    fputs("runtime.root=", out);
    landlockd_cli_dry_run_string(out, ir->runtime_root);
    fputc('\n', out);
  } else {
    fputs("runtime.root=<unset>\n", out);
  }
  if (ir->runtime_cwd != NULL) {
    fputs("runtime.cwd=", out);
    landlockd_cli_dry_run_string(out, ir->runtime_cwd);
    fputc('\n', out);
  } else {
    fputs("runtime.cwd=<unset>\n", out);
  }

  fprintf(out, "seccomp.enabled=%d errno=%u\n", ir->seccomp_enabled ? 1 : 0,
          (unsigned int)ir->seccomp_errno);
  for (i = 0; i < ir->seccomp_deny_count; i++) {
    fprintf(out, "seccomp.deny syscall=%d\n",
            ir->seccomp_deny_rules[i].syscall_nr);
  }
  return 0;
}

static int landlockd_cli_dry_run_requires_seccomp_probe(
    const struct landlockd_policy_ir *ir) {
  return ir->seccomp_enabled || ir->broker_open_read_count > 0 ||
         ir->broker_open_write_count > 0 || ir->broker_scratch_count > 0 ||
         ir->broker_export_count > 0 || ir->broker_mount_tmpfs_count > 0 ||
         ir->broker_mount_bind_count > 0 || ir->broker_mount_object_count > 0;
}

static int landlockd_cli_dry_run_status(const struct landlockd_policy_ir *ir,
                                        FILE *out) {
  struct landlockd_preflight_report preflight;
  int net_unsupported;
  int seccomp_unsupported;

  memset(&preflight, 0, sizeof(preflight));
  if (landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &preflight) < 0) {
    return 1;
  }

  net_unsupported =
      ir->net_enabled &&
      (preflight.probe_errno == ENOSYS || preflight.probe_errno == EOPNOTSUPP ||
       preflight.abi_version < 4);
  seccomp_unsupported = 0;
  if (landlockd_cli_dry_run_requires_seccomp_probe(ir)) {
    if (landlockd_preflight_probe_seccomp_user_notif(&preflight) < 0) {
      return 1;
    }
    seccomp_unsupported = !preflight.seccomp_user_notif_supported;
  }

  if (net_unsupported) {
    fprintf(out, "feature.degraded name=net required_abi=4 actual_abi=%d\n",
            preflight.abi_version);
    fputs("dry-run.status=fail reason=net-unsupported\n", out);
    return 2;
  }
  if (seccomp_unsupported) {
    fprintf(out,
            "feature.degraded name=seccomp_user_notif probe_errno=%d\n",
            preflight.seccomp_probe_errno);
    fputs("dry-run.status=fail reason=seccomp-unsupported\n", out);
    return 2;
  }

  fputs("dry-run.status=ok\n", out);
  return 0;
}

static int landlockd_cli_run_policy_verb(
    const struct landlockd_cli_options *options) {
  struct landlockd_policy_ir ir;
  char *resolved_policy_file;
  const char *policy_file;

  resolved_policy_file = NULL;
  policy_file = options->policy_file;
  if (policy_file == NULL) {
    resolved_policy_file =
        landlockd_cli_resolve_named_policy(options->policy_name, stderr);
    if (resolved_policy_file == NULL) {
      return 1;
    }
    policy_file = resolved_policy_file;
  }

  if (options->verb == LANDLOCKD_CLI_VERB_LINT || options->preflight_only ||
      options->dry_run) {
    int rc;

    landlockd_policy_ir_init(&ir);
    if (landlockd_policy_load_file(policy_file, &ir, stderr) < 0) {
      landlockd_policy_ir_reset(&ir);
      free(resolved_policy_file);
      return 1;
    }
    if (options->dry_run) {
      rc = landlockd_cli_dry_run(&ir, stdout);
      if (rc == 0) {
        rc = landlockd_cli_dry_run_status(&ir, stdout);
      }
    } else {
      rc = 0;
    }
    landlockd_policy_ir_reset(&ir);
    free(resolved_policy_file);
    return rc;
  }

  if (options->socket_path != NULL) {
    int rc = landlockd_daemon_run(options->socket_path, policy_file,
                                  options->command_argv, stderr);
    free(resolved_policy_file);
    return rc;
  }
  {
    int rc;
    int wait_status;

    wait_status = 0;
    rc = landlockd_run_policy_file_wait_status(policy_file, options->command_argv,
                                               stderr, &wait_status);
    if (WIFSIGNALED(wait_status)) {
      int sig = WTERMSIG(wait_status);

      free(resolved_policy_file);
      signal(sig, SIG_DFL);
      raise(sig);
      return 128 + sig;
    }
    free(resolved_policy_file);
    return rc;
  }
}

int landlockd_cli_main(int argc, char *argv[]) {
  struct landlockd_cli_options options;
  struct landlockd_preflight_report preflight;
  struct landlockd_seccomp_plan seccomp_plan;
  struct landlock_path_beneath_attr path_rule;
  int ruleset_fd;
  int saved_errno;
  int listener_fd;
  int parent_fd;
  pid_t pid;
  int status;
  int sig;
  int i;

  if (landlockd_cli_parse(argc, argv, &options) < 0) {
    landlockd_cli_print_usage(stderr);
    return 1;
  }

  if (options.show_help) {
    landlockd_cli_print_usage(stdout);
    landlockd_cli_options_release(&options);
    return 0;
  }

  if (options.verb == LANDLOCKD_CLI_VERB_SERVE) {
    if (options.use_systemd_socket_activation) {
      status = landlockd_daemon_serve_systemd(stderr);
    } else {
      status = landlockd_daemon_serve(options.socket_path, stderr);
    }
    landlockd_cli_options_release(&options);
    return status;
  }
  if (options.verb == LANDLOCKD_CLI_VERB_STOP) {
    status = landlockd_daemon_stop(options.socket_path, stderr);
    landlockd_cli_options_release(&options);
    return status;
  }
  if (options.verb == LANDLOCKD_CLI_VERB_STATUS) {
    status = landlockd_daemon_status(options.socket_path, stdout, stderr);
    landlockd_cli_options_release(&options);
    return status;
  }
  if (options.verb == LANDLOCKD_CLI_VERB_RUN ||
      options.verb == LANDLOCKD_CLI_VERB_LINT) {
    status = landlockd_cli_run_policy_verb(&options);
    landlockd_cli_options_release(&options);
    return status;
  }

  if (landlockd_preflight_run(LANDLOCKD_PREFLIGHT_ABI_FLOOR, &preflight) < 0) {
    saved_errno = errno;
    fprintf(stderr, "landlockd: preflight: Landlock probe failed: %s\n",
            strerror(saved_errno));
    landlockd_cli_emit_event("preflight.fail reason=probe errno=%d",
                             saved_errno);
    landlockd_cli_options_release(&options);
    return 1;
  }
  if (preflight.probe_errno == ENOSYS ||
      preflight.probe_errno == EOPNOTSUPP) {
    fprintf(stderr,
            "landlockd: preflight: Landlock is not supported by this kernel "
            "(%s)\n",
            strerror(preflight.probe_errno));
    landlockd_cli_emit_event("preflight.fail reason=unsupported errno=%d",
                             preflight.probe_errno);
    landlockd_cli_options_release(&options);
    return 1;
  }
  if (!preflight.meets_abi_floor) {
    fprintf(stderr,
            "landlockd: preflight: Landlock ABI %d is below required floor "
            "%d\n",
            preflight.abi_version, preflight.required_abi_floor);
    landlockd_cli_emit_event(
        "preflight.fail reason=abi-floor abi=%d floor=%d",
        preflight.abi_version, preflight.required_abi_floor);
    landlockd_cli_options_release(&options);
    return 1;
  }

  if (options.notify_count > 0) {
    if (landlockd_preflight_probe_seccomp_user_notif(&preflight) < 0) {
      saved_errno = errno;
      fprintf(stderr,
              "landlockd: preflight: seccomp user-notif probe failed: %s\n",
              strerror(saved_errno));
      landlockd_cli_emit_event(
          "preflight.fail reason=seccomp-user-notif errno=%d", saved_errno);
      landlockd_cli_options_release(&options);
      return 1;
    }
    if (!preflight.seccomp_user_notif_supported) {
      fprintf(stderr,
              "landlockd: preflight: seccomp user-notif is not supported "
              "by this kernel (%s)\n",
              strerror(preflight.seccomp_probe_errno));
      landlockd_cli_emit_event(
          "preflight.fail reason=seccomp-user-notif errno=%d",
          preflight.seccomp_probe_errno);
      landlockd_cli_options_release(&options);
      return 1;
    }
  }

  ruleset_fd =
      landlock_create_fs_ruleset(landlockd_cli_handled_access_fs(), NULL);
  if (ruleset_fd < 0) {
    saved_errno = errno;
    if (saved_errno == ENOSYS || saved_errno == EOPNOTSUPP) {
      fprintf(stderr,
              "landlockd: landlock_create_fs_ruleset: Landlock is not "
              "supported by this kernel (%s)\n",
              strerror(saved_errno));
    } else {
      fprintf(stderr, "landlockd: landlock_create_fs_ruleset: Landlock "
                      "ruleset creation failed: %s\n",
              strerror(saved_errno));
    }
    landlockd_cli_emit_event("preflight.fail reason=ruleset-create errno=%d",
                             saved_errno);
    landlockd_cli_options_release(&options);
    return 1;
  }

  path_rule.allowed_access =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  for (i = 0; i < options.ro_path_count; i++) {
    parent_fd = open(options.ro_paths[i], O_PATH | O_CLOEXEC);
    if (parent_fd < 0) {
      saved_errno = errno;
      close(ruleset_fd);
      errno = saved_errno;
      perror("open");
      landlockd_cli_emit_event("preflight.fail reason=ro-open errno=%d",
                               saved_errno);
      landlockd_cli_options_release(&options);
      return 1;
    }

    path_rule.parent_fd = parent_fd;
    if (landlock_add_fs_rule(ruleset_fd, &path_rule, 0) < 0) {
      saved_errno = errno;
      close(parent_fd);
      close(ruleset_fd);
      errno = saved_errno;
      perror("landlock_add_fs_rule");
      landlockd_cli_emit_event("preflight.fail reason=add-rule errno=%d",
                               saved_errno);
      landlockd_cli_options_release(&options);
      return 1;
    }

    close(parent_fd);
  }

  pid = fork();
  if (pid < 0) {
    saved_errno = errno;
    close(ruleset_fd);
    errno = saved_errno;
    perror("fork");
    landlockd_cli_emit_event("preflight.fail reason=fork errno=%d",
                             saved_errno);
    landlockd_cli_options_release(&options);
    return 1;
  }
  if (pid == 0) {
    if (options.notify_count > 0) {
      listener_fd = -1;
      if (landlockd_cli_build_seccomp_plan(&options, &seccomp_plan) < 0) {
        perror("landlockd_cli_build_seccomp_plan");
        _exit(1);
      }
      if (landlockd_apply_sandbox_with_seccomp(ruleset_fd, &seccomp_plan,
                                               &listener_fd) < 0) {
        perror("landlockd_apply_sandbox_with_seccomp");
        _exit(1);
      }
      if (listener_fd >= 0 && close(listener_fd) < 0) {
        perror("close");
        _exit(1);
      }
      if (close(ruleset_fd) < 0) {
        perror("close");
        _exit(1);
      }
    } else {
      if (landlockd_apply_sandbox(ruleset_fd, 0) < 0) {
        perror("landlockd_apply_sandbox");
        _exit(1);
      }
    }
    execvp(options.command_argv[0], options.command_argv);
    perror(options.command_argv[0]);
    _exit(127);
  }

  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      perror("waitpid");
      close(ruleset_fd);
      landlockd_cli_options_release(&options);
      return 1;
    }
  }
  close(ruleset_fd);

  if (WIFEXITED(status)) {
    landlockd_cli_emit_event("child.exit status=%d", WEXITSTATUS(status));
    landlockd_cli_options_release(&options);
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    sig = WTERMSIG(status);
    landlockd_cli_emit_event("child.signal signal=%d", sig);
    landlockd_cli_options_release(&options);
    signal(sig, SIG_DFL);
    raise(sig);
    return 128 + sig;
  }
  landlockd_cli_options_release(&options);
  return 1;
}
