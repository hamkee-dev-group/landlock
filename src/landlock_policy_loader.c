#define _GNU_SOURCE

#include "landlock_policy_loader.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define LANDLOCKD_POLICY_WIRE_MAGIC 0x4c504c44u
#define LANDLOCKD_POLICY_WIRE_VERSION 13u

#ifdef LANDLOCKD_POLICY_LOADER_USE_HELPER
static int helper_path_exists(const char *path) {
  struct stat st;

  return path != NULL && path[0] != '\0' && stat(path, &st) == 0 &&
         (st.st_mode & S_IXUSR) != 0;
}

static int build_sibling_helper_path(const char *basename, char *buf,
                                     size_t buf_size) {
  ssize_t nread;
  char *slash;

  if (basename == NULL || buf == NULL || buf_size == 0) {
    errno = EINVAL;
    return -1;
  }
  nread = readlink("/proc/self/exe", buf, buf_size - 1);
  if (nread < 0) {
    return -1;
  }
  buf[nread] = '\0';
  slash = strrchr(buf, '/');
  if (slash == NULL) {
    errno = EINVAL;
    return -1;
  }
  slash[1] = '\0';
  if (strlen(buf) + strlen(basename) + 1 > buf_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  strcat(buf, basename);
  return 0;
}

static int build_parent_src_helper_path(const char *basename, char *buf,
                                        size_t buf_size) {
  char base[PATH_MAX];
  ssize_t nread;
  char *slash;
  int n;

  if (basename == NULL || buf == NULL || buf_size == 0) {
    errno = EINVAL;
    return -1;
  }
  nread = readlink("/proc/self/exe", base, sizeof(base) - 1);
  if (nread < 0) {
    return -1;
  }
  base[nread] = '\0';
  slash = strrchr(base, '/');
  if (slash == NULL) {
    errno = EINVAL;
    return -1;
  }
  *slash = '\0';
  slash = strrchr(base, '/');
  if (slash == NULL) {
    errno = EINVAL;
    return -1;
  }
  *slash = '\0';
  n = snprintf(buf, buf_size, "%s/src/%s", base, basename);
  if (n < 0 || (size_t)n >= buf_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static const char *policy_helper_path(void) {
  const char *override;
  const char *backend;
  static char sibling_path[PATH_MAX];

  override = getenv("LANDLOCKD_POLICY_HELPER");
  if (override != NULL && override[0] != '\0') {
    return override;
  }
  backend = getenv("LANDLOCKD_POLICY_HELPER_BACKEND");
  if (backend != NULL && strcmp(backend, "rust") == 0) {
    if (build_sibling_helper_path("landlockd-policy-helper-rs", sibling_path,
                                  sizeof(sibling_path)) == 0 &&
        helper_path_exists(sibling_path)) {
      return sibling_path;
    }
    if (build_parent_src_helper_path("landlockd-policy-helper-rs", sibling_path,
                                     sizeof(sibling_path)) == 0 &&
        helper_path_exists(sibling_path)) {
      return sibling_path;
    }
    return LANDLOCKD_POLICY_HELPER_RUST_PATH;
  }
  if (backend != NULL && strcmp(backend, "c") == 0) {
    if (build_sibling_helper_path("landlockd-policy-helper", sibling_path,
                                  sizeof(sibling_path)) == 0 &&
        helper_path_exists(sibling_path)) {
      return sibling_path;
    }
    if (build_parent_src_helper_path("landlockd-policy-helper", sibling_path,
                                     sizeof(sibling_path)) == 0 &&
        helper_path_exists(sibling_path)) {
      return sibling_path;
    }
    return LANDLOCKD_POLICY_HELPER_PATH;
  }
  if (build_sibling_helper_path("landlockd-policy-helper", sibling_path,
                                sizeof(sibling_path)) == 0 &&
      helper_path_exists(sibling_path)) {
    return sibling_path;
  }
  if (build_parent_src_helper_path("landlockd-policy-helper", sibling_path,
                                   sizeof(sibling_path)) == 0 &&
      helper_path_exists(sibling_path)) {
    return sibling_path;
  }
  if (helper_path_exists(LANDLOCKD_POLICY_HELPER_PATH)) {
    return LANDLOCKD_POLICY_HELPER_PATH;
  }
  if (build_sibling_helper_path("landlockd-policy-helper-rs", sibling_path,
                                sizeof(sibling_path)) == 0 &&
      helper_path_exists(sibling_path)) {
    return sibling_path;
  }
  if (build_parent_src_helper_path("landlockd-policy-helper-rs", sibling_path,
                                   sizeof(sibling_path)) == 0 &&
      helper_path_exists(sibling_path)) {
    return sibling_path;
  }
  if (helper_path_exists(LANDLOCKD_POLICY_HELPER_RUST_PATH)) {
    return LANDLOCKD_POLICY_HELPER_RUST_PATH;
  }
  return LANDLOCKD_POLICY_HELPER_PATH;
}

static void report_helper(FILE *err, const char *file_path, const char *fmt,
                          ...) {
  va_list ap;

  if (err == NULL) {
    return;
  }
  fprintf(err, "landlockd: policy %s: ", file_path);
  va_start(ap, fmt);
  vfprintf(err, fmt, ap);
  va_end(ap);
  fputc('\n', err);
}
#endif

static int write_all(int fd, const void *buf, size_t len) {
  const unsigned char *p;
  ssize_t n;

  p = buf;
  while (len > 0) {
    n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 0;
}

static int write_u32(int fd, uint32_t value) {
  return write_all(fd, &value, sizeof(value));
}

static int write_u64(int fd, uint64_t value) {
  return write_all(fd, &value, sizeof(value));
}

static int write_ir(int fd, const struct landlockd_policy_ir *ir) {
  uint32_t i;
  uint32_t j;
  uint32_t path_len;

  if (write_u32(fd, LANDLOCKD_POLICY_WIRE_MAGIC) < 0 ||
      write_u32(fd, LANDLOCKD_POLICY_WIRE_VERSION) < 0 ||
      write_u32(fd, (uint32_t)ir->fs_layer_count) < 0 ||
      write_u32(fd, (uint32_t)ir->net_enabled) < 0 ||
      write_u64(fd, ir->net_handled_access) < 0 ||
      write_u32(fd, (uint32_t)ir->net_rule_count) < 0 ||
      write_u32(fd, (uint32_t)ir->broker_open_read_count) < 0 ||
      write_u32(fd, (uint32_t)ir->broker_open_write_count) < 0 ||
      write_u32(fd, (uint32_t)ir->broker_scratch_count) < 0 ||
      write_u32(fd, (uint32_t)ir->broker_export_count) < 0 ||
      write_u32(fd, (uint32_t)ir->broker_mount_tmpfs_count) < 0 ||
      write_u32(fd, (uint32_t)ir->broker_mount_bind_count) < 0 ||
      write_u32(fd, (uint32_t)ir->broker_mount_object_count) < 0 ||
      write_u32(fd, (uint32_t)ir->mount_tmpfs_count) < 0 ||
      write_u32(fd, (uint32_t)ir->mount_bind_count) < 0 ||
      write_u32(fd, (uint32_t)ir->mount_proc_count) < 0 ||
      write_u32(fd, ir->runtime_root != NULL ? (uint32_t)strlen(ir->runtime_root)
                                             : 0U) < 0 ||
      write_u32(fd, ir->runtime_cwd != NULL ? (uint32_t)strlen(ir->runtime_cwd)
                                            : 0U) < 0 ||
      write_u32(fd, (uint32_t)ir->seccomp_enabled) < 0 ||
      write_u32(fd, (uint32_t)ir->seccomp_errno) < 0 ||
      write_u32(fd, (uint32_t)ir->seccomp_deny_count) < 0) {
    return -1;
  }

  for (i = 0; i < ir->fs_layer_count; i++) {
    if (write_u64(fd, ir->fs_layers[i].handled_access_fs) < 0 ||
        write_u32(fd, (uint32_t)ir->fs_layers[i].rule_count) < 0) {
      return -1;
    }
    for (j = 0; j < ir->fs_layers[i].rule_count; j++) {
      path_len = (uint32_t)strlen(ir->fs_layers[i].rules[j].path);
      if (write_u64(fd, ir->fs_layers[i].rules[j].allowed_access) < 0 ||
          write_u32(fd, path_len) < 0 ||
          write_all(fd, ir->fs_layers[i].rules[j].path, path_len) < 0) {
        return -1;
      }
    }
  }

  for (i = 0; i < ir->net_rule_count; i++) {
    if (write_u32(fd, ir->net_rules[i].port) < 0 ||
        write_u64(fd, ir->net_rules[i].allowed_access) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->broker_open_read_count; i++) {
    path_len = (uint32_t)strlen(ir->broker_open_read_rules[i].path);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_open_read_rules[i].path, path_len) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->broker_open_write_count; i++) {
    path_len = (uint32_t)strlen(ir->broker_open_write_rules[i].path);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_open_write_rules[i].path, path_len) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->broker_scratch_count; i++) {
    path_len = (uint32_t)strlen(ir->broker_scratch_rules[i].path);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_scratch_rules[i].path, path_len) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->broker_export_count; i++) {
    path_len = (uint32_t)strlen(ir->broker_export_rules[i].path);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_export_rules[i].path, path_len) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->broker_mount_tmpfs_count; i++) {
    path_len = (uint32_t)strlen(ir->broker_mount_tmpfs_rules[i].path);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_mount_tmpfs_rules[i].path, path_len) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->broker_mount_bind_count; i++) {
    path_len = (uint32_t)strlen(ir->broker_mount_bind_rules[i].source);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_mount_bind_rules[i].source, path_len) < 0) {
      return -1;
    }
    path_len = (uint32_t)strlen(ir->broker_mount_bind_rules[i].target);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_mount_bind_rules[i].target, path_len) < 0 ||
        write_u32(fd, (uint32_t)ir->broker_mount_bind_rules[i].read_only) <
            0) {
      return -1;
    }
  }

  for (i = 0; i < ir->broker_mount_object_count; i++) {
    uint32_t attach_count;
    uint32_t attr_hi;
    uint32_t attr_lo;
    uint32_t k;

    path_len = (uint32_t)strlen(ir->broker_mount_object_rules[i].name);
    attach_count = (uint32_t)ir->broker_mount_object_rules[i].attach_count;
    attr_lo = (uint32_t)(ir->broker_mount_object_rules[i].allowed_attr_set &
                         0xffffffffu);
    attr_hi = (uint32_t)(ir->broker_mount_object_rules[i].allowed_attr_set >>
                         32);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_mount_object_rules[i].name, path_len) < 0) {
      return -1;
    }
    path_len = (uint32_t)strlen(ir->broker_mount_object_rules[i].fs_type);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->broker_mount_object_rules[i].fs_type, path_len) < 0 ||
        write_u32(fd, attach_count) < 0 || write_u32(fd, attr_lo) < 0 ||
        write_u32(fd, attr_hi) < 0) {
      return -1;
    }
    for (k = 0; k < attach_count; k++) {
      path_len = (uint32_t)strlen(ir->broker_mount_object_rules[i].attach_paths[k]);
      if (write_u32(fd, path_len) < 0 ||
          write_all(fd, ir->broker_mount_object_rules[i].attach_paths[k],
                    path_len) < 0) {
        return -1;
      }
    }
  }

  for (i = 0; i < ir->mount_tmpfs_count; i++) {
    path_len = (uint32_t)strlen(ir->mount_tmpfs_rules[i].path);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->mount_tmpfs_rules[i].path, path_len) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->mount_bind_count; i++) {
    path_len = (uint32_t)strlen(ir->mount_bind_rules[i].source);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->mount_bind_rules[i].source, path_len) < 0) {
      return -1;
    }
    path_len = (uint32_t)strlen(ir->mount_bind_rules[i].target);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->mount_bind_rules[i].target, path_len) < 0 ||
        write_u32(fd, (uint32_t)ir->mount_bind_rules[i].read_only) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->mount_proc_count; i++) {
    path_len = (uint32_t)strlen(ir->mount_proc_rules[i].path);
    if (write_u32(fd, path_len) < 0 ||
        write_all(fd, ir->mount_proc_rules[i].path, path_len) < 0) {
      return -1;
    }
  }

  if (ir->runtime_root != NULL) {
    path_len = (uint32_t)strlen(ir->runtime_root);
    if (write_all(fd, ir->runtime_root, path_len) < 0) {
      return -1;
    }
  }
  if (ir->runtime_cwd != NULL) {
    path_len = (uint32_t)strlen(ir->runtime_cwd);
    if (write_all(fd, ir->runtime_cwd, path_len) < 0) {
      return -1;
    }
  }

  for (i = 0; i < ir->seccomp_deny_count; i++) {
    if (write_u32(fd, (uint32_t)ir->seccomp_deny_rules[i].syscall_nr) < 0) {
      return -1;
    }
  }

  return 0;
}

#ifdef LANDLOCKD_POLICY_LOADER_USE_HELPER
static int append_fd(int fd, unsigned char **buf, size_t *len) {
  unsigned char chunk[512];
  unsigned char *grown;
  ssize_t n;

  for (;;) {
    n = read(fd, chunk, sizeof(chunk));
    if (n == 0) {
      return 0;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    grown = realloc(*buf, *len + (size_t)n);
    if (grown == NULL) {
      return -1;
    }
    memcpy(grown + *len, chunk, (size_t)n);
    *buf = grown;
    *len += (size_t)n;
  }
}

static int read_u32_buf(const unsigned char *buf, size_t len, size_t *off,
                        uint32_t *out) {
  if (*off + sizeof(*out) > len) {
    errno = EINVAL;
    return -1;
  }
  memcpy(out, buf + *off, sizeof(*out));
  *off += sizeof(*out);
  return 0;
}

static int read_u64_buf(const unsigned char *buf, size_t len, size_t *off,
                        uint64_t *out) {
  if (*off + sizeof(*out) > len) {
    errno = EINVAL;
    return -1;
  }
  memcpy(out, buf + *off, sizeof(*out));
  *off += sizeof(*out);
  return 0;
}

static int load_ir_from_wire(const unsigned char *buf, size_t len,
                             struct landlockd_policy_ir *out_ir) {
  uint32_t magic;
  uint32_t version;
  uint32_t fs_layer_count;
  uint32_t net_enabled;
  uint32_t net_rule_count;
  uint32_t broker_open_read_count;
  uint32_t broker_open_write_count;
  uint32_t broker_scratch_count;
  uint32_t broker_export_count;
  uint32_t broker_mount_tmpfs_count;
  uint32_t broker_mount_bind_count;
  uint32_t broker_mount_object_count;
  uint32_t mount_tmpfs_count;
  uint32_t mount_bind_count;
  uint32_t mount_proc_count;
  uint32_t runtime_root_len;
  uint32_t runtime_cwd_len;
  uint32_t seccomp_enabled;
  uint32_t seccomp_errno;
  uint32_t seccomp_deny_count;
  uint64_t net_handled_access;
  uint64_t handled_access_fs;
  uint64_t allowed_access;
  uint32_t rule_count;
  uint32_t path_len;
  uint32_t port;
  size_t off;
  size_t layer_index;
  size_t i;
  size_t j;
  int saved_errno;
  char *path;

  off = 0;
  if (read_u32_buf(buf, len, &off, &magic) < 0 ||
      read_u32_buf(buf, len, &off, &version) < 0 ||
      read_u32_buf(buf, len, &off, &fs_layer_count) < 0 ||
      read_u32_buf(buf, len, &off, &net_enabled) < 0 ||
      read_u64_buf(buf, len, &off, &net_handled_access) < 0 ||
      read_u32_buf(buf, len, &off, &net_rule_count) < 0 ||
      read_u32_buf(buf, len, &off, &broker_open_read_count) < 0 ||
      read_u32_buf(buf, len, &off, &broker_open_write_count) < 0 ||
      read_u32_buf(buf, len, &off, &broker_scratch_count) < 0 ||
      read_u32_buf(buf, len, &off, &broker_export_count) < 0 ||
      read_u32_buf(buf, len, &off, &broker_mount_tmpfs_count) < 0 ||
      read_u32_buf(buf, len, &off, &broker_mount_bind_count) < 0 ||
      read_u32_buf(buf, len, &off, &broker_mount_object_count) < 0 ||
      read_u32_buf(buf, len, &off, &mount_tmpfs_count) < 0 ||
      read_u32_buf(buf, len, &off, &mount_bind_count) < 0 ||
      read_u32_buf(buf, len, &off, &mount_proc_count) < 0 ||
      read_u32_buf(buf, len, &off, &runtime_root_len) < 0 ||
      read_u32_buf(buf, len, &off, &runtime_cwd_len) < 0 ||
      read_u32_buf(buf, len, &off, &seccomp_enabled) < 0 ||
      read_u32_buf(buf, len, &off, &seccomp_errno) < 0 ||
      read_u32_buf(buf, len, &off, &seccomp_deny_count) < 0) {
    return -1;
  }
  if (magic != LANDLOCKD_POLICY_WIRE_MAGIC ||
      version != LANDLOCKD_POLICY_WIRE_VERSION) {
    errno = EINVAL;
    return -1;
  }

  for (i = 0; i < fs_layer_count; i++) {
    if (read_u64_buf(buf, len, &off, &handled_access_fs) < 0 ||
        read_u32_buf(buf, len, &off, &rule_count) < 0 ||
        landlockd_policy_ir_add_fs_layer(out_ir, handled_access_fs,
                                         &layer_index) < 0) {
      return -1;
    }
    for (j = 0; j < rule_count; j++) {
      if (read_u64_buf(buf, len, &off, &allowed_access) < 0 ||
          read_u32_buf(buf, len, &off, &path_len) < 0 ||
          off + path_len > len) {
        errno = EINVAL;
        return -1;
      }
      path = malloc((size_t)path_len + 1);
      if (path == NULL) {
        return -1;
      }
      memcpy(path, buf + off, path_len);
      path[path_len] = '\0';
      off += path_len;
      if (landlockd_policy_ir_add_fs_rule(out_ir, layer_index, path,
                                          allowed_access) < 0) {
        saved_errno = errno;
        free(path);
        errno = saved_errno;
        return -1;
      }
      free(path);
    }
  }

  if (net_enabled != 0) {
    if (landlockd_policy_ir_enable_net(out_ir, net_handled_access) < 0) {
      return -1;
    }
    for (i = 0; i < net_rule_count; i++) {
      if (read_u32_buf(buf, len, &off, &port) < 0 ||
          read_u64_buf(buf, len, &off, &allowed_access) < 0 ||
          landlockd_policy_ir_add_net_rule(out_ir, (uint16_t)port,
                                           allowed_access) < 0) {
        return -1;
      }
    }
  }

  for (i = 0; i < broker_open_read_count; i++) {
    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)path_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, path_len);
    path[path_len] = '\0';
    off += path_len;
    if (landlockd_policy_ir_add_broker_open_read_rule(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  for (i = 0; i < broker_open_write_count; i++) {
    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)path_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, path_len);
    path[path_len] = '\0';
    off += path_len;
    if (landlockd_policy_ir_add_broker_open_write_rule(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  for (i = 0; i < broker_scratch_count; i++) {
    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)path_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, path_len);
    path[path_len] = '\0';
    off += path_len;
    if (landlockd_policy_ir_add_broker_scratch_rule(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  for (i = 0; i < broker_export_count; i++) {
    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)path_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, path_len);
    path[path_len] = '\0';
    off += path_len;
    if (landlockd_policy_ir_add_broker_export_rule(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  for (i = 0; i < broker_mount_tmpfs_count; i++) {
    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)path_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, path_len);
    path[path_len] = '\0';
    off += path_len;
    if (landlockd_policy_ir_add_broker_mount_tmpfs_rule(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  for (i = 0; i < broker_mount_bind_count; i++) {
    uint32_t read_only;
    char *source;
    char *target;

    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    source = malloc((size_t)path_len + 1);
    if (source == NULL) {
      return -1;
    }
    memcpy(source, buf + off, path_len);
    source[path_len] = '\0';
    off += path_len;

    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      free(source);
      errno = EINVAL;
      return -1;
    }
    target = malloc((size_t)path_len + 1);
    if (target == NULL) {
      free(source);
      return -1;
    }
    memcpy(target, buf + off, path_len);
    target[path_len] = '\0';
    off += path_len;
    if (read_u32_buf(buf, len, &off, &read_only) < 0 ||
        read_only > 1 ||
        landlockd_policy_ir_add_broker_mount_bind_rule(out_ir, source, target,
                                                       (int)read_only) < 0) {
      saved_errno = errno;
      free(source);
      free(target);
      errno = saved_errno;
      return -1;
    }
    free(source);
    free(target);
  }

  for (i = 0; i < broker_mount_object_count; i++) {
    uint32_t attach_count;
    uint32_t attr_lo;
    uint32_t attr_hi;
    uint64_t allowed_attr_set;
    char *name;
    char *fs_type;
    char **attach_paths;
    uint32_t k;

    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    name = malloc((size_t)path_len + 1);
    if (name == NULL) {
      return -1;
    }
    memcpy(name, buf + off, path_len);
    name[path_len] = '\0';
    off += path_len;

    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      free(name);
      errno = EINVAL;
      return -1;
    }
    fs_type = malloc((size_t)path_len + 1);
    if (fs_type == NULL) {
      free(name);
      return -1;
    }
    memcpy(fs_type, buf + off, path_len);
    fs_type[path_len] = '\0';
    off += path_len;
    if (read_u32_buf(buf, len, &off, &attach_count) < 0 ||
        read_u32_buf(buf, len, &off, &attr_lo) < 0 ||
        read_u32_buf(buf, len, &off, &attr_hi) < 0 || attach_count == 0) {
      free(name);
      free(fs_type);
      errno = EINVAL;
      return -1;
    }
    allowed_attr_set = ((uint64_t)attr_hi << 32) | (uint64_t)attr_lo;
    attach_paths = calloc(attach_count, sizeof(*attach_paths));
    if (attach_paths == NULL) {
      free(name);
      free(fs_type);
      return -1;
    }
    for (k = 0; k < attach_count; k++) {
      if (read_u32_buf(buf, len, &off, &path_len) < 0 ||
          off + path_len > len) {
        saved_errno = EINVAL;
        goto fail_mount_object;
      }
      attach_paths[k] = malloc((size_t)path_len + 1);
      if (attach_paths[k] == NULL) {
        saved_errno = errno;
        goto fail_mount_object;
      }
      memcpy(attach_paths[k], buf + off, path_len);
      attach_paths[k][path_len] = '\0';
      off += path_len;
    }
    if (landlockd_policy_ir_add_broker_mount_object_rule(
            out_ir, name, fs_type, (const char *const *)attach_paths,
            (size_t)attach_count, allowed_attr_set) < 0) {
      saved_errno = errno;
      goto fail_mount_object;
    }
    for (k = 0; k < attach_count; k++) {
      free(attach_paths[k]);
    }
    free(attach_paths);
    free(name);
    free(fs_type);
    continue;

fail_mount_object:
    for (k = 0; k < attach_count; k++) {
      free(attach_paths[k]);
    }
    free(attach_paths);
    free(name);
    free(fs_type);
    errno = saved_errno;
    return -1;
  }

  for (i = 0; i < mount_tmpfs_count; i++) {
    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)path_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, path_len);
    path[path_len] = '\0';
    off += path_len;
    if (landlockd_policy_ir_add_mount_tmpfs_rule(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  for (i = 0; i < mount_bind_count; i++) {
    uint32_t read_only;
    char *source;
    char *target;

    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    source = malloc((size_t)path_len + 1);
    if (source == NULL) {
      return -1;
    }
    memcpy(source, buf + off, path_len);
    source[path_len] = '\0';
    off += path_len;

    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      free(source);
      errno = EINVAL;
      return -1;
    }
    target = malloc((size_t)path_len + 1);
    if (target == NULL) {
      free(source);
      return -1;
    }
    memcpy(target, buf + off, path_len);
    target[path_len] = '\0';
    off += path_len;
    if (read_u32_buf(buf, len, &off, &read_only) < 0 ||
        read_only > 1 ||
        landlockd_policy_ir_add_mount_bind_rule(out_ir, source, target,
                                                (int)read_only) < 0) {
      saved_errno = errno;
      free(source);
      free(target);
      errno = saved_errno;
      return -1;
    }
    free(source);
    free(target);
  }

  for (i = 0; i < mount_proc_count; i++) {
    if (read_u32_buf(buf, len, &off, &path_len) < 0 || off + path_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)path_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, path_len);
    path[path_len] = '\0';
    off += path_len;
    if (landlockd_policy_ir_add_mount_proc_rule(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  if (runtime_root_len > 0) {
    if (off + runtime_root_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)runtime_root_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, runtime_root_len);
    path[runtime_root_len] = '\0';
    off += runtime_root_len;
    if (landlockd_policy_ir_set_runtime_root(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }
  if (runtime_cwd_len > 0) {
    if (off + runtime_cwd_len > len) {
      errno = EINVAL;
      return -1;
    }
    path = malloc((size_t)runtime_cwd_len + 1);
    if (path == NULL) {
      return -1;
    }
    memcpy(path, buf + off, runtime_cwd_len);
    path[runtime_cwd_len] = '\0';
    off += runtime_cwd_len;
    if (landlockd_policy_ir_set_runtime_cwd(out_ir, path) < 0) {
      saved_errno = errno;
      free(path);
      errno = saved_errno;
      return -1;
    }
    free(path);
  }

  if (seccomp_enabled != 0) {
    if (seccomp_errno == 0 || seccomp_errno > 4095 ||
        landlockd_policy_ir_enable_seccomp(out_ir,
                                           (unsigned short)seccomp_errno) < 0) {
      return -1;
    }
    for (i = 0; i < seccomp_deny_count; i++) {
      uint32_t syscall_nr;

      if (read_u32_buf(buf, len, &off, &syscall_nr) < 0 ||
          syscall_nr > INT32_MAX ||
          landlockd_policy_ir_add_seccomp_deny_rule(out_ir, (int)syscall_nr) <
              0) {
        return -1;
      }
    }
  }

  if (off != len) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}
#endif

int landlockd_policy_loader_uses_helper(void) {
#ifdef LANDLOCKD_POLICY_LOADER_USE_HELPER
  return 1;
#else
  return 0;
#endif
}

int landlockd_policy_load_file(const char *file_path,
                               struct landlockd_policy_ir *out_ir,
                               FILE *err_stream) {
#ifndef LANDLOCKD_POLICY_LOADER_USE_HELPER
  return landlockd_policy_load_file_in_process(file_path, out_ir, err_stream);
#else
  unsigned char *wire_buf;
  unsigned char *stderr_buf;
  size_t wire_len;
  size_t stderr_len;
  int saved_errno;
  int out_pipe[2];
  int err_pipe[2];
  int exec_pipe[2];
  int exec_errno;
  ssize_t exec_nread;
  const char *helper_path;
  pid_t pid;
  int status;

  if (file_path == NULL || out_ir == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (out_ir->fs_layer_count != 0 || out_ir->fs_layers != NULL ||
      out_ir->net_enabled || out_ir->net_rules != NULL ||
      out_ir->broker_open_read_count != 0 ||
      out_ir->broker_open_read_rules != NULL ||
      out_ir->broker_open_write_count != 0 ||
      out_ir->broker_open_write_rules != NULL ||
      out_ir->broker_scratch_count != 0 ||
      out_ir->broker_scratch_rules != NULL ||
      out_ir->broker_export_count != 0 ||
      out_ir->broker_export_rules != NULL ||
      out_ir->broker_mount_tmpfs_count != 0 ||
      out_ir->broker_mount_tmpfs_rules != NULL ||
      out_ir->broker_mount_bind_count != 0 ||
      out_ir->broker_mount_bind_rules != NULL ||
      out_ir->broker_mount_object_count != 0 ||
      out_ir->broker_mount_object_rules != NULL ||
      out_ir->mount_tmpfs_count != 0 ||
      out_ir->mount_tmpfs_rules != NULL || out_ir->mount_bind_count != 0 ||
      out_ir->mount_bind_rules != NULL || out_ir->mount_proc_count != 0 ||
      out_ir->mount_proc_rules != NULL || out_ir->runtime_root != NULL ||
      out_ir->runtime_cwd != NULL ||
      out_ir->seccomp_enabled || out_ir->seccomp_errno != 0 ||
      out_ir->seccomp_deny_count != 0 || out_ir->seccomp_deny_rules != NULL) {
    errno = EINVAL;
    return -1;
  }
  if (pipe(out_pipe) < 0 || pipe(err_pipe) < 0 || pipe(exec_pipe) < 0) {
    return -1;
  }

  helper_path = policy_helper_path();
  pid = fork();
  if (pid < 0) {
    saved_errno = errno;
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    close(exec_pipe[0]);
    close(exec_pipe[1]);
    errno = saved_errno;
    return -1;
  }
  if (pid == 0) {
    close(out_pipe[0]);
    close(err_pipe[0]);
    close(exec_pipe[0]);
    dup2(out_pipe[1], STDOUT_FILENO);
    dup2(err_pipe[1], STDERR_FILENO);
    close(out_pipe[1]);
    close(err_pipe[1]);
    execl(helper_path, helper_path, file_path, NULL);
    saved_errno = errno;
    write_all(exec_pipe[1], &saved_errno, sizeof(saved_errno));
    _exit(127);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  close(exec_pipe[1]);

  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      saved_errno = errno;
      close(out_pipe[0]);
      close(err_pipe[0]);
      close(exec_pipe[0]);
      errno = saved_errno;
      return -1;
    }
  }

  exec_errno = 0;
  exec_nread = read(exec_pipe[0], &exec_errno, sizeof(exec_errno));
  close(exec_pipe[0]);

  wire_buf = NULL;
  stderr_buf = NULL;
  wire_len = 0;
  stderr_len = 0;
  if (append_fd(out_pipe[0], &wire_buf, &wire_len) < 0 ||
      append_fd(err_pipe[0], &stderr_buf, &stderr_len) < 0) {
    saved_errno = errno;
    free(wire_buf);
    free(stderr_buf);
    close(out_pipe[0]);
    close(err_pipe[0]);
    errno = saved_errno;
    return -1;
  }
  close(out_pipe[0]);
  close(err_pipe[0]);

  if (exec_nread == (ssize_t)sizeof(exec_errno)) {
    report_helper(err_stream, file_path, "helper exec failed: %s",
                  strerror(exec_errno));
    free(wire_buf);
    free(stderr_buf);
    errno = exec_errno;
    return -1;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    if (err_stream != NULL && stderr_len > 0) {
      fwrite(stderr_buf, 1, stderr_len, err_stream);
    } else if (err_stream != NULL) {
      report_helper(err_stream, file_path, "helper failed");
    }
    free(wire_buf);
    free(stderr_buf);
    errno = EINVAL;
    return -1;
  }

  if (load_ir_from_wire(wire_buf, wire_len, out_ir) < 0) {
    saved_errno = errno;
    landlockd_policy_ir_reset(out_ir);
    free(wire_buf);
    free(stderr_buf);
    errno = saved_errno;
    return -1;
  }

  free(wire_buf);
  free(stderr_buf);
  return 0;
#endif
}

int landlockd_policy_helper_main(int argc, char *argv[]) {
  struct landlockd_policy_ir ir;
  int rc;
  int saved_errno;

  if (argc != 2) {
    return 1;
  }

  landlockd_policy_ir_init(&ir);
  rc = landlockd_policy_load_file_in_process(argv[1], &ir, stderr);
  if (rc < 0) {
    landlockd_policy_ir_reset(&ir);
    return 1;
  }
  if (write_ir(STDOUT_FILENO, &ir) < 0) {
    saved_errno = errno;
    landlockd_policy_ir_reset(&ir);
    errno = saved_errno;
    perror("landlockd-policy-helper");
    return 1;
  }
  landlockd_policy_ir_reset(&ir);
  return 0;
}
