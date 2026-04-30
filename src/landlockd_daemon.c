#define _GNU_SOURCE

#include "landlockd_daemon.h"

#include "landlock_policy_ir.h"
#include "landlock_policy_loader.h"
#include "landlockd_audit.h"
#include "landlockd_exec.h"
#include "landlockd/seccomp.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define LANDLOCKD_DAEMON_MAGIC 0x4c444344u
#define LANDLOCKD_DAEMON_VERSION 1u
#define LANDLOCKD_DAEMON_CMD_RUN 1u
#define LANDLOCKD_DAEMON_CMD_STOP 2u
#define LANDLOCKD_DAEMON_CMD_STATUS 3u
#define LANDLOCKD_DAEMON_MAX_ARGS 128u
#define LANDLOCKD_DAEMON_MAX_POLICY_LEN 16384u
#define LANDLOCKD_DAEMON_MAX_ARG_LEN 65535u
#define LANDLOCKD_DAEMON_MAX_REQUEST_BYTES (1024u * 1024u)
#define LANDLOCKD_DAEMON_MAX_CACHE_ENTRIES 16u
#define LANDLOCKD_SYSTEMD_FD_START 3

struct landlockd_daemon_request_header {
  uint32_t magic;
  uint32_t version;
  uint32_t command;
  uint32_t argc;
  uint32_t policy_len;
};

struct landlockd_daemon_response {
  uint32_t magic;
  uint32_t version;
  int32_t status;
  int32_t error_value;
};

struct landlockd_daemon_status_response {
  struct landlockd_daemon_response base;
  uint32_t protocol_version;
  uint32_t cache_entries;
  uint64_t cache_hits;
  uint64_t cache_misses;
};

struct landlockd_daemon_cache_entry {
  char *policy_file;
  dev_t dev;
  ino_t ino;
  off_t size;
  struct timespec mtime;
  struct landlockd_policy_ir ir;
  struct landlockd_daemon_cache_entry *next;
};

struct landlockd_daemon_state {
  uid_t uid;
  size_t cache_entries;
  unsigned long long cache_hits;
  unsigned long long cache_misses;
  struct landlockd_daemon_cache_entry *cache_head;
};

static void landlockd_daemon_diag(FILE *diag, const char *fmt, ...) {
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

static void landlockd_daemon_audit_listener(FILE *diag, const char *event,
                                            const char *socket_label,
                                            const char *mode) {
  int first_field;

  landlockd_audit_begin(diag, event, &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)getpid());
  landlockd_audit_field_string(diag, &first_field, "socket", socket_label);
  if (mode != NULL) {
    landlockd_audit_field_string(diag, &first_field, "mode", mode);
  }
  landlockd_audit_end(diag);
}

static void landlockd_daemon_audit_request(FILE *diag, const char *command,
                                           const char *policy_file,
                                           uint32_t argc) {
  int first_field;

  landlockd_audit_begin(diag, "daemon.request", &first_field);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)getpid());
  landlockd_audit_field_string(diag, &first_field, "command", command);
  if (policy_file != NULL) {
    landlockd_audit_field_string(diag, &first_field, "policy_file",
                                 policy_file);
  }
  landlockd_audit_field_uint(diag, &first_field, "argc",
                             (unsigned long long)argc);
  landlockd_audit_end(diag);
}

static void landlockd_daemon_audit_peer(FILE *diag, uid_t uid, pid_t pid,
                                        const char *decision) {
  int first_field;

  landlockd_audit_begin(diag, "daemon.peer", &first_field);
  landlockd_audit_field_int(diag, &first_field, "uid", (long long)uid);
  landlockd_audit_field_int(diag, &first_field, "pid", (long long)pid);
  landlockd_audit_field_string(diag, &first_field, "decision", decision);
  landlockd_audit_end(diag);
}

static int landlockd_daemon_write_all(int fd, const void *buf, size_t len) {
  const unsigned char *p;
  ssize_t nwritten;

  p = buf;
  while (len > 0) {
    nwritten = write(fd, p, len);
    if (nwritten < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    p += (size_t)nwritten;
    len -= (size_t)nwritten;
  }
  return 0;
}

static int landlockd_daemon_read_all(int fd, void *buf, size_t len) {
  unsigned char *p;
  ssize_t nread;

  p = buf;
  while (len > 0) {
    nread = read(fd, p, len);
    if (nread == 0) {
      errno = EPIPE;
      return -1;
    }
    if (nread < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    p += (size_t)nread;
    len -= (size_t)nread;
  }
  return 0;
}

static int landlockd_daemon_connect(const char *socket_path) {
  struct sockaddr_un addr;
  int fd;

  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(socket_path) >= sizeof(addr.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(addr.sun_path, socket_path);

  if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
    int saved_errno;

    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}

static int landlockd_daemon_send_response(int client_fd, int status,
                                          int error_value) {
  struct landlockd_daemon_response response;

  response.magic = LANDLOCKD_DAEMON_MAGIC;
  response.version = LANDLOCKD_DAEMON_VERSION;
  response.status = status;
  response.error_value = error_value;
  return landlockd_daemon_write_all(client_fd, &response, sizeof(response));
}

static int landlockd_daemon_send_status_response(
    int client_fd, const struct landlockd_daemon_state *state) {
  struct landlockd_daemon_status_response response;

  memset(&response, 0, sizeof(response));
  response.base.magic = LANDLOCKD_DAEMON_MAGIC;
  response.base.version = LANDLOCKD_DAEMON_VERSION;
  response.protocol_version = LANDLOCKD_DAEMON_VERSION;
  response.cache_entries = (uint32_t)state->cache_entries;
  response.cache_hits = state->cache_hits;
  response.cache_misses = state->cache_misses;
  return landlockd_daemon_write_all(client_fd, &response, sizeof(response));
}

static void landlockd_daemon_cache_entry_reset(
    struct landlockd_daemon_cache_entry *entry) {
  if (entry == NULL) {
    return;
  }
  free(entry->policy_file);
  entry->policy_file = NULL;
  landlockd_policy_ir_reset(&entry->ir);
  memset(&entry->mtime, 0, sizeof(entry->mtime));
  entry->dev = 0;
  entry->ino = 0;
  entry->size = 0;
}

static void landlockd_daemon_cache_cleanup(struct landlockd_daemon_state *state) {
  struct landlockd_daemon_cache_entry *entry;
  struct landlockd_daemon_cache_entry *next;

  if (state == NULL) {
    return;
  }
  entry = state->cache_head;
  while (entry != NULL) {
    next = entry->next;
    landlockd_daemon_cache_entry_reset(entry);
    free(entry);
    entry = next;
  }
  state->cache_head = NULL;
  state->cache_entries = 0;
}

static int landlockd_daemon_cache_stat_matches(
    const struct landlockd_daemon_cache_entry *entry, const struct stat *st) {
  return entry->dev == st->st_dev && entry->ino == st->st_ino &&
         entry->size == st->st_size &&
         entry->mtime.tv_sec == st->st_mtim.tv_sec &&
         entry->mtime.tv_nsec == st->st_mtim.tv_nsec;
}

static int landlockd_daemon_cache_load_entry(
    struct landlockd_daemon_cache_entry *entry, const char *policy_file,
    const struct stat *st, FILE *diag) {
  landlockd_policy_ir_init(&entry->ir);
  if (landlockd_policy_load_file(policy_file, &entry->ir, diag) < 0) {
    landlockd_policy_ir_reset(&entry->ir);
    return -1;
  }
  entry->policy_file = strdup(policy_file);
  if (entry->policy_file == NULL) {
    landlockd_policy_ir_reset(&entry->ir);
    return -1;
  }
  entry->dev = st->st_dev;
  entry->ino = st->st_ino;
  entry->size = st->st_size;
  entry->mtime = st->st_mtim;
  return 0;
}

static void landlockd_daemon_cache_evict_tail(struct landlockd_daemon_state *state) {
  struct landlockd_daemon_cache_entry *entry;
  struct landlockd_daemon_cache_entry *prev;

  if (state == NULL || state->cache_entries < LANDLOCKD_DAEMON_MAX_CACHE_ENTRIES) {
    return;
  }
  prev = NULL;
  entry = state->cache_head;
  while (entry != NULL && entry->next != NULL) {
    prev = entry;
    entry = entry->next;
  }
  if (entry == NULL) {
    return;
  }
  if (prev == NULL) {
    state->cache_head = NULL;
  } else {
    prev->next = NULL;
  }
  landlockd_daemon_cache_entry_reset(entry);
  free(entry);
  state->cache_entries--;
}

static int landlockd_daemon_cache_get_policy(
    struct landlockd_daemon_state *state, const char *policy_file,
    const struct landlockd_policy_ir **out_ir, FILE *diag) {
  struct landlockd_daemon_cache_entry *entry;
  struct stat st;
  int saved_errno;

  if (state == NULL || policy_file == NULL || out_ir == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (stat(policy_file, &st) < 0) {
    return -1;
  }

  for (entry = state->cache_head; entry != NULL; entry = entry->next) {
    if (entry->policy_file == NULL || strcmp(entry->policy_file, policy_file) != 0) {
      continue;
    }
    if (landlockd_daemon_cache_stat_matches(entry, &st)) {
      state->cache_hits++;
      *out_ir = &entry->ir;
      return 0;
    }
    landlockd_daemon_cache_entry_reset(entry);
    landlockd_policy_ir_init(&entry->ir);
    if (landlockd_daemon_cache_load_entry(entry, policy_file, &st, diag) < 0) {
      saved_errno = errno;
      landlockd_daemon_cache_entry_reset(entry);
      errno = saved_errno;
      return -1;
    }
    state->cache_misses++;
    *out_ir = &entry->ir;
    return 0;
  }

  landlockd_daemon_cache_evict_tail(state);
  entry = calloc(1, sizeof(*entry));
  if (entry == NULL) {
    return -1;
  }
  landlockd_policy_ir_init(&entry->ir);
  if (landlockd_daemon_cache_load_entry(entry, policy_file, &st, diag) < 0) {
    saved_errno = errno;
    free(entry);
    errno = saved_errno;
    return -1;
  }
  entry->next = state->cache_head;
  state->cache_head = entry;
  state->cache_entries++;
  state->cache_misses++;
  *out_ir = &entry->ir;
  return 0;
}

static int landlockd_daemon_peer_authorized(
    int client_fd, const struct landlockd_daemon_state *state, FILE *diag) {
#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t cred_len;

  cred_len = sizeof(cred);
  memset(&cred, 0, sizeof(cred));
  if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
    return -1;
  }
  if ((uid_t)cred.uid != state->uid) {
    landlockd_daemon_audit_peer(diag, (uid_t)cred.uid, (pid_t)cred.pid, "deny");
    errno = EPERM;
    return 0;
  }
  landlockd_daemon_audit_peer(diag, (uid_t)cred.uid, (pid_t)cred.pid, "allow");
#else
  (void)client_fd;
  (void)state;
  (void)diag;
#endif
  return 1;
}

static int landlockd_daemon_handle_run(
    int client_fd, const struct landlockd_daemon_request_header *hdr,
    struct landlockd_daemon_state *state, FILE *diag) {
  const struct landlockd_policy_ir *policy_ir;
  char *policy_file;
  char **argv;
  uint32_t i;
  uint32_t arg_len;
  uint32_t total_bytes;
  int status;
  int saved_errno;

  if (hdr->argc == 0 || hdr->argc > LANDLOCKD_DAEMON_MAX_ARGS ||
      hdr->policy_len == 0 ||
      hdr->policy_len > LANDLOCKD_DAEMON_MAX_POLICY_LEN) {
    return landlockd_daemon_send_response(client_fd, 1, EINVAL);
  }

  policy_file = calloc((size_t)hdr->policy_len + 1, 1);
  if (policy_file == NULL) {
    return landlockd_daemon_send_response(client_fd, 1, errno);
  }
  if (landlockd_daemon_read_all(client_fd, policy_file, hdr->policy_len) < 0) {
    saved_errno = errno;
    free(policy_file);
    errno = saved_errno;
    return -1;
  }

  argv = calloc((size_t)hdr->argc + 1, sizeof(*argv));
  if (argv == NULL) {
    saved_errno = errno;
    free(policy_file);
    return landlockd_daemon_send_response(client_fd, 1, saved_errno);
  }
  total_bytes = hdr->policy_len;

  for (i = 0; i < hdr->argc; i++) {
    if (landlockd_daemon_read_all(client_fd, &arg_len, sizeof(arg_len)) < 0) {
      saved_errno = errno;
      goto fail;
    }
    total_bytes += (uint32_t)sizeof(arg_len);
    if (arg_len == 0 || arg_len > LANDLOCKD_DAEMON_MAX_ARG_LEN ||
        total_bytes > LANDLOCKD_DAEMON_MAX_REQUEST_BYTES ||
        total_bytes + arg_len > LANDLOCKD_DAEMON_MAX_REQUEST_BYTES) {
      saved_errno = EINVAL;
      goto fail;
    }
    argv[i] = calloc((size_t)arg_len + 1, 1);
    if (argv[i] == NULL) {
      saved_errno = errno;
      goto fail;
    }
    if (landlockd_daemon_read_all(client_fd, argv[i], arg_len) < 0) {
      saved_errno = errno;
      goto fail;
    }
    total_bytes += arg_len;
  }
  argv[hdr->argc] = NULL;

  landlockd_daemon_audit_request(diag, "run", policy_file, hdr->argc);
  if (landlockd_daemon_cache_get_policy(state, policy_file, &policy_ir, diag) <
      0) {
    saved_errno = errno;
    for (i = 0; i < hdr->argc; i++) {
      free(argv[i]);
    }
    free(argv);
    free(policy_file);
    return landlockd_daemon_send_response(client_fd, 1, saved_errno);
  }
  status = landlockd_run_policy_ir_loaded(policy_ir, policy_file, argv, diag);
  for (i = 0; i < hdr->argc; i++) {
    free(argv[i]);
  }
  free(argv);
  free(policy_file);
  return landlockd_daemon_send_response(client_fd, status, 0);

fail:
  for (i = 0; i < hdr->argc; i++) {
    free(argv[i]);
  }
  free(argv);
  free(policy_file);
  return landlockd_daemon_send_response(client_fd, 1, saved_errno);
}

static int landlockd_daemon_serve_listener(int listen_fd,
                                           const char *socket_label,
                                           int unlink_on_exit, FILE *diag) {
  struct landlockd_daemon_state state;
  struct landlockd_daemon_request_header hdr;
  int client_fd;
  int peer_ok;
  int should_stop;

  memset(&state, 0, sizeof(state));
  state.uid = getuid();
  should_stop = 0;
  landlockd_daemon_audit_listener(diag, "daemon.listen", socket_label,
                                  unlink_on_exit ? "socket" : "systemd");
  if (landlockd_seccomp_apply_daemon_hardening() < 0) {
    landlockd_daemon_diag(diag, "landlockd: daemon hardening failed: %s",
                          strerror(errno));
    close(listen_fd);
    if (unlink_on_exit && socket_label != NULL) {
      unlink(socket_label);
    }
    return 1;
  }
  while (!should_stop) {
    client_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (client_fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    peer_ok = landlockd_daemon_peer_authorized(client_fd, &state, diag);
    if (peer_ok < 0) {
      close(client_fd);
      continue;
    }
    if (peer_ok == 0) {
      landlockd_daemon_send_response(client_fd, 1, EPERM);
      close(client_fd);
      continue;
    }

    if (landlockd_daemon_read_all(client_fd, &hdr, sizeof(hdr)) < 0) {
      close(client_fd);
      continue;
    }
    if (hdr.magic != LANDLOCKD_DAEMON_MAGIC ||
        hdr.version != LANDLOCKD_DAEMON_VERSION) {
      landlockd_daemon_send_response(client_fd, 1, EPROTO);
      close(client_fd);
      continue;
    }

    if (hdr.command == LANDLOCKD_DAEMON_CMD_RUN) {
      landlockd_daemon_handle_run(client_fd, &hdr, &state, diag);
    } else if (hdr.command == LANDLOCKD_DAEMON_CMD_STOP) {
      landlockd_daemon_audit_request(diag, "stop", NULL, 0U);
      landlockd_daemon_send_response(client_fd, 0, 0);
      should_stop = 1;
    } else if (hdr.command == LANDLOCKD_DAEMON_CMD_STATUS) {
      landlockd_daemon_audit_request(diag, "status", NULL, 0U);
      landlockd_daemon_send_status_response(client_fd, &state);
    } else {
      landlockd_daemon_send_response(client_fd, 1, EINVAL);
    }
    close(client_fd);
  }

  close(listen_fd);
  landlockd_daemon_cache_cleanup(&state);
  if (unlink_on_exit && socket_label != NULL) {
    unlink(socket_label);
  }
  landlockd_daemon_audit_listener(diag, "daemon.exit", socket_label, NULL);
  landlockd_daemon_diag(diag, "landlockd: server exiting on %s",
                        socket_label != NULL ? socket_label : "(listener)");
  return 0;
}

static int landlockd_daemon_listen_path(const char *socket_path) {
  struct sockaddr_un addr;
  int listen_fd;
  int saved_errno;

  listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd < 0) {
    return -1;
  }

  unlink(socket_path);
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(socket_path) >= sizeof(addr.sun_path)) {
    close(listen_fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(addr.sun_path, socket_path);

  if (bind(listen_fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0 ||
      listen(listen_fd, 16) < 0) {
    saved_errno = errno;
    close(listen_fd);
    unlink(socket_path);
    errno = saved_errno;
    return -1;
  }

  return listen_fd;
}

static int landlockd_daemon_parse_uint_env(const char *name,
                                           unsigned int *value_out) {
  const char *value_str;
  char *end;
  unsigned long value;

  value_str = getenv(name);
  if (value_str == NULL || *value_str == '\0') {
    errno = ENOENT;
    return -1;
  }

  errno = 0;
  value = strtoul(value_str, &end, 10);
  if (errno != 0 || end == value_str || *end != '\0') {
    errno = EINVAL;
    return -1;
  }
  *value_out = (unsigned int)value;
  return 0;
}

static int landlockd_daemon_describe_listener(int listen_fd, char *buf,
                                              size_t buf_size) {
  struct sockaddr_un addr;
  socklen_t addr_len;

  if (buf_size == 0) {
    errno = EINVAL;
    return -1;
  }

  addr_len = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  if (getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) < 0) {
    return -1;
  }
  if (addr.sun_family != AF_UNIX || addr.sun_path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  if (strlen(addr.sun_path) >= buf_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(buf, addr.sun_path);
  return 0;
}

static int landlockd_daemon_get_systemd_listener(char *socket_label,
                                                 size_t socket_label_size,
                                                 FILE *diag) {
  unsigned int listen_pid;
  unsigned int listen_fds;
  int accept_conn;
  socklen_t accept_conn_len;
  int listen_fd;

  if (landlockd_daemon_parse_uint_env("LISTEN_PID", &listen_pid) < 0 ||
      landlockd_daemon_parse_uint_env("LISTEN_FDS", &listen_fds) < 0) {
    landlockd_daemon_diag(diag,
                          "landlockd: socket activation requires LISTEN_PID"
                          " and LISTEN_FDS");
    errno = EINVAL;
    return -1;
  }
  if (listen_pid != (unsigned int)getpid()) {
    landlockd_daemon_diag(diag,
                          "landlockd: LISTEN_PID %u does not match pid %d",
                          listen_pid, (int)getpid());
    errno = EINVAL;
    return -1;
  }
  if (listen_fds != 1U) {
    landlockd_daemon_diag(diag,
                          "landlockd: expected exactly one activated socket,"
                          " got %u",
                          listen_fds);
    errno = EINVAL;
    return -1;
  }

  listen_fd = LANDLOCKD_SYSTEMD_FD_START;
  accept_conn = 0;
  accept_conn_len = sizeof(accept_conn);
  if (getsockopt(listen_fd, SOL_SOCKET, SO_ACCEPTCONN, &accept_conn,
                 &accept_conn_len) < 0 ||
      accept_conn == 0) {
    landlockd_daemon_diag(diag,
                          "landlockd: inherited fd %d is not a listening"
                          " socket",
                          listen_fd);
    errno = EINVAL;
    return -1;
  }

  if (landlockd_daemon_describe_listener(listen_fd, socket_label,
                                         socket_label_size) < 0) {
    strncpy(socket_label, "(socket-activated)", socket_label_size - 1);
    socket_label[socket_label_size - 1] = '\0';
  }
  return listen_fd;
}

int landlockd_daemon_serve(const char *socket_path, FILE *diag) {
  int listen_fd;

  listen_fd = landlockd_daemon_listen_path(socket_path);
  if (listen_fd < 0) {
    return 1;
  }
  return landlockd_daemon_serve_listener(listen_fd, socket_path, 1, diag);
}

int landlockd_daemon_serve_systemd(FILE *diag) {
  char socket_label[sizeof(((struct sockaddr_un *)0)->sun_path)];
  int listen_fd;

  listen_fd =
      landlockd_daemon_get_systemd_listener(socket_label, sizeof(socket_label),
                                            diag);
  if (listen_fd < 0) {
    return 1;
  }
  return landlockd_daemon_serve_listener(listen_fd, socket_label, 0, diag);
}

int landlockd_daemon_run(const char *socket_path, const char *policy_file,
                         char *const argv[], FILE *diag) {
  struct landlockd_daemon_request_header hdr;
  struct landlockd_daemon_response response;
  uint32_t i;
  uint32_t argc;
  uint32_t len;
  uint32_t total_bytes;
  int fd;

  argc = 0;
  total_bytes = 0;
  while (argv[argc] != NULL) {
    len = (uint32_t)strlen(argv[argc]);
    if (len == 0 || len > LANDLOCKD_DAEMON_MAX_ARG_LEN) {
      errno = EINVAL;
      return 1;
    }
    total_bytes += (uint32_t)sizeof(len) + len;
    if (total_bytes > LANDLOCKD_DAEMON_MAX_REQUEST_BYTES) {
      errno = EINVAL;
      return 1;
    }
    argc++;
  }
  if (argc == 0 || argc > LANDLOCKD_DAEMON_MAX_ARGS) {
    errno = EINVAL;
    return 1;
  }
  len = (uint32_t)strlen(policy_file);
  if (len == 0 || len > LANDLOCKD_DAEMON_MAX_POLICY_LEN ||
      len > LANDLOCKD_DAEMON_MAX_REQUEST_BYTES ||
      total_bytes + len > LANDLOCKD_DAEMON_MAX_REQUEST_BYTES) {
    errno = EINVAL;
    return 1;
  }

  fd = landlockd_daemon_connect(socket_path);
  if (fd < 0) {
    landlockd_daemon_diag(diag, "landlockd: connect %s failed: %s", socket_path,
                          strerror(errno));
    return 1;
  }

  hdr.magic = LANDLOCKD_DAEMON_MAGIC;
  hdr.version = LANDLOCKD_DAEMON_VERSION;
  hdr.command = LANDLOCKD_DAEMON_CMD_RUN;
  hdr.argc = argc;
  hdr.policy_len = len;

  if (landlockd_daemon_write_all(fd, &hdr, sizeof(hdr)) < 0 ||
      landlockd_daemon_write_all(fd, policy_file, hdr.policy_len) < 0) {
    close(fd);
    return 1;
  }

  for (i = 0; i < argc; i++) {
    len = (uint32_t)strlen(argv[i]);
    if (landlockd_daemon_write_all(fd, &len, sizeof(len)) < 0 ||
        landlockd_daemon_write_all(fd, argv[i], len) < 0) {
      close(fd);
      return 1;
    }
  }

  if (landlockd_daemon_read_all(fd, &response, sizeof(response)) < 0) {
    close(fd);
    return 1;
  }
  close(fd);

  if (response.magic != LANDLOCKD_DAEMON_MAGIC ||
      response.version != LANDLOCKD_DAEMON_VERSION) {
    errno = EPROTO;
    return 1;
  }
  if (response.error_value != 0) {
    errno = response.error_value;
  }
  return response.status;
}

int landlockd_daemon_status(const char *socket_path, FILE *out, FILE *diag) {
  struct landlockd_daemon_request_header hdr;
  struct landlockd_daemon_status_response response;
  int fd;

  fd = landlockd_daemon_connect(socket_path);
  if (fd < 0) {
    landlockd_daemon_diag(diag, "landlockd: connect %s failed: %s", socket_path,
                          strerror(errno));
    return 1;
  }

  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = LANDLOCKD_DAEMON_MAGIC;
  hdr.version = LANDLOCKD_DAEMON_VERSION;
  hdr.command = LANDLOCKD_DAEMON_CMD_STATUS;

  if (landlockd_daemon_write_all(fd, &hdr, sizeof(hdr)) < 0 ||
      landlockd_daemon_read_all(fd, &response, sizeof(response)) < 0) {
    close(fd);
    return 1;
  }
  close(fd);

  if (response.base.magic != LANDLOCKD_DAEMON_MAGIC ||
      response.base.version != LANDLOCKD_DAEMON_VERSION) {
    errno = EPROTO;
    return 1;
  }
  if (response.base.error_value != 0) {
    errno = response.base.error_value;
    return response.base.status;
  }
  if (out != NULL) {
    fprintf(out,
            "{\"protocol_version\":%u,\"cache_entries\":%u,"
            "\"cache_hits\":%llu,\"cache_misses\":%llu}\n",
            response.protocol_version, response.cache_entries,
            (unsigned long long)response.cache_hits,
            (unsigned long long)response.cache_misses);
    fflush(out);
  }
  return response.base.status;
}

int landlockd_daemon_stop(const char *socket_path, FILE *diag) {
  struct landlockd_daemon_request_header hdr;
  struct landlockd_daemon_response response;
  int fd;

  fd = landlockd_daemon_connect(socket_path);
  if (fd < 0) {
    landlockd_daemon_diag(diag, "landlockd: connect %s failed: %s", socket_path,
                          strerror(errno));
    return 1;
  }

  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = LANDLOCKD_DAEMON_MAGIC;
  hdr.version = LANDLOCKD_DAEMON_VERSION;
  hdr.command = LANDLOCKD_DAEMON_CMD_STOP;

  if (landlockd_daemon_write_all(fd, &hdr, sizeof(hdr)) < 0 ||
      landlockd_daemon_read_all(fd, &response, sizeof(response)) < 0) {
    close(fd);
    return 1;
  }
  close(fd);

  if (response.magic != LANDLOCKD_DAEMON_MAGIC ||
      response.version != LANDLOCKD_DAEMON_VERSION) {
    errno = EPROTO;
    return 1;
  }
  if (response.error_value != 0) {
    errno = response.error_value;
  }
  return response.status;
}
