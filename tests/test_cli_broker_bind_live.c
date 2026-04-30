#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/seccomp.h"
#include "tap.h"

static int write_exact_file(const char *path, const char *content) {
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

static int write_text_file(const char *path, const char *content) {
  int fd;
  size_t len;
  ssize_t nwritten;

  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
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

static int file_matches(const char *path, const char *expected) {
  char buf[64];
  int fd;
  ssize_t nread;
  size_t expected_len;

  fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  memset(buf, 0, sizeof(buf));
  nread = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (nread < 0) {
    return 0;
  }
  expected_len = strlen(expected);
  return (size_t)nread == expected_len &&
         memcmp(buf, expected, expected_len) == 0;
}

static int probe_brokered_bind_mount(void) {
  char root[] = "/tmp/landlockd-broker-bind-probe-XXXXXX";
  char source_dir[PATH_MAX];
  char target_dir[PATH_MAX];
  int ready_pipe[2];
  int done_pipe[2];
  pid_t sandbox_pid;
  pid_t helper_pid;
  int status;
  char ch;

  if (mkdtemp(root) == NULL) {
    return 0;
  }
  if (snprintf(source_dir, sizeof(source_dir), "%s/source", root) >=
          (int)sizeof(source_dir) ||
      snprintf(target_dir, sizeof(target_dir), "%s/target", root) >=
          (int)sizeof(target_dir) ||
      mkdir(source_dir, 0700) < 0 || mkdir(target_dir, 0700) < 0 ||
      pipe(ready_pipe) < 0 || pipe(done_pipe) < 0) {
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }

  sandbox_pid = fork();
  if (sandbox_pid < 0) {
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(done_pipe[0]);
    close(done_pipe[1]);
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }
  if (sandbox_pid == 0) {
    uid_t uid;
    gid_t gid;
    char map[64];
    char ack;
    int n;

    close(ready_pipe[0]);
    close(done_pipe[1]);
    uid = getuid();
    gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
      _exit(1);
    }
    if (write_exact_file("/proc/self/setgroups", "deny\n") < 0 &&
        errno != ENOENT) {
      _exit(1);
    }
    n = snprintf(map, sizeof(map), "0 %u 1\n", (unsigned int)uid);
    if (n < 0 || (size_t)n >= sizeof(map) ||
        write_exact_file("/proc/self/uid_map", map) < 0) {
      _exit(1);
    }
    n = snprintf(map, sizeof(map), "0 %u 1\n", (unsigned int)gid);
    if (n < 0 || (size_t)n >= sizeof(map) ||
        write_exact_file("/proc/self/gid_map", map) < 0) {
      _exit(1);
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
      _exit(1);
    }
    if (write(ready_pipe[1], "R", 1) != 1) {
      _exit(1);
    }
    close(ready_pipe[1]);
    if (read(done_pipe[0], &ack, 1) != 1) {
      _exit(1);
    }
    close(done_pipe[0]);
    _exit(0);
  }

  close(ready_pipe[1]);
  close(done_pipe[0]);
  if (read(ready_pipe[0], &ch, 1) != 1) {
    close(ready_pipe[0]);
    close(done_pipe[1]);
    kill(sandbox_pid, SIGTERM);
    waitpid(sandbox_pid, NULL, 0);
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }

  helper_pid = fork();
  if (helper_pid < 0) {
    close(ready_pipe[0]);
    close(done_pipe[1]);
    kill(sandbox_pid, SIGTERM);
    waitpid(sandbox_pid, NULL, 0);
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }
  if (helper_pid == 0) {
    char proc_path[PATH_MAX];
    int user_fd;
    int mount_fd;

    if (snprintf(proc_path, sizeof(proc_path), "/proc/%d/ns/user",
                 (int)sandbox_pid) >= (int)sizeof(proc_path)) {
      _exit(1);
    }
    user_fd = open(proc_path, O_RDONLY | O_CLOEXEC);
    if (user_fd < 0) {
      _exit(1);
    }
    if (snprintf(proc_path, sizeof(proc_path), "/proc/%d/ns/mnt",
                 (int)sandbox_pid) >= (int)sizeof(proc_path)) {
      _exit(1);
    }
    mount_fd = open(proc_path, O_RDONLY | O_CLOEXEC);
    if (mount_fd < 0) {
      close(user_fd);
      _exit(1);
    }
    if (setns(user_fd, CLONE_NEWUSER) < 0 ||
        setns(mount_fd, CLONE_NEWNS) < 0 ||
        mount(source_dir, target_dir, NULL, MS_BIND, NULL) < 0 ||
        umount2(target_dir, 0) < 0) {
      close(user_fd);
      close(mount_fd);
      _exit(1);
    }
    close(user_fd);
    close(mount_fd);
    _exit(0);
  }

  if (waitpid(helper_pid, &status, 0) < 0) {
    close(ready_pipe[0]);
    close(done_pipe[1]);
    kill(sandbox_pid, SIGTERM);
    waitpid(sandbox_pid, NULL, 0);
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }
  write(done_pipe[1], "Q", 1);
  close(done_pipe[1]);
  close(ready_pipe[0]);
  waitpid(sandbox_pid, NULL, 0);
  rmdir(target_dir);
  rmdir(source_dir);
  rmdir(root);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int parent_dir_of(const char *path, char *buf, size_t buf_size) {
  const char *slash;
  size_t len;

  slash = strrchr(path, '/');
  if (slash == NULL) {
    errno = EINVAL;
    return -1;
  }
  len = (size_t)(slash - path);
  if (len == 0 || len >= buf_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(buf, path, len);
  buf[len] = '\0';
  return 0;
}

static int emit_rule(FILE *fp, const char *path, const char *access_list) {
  return fprintf(fp,
                 "  [[fs_layer.rule]]\n"
                 "  path = \"%s\"\n"
                 "  allowed_access = %s\n",
                 path, access_list) < 0
             ? -1
             : 0;
}

static int maybe_emit_rule(FILE *fp, const char *path, const char *access_list) {
  if (access(path, F_OK) == 0) {
    return emit_rule(fp, path, access_list);
  }
  return 0;
}

static int write_policy(const char *policy_path, const char *helper_dir,
                        const char *target_ro_dir, const char *target_rw_dir,
                        const char *source_ro_dir, const char *source_rw_dir,
                        int with_bind_broker) {
  FILE *fp;

  fp = fopen(policy_path, "w");
  if (fp == NULL) {
    return -1;
  }

  if (fprintf(fp,
              "version = 1\n\n"
              "[[fs_layer]]\n"
              "handled_access_fs = [\"execute\", \"read_file\", \"read_dir\", \"write_file\", \"make_reg\", \"truncate\"]\n") <
          0 ||
      emit_rule(fp, helper_dir, "[\"execute\", \"read_file\", \"read_dir\"]") <
          0 ||
      emit_rule(fp, target_ro_dir,
                "[\"read_file\", \"read_dir\", \"write_file\", \"make_reg\", \"truncate\"]") < 0 ||
      emit_rule(fp, target_rw_dir,
                "[\"read_file\", \"read_dir\", \"write_file\", \"make_reg\", \"truncate\"]") < 0 ||
      maybe_emit_rule(fp, "/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0) {
    fclose(fp);
    return -1;
  }

  if (with_bind_broker &&
      fprintf(fp,
              "\n[broker]\n"
              "  [[broker.mount_bind]]\n"
              "  source = \"%s\"\n"
              "  target = \"%s\"\n"
              "  read_only = true\n"
              "\n"
              "  [[broker.mount_bind]]\n"
              "  source = \"%s\"\n"
              "  target = \"%s\"\n"
              "  read_only = false\n",
              source_ro_dir, target_ro_dir, source_rw_dir, target_rw_dir) < 0) {
    fclose(fp);
    return -1;
  }

  return fclose(fp) < 0 ? -1 : 0;
}

static int wait_for_socket(const char *path) {
  int i;
  struct stat st;

  for (i = 0; i < 100; i++) {
    if (stat(path, &st) == 0) {
      return 0;
    }
    usleep(10000);
  }
  errno = ETIMEDOUT;
  return -1;
}

static int run_landlockd(const char *binary, char *const argv[], int *status_out) {
  pid_t pid;
  int status;

  pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    execv(binary, argv);
    _exit(127);
  }
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  *status_out = status;
  return 0;
}

static int spawn_quiet(const char *binary, char *const argv[], pid_t *pid_out) {
  pid_t pid;

  pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int devnull;

    devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    execv(binary, argv);
    _exit(127);
  }
  *pid_out = pid;
  return 0;
}

int main(int argc, char *argv[]) {
  char tempdir[] = "/tmp/landlockd-broker-bind-live-XXXXXX";
  char helper_dir[PATH_MAX];
  char source_ro_dir[PATH_MAX];
  char source_rw_dir[PATH_MAX];
  char target_ro_dir[PATH_MAX];
  char target_rw_dir[PATH_MAX];
  char denied_target_dir[PATH_MAX];
  char source_ro_file[PATH_MAX];
  char source_rw_file[PATH_MAX];
  char target_ro_file[PATH_MAX];
  char target_rw_file[PATH_MAX];
  char denied_target_file[PATH_MAX];
  char policy_without_bind[PATH_MAX];
  char policy_with_bind[PATH_MAX];
  char socket_path[PATH_MAX];
  char *direct_no_broker_argv[11];
  char *direct_ro_read_argv[11];
  char *direct_ro_write_argv[11];
  char *direct_rw_write_argv[11];
  char *direct_denied_argv[11];
  char *serve_argv[5];
  char *daemon_rw_write_argv[13];
  char *stop_argv[5];
  pid_t daemon_pid;
  int status;
  int daemon_status;

  if (argc < 3) {
    diag("usage: %s <landlockd> <broker-helper>", argv[0]);
    return 1;
  }

  if (landlock_abi_version() == 0 || !landlockd_seccomp_probe_user_notif() ||
      !probe_brokered_bind_mount()) {
    plan(SKIP_ALL,
         "Landlock, seccomp notify, or brokered bind mounts are unavailable");
    done_testing();
  }

  if (mkdtemp(tempdir) == NULL) {
    diag("mkdtemp failed: %s", strerror(errno));
    return 1;
  }
  if (parent_dir_of(argv[2], helper_dir, sizeof(helper_dir)) < 0) {
    diag("cannot derive helper directory: %s", strerror(errno));
    return 1;
  }
  if (snprintf(source_ro_dir, sizeof(source_ro_dir), "%s/source-ro", tempdir) >=
          (int)sizeof(source_ro_dir) ||
      snprintf(source_rw_dir, sizeof(source_rw_dir), "%s/source-rw", tempdir) >=
          (int)sizeof(source_rw_dir) ||
      snprintf(target_ro_dir, sizeof(target_ro_dir), "%s/target-ro", tempdir) >=
          (int)sizeof(target_ro_dir) ||
      snprintf(target_rw_dir, sizeof(target_rw_dir), "%s/target-rw", tempdir) >=
          (int)sizeof(target_rw_dir) ||
      snprintf(denied_target_dir, sizeof(denied_target_dir), "%s/target-denied",
               tempdir) >= (int)sizeof(denied_target_dir) ||
      snprintf(source_ro_file, sizeof(source_ro_file), "%s/data.txt",
               source_ro_dir) >= (int)sizeof(source_ro_file) ||
      snprintf(source_rw_file, sizeof(source_rw_file), "%s/data.txt",
               source_rw_dir) >= (int)sizeof(source_rw_file) ||
      snprintf(target_ro_file, sizeof(target_ro_file), "%s/data.txt",
               target_ro_dir) >= (int)sizeof(target_ro_file) ||
      snprintf(target_rw_file, sizeof(target_rw_file), "%s/data.txt",
               target_rw_dir) >= (int)sizeof(target_rw_file) ||
      snprintf(denied_target_file, sizeof(denied_target_file), "%s/data.txt",
               denied_target_dir) >= (int)sizeof(denied_target_file) ||
      snprintf(policy_without_bind, sizeof(policy_without_bind),
               "%s/no-broker-bind.toml", tempdir) >=
          (int)sizeof(policy_without_bind) ||
      snprintf(policy_with_bind, sizeof(policy_with_bind),
               "%s/with-broker-bind.toml", tempdir) >=
          (int)sizeof(policy_with_bind) ||
      snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
          (int)sizeof(socket_path)) {
    diag("path too long");
    return 1;
  }

  if (mkdir(source_ro_dir, 0700) < 0 || mkdir(source_rw_dir, 0700) < 0 ||
      mkdir(target_ro_dir, 0700) < 0 || mkdir(target_rw_dir, 0700) < 0 ||
      mkdir(denied_target_dir, 0700) < 0 ||
      write_text_file(source_ro_file, "ro") < 0 ||
      write_text_file(source_rw_file, "rw") < 0) {
    diag("setup failed: %s", strerror(errno));
    return 1;
  }

  if (write_policy(policy_without_bind, helper_dir, target_ro_dir, target_rw_dir,
                   source_ro_dir, source_rw_dir, 0) < 0 ||
      write_policy(policy_with_bind, helper_dir, target_ro_dir, target_rw_dir,
                   source_ro_dir, source_rw_dir, 1) < 0) {
    diag("cannot write broker bind policies: %s", strerror(errno));
    return 1;
  }

  plan(10);

  direct_no_broker_argv[0] = argv[1];
  direct_no_broker_argv[1] = "run";
  direct_no_broker_argv[2] = "--policy-file";
  direct_no_broker_argv[3] = policy_without_bind;
  direct_no_broker_argv[4] = "--";
  direct_no_broker_argv[5] = argv[2];
  direct_no_broker_argv[6] = source_ro_dir;
  direct_no_broker_argv[7] = target_ro_dir;
  direct_no_broker_argv[8] = target_ro_file;
  direct_no_broker_argv[9] = "bind-read-cycle";
  direct_no_broker_argv[10] = NULL;
  ok(run_landlockd(argv[1], direct_no_broker_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 14,
     "without a broker bind rule, runtime bind mount requests fail closed");

  direct_ro_read_argv[0] = argv[1];
  direct_ro_read_argv[1] = "run";
  direct_ro_read_argv[2] = "--policy-file";
  direct_ro_read_argv[3] = policy_with_bind;
  direct_ro_read_argv[4] = "--";
  direct_ro_read_argv[5] = argv[2];
  direct_ro_read_argv[6] = source_ro_dir;
  direct_ro_read_argv[7] = target_ro_dir;
  direct_ro_read_argv[8] = target_ro_file;
  direct_ro_read_argv[9] = "bind-read-cycle";
  direct_ro_read_argv[10] = NULL;
  ok(run_landlockd(argv[1], direct_ro_read_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(target_ro_file, F_OK) < 0 && errno == ENOENT,
     "brokered read-only bind mount requests succeed and remain ephemeral");

  direct_ro_write_argv[0] = argv[1];
  direct_ro_write_argv[1] = "run";
  direct_ro_write_argv[2] = "--policy-file";
  direct_ro_write_argv[3] = policy_with_bind;
  direct_ro_write_argv[4] = "--";
  direct_ro_write_argv[5] = argv[2];
  direct_ro_write_argv[6] = source_ro_dir;
  direct_ro_write_argv[7] = target_ro_dir;
  direct_ro_write_argv[8] = target_ro_file;
  direct_ro_write_argv[9] = "bind-append-denied-cycle";
  direct_ro_write_argv[10] = NULL;
  ok(run_landlockd(argv[1], direct_ro_write_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         file_matches(source_ro_file, "ro"),
     "brokered read-only bind mounts do not permit writes");

  direct_rw_write_argv[0] = argv[1];
  direct_rw_write_argv[1] = "run";
  direct_rw_write_argv[2] = "--policy-file";
  direct_rw_write_argv[3] = policy_with_bind;
  direct_rw_write_argv[4] = "--";
  direct_rw_write_argv[5] = argv[2];
  direct_rw_write_argv[6] = source_rw_dir;
  direct_rw_write_argv[7] = target_rw_dir;
  direct_rw_write_argv[8] = target_rw_file;
  direct_rw_write_argv[9] = "bind-append-cycle";
  direct_rw_write_argv[10] = NULL;
  ok(run_landlockd(argv[1], direct_rw_write_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         file_matches(source_rw_file, "rw!") &&
         access(target_rw_file, F_OK) < 0 && errno == ENOENT,
     "brokered read-write bind mounts can modify the declared source");

  direct_denied_argv[0] = argv[1];
  direct_denied_argv[1] = "run";
  direct_denied_argv[2] = "--policy-file";
  direct_denied_argv[3] = policy_with_bind;
  direct_denied_argv[4] = "--";
  direct_denied_argv[5] = argv[2];
  direct_denied_argv[6] = source_rw_dir;
  direct_denied_argv[7] = denied_target_dir;
  direct_denied_argv[8] = denied_target_file;
  direct_denied_argv[9] = "bind-read-cycle";
  direct_denied_argv[10] = NULL;
  ok(run_landlockd(argv[1], direct_denied_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 14,
     "brokered bind mounts are denied on undeclared targets");

  serve_argv[0] = argv[1];
  serve_argv[1] = "serve";
  serve_argv[2] = "--socket";
  serve_argv[3] = socket_path;
  serve_argv[4] = NULL;
  ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
         wait_for_socket(socket_path) == 0,
     "daemon starts for broker bind runs");

  if (write_text_file(source_rw_file, "rw") < 0) {
    diag("cannot reset rw source file: %s", strerror(errno));
    return 1;
  }

  daemon_rw_write_argv[0] = argv[1];
  daemon_rw_write_argv[1] = "run";
  daemon_rw_write_argv[2] = "--socket";
  daemon_rw_write_argv[3] = socket_path;
  daemon_rw_write_argv[4] = "--policy-file";
  daemon_rw_write_argv[5] = policy_with_bind;
  daemon_rw_write_argv[6] = "--";
  daemon_rw_write_argv[7] = argv[2];
  daemon_rw_write_argv[8] = source_rw_dir;
  daemon_rw_write_argv[9] = target_rw_dir;
  daemon_rw_write_argv[10] = target_rw_file;
  daemon_rw_write_argv[11] = "bind-append-cycle";
  daemon_rw_write_argv[12] = NULL;
  ok(run_landlockd(argv[1], daemon_rw_write_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         file_matches(source_rw_file, "rw!"),
     "daemon runs also broker bind mount requests inside the sandbox namespace");

  stop_argv[0] = argv[1];
  stop_argv[1] = "stop";
  stop_argv[2] = "--socket";
  stop_argv[3] = socket_path;
  stop_argv[4] = NULL;
  ok(run_landlockd(argv[1], stop_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "daemon stop exits successfully after broker bind runs");

  ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
         WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
     "daemon exits cleanly after broker bind runs");

  ok(access(socket_path, F_OK) < 0 && errno == ENOENT,
     "daemon stop removes the control socket after broker bind runs");

  done_testing();
}
