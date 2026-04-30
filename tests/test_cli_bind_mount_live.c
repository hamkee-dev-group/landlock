#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
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

static int probe_unprivileged_bind_mount(void) {
  char root[] = "/tmp/landlockd-bind-probe-XXXXXX";
  char source_dir[PATH_MAX];
  char target_dir[PATH_MAX];
  pid_t pid;
  int status;

  if (mkdtemp(root) == NULL) {
    return 0;
  }
  if (snprintf(source_dir, sizeof(source_dir), "%s/source", root) >=
          (int)sizeof(source_dir) ||
      snprintf(target_dir, sizeof(target_dir), "%s/target", root) >=
          (int)sizeof(target_dir)) {
    rmdir(root);
    return 0;
  }
  if (mkdir(source_dir, 0700) < 0 || mkdir(target_dir, 0700) < 0) {
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }

  pid = fork();
  if (pid < 0) {
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }
  if (pid == 0) {
    uid_t uid;
    gid_t gid;
    char map[64];
    int n;

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
    if (mount(source_dir, target_dir, NULL, MS_BIND, NULL) < 0) {
      _exit(1);
    }
    if (mount(NULL, target_dir, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY,
              NULL) < 0) {
      _exit(1);
    }
    if (umount2(target_dir, MNT_DETACH) < 0) {
      _exit(1);
    }
    _exit(0);
  }

  if (waitpid(pid, &status, 0) < 0) {
    rmdir(target_dir);
    rmdir(source_dir);
    rmdir(root);
    return 0;
  }

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
                        int with_bind) {
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

  if (with_bind &&
      fprintf(fp,
              "\n[mount]\n"
              "  [[mount.bind]]\n"
              "  source = \"%s\"\n"
              "  target = \"%s\"\n"
              "  read_only = true\n"
              "\n"
              "  [[mount.bind]]\n"
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
  char tempdir[] = "/tmp/landlockd-bind-live-XXXXXX";
  char helper_dir[PATH_MAX];
  char source_ro_dir[PATH_MAX];
  char target_ro_dir[PATH_MAX];
  char source_rw_dir[PATH_MAX];
  char target_rw_dir[PATH_MAX];
  char source_ro_file[PATH_MAX];
  char target_ro_file[PATH_MAX];
  char target_ro_new_file[PATH_MAX];
  char source_rw_file[PATH_MAX];
  char target_rw_file[PATH_MAX];
  char policy_without_bind[PATH_MAX];
  char policy_with_bind[PATH_MAX];
  char socket_path[PATH_MAX];
  char *direct_no_bind_argv[9];
  char *direct_read_bind_argv[9];
  char *direct_ro_write_argv[9];
  char *direct_rw_write_argv[9];
  char *serve_argv[5];
  char *daemon_no_bind_argv[11];
  char *daemon_read_bind_argv[11];
  char *daemon_rw_write_argv[11];
  char *stop_argv[5];
  pid_t daemon_pid;
  int status;
  int daemon_status;

  if (argc < 3) {
    diag("usage: %s <landlockd> <broker-helper>", argv[0]);
    return 1;
  }

  if (landlock_abi_version() == 0 || !probe_unprivileged_bind_mount()) {
    plan(SKIP_ALL,
         "Landlock or unprivileged bind mounts are unavailable");
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
      snprintf(target_ro_dir, sizeof(target_ro_dir), "%s/target-ro", tempdir) >=
          (int)sizeof(target_ro_dir) ||
      snprintf(source_rw_dir, sizeof(source_rw_dir), "%s/source-rw", tempdir) >=
          (int)sizeof(source_rw_dir) ||
      snprintf(target_rw_dir, sizeof(target_rw_dir), "%s/target-rw", tempdir) >=
          (int)sizeof(target_rw_dir) ||
      snprintf(source_ro_file, sizeof(source_ro_file), "%s/input.txt",
               source_ro_dir) >= (int)sizeof(source_ro_file) ||
      snprintf(target_ro_file, sizeof(target_ro_file), "%s/input.txt",
               target_ro_dir) >= (int)sizeof(target_ro_file) ||
      snprintf(target_ro_new_file, sizeof(target_ro_new_file), "%s/new.txt",
               target_ro_dir) >= (int)sizeof(target_ro_new_file) ||
      snprintf(source_rw_file, sizeof(source_rw_file), "%s/output.txt",
               source_rw_dir) >= (int)sizeof(source_rw_file) ||
      snprintf(target_rw_file, sizeof(target_rw_file), "%s/output.txt",
               target_rw_dir) >= (int)sizeof(target_rw_file) ||
      snprintf(policy_without_bind, sizeof(policy_without_bind),
               "%s/no-bind.toml", tempdir) >= (int)sizeof(policy_without_bind) ||
      snprintf(policy_with_bind, sizeof(policy_with_bind),
               "%s/with-bind.toml", tempdir) >= (int)sizeof(policy_with_bind) ||
      snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
          (int)sizeof(socket_path)) {
    diag("path too long");
    return 1;
  }

  if (mkdir(source_ro_dir, 0700) < 0 || mkdir(target_ro_dir, 0700) < 0 ||
      mkdir(source_rw_dir, 0700) < 0 || mkdir(target_rw_dir, 0700) < 0) {
    diag("mkdir failed: %s", strerror(errno));
    return 1;
  }
  if (write_text_file(source_ro_file, "bound") < 0) {
    diag("cannot write source file: %s", strerror(errno));
    return 1;
  }
  if (write_policy(policy_without_bind, helper_dir, target_ro_dir, target_rw_dir,
                   source_ro_dir, source_rw_dir, 0) < 0 ||
      write_policy(policy_with_bind, helper_dir, target_ro_dir, target_rw_dir,
                   source_ro_dir, source_rw_dir, 1) < 0) {
    diag("cannot write bind policies: %s", strerror(errno));
    return 1;
  }

  plan(11);

  direct_no_bind_argv[0] = argv[1];
  direct_no_bind_argv[1] = "run";
  direct_no_bind_argv[2] = "--policy-file";
  direct_no_bind_argv[3] = policy_without_bind;
  direct_no_bind_argv[4] = "--";
  direct_no_bind_argv[5] = argv[2];
  direct_no_bind_argv[6] = target_ro_file;
  direct_no_bind_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_no_bind_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 3,
     "without bind mounts, target paths do not expose host source files");

  direct_read_bind_argv[0] = argv[1];
  direct_read_bind_argv[1] = "run";
  direct_read_bind_argv[2] = "--policy-file";
  direct_read_bind_argv[3] = policy_with_bind;
  direct_read_bind_argv[4] = "--";
  direct_read_bind_argv[5] = argv[2];
  direct_read_bind_argv[6] = target_ro_file;
  direct_read_bind_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_read_bind_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "read-only bind mounts expose source files to direct runs");

  direct_ro_write_argv[0] = argv[1];
  direct_ro_write_argv[1] = "run";
  direct_ro_write_argv[2] = "--policy-file";
  direct_ro_write_argv[3] = policy_with_bind;
  direct_ro_write_argv[4] = "--";
  direct_ro_write_argv[5] = argv[2];
  direct_ro_write_argv[6] = target_ro_new_file;
  direct_ro_write_argv[7] = "create";
  direct_ro_write_argv[8] = NULL;
  ok(run_landlockd(argv[1], direct_ro_write_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 3 &&
         access(target_ro_new_file, F_OK) < 0 && errno == ENOENT,
     "read-only bind mounts reject direct writes");

  direct_rw_write_argv[0] = argv[1];
  direct_rw_write_argv[1] = "run";
  direct_rw_write_argv[2] = "--policy-file";
  direct_rw_write_argv[3] = policy_with_bind;
  direct_rw_write_argv[4] = "--";
  direct_rw_write_argv[5] = argv[2];
  direct_rw_write_argv[6] = target_rw_file;
  direct_rw_write_argv[7] = "create";
  direct_rw_write_argv[8] = NULL;
  ok(run_landlockd(argv[1], direct_rw_write_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(source_rw_file, F_OK) == 0,
     "writable bind mounts propagate direct-run writes to the source tree");

  unlink(source_rw_file);

  serve_argv[0] = argv[1];
  serve_argv[1] = "serve";
  serve_argv[2] = "--socket";
  serve_argv[3] = socket_path;
  serve_argv[4] = NULL;
  ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
         wait_for_socket(socket_path) == 0,
     "daemon starts for bind mount runs");

  daemon_no_bind_argv[0] = argv[1];
  daemon_no_bind_argv[1] = "run";
  daemon_no_bind_argv[2] = "--socket";
  daemon_no_bind_argv[3] = socket_path;
  daemon_no_bind_argv[4] = "--policy-file";
  daemon_no_bind_argv[5] = policy_without_bind;
  daemon_no_bind_argv[6] = "--";
  daemon_no_bind_argv[7] = argv[2];
  daemon_no_bind_argv[8] = target_ro_file;
  daemon_no_bind_argv[9] = NULL;
  ok(run_landlockd(argv[1], daemon_no_bind_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 3,
     "daemon runs also keep host source files hidden without bind mounts");

  daemon_read_bind_argv[0] = argv[1];
  daemon_read_bind_argv[1] = "run";
  daemon_read_bind_argv[2] = "--socket";
  daemon_read_bind_argv[3] = socket_path;
  daemon_read_bind_argv[4] = "--policy-file";
  daemon_read_bind_argv[5] = policy_with_bind;
  daemon_read_bind_argv[6] = "--";
  daemon_read_bind_argv[7] = argv[2];
  daemon_read_bind_argv[8] = target_ro_file;
  daemon_read_bind_argv[9] = NULL;
  ok(run_landlockd(argv[1], daemon_read_bind_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "daemon runs see read-only bind-mounted files");

  daemon_rw_write_argv[0] = argv[1];
  daemon_rw_write_argv[1] = "run";
  daemon_rw_write_argv[2] = "--socket";
  daemon_rw_write_argv[3] = socket_path;
  daemon_rw_write_argv[4] = "--policy-file";
  daemon_rw_write_argv[5] = policy_with_bind;
  daemon_rw_write_argv[6] = "--";
  daemon_rw_write_argv[7] = argv[2];
  daemon_rw_write_argv[8] = target_rw_file;
  daemon_rw_write_argv[9] = "create";
  daemon_rw_write_argv[10] = NULL;
  ok(run_landlockd(argv[1], daemon_rw_write_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(source_rw_file, F_OK) == 0,
     "daemon runs also propagate writable bind mount changes");

  stop_argv[0] = argv[1];
  stop_argv[1] = "stop";
  stop_argv[2] = "--socket";
  stop_argv[3] = socket_path;
  stop_argv[4] = NULL;
  ok(run_landlockd(argv[1], stop_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "daemon stop exits successfully after bind mount runs");

  ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
         WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
     "daemon exits cleanly after bind mount runs");

  ok(access(socket_path, F_OK) < 0 && errno == ENOENT,
     "daemon stop removes the control socket after bind mount runs");

  done_testing();
}
