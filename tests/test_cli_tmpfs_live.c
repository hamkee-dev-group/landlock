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

static int probe_unprivileged_tmpfs_mount(void) {
  char tempdir[] = "/tmp/landlockd-tmpfs-probe-XXXXXX";
  pid_t pid;
  int status;

  if (mkdtemp(tempdir) == NULL) {
    return 0;
  }

  pid = fork();
  if (pid < 0) {
    rmdir(tempdir);
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
    if (mount("tmpfs", tempdir, "tmpfs", MS_NODEV | MS_NOSUID,
              "mode=700") < 0) {
      _exit(1);
    }
    if (umount2(tempdir, MNT_DETACH) < 0) {
      _exit(1);
    }
    _exit(0);
  }

  if (waitpid(pid, &status, 0) < 0) {
    rmdir(tempdir);
    return 0;
  }
  rmdir(tempdir);
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
                        const char *scratch_dir, int with_tmpfs) {
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
      emit_rule(fp, helper_dir,
                "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      emit_rule(fp, scratch_dir,
                "[\"read_file\", \"read_dir\", \"write_file\", \"make_reg\", \"truncate\"]") < 0 ||
      maybe_emit_rule(fp, "/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0) {
    fclose(fp);
    return -1;
  }

  if (with_tmpfs &&
      fprintf(fp, "\n[mount]\ntmpfs = [\"%s\"]\n", scratch_dir) < 0) {
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
  char tempdir[] = "/tmp/landlockd-tmpfs-live-XXXXXX";
  char helper_dir[PATH_MAX];
  char scratch_dir[PATH_MAX];
  char host_file[PATH_MAX];
  char policy_without_mount[PATH_MAX];
  char policy_with_mount[PATH_MAX];
  char socket_path[PATH_MAX];
  char *direct_host_argv[9];
  char *direct_tmpfs_argv[9];
  char *serve_argv[5];
  char *daemon_host_argv[11];
  char *daemon_tmpfs_argv[11];
  char *stop_argv[5];
  pid_t daemon_pid;
  int status;
  int daemon_status;

  if (argc < 3) {
    diag("usage: %s <landlockd> <broker-helper>", argv[0]);
    return 1;
  }

  if (landlock_abi_version() == 0 || !probe_unprivileged_tmpfs_mount()) {
    plan(SKIP_ALL,
         "Landlock or unprivileged tmpfs scratch mounts are unavailable");
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
  if (snprintf(scratch_dir, sizeof(scratch_dir), "%s/scratch", tempdir) >=
          (int)sizeof(scratch_dir) ||
      snprintf(host_file, sizeof(host_file), "%s/out.txt", scratch_dir) >=
          (int)sizeof(host_file) ||
      snprintf(policy_without_mount, sizeof(policy_without_mount),
               "%s/no-mount.toml", tempdir) >= (int)sizeof(policy_without_mount) ||
      snprintf(policy_with_mount, sizeof(policy_with_mount),
               "%s/with-mount.toml", tempdir) >= (int)sizeof(policy_with_mount) ||
      snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
          (int)sizeof(socket_path)) {
    diag("path too long");
    return 1;
  }

  if (mkdir(scratch_dir, 0700) < 0) {
    diag("mkdir scratch_dir failed: %s", strerror(errno));
    return 1;
  }
  if (write_policy(policy_without_mount, helper_dir, scratch_dir, 0) < 0 ||
      write_policy(policy_with_mount, helper_dir, scratch_dir, 1) < 0) {
    diag("cannot write mount policies: %s", strerror(errno));
    return 1;
  }

  plan(9);

  direct_host_argv[0] = argv[1];
  direct_host_argv[1] = "run";
  direct_host_argv[2] = "--policy-file";
  direct_host_argv[3] = policy_without_mount;
  direct_host_argv[4] = "--";
  direct_host_argv[5] = argv[2];
  direct_host_argv[6] = host_file;
  direct_host_argv[7] = "create";
  direct_host_argv[8] = NULL;
  ok(run_landlockd(argv[1], direct_host_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(host_file, F_OK) == 0,
     "without tmpfs mounts, scratch writes persist on the host");

  unlink(host_file);
  direct_tmpfs_argv[0] = argv[1];
  direct_tmpfs_argv[1] = "run";
  direct_tmpfs_argv[2] = "--policy-file";
  direct_tmpfs_argv[3] = policy_with_mount;
  direct_tmpfs_argv[4] = "--";
  direct_tmpfs_argv[5] = argv[2];
  direct_tmpfs_argv[6] = host_file;
  direct_tmpfs_argv[7] = "create";
  direct_tmpfs_argv[8] = NULL;
  ok(run_landlockd(argv[1], direct_tmpfs_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(host_file, F_OK) < 0 && errno == ENOENT,
     "tmpfs scratch mounts keep direct-run scratch writes ephemeral");

  serve_argv[0] = argv[1];
  serve_argv[1] = "serve";
  serve_argv[2] = "--socket";
  serve_argv[3] = socket_path;
  serve_argv[4] = NULL;
  ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
         wait_for_socket(socket_path) == 0,
     "daemon starts for tmpfs scratch runs");

  daemon_host_argv[0] = argv[1];
  daemon_host_argv[1] = "run";
  daemon_host_argv[2] = "--socket";
  daemon_host_argv[3] = socket_path;
  daemon_host_argv[4] = "--policy-file";
  daemon_host_argv[5] = policy_without_mount;
  daemon_host_argv[6] = "--";
  daemon_host_argv[7] = argv[2];
  daemon_host_argv[8] = host_file;
  daemon_host_argv[9] = "create";
  daemon_host_argv[10] = NULL;
  ok(run_landlockd(argv[1], daemon_host_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(host_file, F_OK) == 0,
     "daemon runs still persist scratch writes without tmpfs mounts");

  unlink(host_file);
  daemon_tmpfs_argv[0] = argv[1];
  daemon_tmpfs_argv[1] = "run";
  daemon_tmpfs_argv[2] = "--socket";
  daemon_tmpfs_argv[3] = socket_path;
  daemon_tmpfs_argv[4] = "--policy-file";
  daemon_tmpfs_argv[5] = policy_with_mount;
  daemon_tmpfs_argv[6] = "--";
  daemon_tmpfs_argv[7] = argv[2];
  daemon_tmpfs_argv[8] = host_file;
  daemon_tmpfs_argv[9] = "create";
  daemon_tmpfs_argv[10] = NULL;
  ok(run_landlockd(argv[1], daemon_tmpfs_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(host_file, F_OK) < 0 && errno == ENOENT,
     "daemon runs also keep tmpfs scratch writes ephemeral");

  stop_argv[0] = argv[1];
  stop_argv[1] = "stop";
  stop_argv[2] = "--socket";
  stop_argv[3] = socket_path;
  stop_argv[4] = NULL;
  ok(run_landlockd(argv[1], stop_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "daemon stop exits successfully after tmpfs runs");

  ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
         WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
     "daemon exits cleanly after tmpfs runs");

  ok(access(socket_path, F_OK) < 0 && errno == ENOENT,
     "daemon stop removes the control socket after tmpfs runs");

  ok(access(scratch_dir, F_OK) == 0,
     "host scratch mountpoint directory remains after ephemeral tmpfs runs");

  done_testing();
}
