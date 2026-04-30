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
  char tempdir[] = "/tmp/landlockd-mount-hardening-probe-XXXXXX";
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
    if (mount("tmpfs", tempdir, "tmpfs", MS_NODEV | MS_NOSUID, "mode=700") <
        0) {
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
                        const char *scratch_dir, const char *mount_target) {
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
      emit_rule(fp, scratch_dir,
                "[\"read_file\", \"read_dir\", \"write_file\", \"make_reg\", \"truncate\"]") < 0 ||
      emit_rule(fp, mount_target,
                "[\"read_file\", \"read_dir\", \"write_file\", \"make_reg\", \"truncate\"]") < 0 ||
      maybe_emit_rule(fp, "/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0 ||
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
  char tempdir[] = "/tmp/landlockd-mount-hardening-live-XXXXXX";
  char helper_dir[PATH_MAX];
  char scratch_dir[PATH_MAX];
  char mount_target[PATH_MAX];
  char mounted_file[PATH_MAX];
  char policy_path[PATH_MAX];
  char socket_path[PATH_MAX];
  char *direct_argv[10];
  char *serve_argv[5];
  char *daemon_argv[12];
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
         "Landlock or unprivileged tmpfs mounts are unavailable");
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
      snprintf(mount_target, sizeof(mount_target), "%s/target", tempdir) >=
          (int)sizeof(mount_target) ||
      snprintf(mounted_file, sizeof(mounted_file), "%s/out.txt", mount_target) >=
          (int)sizeof(mounted_file) ||
      snprintf(policy_path, sizeof(policy_path), "%s/policy.toml", tempdir) >=
          (int)sizeof(policy_path) ||
      snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
          (int)sizeof(socket_path)) {
    diag("path too long");
    return 1;
  }
  if (mkdir(scratch_dir, 0700) < 0 || mkdir(mount_target, 0700) < 0) {
    diag("mkdir failed: %s", strerror(errno));
    return 1;
  }
  if (write_policy(policy_path, helper_dir, scratch_dir, mount_target) < 0) {
    diag("cannot write mount hardening policy: %s", strerror(errno));
    return 1;
  }

  plan(5);

  direct_argv[0] = argv[1];
  direct_argv[1] = "run";
  direct_argv[2] = "--policy-file";
  direct_argv[3] = policy_path;
  direct_argv[4] = "--";
  direct_argv[5] = argv[2];
  direct_argv[6] = mount_target;
  direct_argv[7] = mounted_file;
  direct_argv[8] = "mount-cycle";
  direct_argv[9] = NULL;
  ok(run_landlockd(argv[1], direct_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 12,
     "direct runs deny raw mount syscalls inside a sandbox mount namespace");

  serve_argv[0] = argv[1];
  serve_argv[1] = "serve";
  serve_argv[2] = "--socket";
  serve_argv[3] = socket_path;
  serve_argv[4] = NULL;
  ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
         wait_for_socket(socket_path) == 0,
     "daemon starts for mount hardening runs");

  daemon_argv[0] = argv[1];
  daemon_argv[1] = "run";
  daemon_argv[2] = "--socket";
  daemon_argv[3] = socket_path;
  daemon_argv[4] = "--policy-file";
  daemon_argv[5] = policy_path;
  daemon_argv[6] = "--";
  daemon_argv[7] = argv[2];
  daemon_argv[8] = mount_target;
  daemon_argv[9] = mounted_file;
  daemon_argv[10] = "mount-cycle";
  daemon_argv[11] = NULL;
  ok(run_landlockd(argv[1], daemon_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 12,
     "daemon-managed runs also deny raw mount syscalls in the sandbox");

  stop_argv[0] = argv[1];
  stop_argv[1] = "stop";
  stop_argv[2] = "--socket";
  stop_argv[3] = socket_path;
  stop_argv[4] = NULL;
  ok(run_landlockd(argv[1], stop_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "daemon stop exits successfully after mount hardening runs");

  ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
         WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
     "daemon exits cleanly after mount hardening runs");

  done_testing();
}
