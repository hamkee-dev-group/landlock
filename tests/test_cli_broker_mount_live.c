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

static int probe_brokered_tmpfs_mount(void) {
  char root[] = "/tmp/landlockd-broker-mount-probe-XXXXXX";
  char target[PATH_MAX];
  int ready_pipe[2];
  int done_pipe[2];
  pid_t sandbox_pid;
  pid_t helper_pid;
  int status;
  char ch;

  if (mkdtemp(root) == NULL) {
    return 0;
  }
  if (snprintf(target, sizeof(target), "%s/target", root) >=
          (int)sizeof(target) ||
      mkdir(target, 0700) < 0 || pipe(ready_pipe) < 0 || pipe(done_pipe) < 0) {
    rmdir(target);
    rmdir(root);
    return 0;
  }

  sandbox_pid = fork();
  if (sandbox_pid < 0) {
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(done_pipe[0]);
    close(done_pipe[1]);
    rmdir(target);
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
    rmdir(target);
    rmdir(root);
    return 0;
  }

  helper_pid = fork();
  if (helper_pid < 0) {
    close(ready_pipe[0]);
    close(done_pipe[1]);
    kill(sandbox_pid, SIGTERM);
    waitpid(sandbox_pid, NULL, 0);
    rmdir(target);
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
        mount("tmpfs", target, "tmpfs", MS_NODEV | MS_NOSUID, "mode=700") < 0 ||
        umount2(target, 0) < 0) {
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
    rmdir(target);
    rmdir(root);
    return 0;
  }
  write(done_pipe[1], "Q", 1);
  close(done_pipe[1]);
  close(ready_pipe[0]);
  waitpid(sandbox_pid, NULL, 0);
  rmdir(target);
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
                        const char *mount_target, int with_mount_broker) {
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
      emit_rule(fp, mount_target,
                "[\"read_file\", \"read_dir\", \"write_file\", \"make_reg\", \"truncate\"]") < 0 ||
      maybe_emit_rule(fp, "/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0) {
    fclose(fp);
    return -1;
  }
  if (with_mount_broker &&
      fprintf(fp, "\n[broker]\nmount_tmpfs = [\"%s\"]\n", mount_target) < 0) {
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
  char tempdir[] = "/tmp/landlockd-broker-mount-live-XXXXXX";
  char helper_dir[PATH_MAX];
  char mount_target[PATH_MAX];
  char denied_target[PATH_MAX];
  char mounted_file[PATH_MAX];
  char denied_file[PATH_MAX];
  char policy_without_mount[PATH_MAX];
  char policy_with_mount[PATH_MAX];
  char socket_path[PATH_MAX];
  char *direct_no_broker_argv[10];
  char *direct_with_broker_argv[10];
  char *direct_denied_argv[10];
  char *serve_argv[5];
  char *daemon_with_broker_argv[12];
  char *stop_argv[5];
  pid_t daemon_pid;
  int status;
  int daemon_status;

  if (argc < 3) {
    diag("usage: %s <landlockd> <broker-helper>", argv[0]);
    return 1;
  }

  if (landlock_abi_version() == 0 || !landlockd_seccomp_probe_user_notif() ||
      !probe_brokered_tmpfs_mount()) {
    plan(SKIP_ALL,
         "Landlock, seccomp notify, or brokered tmpfs mounts are unavailable");
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
  if (snprintf(mount_target, sizeof(mount_target), "%s/mount-target", tempdir) >=
          (int)sizeof(mount_target) ||
      snprintf(denied_target, sizeof(denied_target), "%s/denied-target", tempdir) >=
          (int)sizeof(denied_target) ||
      snprintf(mounted_file, sizeof(mounted_file), "%s/out.txt", mount_target) >=
          (int)sizeof(mounted_file) ||
      snprintf(denied_file, sizeof(denied_file), "%s/out.txt", denied_target) >=
          (int)sizeof(denied_file) ||
      snprintf(policy_without_mount, sizeof(policy_without_mount),
               "%s/no-broker-mount.toml", tempdir) >=
          (int)sizeof(policy_without_mount) ||
      snprintf(policy_with_mount, sizeof(policy_with_mount),
               "%s/with-broker-mount.toml", tempdir) >=
          (int)sizeof(policy_with_mount) ||
      snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
          (int)sizeof(socket_path)) {
    diag("path too long");
    return 1;
  }
  if (mkdir(mount_target, 0700) < 0 || mkdir(denied_target, 0700) < 0) {
    diag("mkdir failed: %s", strerror(errno));
    return 1;
  }
  if (write_policy(policy_without_mount, helper_dir, mount_target, 0) < 0 ||
      write_policy(policy_with_mount, helper_dir, mount_target, 1) < 0) {
    diag("cannot write broker mount policies: %s", strerror(errno));
    return 1;
  }

  plan(8);

  direct_no_broker_argv[0] = argv[1];
  direct_no_broker_argv[1] = "run";
  direct_no_broker_argv[2] = "--policy-file";
  direct_no_broker_argv[3] = policy_without_mount;
  direct_no_broker_argv[4] = "--";
  direct_no_broker_argv[5] = argv[2];
  direct_no_broker_argv[6] = mount_target;
  direct_no_broker_argv[7] = mounted_file;
  direct_no_broker_argv[8] = "mount-cycle";
  direct_no_broker_argv[9] = NULL;
  ok(run_landlockd(argv[1], direct_no_broker_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 12,
     "without a broker mount rule, runtime tmpfs mount requests fail closed");

  direct_with_broker_argv[0] = argv[1];
  direct_with_broker_argv[1] = "run";
  direct_with_broker_argv[2] = "--policy-file";
  direct_with_broker_argv[3] = policy_with_mount;
  direct_with_broker_argv[4] = "--";
  direct_with_broker_argv[5] = argv[2];
  direct_with_broker_argv[6] = mount_target;
  direct_with_broker_argv[7] = mounted_file;
  direct_with_broker_argv[8] = "mount-cycle";
  direct_with_broker_argv[9] = NULL;
  ok(run_landlockd(argv[1], direct_with_broker_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(mounted_file, F_OK) < 0 && errno == ENOENT,
     "brokered tmpfs mount requests succeed and remain ephemeral in direct runs");

  direct_denied_argv[0] = argv[1];
  direct_denied_argv[1] = "run";
  direct_denied_argv[2] = "--policy-file";
  direct_denied_argv[3] = policy_with_mount;
  direct_denied_argv[4] = "--";
  direct_denied_argv[5] = argv[2];
  direct_denied_argv[6] = denied_target;
  direct_denied_argv[7] = denied_file;
  direct_denied_argv[8] = "mount-cycle";
  direct_denied_argv[9] = NULL;
  ok(run_landlockd(argv[1], direct_denied_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 12,
     "brokered tmpfs mount requests are denied on undeclared targets");

  serve_argv[0] = argv[1];
  serve_argv[1] = "serve";
  serve_argv[2] = "--socket";
  serve_argv[3] = socket_path;
  serve_argv[4] = NULL;
  ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
         wait_for_socket(socket_path) == 0,
     "daemon starts for broker mount runs");

  daemon_with_broker_argv[0] = argv[1];
  daemon_with_broker_argv[1] = "run";
  daemon_with_broker_argv[2] = "--socket";
  daemon_with_broker_argv[3] = socket_path;
  daemon_with_broker_argv[4] = "--policy-file";
  daemon_with_broker_argv[5] = policy_with_mount;
  daemon_with_broker_argv[6] = "--";
  daemon_with_broker_argv[7] = argv[2];
  daemon_with_broker_argv[8] = mount_target;
  daemon_with_broker_argv[9] = mounted_file;
  daemon_with_broker_argv[10] = "mount-cycle";
  daemon_with_broker_argv[11] = NULL;
  ok(run_landlockd(argv[1], daemon_with_broker_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
         access(mounted_file, F_OK) < 0 && errno == ENOENT,
     "daemon runs also broker tmpfs mount requests inside the sandbox namespace");

  stop_argv[0] = argv[1];
  stop_argv[1] = "stop";
  stop_argv[2] = "--socket";
  stop_argv[3] = socket_path;
  stop_argv[4] = NULL;
  ok(run_landlockd(argv[1], stop_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "daemon stop exits successfully after broker mount runs");

  ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
         WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
     "daemon exits cleanly after broker mount runs");

  ok(access(socket_path, F_OK) < 0 && errno == ENOENT,
     "daemon stop removes the control socket after broker mount runs");

  done_testing();
}
