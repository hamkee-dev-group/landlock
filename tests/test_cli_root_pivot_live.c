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
#include <sys/syscall.h>
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

static int make_dir(const char *path) {
  if (mkdir(path, 0700) < 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static int join_path(const char *parent, const char *child, char *buf,
                     size_t buf_size) {
  int n;

  if (strcmp(parent, "/") == 0) {
    n = snprintf(buf, buf_size, "/%s", child);
  } else {
    n = snprintf(buf, buf_size, "%s/%s", parent, child);
  }
  if (n < 0 || (size_t)n >= buf_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
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

static int run_landlockd(const char *binary, char *const argv[],
                         int *status_out) {
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

static int run_landlockd_capture_stderr(const char *binary, char *const argv[],
                                        int *status_out, char *stderr_buf,
                                        size_t stderr_buf_size) {
  pid_t pid;
  int devnull;
  int pipe_fds[2];
  ssize_t nread;
  size_t total;

  if (pipe(pipe_fds) < 0) {
    return -1;
  }

  pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return -1;
  }
  if (pid == 0) {
    close(pipe_fds[0]);
    devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      close(devnull);
    }
    dup2(pipe_fds[1], STDERR_FILENO);
    close(pipe_fds[1]);
    execv(binary, argv);
    _exit(127);
  }

  close(pipe_fds[1]);
  total = 0;
  while (total + 1 < stderr_buf_size &&
         (nread = read(pipe_fds[0], stderr_buf + total,
                       stderr_buf_size - 1 - total)) > 0) {
    total += (size_t)nread;
  }
  close(pipe_fds[0]);
  stderr_buf[total] = '\0';

  if (waitpid(pid, status_out, 0) < 0) {
    return -1;
  }
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

static int maybe_emit_rule(FILE *fp, const char *path, const char *access_list) {
  if (access(path, F_OK) == 0) {
    return fprintf(fp,
                   "  [[fs_layer.rule]]\n"
                   "  path = \"%s\"\n"
                   "  allowed_access = %s\n",
                   path, access_list) < 0
               ? -1
               : 0;
  }
  return 0;
}

static int maybe_emit_bind(FILE *fp, const char *source, const char *target) {
  if (access(source, F_OK) == 0) {
    return fprintf(fp,
                   "  [[mount.bind]]\n"
                   "  source = \"%s\"\n"
                   "  target = \"%s\"\n"
                   "  read_only = true\n",
                   source, target) < 0
               ? -1
               : 0;
  }
  return 0;
}

static int probe_unprivileged_pivot_root(void) {
  char tempdir[] = "/tmp/landlockd-pivot-root-probe-XXXXXX";
  char root_dir[PATH_MAX];
  char bind_source[PATH_MAX];
  char bind_target[PATH_MAX];
  char old_root[PATH_MAX];
  pid_t pid;
  int status;

  if (mkdtemp(tempdir) == NULL) {
    return 0;
  }
  if (join_path(tempdir, "root", root_dir, sizeof(root_dir)) < 0 ||
      join_path(tempdir, "bind-source", bind_source, sizeof(bind_source)) < 0 ||
      join_path(tempdir, "bind-target", bind_target, sizeof(bind_target)) < 0 ||
      make_dir(root_dir) < 0 ||
      make_dir(bind_source) < 0 || make_dir(bind_target) < 0 ||
      join_path(root_dir, ".old", old_root, sizeof(old_root)) < 0) {
    rmdir(bind_target);
    rmdir(bind_source);
    rmdir(root_dir);
    rmdir(tempdir);
    return 0;
  }

  pid = fork();
  if (pid < 0) {
    rmdir(root_dir);
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
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0 ||
        mount(bind_source, bind_target, NULL, MS_BIND, NULL) < 0 ||
        mount(NULL, bind_target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY,
              NULL) < 0 ||
        umount2(bind_target, MNT_DETACH) < 0 ||
        mount(root_dir, root_dir, NULL, MS_BIND, NULL) < 0 ||
        mkdir(old_root, 0700) < 0 || chdir(root_dir) < 0) {
      _exit(1);
    }
#ifdef SYS_pivot_root
    if (syscall(SYS_pivot_root, ".", ".old") < 0) {
      _exit(1);
    }
#else
    _exit(1);
#endif
    if (chdir("/") < 0 || umount2("/.old", MNT_DETACH) < 0 ||
        rmdir("/.old") < 0) {
      _exit(1);
    }
    _exit(0);
  }

  if (waitpid(pid, &status, 0) < 0) {
    rmdir(old_root);
    rmdir(bind_target);
    rmdir(bind_source);
    rmdir(root_dir);
    rmdir(tempdir);
    return 0;
  }
  rmdir(old_root);
  rmdir(bind_target);
  rmdir(bind_source);
  rmdir(root_dir);
  rmdir(tempdir);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int write_policy(const char *policy_path, const char *helper_dir,
                        const char *root_dir, const char *exec_dir,
                        const char *data_dir, const char *proc_dir,
                        int with_runtime_root) {
  FILE *fp;
  char root_lib[PATH_MAX];
  char root_lib64[PATH_MAX];
  char root_usr[PATH_MAX];
  char root_usr_lib[PATH_MAX];
  char root_usr_lib64[PATH_MAX];
  char root_etc[PATH_MAX];

  if (join_path(root_dir, "lib", root_lib, sizeof(root_lib)) < 0 ||
      join_path(root_dir, "lib64", root_lib64, sizeof(root_lib64)) < 0 ||
      join_path(root_dir, "usr", root_usr, sizeof(root_usr)) < 0 ||
      join_path(root_usr, "lib", root_usr_lib, sizeof(root_usr_lib)) < 0 ||
      join_path(root_usr, "lib64", root_usr_lib64, sizeof(root_usr_lib64)) < 0 ||
      join_path(root_dir, "etc", root_etc, sizeof(root_etc)) < 0) {
    return -1;
  }

  fp = fopen(policy_path, "w");
  if (fp == NULL) {
    return -1;
  }

  if (fprintf(fp,
              "version = 1\n\n"
              "[[fs_layer]]\n"
              "handled_access_fs = [\"execute\", \"read_file\", \"read_dir\"]\n") <
          0 ||
      maybe_emit_rule(fp, exec_dir, "[\"execute\", \"read_file\", \"read_dir\"]") <
          0 ||
      maybe_emit_rule(fp, data_dir, "[\"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, root_lib, "[\"execute\", \"read_file\", \"read_dir\"]") <
          0 ||
      maybe_emit_rule(fp, root_lib64,
                      "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, root_usr, "[\"execute\", \"read_file\", \"read_dir\"]") <
          0 ||
      maybe_emit_rule(fp, root_usr_lib,
                      "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, root_usr_lib64,
                      "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, root_etc, "[\"read_file\", \"read_dir\"]") < 0 ||
      fprintf(fp,
              "\n[mount]\n"
              "  [[mount.bind]]\n"
              "  source = \"%s\"\n"
              "  target = \"%s\"\n"
              "  read_only = true\n",
              helper_dir, exec_dir) < 0 ||
      fprintf(fp, "proc = [\"%s\"]\n", proc_dir) < 0 ||
      maybe_emit_bind(fp, "/lib", root_lib) < 0 ||
      maybe_emit_bind(fp, "/lib64", root_lib64) < 0 ||
      maybe_emit_bind(fp, "/usr/lib", root_usr_lib) < 0 ||
      maybe_emit_bind(fp, "/usr/lib64", root_usr_lib64) < 0 ||
      maybe_emit_bind(fp, "/etc", root_etc) < 0) {
    fclose(fp);
    return -1;
  }

  if (with_runtime_root &&
      fprintf(fp, "\n[runtime]\nroot = \"%s\"\ncwd = \"/work\"\n", root_dir) <
          0) {
    fclose(fp);
    return -1;
  }

  return fclose(fp) < 0 ? -1 : 0;
}

int main(int argc, char *argv[]) {
  char tempdir[] = "/tmp/landlockd-root-pivot-live-XXXXXX";
  char helper_path[PATH_MAX];
  char helper_dir[PATH_MAX];
  char root_dir[PATH_MAX];
  char exec_dir[PATH_MAX];
  char data_dir[PATH_MAX];
  char data_file[PATH_MAX];
  char proc_dir[PATH_MAX];
  char work_dir[PATH_MAX];
  char work_input[PATH_MAX];
  char path_buf[PATH_MAX];
  char policy_without_root[PATH_MAX];
  char policy_with_root[PATH_MAX];
  char policy_missing_root[PATH_MAX];
  char missing_root_dir[PATH_MAX];
  char socket_path[PATH_MAX];
  char missing_exec_stderr[4096];
  char missing_root_stderr[4096];
  char *direct_without_root_argv[8];
  char *direct_with_root_argv[8];
  char *direct_with_proc_argv[8];
  char *direct_missing_exec_argv[8];
  char *direct_missing_root_argv[8];
  char *serve_argv[5];
  char *daemon_with_root_argv[10];
  char *daemon_with_proc_argv[10];
  char *stop_argv[5];
  pid_t daemon_pid;
  int status;
  int daemon_status;

  if (argc < 3) {
    diag("usage: %s <landlockd> <broker-helper>", argv[0]);
    return 1;
  }

  if (landlock_abi_version() == 0 || !probe_unprivileged_pivot_root()) {
    plan(SKIP_ALL,
         "Landlock or unprivileged pivot_root-based runtime roots are unavailable");
    done_testing();
  }

  if (mkdtemp(tempdir) == NULL) {
    diag("mkdtemp failed: %s", strerror(errno));
    return 1;
  }
  if (realpath(argv[2], helper_path) == NULL) {
    diag("cannot resolve helper path: %s", strerror(errno));
    return 1;
  }
  if (parent_dir_of(helper_path, helper_dir, sizeof(helper_dir)) < 0 ||
      join_path(tempdir, "rootfs", root_dir, sizeof(root_dir)) < 0 ||
      join_path(root_dir, "exec", exec_dir, sizeof(exec_dir)) < 0 ||
      join_path(root_dir, "data", data_dir, sizeof(data_dir)) < 0 ||
      join_path(data_dir, "input.txt", data_file, sizeof(data_file)) < 0 ||
      join_path(root_dir, "proc", proc_dir, sizeof(proc_dir)) < 0 ||
      join_path(root_dir, "work", work_dir, sizeof(work_dir)) < 0 ||
      join_path(work_dir, "input.txt", work_input, sizeof(work_input)) < 0 ||
      join_path(tempdir, "no-root.toml", policy_without_root,
                sizeof(policy_without_root)) < 0 ||
      join_path(tempdir, "with-root.toml", policy_with_root,
                sizeof(policy_with_root)) < 0 ||
      join_path(tempdir, "missing-root.toml", policy_missing_root,
                sizeof(policy_missing_root)) < 0 ||
      join_path(tempdir, "missing-root", missing_root_dir,
                sizeof(missing_root_dir)) < 0 ||
      join_path(tempdir, "landlockd.sock", socket_path, sizeof(socket_path)) <
          0) {
    diag("path setup failed: %s", strerror(errno));
    return 1;
  }

  if (make_dir(root_dir) < 0 || make_dir(exec_dir) < 0 ||
      make_dir(data_dir) < 0 || make_dir(proc_dir) < 0 ||
      make_dir(work_dir) < 0 ||
      join_path(root_dir, "usr", path_buf, sizeof(path_buf)) < 0 ||
      make_dir(path_buf) < 0 ||
      join_path(path_buf, "lib", path_buf, sizeof(path_buf)) < 0 ||
      make_dir(path_buf) < 0 ||
      join_path(root_dir, "usr", path_buf, sizeof(path_buf)) < 0 ||
      join_path(path_buf, "lib64", path_buf, sizeof(path_buf)) < 0 ||
      make_dir(path_buf) < 0 ||
      join_path(root_dir, "lib", path_buf, sizeof(path_buf)) < 0 ||
      make_dir(path_buf) < 0 ||
      join_path(root_dir, "lib64", path_buf, sizeof(path_buf)) < 0 ||
      make_dir(path_buf) < 0 ||
      join_path(root_dir, "etc", path_buf, sizeof(path_buf)) < 0 ||
      make_dir(path_buf) < 0) {
    diag("rootfs setup failed: %s", strerror(errno));
    return 1;
  }
  if (write_text_file(data_file, "inside-root") < 0) {
    diag("cannot write rootfs data file: %s", strerror(errno));
    return 1;
  }
  if (write_text_file(work_input, "inside-work") < 0) {
    diag("cannot write runtime cwd data file: %s", strerror(errno));
    return 1;
  }
  if (write_policy(policy_without_root, helper_dir, root_dir, exec_dir, data_dir,
                   proc_dir, 0) < 0 ||
      write_policy(policy_with_root, helper_dir, root_dir, exec_dir, data_dir,
                   proc_dir, 1) < 0) {
    diag("cannot write runtime-root policies: %s", strerror(errno));
    return 1;
  }
  {
    FILE *fp = fopen(policy_missing_root, "w");
    if (fp == NULL) {
      diag("cannot open missing-root policy: %s", strerror(errno));
      return 1;
    }
    if (fprintf(fp, "version = 1\n\n[runtime]\nroot = \"%s\"\ncwd = \"/\"\n",
                missing_root_dir) < 0) {
      diag("cannot write missing-root policy: %s", strerror(errno));
      fclose(fp);
      return 1;
    }
    if (fclose(fp) < 0) {
      diag("cannot close missing-root policy: %s", strerror(errno));
      return 1;
    }
  }

  if (access(missing_root_dir, F_OK) == 0) {
    diag("cannot write runtime-root policies: %s", strerror(errno));
    return 1;
  }

  plan(13);

  direct_without_root_argv[0] = argv[1];
  direct_without_root_argv[1] = "run";
  direct_without_root_argv[2] = "--policy-file";
  direct_without_root_argv[3] = policy_without_root;
  direct_without_root_argv[4] = "--";
  direct_without_root_argv[5] = "/exec/test_cli_broker_open_helper";
  direct_without_root_argv[6] = "/data/input.txt";
  direct_without_root_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_without_root_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 127,
     "without runtime.root, rootfs-local exec paths are not resolved");

  direct_with_root_argv[0] = argv[1];
  direct_with_root_argv[1] = "run";
  direct_with_root_argv[2] = "--policy-file";
  direct_with_root_argv[3] = policy_with_root;
  direct_with_root_argv[4] = "--";
  direct_with_root_argv[5] = "/exec/test_cli_broker_open_helper";
  direct_with_root_argv[6] = "input.txt";
  direct_with_root_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_with_root_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "runtime.root pivots into the declared rootfs and runtime.cwd applies before exec");

  direct_with_proc_argv[0] = argv[1];
  direct_with_proc_argv[1] = "run";
  direct_with_proc_argv[2] = "--policy-file";
  direct_with_proc_argv[3] = policy_with_root;
  direct_with_proc_argv[4] = "--";
  direct_with_proc_argv[5] = "/exec/test_cli_broker_open_helper";
  direct_with_proc_argv[6] = "/proc/self/status";
  direct_with_proc_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_with_proc_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "mount.proc mounts proc inside the runtime root before exec");

  direct_missing_exec_argv[0] = argv[1];
  direct_missing_exec_argv[1] = "run";
  direct_missing_exec_argv[2] = "--policy-file";
  direct_missing_exec_argv[3] = policy_with_root;
  direct_missing_exec_argv[4] = "--";
  direct_missing_exec_argv[5] = "/exec/no-such-binary";
  direct_missing_exec_argv[6] = NULL;
  ok(run_landlockd_capture_stderr(argv[1], direct_missing_exec_argv, &status,
                                  missing_exec_stderr,
                                  sizeof(missing_exec_stderr)) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 127,
     "missing workload inside runtime.root exits 127");
  ok(strstr(missing_exec_stderr, "/exec/no-such-binary") != NULL &&
         strstr(missing_exec_stderr, "No such file or directory") != NULL,
     "missing workload inside runtime.root prints an exec failure diagnostic");

  direct_missing_root_argv[0] = argv[1];
  direct_missing_root_argv[1] = "run";
  direct_missing_root_argv[2] = "--policy-file";
  direct_missing_root_argv[3] = policy_missing_root;
  direct_missing_root_argv[4] = "--";
  direct_missing_root_argv[5] = "/bin/true";
  direct_missing_root_argv[6] = NULL;
  ok(run_landlockd_capture_stderr(argv[1], direct_missing_root_argv, &status,
                                  missing_root_stderr,
                                  sizeof(missing_root_stderr)) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 1,
     "missing runtime.root exits 1 before the workload runs");
  ok(strstr(missing_root_stderr, missing_root_dir) != NULL &&
         strstr(missing_root_stderr, "runtime root bind mount failed") != NULL,
     "missing runtime.root prints a fail-closed setup diagnostic");

  serve_argv[0] = argv[1];
  serve_argv[1] = "serve";
  serve_argv[2] = "--socket";
  serve_argv[3] = socket_path;
  serve_argv[4] = NULL;
  ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
         wait_for_socket(socket_path) == 0,
     "daemon starts for runtime-root runs");

  daemon_with_root_argv[0] = argv[1];
  daemon_with_root_argv[1] = "run";
  daemon_with_root_argv[2] = "--socket";
  daemon_with_root_argv[3] = socket_path;
  daemon_with_root_argv[4] = "--policy-file";
  daemon_with_root_argv[5] = policy_with_root;
  daemon_with_root_argv[6] = "--";
  daemon_with_root_argv[7] = "/exec/test_cli_broker_open_helper";
  daemon_with_root_argv[8] = "input.txt";
  daemon_with_root_argv[9] = NULL;
  ok(run_landlockd(argv[1], daemon_with_root_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "daemon runs also pivot into the declared rootfs");

  daemon_with_proc_argv[0] = argv[1];
  daemon_with_proc_argv[1] = "run";
  daemon_with_proc_argv[2] = "--socket";
  daemon_with_proc_argv[3] = socket_path;
  daemon_with_proc_argv[4] = "--policy-file";
  daemon_with_proc_argv[5] = policy_with_root;
  daemon_with_proc_argv[6] = "--";
  daemon_with_proc_argv[7] = "/exec/test_cli_broker_open_helper";
  daemon_with_proc_argv[8] = "/proc/self/status";
  daemon_with_proc_argv[9] = NULL;
  ok(run_landlockd(argv[1], daemon_with_proc_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "daemon runs also mount proc inside the runtime root");

  stop_argv[0] = argv[1];
  stop_argv[1] = "stop";
  stop_argv[2] = "--socket";
  stop_argv[3] = socket_path;
  stop_argv[4] = NULL;
  ok(run_landlockd(argv[1], stop_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "daemon stop exits successfully after runtime-root runs");

  ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
         WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
     "daemon exits cleanly after runtime-root runs");

  ok(access(socket_path, F_OK) < 0 && errno == ENOENT,
     "daemon stop removes the control socket after runtime-root runs");

  done_testing();
}
