#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "tap.h"

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
                        const char *seccomp_block) {
  FILE *fp;

  fp = fopen(policy_path, "w");
  if (fp == NULL) {
    return -1;
  }

  if (fprintf(fp,
              "version = 1\n\n"
              "[[fs_layer]]\n"
              "handled_access_fs = [\"execute\", \"read_file\", \"read_dir\"]\n") <
          0 ||
      emit_rule(fp, helper_dir,
                "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/usr/lib64", "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
      maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0) {
    fclose(fp);
    return -1;
  }

  if (seccomp_block != NULL && seccomp_block[0] != '\0') {
    if (fprintf(fp, "\n%s", seccomp_block) < 0) {
      fclose(fp);
      return -1;
    }
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
  char tempdir[] = "/tmp/landlockd-seccomp-XXXXXX";
  char helper_dir[PATH_MAX];
  char policy_allow[PATH_MAX];
  char policy_deny_getpid[PATH_MAX];
  char policy_deny_getppid[PATH_MAX];
  char socket_path[PATH_MAX];
  char *direct_allow_argv[8];
  char *direct_deny_getpid_argv[8];
  char *direct_deny_getppid_argv[8];
  char *serve_argv[5];
  char *daemon_deny_getpid_argv[10];
  char *daemon_allow_argv[10];
  char *stop_argv[5];
  pid_t daemon_pid;
  int status;
  int daemon_status;

  if (argc < 3) {
    diag("usage: %s <landlockd> <seccomp-helper>", argv[0]);
    return 1;
  }

  if (landlock_abi_version() == 0) {
    plan(SKIP_ALL, "Landlock is unavailable on this kernel");
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
  if (snprintf(policy_allow, sizeof(policy_allow), "%s/allow.toml", tempdir) >=
          (int)sizeof(policy_allow) ||
      snprintf(policy_deny_getpid, sizeof(policy_deny_getpid),
               "%s/deny-getpid.toml", tempdir) >= (int)sizeof(policy_deny_getpid) ||
      snprintf(policy_deny_getppid, sizeof(policy_deny_getppid),
               "%s/deny-getppid.toml", tempdir) >= (int)sizeof(policy_deny_getppid) ||
      snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
          (int)sizeof(socket_path)) {
    diag("path too long");
    return 1;
  }

  if (write_policy(policy_allow, helper_dir, NULL) < 0 ||
      write_policy(policy_deny_getpid, helper_dir,
                   "[seccomp]\n"
                   "deny = [\"getpid\"]\n"
                   "errno = 13\n") < 0 ||
      write_policy(policy_deny_getppid, helper_dir,
                   "[seccomp]\n"
                   "deny = [\"getppid\"]\n") < 0) {
    diag("cannot write policy fixtures: %s", strerror(errno));
    return 1;
  }

  plan(8);

  direct_allow_argv[0] = argv[1];
  direct_allow_argv[1] = "run";
  direct_allow_argv[2] = "--policy-file";
  direct_allow_argv[3] = policy_allow;
  direct_allow_argv[4] = "--";
  direct_allow_argv[5] = argv[2];
  direct_allow_argv[6] = "getpid";
  direct_allow_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_allow_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "direct run leaves allowed syscalls untouched");

  direct_deny_getpid_argv[0] = argv[1];
  direct_deny_getpid_argv[1] = "run";
  direct_deny_getpid_argv[2] = "--policy-file";
  direct_deny_getpid_argv[3] = policy_deny_getpid;
  direct_deny_getpid_argv[4] = "--";
  direct_deny_getpid_argv[5] = argv[2];
  direct_deny_getpid_argv[6] = "getpid";
  direct_deny_getpid_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_deny_getpid_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 13,
     "direct run enforces declarative seccomp deny rules with custom errno");

  direct_deny_getppid_argv[0] = argv[1];
  direct_deny_getppid_argv[1] = "run";
  direct_deny_getppid_argv[2] = "--policy-file";
  direct_deny_getppid_argv[3] = policy_deny_getppid;
  direct_deny_getppid_argv[4] = "--";
  direct_deny_getppid_argv[5] = argv[2];
  direct_deny_getppid_argv[6] = "getppid";
  direct_deny_getppid_argv[7] = NULL;
  ok(run_landlockd(argv[1], direct_deny_getppid_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 1,
     "seccomp policy defaults denied syscalls to EPERM when errno is omitted");

  serve_argv[0] = argv[1];
  serve_argv[1] = "serve";
  serve_argv[2] = "--socket";
  serve_argv[3] = socket_path;
  serve_argv[4] = NULL;
  ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
         wait_for_socket(socket_path) == 0,
     "daemon starts for seccomp policy runs");

  daemon_deny_getpid_argv[0] = argv[1];
  daemon_deny_getpid_argv[1] = "run";
  daemon_deny_getpid_argv[2] = "--socket";
  daemon_deny_getpid_argv[3] = socket_path;
  daemon_deny_getpid_argv[4] = "--policy-file";
  daemon_deny_getpid_argv[5] = policy_deny_getpid;
  daemon_deny_getpid_argv[6] = "--";
  daemon_deny_getpid_argv[7] = argv[2];
  daemon_deny_getpid_argv[8] = "getpid";
  daemon_deny_getpid_argv[9] = NULL;
  ok(run_landlockd(argv[1], daemon_deny_getpid_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 13,
     "daemon run enforces the same seccomp deny policy");

  daemon_allow_argv[0] = argv[1];
  daemon_allow_argv[1] = "run";
  daemon_allow_argv[2] = "--socket";
  daemon_allow_argv[3] = socket_path;
  daemon_allow_argv[4] = "--policy-file";
  daemon_allow_argv[5] = policy_allow;
  daemon_allow_argv[6] = "--";
  daemon_allow_argv[7] = argv[2];
  daemon_allow_argv[8] = "getppid";
  daemon_allow_argv[9] = NULL;
  ok(run_landlockd(argv[1], daemon_allow_argv, &status) == 0 &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "daemon run preserves allowed syscalls under the same Landlock policy");

  stop_argv[0] = argv[1];
  stop_argv[1] = "stop";
  stop_argv[2] = "--socket";
  stop_argv[3] = socket_path;
  stop_argv[4] = NULL;
  ok(run_landlockd(argv[1], stop_argv, &status) == 0 && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0,
     "daemon stop exits successfully after seccomp runs");

  ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
         WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
     "daemon exits cleanly after seccomp policy runs");

  done_testing();
}
