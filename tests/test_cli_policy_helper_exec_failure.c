#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlock_policy_loader.h"
#include "tap.h"

static int run_and_capture(const char *binary, const char *policy_path,
                           char *buf, size_t bufsize) {
  pid_t pid;
  int pipe_fds[2];
  int status;
  ssize_t n;
  size_t total;
  char *const argv[] = {(char *)binary, "lint", "--policy-file",
                        (char *)policy_path, NULL};

  if (pipe(pipe_fds) < 0) {
    return -1;
  }

  pid = fork();
  if (pid == 0) {
    close(pipe_fds[0]);
    dup2(pipe_fds[1], STDERR_FILENO);
    close(pipe_fds[1]);
    setenv("LANDLOCKD_POLICY_HELPER", "/definitely/missing-helper", 1);
    execv(binary, argv);
    _exit(127);
  }

  close(pipe_fds[1]);
  total = 0;
  while (total + 1 < bufsize &&
         (n = read(pipe_fds[0], buf + total, bufsize - 1 - total)) > 0) {
    total += (size_t)n;
  }
  buf[total] = '\0';
  close(pipe_fds[0]);

  if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

int main(int argc, char *argv[]) {
  char buf[512];
  int rc;

  plan(1);

  if (argc < 3) {
    diag("missing landlockd binary or policy path argument");
    return 1;
  }

  if (!landlockd_policy_loader_uses_helper()) {
    tap_skip(1, "policy loader helper build mode is disabled");
    done_testing();
    return 0;
  }

  rc = run_and_capture(argv[1], argv[2], buf, sizeof(buf));
  ok(rc == 1 && strstr(buf, "helper exec failed") != NULL,
     "helper exec failure returns CLI failure without in-process fallback");

  done_testing();
}
