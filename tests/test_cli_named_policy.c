#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "landlock_policy_ir.h"
#include "landlockd_cli.h"
#include "landlockd_exec.h"
#include "tap.h"

static int load_file_call_count;
static int run_policy_call_count;
static int daemon_run_call_count;
static char loaded_policy_path[PATH_MAX];
static char run_policy_path[PATH_MAX];
static char daemon_policy_path[PATH_MAX];
static char daemon_socket_path[PATH_MAX];
static char captured_argv0[PATH_MAX];

static int write_empty_file(const char *path) {
  FILE *fp;

  fp = fopen(path, "w");
  if (fp == NULL) {
    return -1;
  }
  return fclose(fp);
}

static int mkdir_policies_dir(const char *base, char *out, size_t out_size) {
  char landlockd_dir[PATH_MAX];

  if (snprintf(landlockd_dir, sizeof(landlockd_dir), "%s/landlockd", base) >=
          (int)sizeof(landlockd_dir) ||
      snprintf(out, out_size, "%s/policies", landlockd_dir) >=
          (int)out_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (mkdir(landlockd_dir, 0700) < 0 && errno != EEXIST) {
    return -1;
  }
  if (mkdir(out, 0700) < 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static void reset_captures(void) {
  load_file_call_count = 0;
  run_policy_call_count = 0;
  daemon_run_call_count = 0;
  loaded_policy_path[0] = '\0';
  run_policy_path[0] = '\0';
  daemon_policy_path[0] = '\0';
  daemon_socket_path[0] = '\0';
  captured_argv0[0] = '\0';
}

int landlockd_policy_load_file(const char *file_path,
                               struct landlockd_policy_ir *out_ir,
                               FILE *err_stream) {
  (void)err_stream;

  load_file_call_count++;
  snprintf(loaded_policy_path, sizeof(loaded_policy_path), "%s", file_path);
  landlockd_policy_ir_init(out_ir);
  return 0;
}

int landlockd_run_policy_file(const char *policy_file, char *const argv[],
                              FILE *diag) {
  return landlockd_run_policy_file_wait_status(policy_file, argv, diag, NULL);
}

int landlockd_run_policy_file_wait_status(const char *policy_file,
                                          char *const argv[], FILE *diag,
                                          int *wait_status_out) {
  (void)diag;

  run_policy_call_count++;
  snprintf(run_policy_path, sizeof(run_policy_path), "%s", policy_file);
  if (argv != NULL && argv[0] != NULL) {
    snprintf(captured_argv0, sizeof(captured_argv0), "%s", argv[0]);
  }
  if (wait_status_out != NULL) {
    *wait_status_out = 0;
  }
  return 0;
}

int landlockd_daemon_run(const char *socket_path, const char *policy_file,
                         char *const argv[], FILE *diag) {
  (void)diag;
  (void)argv;

  daemon_run_call_count++;
  snprintf(daemon_socket_path, sizeof(daemon_socket_path), "%s", socket_path);
  snprintf(daemon_policy_path, sizeof(daemon_policy_path), "%s", policy_file);
  return 0;
}

static ssize_t capture_stderr(int argc, char *argv[], int *rc, char *buffer,
                              size_t buffer_size) {
  int pipefd[2];
  int saved_stderr;
  ssize_t output_len;

  if (pipe(pipefd) < 0) {
    return -1;
  }
  saved_stderr = dup(STDERR_FILENO);
  fflush(stderr);
  dup2(pipefd[1], STDERR_FILENO);
  *rc = landlockd_cli_main(argc, argv);
  fflush(stderr);
  dup2(saved_stderr, STDERR_FILENO);
  close(saved_stderr);
  close(pipefd[1]);
  output_len = read(pipefd[0], buffer, buffer_size - 1);
  if (output_len >= 0) {
    buffer[output_len] = '\0';
  } else {
    buffer[0] = '\0';
  }
  close(pipefd[0]);
  return output_len;
}

int main(void) {
  char tempdir[] = "/tmp/landlockd-named-policy-XXXXXX";
  char search_dir[PATH_MAX];
  char xdg_home[PATH_MAX];
  char xdg_policy_dir[PATH_MAX];
  char system_dir[PATH_MAX];
  char policy_path[PATH_MAX];
  char xdg_policy_path[PATH_MAX];
  char system_policy_path[PATH_MAX];
  char stderr_buf[512];
  char *lint_argv[] = {"landlockd", "lint", "--policy", "strict", NULL};
  char *run_argv[] = {"landlockd", "run", "--policy", "strict", "--",
                      "/bin/true", NULL};
  char *daemon_argv[] = {"landlockd", "run", "--socket", "/tmp/landlockd.sock",
                         "--policy", "strict", "--", "/bin/true", NULL};
  char *invalid_argv[] = {"landlockd", "lint", "--policy", "bad/name", NULL};
  char *missing_argv[] = {"landlockd", "lint", "--policy", "missing", NULL};
  char *split_run_argv[] = {"/usr/bin/landlockd-run", "--policy", "strict",
                            "--", "/bin/true", NULL};
  int rc;

  plan(13);

  if (mkdtemp(tempdir) == NULL) {
    diag("mkdtemp failed: %s", strerror(errno));
    return 1;
  }
  if (snprintf(search_dir, sizeof(search_dir), "%s/search", tempdir) >=
          (int)sizeof(search_dir) ||
      snprintf(xdg_home, sizeof(xdg_home), "%s/xdg", tempdir) >=
          (int)sizeof(xdg_home) ||
      snprintf(system_dir, sizeof(system_dir), "%s/system", tempdir) >=
          (int)sizeof(system_dir) ||
      mkdir(search_dir, 0700) < 0 ||
      mkdir(xdg_home, 0700) < 0 ||
      mkdir(system_dir, 0700) < 0 ||
      mkdir_policies_dir(search_dir, search_dir, sizeof(search_dir)) < 0 ||
      mkdir_policies_dir(xdg_home, xdg_policy_dir, sizeof(xdg_policy_dir)) < 0 ||
      snprintf(policy_path, sizeof(policy_path), "%s/strict.toml", search_dir) >=
          (int)sizeof(policy_path) ||
      snprintf(xdg_policy_path, sizeof(xdg_policy_path), "%s/strict.toml",
               xdg_policy_dir) >= (int)sizeof(xdg_policy_path) ||
      snprintf(system_policy_path, sizeof(system_policy_path), "%s/strict.toml",
               system_dir) >= (int)sizeof(system_policy_path) ||
      write_empty_file(policy_path) < 0 || write_empty_file(xdg_policy_path) < 0 ||
      write_empty_file(system_policy_path) < 0) {
    diag("policy fixture setup failed: %s", strerror(errno));
    return 1;
  }

  if (setenv("LANDLOCKD_POLICY_PATH", search_dir, 1) < 0) {
    diag("setenv LANDLOCKD_POLICY_PATH failed: %s", strerror(errno));
    return 1;
  }
  unsetenv("XDG_CONFIG_HOME");

  reset_captures();
  rc = landlockd_cli_main(4, lint_argv);
  ok(rc == 0, "lint --policy resolves named policies through LANDLOCKD_POLICY_PATH");
  ok(load_file_call_count == 1 &&
         strcmp(loaded_policy_path, policy_path) == 0,
     "lint passes the resolved policy file path to the loader");

  reset_captures();
  rc = landlockd_cli_main(7, run_argv);
  ok(rc == 0, "run --policy resolves named policies for direct runs");
  ok(run_policy_call_count == 1 &&
         strcmp(run_policy_path, policy_path) == 0 &&
         strcmp(captured_argv0, "/bin/true") == 0,
     "direct runs receive the resolved policy file and command argv");

  reset_captures();
  rc = landlockd_cli_main(6, split_run_argv);
  ok(rc == 0 && run_policy_call_count == 1 &&
         strcmp(run_policy_path, policy_path) == 0 &&
         strcmp(captured_argv0, "/bin/true") == 0,
     "landlockd-run argv[0] wrapper dispatches to a direct policy run");

  reset_captures();
  rc = landlockd_cli_main(9, daemon_argv);
  ok(rc == 0, "run --socket --policy resolves named policies for daemon runs");
  ok(daemon_run_call_count == 1 &&
         strcmp(daemon_policy_path, policy_path) == 0 &&
         strcmp(daemon_socket_path, "/tmp/landlockd.sock") == 0,
     "daemon runs receive the resolved policy path and socket path");

  unsetenv("LANDLOCKD_POLICY_PATH");
  if (setenv("XDG_CONFIG_HOME", xdg_home, 1) < 0) {
    diag("setenv XDG_CONFIG_HOME failed: %s", strerror(errno));
    return 1;
  }

  reset_captures();
  rc = landlockd_cli_main(4, lint_argv);
  ok(rc == 0, "lint --policy falls back to XDG user policy directories");
  ok(load_file_call_count == 1 &&
         strcmp(loaded_policy_path, xdg_policy_path) == 0,
     "XDG fallback resolves to $XDG_CONFIG_HOME/landlockd/policies");

  unsetenv("XDG_CONFIG_HOME");
  if (setenv("LANDLOCKD_POLICY_SYSTEM_DIR", system_dir, 1) < 0) {
    diag("setenv LANDLOCKD_POLICY_SYSTEM_DIR failed: %s", strerror(errno));
    return 1;
  }

  reset_captures();
  rc = landlockd_cli_main(4, lint_argv);
  ok(rc == 0, "lint --policy falls back to the installed policy directory override");
  ok(load_file_call_count == 1 &&
         strcmp(loaded_policy_path, system_policy_path) == 0,
     "system policy override resolves through LANDLOCKD_POLICY_SYSTEM_DIR");

  reset_captures();
  capture_stderr(4, invalid_argv, &rc, stderr_buf, sizeof(stderr_buf));
  ok(rc == 1 && strstr(stderr_buf, "invalid policy name") != NULL,
     "invalid named policies are rejected before resolution");

  reset_captures();
  capture_stderr(4, missing_argv, &rc, stderr_buf, sizeof(stderr_buf));
  ok(rc == 1 && strstr(stderr_buf, "named policy \"missing\" not found") != NULL,
     "missing named policies report the search failure clearly");

  done_testing();
}
