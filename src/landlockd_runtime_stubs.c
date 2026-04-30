#include "landlockd_daemon.h"
#include "landlockd_exec.h"

#include <errno.h>
#include <stdio.h>

__attribute__((weak)) int landlockd_run_policy_file(const char *policy_file,
                                                    char *const argv[],
                                                    FILE *diag) {
  return landlockd_run_policy_file_wait_status(policy_file, argv, diag, NULL);
}

__attribute__((weak)) int landlockd_run_policy_file_wait_status(
    const char *policy_file, char *const argv[], FILE *diag,
    int *wait_status_out) {
  (void)policy_file;
  (void)argv;
  if (wait_status_out != NULL) {
    *wait_status_out = 0;
  }
  if (diag != NULL) {
    fputs("landlockd: policy runtime is unavailable in this test build\n", diag);
  }
  errno = ENOSYS;
  return 1;
}

__attribute__((weak)) int landlockd_daemon_serve(const char *socket_path,
                                                 FILE *diag) {
  (void)socket_path;
  if (diag != NULL) {
    fputs("landlockd: daemon runtime is unavailable in this test build\n", diag);
  }
  errno = ENOSYS;
  return 1;
}

__attribute__((weak)) int landlockd_daemon_serve_systemd(FILE *diag) {
  if (diag != NULL) {
    fputs("landlockd: daemon runtime is unavailable in this test build\n", diag);
  }
  errno = ENOSYS;
  return 1;
}

__attribute__((weak)) int landlockd_daemon_run(const char *socket_path,
                                               const char *policy_file,
                                               char *const argv[],
                                               FILE *diag) {
  (void)socket_path;
  (void)policy_file;
  (void)argv;
  if (diag != NULL) {
    fputs("landlockd: daemon runtime is unavailable in this test build\n", diag);
  }
  errno = ENOSYS;
  return 1;
}

__attribute__((weak)) int landlockd_daemon_stop(const char *socket_path,
                                                FILE *diag) {
  (void)socket_path;
  if (diag != NULL) {
    fputs("landlockd: daemon runtime is unavailable in this test build\n", diag);
  }
  errno = ENOSYS;
  return 1;
}

__attribute__((weak)) int landlockd_daemon_status(const char *socket_path,
                                                  FILE *out, FILE *diag) {
  (void)socket_path;
  (void)out;
  if (diag != NULL) {
    fputs("landlockd: daemon runtime is unavailable in this test build\n", diag);
  }
  errno = ENOSYS;
  return 1;
}
