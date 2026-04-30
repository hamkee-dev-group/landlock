#ifndef LANDLOCKD_DAEMON_H
#define LANDLOCKD_DAEMON_H

#include <stdio.h>

int landlockd_daemon_serve(const char *socket_path, FILE *diag);
int landlockd_daemon_serve_systemd(FILE *diag);
int landlockd_daemon_run(const char *socket_path, const char *policy_file,
                         char *const argv[], FILE *diag);
int landlockd_daemon_status(const char *socket_path, FILE *out, FILE *diag);
int landlockd_daemon_stop(const char *socket_path, FILE *diag);

#endif
