#ifndef LANDLOCKD_CLI_H
#define LANDLOCKD_CLI_H

#include "landlockd/seccomp.h"

enum landlockd_cli_verb {
  LANDLOCKD_CLI_VERB_NONE = 0,
  LANDLOCKD_CLI_VERB_RUN,
  LANDLOCKD_CLI_VERB_LINT,
  LANDLOCKD_CLI_VERB_SERVE,
  LANDLOCKD_CLI_VERB_STATUS,
  LANDLOCKD_CLI_VERB_STOP,
};

struct landlockd_cli_options {
  char **argv;
  enum landlockd_cli_verb verb;
  const char *policy_name;
  const char *policy_file;
  const char *socket_path;
  int use_systemd_socket_activation;
  int preflight_only;
  int dry_run;
  int ro_path_count;
  char **ro_paths;
  int notify_count;
  int *notify_syscalls;
  char **command_argv;
  int show_help;
};

int landlockd_cli_parse(int argc, char *argv[],
                        struct landlockd_cli_options *options);
void landlockd_cli_options_release(struct landlockd_cli_options *options);
int landlockd_cli_build_seccomp_plan(const struct landlockd_cli_options *options,
                                     struct landlockd_seccomp_plan *plan);
int landlockd_cli_main(int argc, char *argv[]);

#endif
