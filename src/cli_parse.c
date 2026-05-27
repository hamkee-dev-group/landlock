#include "landlockd_cli.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int cli_parse_syscall_nr(const char *s, int *out) {
  char *end;
  long value;

  errno = 0;
  value = strtol(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0' || value < 0 || value > INT_MAX) {
    return -1;
  }
  *out = (int)value;
  return 0;
}

static const char *cli_basename(const char *path) {
  const char *slash;

  if (path == NULL) {
    return "";
  }
  slash = strrchr(path, '/');
  return slash != NULL ? slash + 1 : path;
}

static int cli_parse_policy_verb(int argc, char *argv[],
                                 struct landlockd_cli_options *options,
                                 enum landlockd_cli_verb verb, int argi) {
  options->verb = verb;
  while (argi < argc && strcmp(argv[argi], "--") != 0) {
    if (strcmp(argv[argi], "--preflight") == 0) {
      options->preflight_only = 1;
      argi += 1;
      continue;
    }
    if (strcmp(argv[argi], "--dry-run") == 0) {
      options->dry_run = 1;
      argi += 1;
      continue;
    }
    if (argi + 1 >= argc || strcmp(argv[argi + 1], "--") == 0) {
      errno = EINVAL;
      return -1;
    }
    if (strcmp(argv[argi], "--policy") == 0) {
      if (options->policy_name != NULL || options->policy_file != NULL) {
        errno = EINVAL;
        return -1;
      }
      options->policy_name = argv[argi + 1];
    } else if (strcmp(argv[argi], "--policy-file") == 0) {
      if (options->policy_name != NULL || options->policy_file != NULL) {
        errno = EINVAL;
        return -1;
      }
      options->policy_file = argv[argi + 1];
    } else if (strcmp(argv[argi], "--socket") == 0) {
      if (options->socket_path != NULL) {
        errno = EINVAL;
        return -1;
      }
      options->socket_path = argv[argi + 1];
    } else {
      errno = EINVAL;
      return -1;
    }
    argi += 2;
  }

  if (options->preflight_only && options->dry_run) {
    errno = EINVAL;
    return -1;
  }

  if (options->policy_name == NULL && options->policy_file == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (verb == LANDLOCKD_CLI_VERB_LINT) {
    if (argi != argc) {
      errno = EINVAL;
      return -1;
    }
    options->argv = argv;
    return 0;
  }

  if (argi == argc) {
    if (!options->preflight_only && !options->dry_run) {
      errno = EINVAL;
      return -1;
    }
    options->argv = argv;
    return 0;
  }
  if (argi + 1 >= argc) {
    errno = EINVAL;
    return -1;
  }
  options->argv = argv;
  options->command_argv = &argv[argi + 1];
  return 0;
}

int landlockd_cli_parse(int argc, char *argv[],
                        struct landlockd_cli_options *options) {
  int argi;
  int ro_count;
  int notify_count;
  int parsed_nr;
  char **ro_paths;
  int *notify_syscalls;

  if (argv == NULL || options == NULL) {
    errno = EINVAL;
    return -1;
  }

  options->argv = NULL;
  options->verb = LANDLOCKD_CLI_VERB_NONE;
  options->policy_name = NULL;
  options->policy_file = NULL;
  options->socket_path = NULL;
  options->use_systemd_socket_activation = 0;
  options->preflight_only = 0;
  options->dry_run = 0;
  options->ro_path_count = 0;
  options->ro_paths = NULL;
  options->notify_count = 0;
  options->notify_syscalls = NULL;
  options->command_argv = NULL;
  options->show_help = 0;

  if (argc == 2 && strcmp(argv[1], "--help") == 0) {
    options->show_help = 1;
    return 0;
  }

  if (argc >= 1) {
    const char *base = cli_basename(argv[0]);
    if (strcmp(base, "landlockd-run") == 0) {
      return cli_parse_policy_verb(argc, argv, options,
                                   LANDLOCKD_CLI_VERB_RUN, 1);
    }
    if (strcmp(base, "landlockd-policy") == 0 && argc >= 2) {
      if (strcmp(argv[1], "lint") == 0) {
        return cli_parse_policy_verb(argc, argv, options,
                                     LANDLOCKD_CLI_VERB_LINT, 2);
      }
      if (strcmp(argv[1], "dry-run") == 0) {
        options->dry_run = 1;
        return cli_parse_policy_verb(argc, argv, options,
                                     LANDLOCKD_CLI_VERB_RUN, 2);
      }
    }
  }

  if (argc >= 2 && strcmp(argv[1], "run") == 0) {
    return cli_parse_policy_verb(argc, argv, options,
                                 LANDLOCKD_CLI_VERB_RUN, 2);
  }
  if (argc >= 2 && strcmp(argv[1], "lint") == 0) {
    return cli_parse_policy_verb(argc, argv, options,
                                 LANDLOCKD_CLI_VERB_LINT, 2);
  }
  if (argc == 4 && strcmp(argv[1], "serve") == 0 &&
      strcmp(argv[2], "--socket") == 0) {
    options->verb = LANDLOCKD_CLI_VERB_SERVE;
    options->socket_path = argv[3];
    options->argv = argv;
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "serve") == 0 &&
      strcmp(argv[2], "--systemd") == 0) {
    options->verb = LANDLOCKD_CLI_VERB_SERVE;
    options->use_systemd_socket_activation = 1;
    options->argv = argv;
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "stop") == 0 &&
      strcmp(argv[2], "--socket") == 0) {
    options->verb = LANDLOCKD_CLI_VERB_STOP;
    options->socket_path = argv[3];
    options->argv = argv;
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "status") == 0 &&
      strcmp(argv[2], "--socket") == 0) {
    options->verb = LANDLOCKD_CLI_VERB_STATUS;
    options->socket_path = argv[3];
    options->argv = argv;
    return 0;
  }

  ro_count = 0;
  notify_count = 0;
  argi = 1;
  while (argi < argc && strcmp(argv[argi], "--") != 0) {
    if (argi + 1 >= argc || strcmp(argv[argi + 1], "--") == 0) {
      errno = EINVAL;
      return -1;
    }
    if (strcmp(argv[argi], "--ro") == 0) {
      ro_count++;
    } else if (strcmp(argv[argi], "--notify") == 0) {
      if (cli_parse_syscall_nr(argv[argi + 1], &parsed_nr) < 0) {
        errno = EINVAL;
        return -1;
      }
      notify_count++;
    } else {
      errno = EINVAL;
      return -1;
    }
    argi += 2;
  }

  if (ro_count == 0 || argi >= argc || argi + 1 >= argc) {
    errno = EINVAL;
    return -1;
  }

  ro_paths = calloc((size_t)ro_count, sizeof(*ro_paths));
  if (ro_paths == NULL) {
    return -1;
  }
  notify_syscalls = NULL;
  if (notify_count > 0) {
    notify_syscalls = calloc((size_t)notify_count, sizeof(*notify_syscalls));
    if (notify_syscalls == NULL) {
      free(ro_paths);
      return -1;
    }
  }

  argi = 1;
  while (argi < argc && strcmp(argv[argi], "--") != 0) {
    if (strcmp(argv[argi], "--ro") == 0) {
      ro_paths[options->ro_path_count++] = argv[argi + 1];
    } else {
      cli_parse_syscall_nr(argv[argi + 1],
                           &notify_syscalls[options->notify_count++]);
    }
    argi += 2;
  }

  options->argv = argv;
  options->ro_paths = ro_paths;
  options->notify_syscalls = notify_syscalls;
  options->command_argv = &argv[argi + 1];
  return 0;
}

int landlockd_cli_build_seccomp_plan(const struct landlockd_cli_options *options,
                                     struct landlockd_seccomp_plan *plan) {
  int i;

  if (options == NULL || plan == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (landlockd_seccomp_plan_init(plan) < 0) {
    return -1;
  }
  for (i = 0; i < options->notify_count; i++) {
    if (landlockd_seccomp_plan_add(plan, options->notify_syscalls[i]) < 0) {
      return -1;
    }
  }
  return 0;
}

void landlockd_cli_options_release(struct landlockd_cli_options *options) {
  if (options == NULL) {
    return;
  }
  free(options->ro_paths);
  free(options->notify_syscalls);
  options->ro_paths = NULL;
  options->notify_syscalls = NULL;
  options->ro_path_count = 0;
  options->notify_count = 0;
}
