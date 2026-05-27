#include <errno.h>
#include <string.h>

#include "landlockd_cli.h"
#include "tap.h"

int main(void)
{
    char *help_argv[] = {"landlockd", "--help", NULL};
    char *run_argv[] = {"landlockd", "run", "--policy", "strict", "--",
                        "/bin/echo", "ok", NULL};
    char *lint_name_argv[] = {"landlockd", "lint", "--policy", "strict", NULL};
    char *lint_file_argv[] = {"landlockd", "lint", "--policy-file",
                              "/etc/policy.yaml", NULL};
    char *preflight_argv[] = {"landlockd", "run", "--preflight", "--policy",
                              "strict", NULL};
    char *dry_run_argv[] = {"landlockd", "run", "--policy-file",
                            "/etc/policy.yaml", "--dry-run", "--",
                            "/bin/true", NULL};
    char *missing_sep_argv[] = {"landlockd", "run", "--policy", "strict",
                                NULL};
    char *missing_cmd_argv[] = {"landlockd", "run", "--policy", "strict",
                                "--", NULL};
    char *conflict_argv[] = {"landlockd", "run", "--policy", "a",
                             "--policy-file", "b", "--", "/bin/true", NULL};
    char *run_no_policy_argv[] = {"landlockd", "run", "--", "/bin/true", NULL};
    char *lint_no_policy_argv[] = {"landlockd", "lint", NULL};
    char *lint_with_cmd_argv[] = {"landlockd", "lint", "--policy", "strict",
                                  "--", "/bin/true", NULL};
    char *split_run_argv[] = {"landlockd-run", "--policy", "strict", "--",
                              "/bin/echo", "ok", NULL};
    char *split_run_file_argv[] = {"/usr/local/bin/landlockd-run",
                                   "--policy-file", "/etc/policy.yaml", "--",
                                   "/bin/true", NULL};
    char *split_policy_dry_run_argv[] = {"landlockd-policy", "dry-run",
                                         "--policy-file", "/etc/policy.yaml",
                                         NULL};
    char *split_policy_dry_run_name_argv[] = {"landlockd-policy", "dry-run",
                                              "--policy", "strict", NULL};
    char *plain_dry_run_argv[] = {"landlockd", "dry-run", "--policy", "strict",
                                  NULL};
    struct landlockd_cli_options options;
    int rc;

    plan(17);

    errno = 0;
    rc = landlockd_cli_parse(2, help_argv, &options);
    ok(rc == 0 && options.show_help == 1 &&
           options.verb == LANDLOCKD_CLI_VERB_NONE,
       "--help sets show_help and leaves verb unset");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(7, run_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           options.policy_name != NULL &&
           strcmp(options.policy_name, "strict") == 0 &&
           options.policy_file == NULL && options.preflight_only == 0 &&
           options.command_argv != NULL &&
           strcmp(options.command_argv[0], "/bin/echo") == 0 &&
           strcmp(options.command_argv[1], "ok") == 0 &&
           options.command_argv[2] == NULL,
       "run with --policy NAME captures verb, policy, and command");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(4, lint_name_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_LINT &&
           options.policy_name != NULL &&
           strcmp(options.policy_name, "strict") == 0 &&
           options.policy_file == NULL && options.command_argv == NULL,
       "lint with --policy NAME captures verb and named policy");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(4, lint_file_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_LINT &&
           options.policy_file != NULL &&
           strcmp(options.policy_file, "/etc/policy.yaml") == 0 &&
           options.policy_name == NULL && options.command_argv == NULL,
       "lint with --policy-file PATH captures verb and policy file");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(5, preflight_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           options.preflight_only == 1 &&
           options.dry_run == 0 &&
           options.policy_name != NULL &&
           strcmp(options.policy_name, "strict") == 0 &&
           options.command_argv == NULL,
       "run --preflight parses without requiring a command");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(7, dry_run_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           options.dry_run == 1 &&
           options.policy_file != NULL &&
           strcmp(options.policy_file, "/etc/policy.yaml") == 0 &&
           options.command_argv != NULL &&
           strcmp(options.command_argv[0], "/bin/true") == 0,
       "run --policy-file --dry-run captures the policy and command");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(4, missing_sep_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "run without -- and command is rejected");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(5, missing_cmd_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "run with -- but no command is rejected");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(8, conflict_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "run with both --policy and --policy-file is rejected");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(4, run_no_policy_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "run without any policy selector is rejected");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(2, lint_no_policy_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "lint without any policy selector is rejected");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(6, lint_with_cmd_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "lint with a command after -- is rejected");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(6, split_run_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           options.policy_name != NULL &&
           strcmp(options.policy_name, "strict") == 0 &&
           options.command_argv != NULL &&
           strcmp(options.command_argv[0], "/bin/echo") == 0 &&
           strcmp(options.command_argv[1], "ok") == 0 &&
           options.command_argv[2] == NULL,
       "landlockd-run argv[0] dispatches to run verb with named policy");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(5, split_run_file_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           options.policy_file != NULL &&
           strcmp(options.policy_file, "/etc/policy.yaml") == 0 &&
           options.command_argv != NULL &&
           strcmp(options.command_argv[0], "/bin/true") == 0,
       "landlockd-run argv[0] with absolute path dispatches via basename");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(4, split_policy_dry_run_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           options.dry_run == 1 && options.policy_file != NULL &&
           strcmp(options.policy_file, "/etc/policy.yaml") == 0 &&
           options.command_argv == NULL,
       "landlockd-policy dry-run --policy-file parses as run with dry_run");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(4, split_policy_dry_run_name_argv, &options);
    ok(rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           options.dry_run == 1 && options.policy_name != NULL &&
           strcmp(options.policy_name, "strict") == 0 &&
           options.command_argv == NULL,
       "landlockd-policy dry-run --policy NAME parses as run with dry_run");
    landlockd_cli_options_release(&options);

    errno = 0;
    rc = landlockd_cli_parse(4, plain_dry_run_argv, &options);
    ok(rc == -1 && errno == EINVAL,
       "landlockd dry-run without landlockd-policy basename is rejected");
    landlockd_cli_options_release(&options);

    done_testing();
}
