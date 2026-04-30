#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/preflight.h"
#include "landlockd_cli.h"
#include "tap.h"

static int create_fs_ruleset_call_count;
static int add_fs_rule_call_count;
static int apply_sandbox_call_count;

int landlockd_preflight_run(int required_abi_floor,
                            struct landlockd_preflight_report *out)
{
    out->abi_version = 1;
    out->required_abi_floor = required_abi_floor;
    out->meets_abi_floor = 1;
    out->stacking_supported = 1;
    out->probe_errno = 0;
    return 0;
}

int landlock_create_fs_ruleset(uint64_t requested_access_fs,
                               uint64_t *granted_access_fs)
{
    (void)requested_access_fs;
    (void)granted_access_fs;
    create_fs_ruleset_call_count++;
    errno = EIO;
    return -1;
}

int landlock_add_fs_rule(int ruleset_fd,
                         const struct landlock_path_beneath_attr *attr,
                         unsigned int flags)
{
    (void)ruleset_fd;
    (void)attr;
    (void)flags;
    add_fs_rule_call_count++;
    errno = EIO;
    return -1;
}

int landlockd_apply_sandbox(int ruleset_fd, unsigned int flags)
{
    (void)ruleset_fd;
    (void)flags;
    apply_sandbox_call_count++;
    errno = EIO;
    return -1;
}

static void reset_helper_call_counts(void)
{
    create_fs_ruleset_call_count = 0;
    add_fs_rule_call_count = 0;
    apply_sandbox_call_count = 0;
}

static ssize_t capture_cli_output(int argc, char *argv[], int fd, int *rc,
                                  char *buffer, size_t buffer_size)
{
    int capture_pipe[2];
    int saved_fd;
    ssize_t output_len;

    pipe(capture_pipe);
    saved_fd = dup(fd);

    fflush(stdout);
    fflush(stderr);
    dup2(capture_pipe[1], fd);
    *rc = landlockd_cli_main(argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_fd, fd);
    close(saved_fd);
    close(capture_pipe[1]);

    output_len = read(capture_pipe[0], buffer, buffer_size - 1);
    if (output_len >= 0) {
        buffer[output_len] = '\0';
    } else {
        buffer[0] = '\0';
    }
    close(capture_pipe[0]);
    return output_len;
}

int main(void)
{
    char output[1024];
    char *help_argv[] = {"landlockd", "--help", NULL};
    char *single_path_argv[] = {"landlockd", "--ro", "/tmp", "--", "cat", NULL};
    char *multi_path_argv[] = {"landlockd", "--ro", "/tmp", "--ro", "/", "--",
                               "cat", NULL};
    char *missing_path_argv[] = {"landlockd", "--ro", "--", "cat", NULL};
    char *missing_second_path_argv[] = {"landlockd", "--ro", "/tmp", "--ro", "--",
                                        "cat", NULL};
    char *missing_separator_argv[] = {"landlockd", "--ro", "/tmp", "cat", NULL};
    char *missing_command_argv[] = {"landlockd", "--ro", "/tmp", "--", NULL};
    char *mixed_argv[] = {"landlockd", "--notify", "39", "--ro", "/a",
                          "--notify", "102", "--ro", "/b", "--", "/bin/true",
                          NULL};
    char *bad_notify_argv[] = {"landlockd", "--ro", "/tmp", "--notify", "abc",
                               "--", "cat", NULL};
    char *overflow_notify_argv[] = {"landlockd",    "--ro", "/tmp",
                                    "--notify",     "99999999999",
                                    "--",           "cat",  NULL};
    char *serve_argv[] = {"landlockd", "serve", "--socket", "/tmp/landlockd.sock",
                          NULL};
    char *serve_systemd_argv[] = {"landlockd", "serve", "--systemd", NULL};
    char *status_argv[] = {"landlockd", "status", "--socket", "/tmp/landlockd.sock",
                           NULL};
    char *stop_argv[] = {"landlockd", "stop", "--socket", "/tmp/landlockd.sock",
                         NULL};
    char *run_socket_argv[] = {"landlockd", "run", "--socket", "/tmp/landlockd.sock",
                               "--policy-file", "policy.toml", "--", "/bin/true",
                               NULL};
    char *run_dry_argv[] = {"landlockd", "run", "--policy-file", "policy.toml",
                            "--dry-run", "--", "/bin/true", NULL};
    char *run_dry_no_command_argv[] = {"landlockd", "run", "--policy-file",
                                       "policy.toml", "--dry-run", NULL};
    char *run_dry_preflight_argv[] = {"landlockd", "run", "--policy-file",
                                      "policy.toml", "--dry-run", "--preflight",
                                      "--", "/bin/true", NULL};
    struct landlockd_cli_options options;
    int parse_rc;
    int rc;
    ssize_t output_len;

    plan(32);

    reset_helper_call_counts();
    errno = 0;
    output_len = capture_cli_output(2, help_argv, STDOUT_FILENO, &rc, output,
                                    sizeof(output));
    ok(rc == 0 && output_len > 0 &&
           strstr(output, "landlockd --ro PATH [--ro PATH ...]") != NULL &&
           strstr(output, "landlockd lint --policy-file POLICY.toml") != NULL &&
           strstr(output, "landlockd run --policy-file POLICY.toml") != NULL &&
           strstr(output, "landlockd serve --systemd") != NULL &&
           strstr(output, "landlockd status --socket PATH") != NULL,
       "prints help usage to stdout");
    ok(create_fs_ruleset_call_count == 0 &&
           add_fs_rule_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "help exits before any sandbox helper call");
    ok(errno == 0,
       "help leaves errno unchanged");

    reset_helper_call_counts();
    errno = 0;
    output_len = capture_cli_output(5, single_path_argv, STDERR_FILENO, &rc,
                                    output, sizeof(output));
    ok(rc == 1,
       "accepts a single --ro path before the command");
    ok(create_fs_ruleset_call_count == 1 &&
           add_fs_rule_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "single-path form reaches ruleset creation");

    reset_helper_call_counts();
    errno = 0;
    output_len = capture_cli_output(7, multi_path_argv, STDERR_FILENO, &rc,
                                    output, sizeof(output));
    ok(rc == 1 && errno == EIO && output_len > 0 &&
           strstr(output, "landlock_create_fs_ruleset") != NULL,
       "accepts repeated --ro path pairs before the command");
    ok(create_fs_ruleset_call_count == 1 &&
           add_fs_rule_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "repeated --ro form reaches ruleset creation");

    reset_helper_call_counts();
    errno = 0;
    output_len = capture_cli_output(4, missing_path_argv, STDERR_FILENO, &rc,
                                    output, sizeof(output));
    ok(rc == 1 && errno == EINVAL && output_len > 0 &&
           strstr(output, "Usage: landlockd") != NULL,
       "rejects a missing path after --ro in the parser");
    ok(create_fs_ruleset_call_count == 0 &&
           add_fs_rule_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "missing path does not call sandbox helpers");
    ok(strstr(output, "--ro PATH [--ro PATH ...]") != NULL,
       "missing path prints the usage string");

    reset_helper_call_counts();
    errno = 0;
    output_len = capture_cli_output(6, missing_second_path_argv, STDERR_FILENO,
                                    &rc, output, sizeof(output));
    ok(rc == 1 && errno == EINVAL && output_len > 0,
       "rejects a missing path after a repeated --ro");
    ok(create_fs_ruleset_call_count == 0 &&
           add_fs_rule_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "missing repeated path does not call sandbox helpers");
    ok(strstr(output, "--ro PATH [--ro PATH ...]") != NULL,
       "missing repeated path prints the usage string");

    reset_helper_call_counts();
    errno = 0;
    output_len = capture_cli_output(4, missing_separator_argv, STDERR_FILENO,
                                    &rc, output, sizeof(output));
    ok(rc == 1 && errno == EINVAL && output_len > 0,
       "rejects a missing -- separator in the parser");
    ok(create_fs_ruleset_call_count == 0 &&
           add_fs_rule_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "missing -- does not call sandbox helpers");
    ok(strstr(output, "--ro PATH [--ro PATH ...]") != NULL,
       "missing -- prints the usage string");

    reset_helper_call_counts();
    errno = 0;
    output_len = capture_cli_output(4, missing_command_argv, STDERR_FILENO,
                                    &rc, output, sizeof(output));
    ok(rc == 1 && errno == EINVAL && output_len > 0,
       "rejects a missing command after -- in the parser");
    ok(create_fs_ruleset_call_count == 0 &&
           add_fs_rule_call_count == 0 &&
           apply_sandbox_call_count == 0,
       "missing command does not call sandbox helpers");
    ok(strstr(output, "--ro PATH [--ro PATH ...]") != NULL,
       "missing command prints the usage string");

    errno = 0;
    parse_rc = landlockd_cli_parse(11, mixed_argv, &options);
    ok(parse_rc == 0 && options.ro_path_count == 2 &&
           strcmp(options.ro_paths[0], "/a") == 0 &&
           strcmp(options.ro_paths[1], "/b") == 0,
       "captures --ro paths in parse order despite interleaved --notify");
    ok(options.notify_count == 2 && options.notify_syscalls[0] == 39 &&
           options.notify_syscalls[1] == 102,
       "captures --notify syscall numbers in parse order");
    ok(options.command_argv != NULL &&
           strcmp(options.command_argv[0], "/bin/true") == 0,
       "mixed layout resolves command argv after the -- separator");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(7, bad_notify_argv, &options);
    ok(parse_rc == -1 && errno == EINVAL,
       "rejects --notify with a non-numeric argument");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(7, overflow_notify_argv, &options);
    ok(parse_rc == -1 && errno == EINVAL,
       "rejects --notify with a syscall number above INT_MAX");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(4, serve_argv, &options);
    ok(parse_rc == 0 && options.verb == LANDLOCKD_CLI_VERB_SERVE &&
           strcmp(options.socket_path, "/tmp/landlockd.sock") == 0,
       "parses serve --socket for daemon mode");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(3, serve_systemd_argv, &options);
    ok(parse_rc == 0 && options.verb == LANDLOCKD_CLI_VERB_SERVE &&
           options.use_systemd_socket_activation == 1 &&
           options.socket_path == NULL,
       "parses serve --systemd for socket activation mode");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(4, stop_argv, &options);
    ok(parse_rc == 0 && options.verb == LANDLOCKD_CLI_VERB_STOP &&
           strcmp(options.socket_path, "/tmp/landlockd.sock") == 0,
       "parses stop --socket for daemon shutdown");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(4, status_argv, &options);
    ok(parse_rc == 0 && options.verb == LANDLOCKD_CLI_VERB_STATUS &&
           strcmp(options.socket_path, "/tmp/landlockd.sock") == 0,
       "parses status --socket for daemon status queries");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(8, run_socket_argv, &options);
    ok(parse_rc == 0 && options.verb == LANDLOCKD_CLI_VERB_RUN &&
           strcmp(options.socket_path, "/tmp/landlockd.sock") == 0 &&
           options.command_argv != NULL &&
           strcmp(options.command_argv[0], "/bin/true") == 0,
       "parses run --socket with a policy file and command argv");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(7, run_dry_argv, &options);
    ok(parse_rc == 0 && options.dry_run == 1 &&
           options.command_argv != NULL &&
           strcmp(options.command_argv[0], "/bin/true") == 0,
       "parses run --dry-run with command argv");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(5, run_dry_no_command_argv, &options);
    ok(parse_rc == 0 && options.dry_run == 1 && options.command_argv == NULL,
       "parses run --dry-run without command argv");
    landlockd_cli_options_release(&options);

    errno = 0;
    parse_rc = landlockd_cli_parse(8, run_dry_preflight_argv, &options);
    ok(parse_rc == -1 && errno == EINVAL,
       "rejects run --dry-run with --preflight");
    landlockd_cli_options_release(&options);

    done_testing();
}
