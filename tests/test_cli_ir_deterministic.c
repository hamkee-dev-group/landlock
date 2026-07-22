#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd_cli.h"
#include "tap.h"

static int write_text_file(const char *path, const char *content)
{
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

static int run_landlockd_capture_stdout(const char *binary, char *const argv[],
                                        int *status_out, char *stdout_buf,
                                        size_t stdout_buf_size)
{
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
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        dup2(pipe_fds[1], STDOUT_FILENO);
        close(pipe_fds[1]);
        execv(binary, argv);
        _exit(127);
    }

    close(pipe_fds[1]);
    total = 0;
    while (total + 1 < stdout_buf_size &&
           (nread = read(pipe_fds[0], stdout_buf + total,
                         stdout_buf_size - 1 - total)) > 0) {
        total += (size_t)nread;
    }
    close(pipe_fds[0]);
    stdout_buf[total] = '\0';

    if (waitpid(pid, status_out, 0) < 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char tempdir[] = "/tmp/landlockd-ir-deterministic-XXXXXX";
    char policy_path[256];
    char addfd_policy_path[256];
    char *dry_run_argv[] = {"landlockd", "run", "--policy-file", policy_path,
                            "--dry-run", "--", "/bin/true", NULL};
    char *addfd_dry_run_argv[] = {"landlockd",       "run", "--policy-file",
                                  addfd_policy_path, "--dry-run", "--",
                                  "/bin/true",       NULL};
    char stdout_c[4096];
    char stdout_d[4096];
    int status_c;
    int status_d;
    char *argv_a[] = {"landlockd", "--ro", "/a", "--ro", "/b", "--", "/bin/echo",
                      "hi", NULL};
    char *argv_b[] = {"landlockd", "--ro", "/a", "--ro", "/b", "--", "/bin/echo",
                      "hi", NULL};
    char *mixed_a[] = {"landlockd", "--notify", "39", "--ro", "/a", "--notify",
                       "102", "--ro", "/b", "--", "/bin/true", NULL};
    char *mixed_b[] = {"landlockd", "--notify", "39", "--ro", "/a", "--notify",
                       "102", "--ro", "/b", "--", "/bin/true", NULL};
    struct landlockd_cli_options first;
    struct landlockd_cli_options second;
    char stdout_a[4096];
    char stdout_b[4096];
    int rc_a;
    int rc_b;
    int status_a;
    int status_b;

    if (argc < 2) {
        diag("usage: %s <landlockd>", argv[0]);
        return 1;
    }

    plan(16);

    errno = 0;
    rc_a = landlockd_cli_parse(8, argv_a, &first);
    rc_b = landlockd_cli_parse(8, argv_b, &second);
    ok(rc_a == 0 && rc_b == 0, "parser succeeds on identical inputs");
    ok(first.show_help == second.show_help,
       "show_help is deterministic across parses");
    ok(first.ro_path_count == second.ro_path_count &&
           first.ro_path_count == 2,
       "ro_path_count is deterministic across parses");
    ok(first.argv == argv_a && second.argv == argv_b,
       "argv field points at the input argv");
    ok(strcmp(first.command_argv[0], second.command_argv[0]) == 0 &&
           strcmp(first.command_argv[1], second.command_argv[1]) == 0 &&
           first.command_argv[2] == NULL && second.command_argv[2] == NULL,
       "command_argv contents are deterministic across parses");
    landlockd_cli_options_release(&first);
    landlockd_cli_options_release(&second);

    errno = 0;
    rc_a = landlockd_cli_parse(8, argv_a, &first);
    ok(rc_a == 0 && first.ro_path_count == 2 && first.show_help == 0,
       "re-parsing the same argv yields the same IR fields");
    landlockd_cli_options_release(&first);

    errno = 0;
    rc_a = landlockd_cli_parse(11, mixed_a, &first);
    rc_b = landlockd_cli_parse(11, mixed_b, &second);
    ok(rc_a == 0 && rc_b == 0,
       "parser succeeds on identical mixed --ro/--notify inputs");
    ok(first.ro_path_count == second.ro_path_count &&
           first.ro_path_count == 2 &&
           strcmp(first.ro_paths[0], second.ro_paths[0]) == 0 &&
           strcmp(first.ro_paths[1], second.ro_paths[1]) == 0 &&
           strcmp(first.ro_paths[0], "/a") == 0 &&
           strcmp(first.ro_paths[1], "/b") == 0,
       "ro_paths are deterministic across parses of interleaved layouts");
    ok(first.notify_count == second.notify_count &&
           first.notify_count == 2 &&
           first.notify_syscalls[0] == second.notify_syscalls[0] &&
           first.notify_syscalls[1] == second.notify_syscalls[1] &&
           first.notify_syscalls[0] == 39 &&
           first.notify_syscalls[1] == 102,
       "notify_syscalls are deterministic across parses of interleaved layouts");
    landlockd_cli_options_release(&first);
    landlockd_cli_options_release(&second);

    if (mkdtemp(tempdir) == NULL ||
        snprintf(policy_path, sizeof(policy_path), "%s/policy.toml", tempdir) >=
            (int)sizeof(policy_path) ||
        write_text_file(policy_path,
                        "version = 1\n\n"
                        "[[fs_layer]]\n"
                        "handled_access_fs = [\"read_file\", \"read_dir\"]\n\n"
                        "  [[fs_layer.rule]]\n"
                        "  path = \"/usr\"\n"
                        "  allowed_access = [\"read_file\", \"read_dir\"]\n\n"
                        "  [[fs_layer.rule]]\n"
                        "  path = \"/etc\"\n"
                        "  allowed_access = [\"read_file\", \"read_dir\"]\n") <
            0) {
        diag("fixture setup failed: %s", strerror(errno));
        return 1;
    }

    ok(run_landlockd_capture_stdout(argv[1], dry_run_argv, &status_a, stdout_a,
                                    sizeof(stdout_a)) == 0 &&
           run_landlockd_capture_stdout(argv[1], dry_run_argv, &status_b,
                                        stdout_b, sizeof(stdout_b)) == 0,
       "dry-run output can be captured twice from the real binary");
    ok(WIFEXITED(status_a) && WEXITSTATUS(status_a) == 0 &&
           WIFEXITED(status_b) && WEXITSTATUS(status_b) == 0,
       "real dry-run exits 0 twice for the same policy file");
    ok(strcmp(stdout_a, stdout_b) == 0,
       "real dry-run output is byte-for-byte deterministic");
    ok(strncmp(stdout_a, "landlockd dry-run v1\n",
               strlen("landlockd dry-run v1\n")) == 0,
       "real dry-run output begins with the stable header");

    if (snprintf(addfd_policy_path, sizeof(addfd_policy_path),
                 "%s/addfd.toml", tempdir) >= (int)sizeof(addfd_policy_path) ||
        write_text_file(addfd_policy_path,
                        "version = 1\n\n"
                        "[[fs_layer]]\n"
                        "handled_access_fs = [\"read_file\"]\n\n"
                        "  [[fs_layer.rule]]\n"
                        "  path = \"/etc\"\n"
                        "  allowed_access = [\"read_file\"]\n\n"
                        "[broker]\n"
                        "allow_read = [\"/etc/resolv.conf\"]\n\n"
                        "  [[broker.addfd]]\n"
                        "  action = \"open\"\n"
                        "  target = \"/etc/resolv.conf\"\n"
                        "  mode = \"read\"\n") < 0) {
        diag("addfd fixture setup failed: %s", strerror(errno));
        return 1;
    }

    ok(run_landlockd_capture_stdout(argv[1], addfd_dry_run_argv, &status_c,
                                    stdout_c, sizeof(stdout_c)) == 0 &&
           run_landlockd_capture_stdout(argv[1], addfd_dry_run_argv, &status_d,
                                        stdout_d, sizeof(stdout_d)) == 0,
       "broker.addfd dry-run output can be captured twice from the real binary");
    ok(WIFEXITED(status_c) && WEXITSTATUS(status_c) == 0 &&
           WIFEXITED(status_d) && WEXITSTATUS(status_d) == 0,
       "real dry-run exits 0 twice for a broker.addfd policy file");
    ok(strcmp(stdout_c, stdout_d) == 0,
       "broker.addfd wire serialization is byte-for-byte reproducible");

    done_testing();
}
