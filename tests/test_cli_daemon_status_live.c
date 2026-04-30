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

#include "tap.h"

static int wait_for_socket(const char *path)
{
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

static int run_landlockd(const char *binary, char *const argv[], int *status)
{
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execv(binary, argv);
        _exit(127);
    }
    if (waitpid(pid, status, 0) < 0) {
        return -1;
    }
    return 0;
}

static int run_landlockd_capture_stdout(const char *binary, char *const argv[],
                                        int *status, char *buf, size_t buf_size)
{
    pid_t pid;
    int pipefd[2];
    ssize_t nread;
    size_t total;

    if (pipe(pipefd) < 0) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execv(binary, argv);
        _exit(127);
    }

    close(pipefd[1]);
    total = 0;
    while (total + 1 < buf_size &&
           (nread = read(pipefd[0], buf + total, buf_size - 1 - total)) > 0) {
        total += (size_t)nread;
    }
    buf[total] = '\0';
    close(pipefd[0]);

    if (waitpid(pid, status, 0) < 0) {
        return -1;
    }
    return 0;
}

static int spawn_quiet(const char *binary, char *const argv[], pid_t *pid_out)
{
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

static int parent_dir_of(const char *path, char *buf, size_t buf_size)
{
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

static int emit_rule(FILE *fp, const char *path, const char *access_list)
{
    return fprintf(fp,
                   "  [[fs_layer.rule]]\n"
                   "  path = \"%s\"\n"
                   "  allowed_access = %s\n",
                   path, access_list) < 0
               ? -1
               : 0;
}

static int maybe_emit_rule(FILE *fp, const char *path, const char *access_list)
{
    if (access(path, F_OK) == 0) {
        return emit_rule(fp, path, access_list);
    }
    return 0;
}

static int write_policy(const char *policy_path, const char *command_dir)
{
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
        emit_rule(fp, command_dir,
                  "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/lib",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/lib64",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/usr/lib",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/usr/lib64",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0) {
        fclose(fp);
        return -1;
    }

    return fclose(fp) < 0 ? -1 : 0;
}

static const char *pick_true_binary(void)
{
    if (access("/usr/bin/true", X_OK) == 0) {
        return "/usr/bin/true";
    }
    if (access("/bin/true", X_OK) == 0) {
        return "/bin/true";
    }
    return NULL;
}

static int parse_status_json(const char *buf, unsigned int *protocol_version,
                             unsigned int *cache_entries,
                             unsigned long long *cache_hits,
                             unsigned long long *cache_misses)
{
    return sscanf(buf,
                  "{\"protocol_version\":%u,\"cache_entries\":%u,\"cache_hits\":%llu,\"cache_misses\":%llu}",
                  protocol_version, cache_entries, cache_hits, cache_misses) ==
                   4
               ? 0
               : -1;
}

int main(int argc, char *argv[])
{
    char tempdir[] = "/tmp/landlockd-daemon-status-XXXXXX";
    char policy_path[PATH_MAX];
    char socket_path[PATH_MAX];
    char command_dir[PATH_MAX];
    char status_buf[256];
    char *serve_argv[5];
    char *run_argv[9];
    char *status_argv[5];
    char *stop_argv[5];
    const char *true_binary;
    pid_t daemon_pid;
    int status;
    int daemon_status;
    unsigned int protocol_version;
    unsigned int cache_entries;
    unsigned long long cache_hits;
    unsigned long long cache_misses;

    if (argc < 2) {
        diag("usage: %s <landlockd>", argv[0]);
        return 1;
    }

    true_binary = pick_true_binary();
    if (true_binary == NULL) {
        plan(SKIP_ALL, "no usable true binary found");
        done_testing();
    }

    if (mkdtemp(tempdir) == NULL) {
        diag("mkdtemp failed: %s", strerror(errno));
        return 1;
    }

    snprintf(policy_path, sizeof(policy_path), "%s/policy.toml", tempdir);
    snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir);
    if (parent_dir_of(true_binary, command_dir, sizeof(command_dir)) < 0) {
        diag("cannot derive command directory: %s", strerror(errno));
        return 1;
    }
    if (write_policy(policy_path, command_dir) < 0) {
        diag("cannot write policy: %s", strerror(errno));
        return 1;
    }

    serve_argv[0] = argv[1];
    serve_argv[1] = "serve";
    serve_argv[2] = "--socket";
    serve_argv[3] = socket_path;
    serve_argv[4] = NULL;
    if (spawn_quiet(argv[1], serve_argv, &daemon_pid) < 0 ||
        wait_for_socket(socket_path) < 0) {
        diag("cannot start daemon: %s", strerror(errno));
        return 1;
    }

    plan(9);
    ok(1, "daemon starts for status and cache accounting");

    run_argv[0] = argv[1];
    run_argv[1] = "run";
    run_argv[2] = "--socket";
    run_argv[3] = socket_path;
    run_argv[4] = "--policy-file";
    run_argv[5] = policy_path;
    run_argv[6] = "--";
    run_argv[7] = (char *)true_binary;
    run_argv[8] = NULL;
    ok(run_landlockd(argv[1], run_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "first daemon run succeeds");

    status_argv[0] = argv[1];
    status_argv[1] = "status";
    status_argv[2] = "--socket";
    status_argv[3] = socket_path;
    status_argv[4] = NULL;
    ok(run_landlockd_capture_stdout(argv[1], status_argv, &status, status_buf,
                                    sizeof(status_buf)) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "status command succeeds against the daemon");
    ok(parse_status_json(status_buf, &protocol_version, &cache_entries,
                         &cache_hits, &cache_misses) == 0 &&
           protocol_version == 1 && cache_entries == 1 && cache_hits == 0 &&
           cache_misses == 1,
       "status reports one cached policy and the initial cache miss");

    ok(run_landlockd(argv[1], run_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "second daemon run succeeds");

    ok(run_landlockd_capture_stdout(argv[1], status_argv, &status, status_buf,
                                    sizeof(status_buf)) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "status command remains available after repeated runs");
    ok(parse_status_json(status_buf, &protocol_version, &cache_entries,
                         &cache_hits, &cache_misses) == 0 &&
           cache_entries == 1 && cache_hits >= 1 && cache_misses == 1,
       "status reports cache hits after a repeated policy run");

    stop_argv[0] = argv[1];
    stop_argv[1] = "stop";
    stop_argv[2] = "--socket";
    stop_argv[3] = socket_path;
    stop_argv[4] = NULL;
    ok(run_landlockd(argv[1], stop_argv, &status) == 0 &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "stop succeeds after status queries");

    ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
       "daemon exits cleanly after status-driven runs");

    done_testing();
}
