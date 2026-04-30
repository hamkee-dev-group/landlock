#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tap.h"

static int run_landlockd(const char *binary, char *const argv[], int *status)
{
    pid_t pid;
    int devnull;

    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(binary, argv);
        _exit(127);
    }
    if (waitpid(pid, status, 0) < 0) {
        return -1;
    }
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

    if (fclose(fp) < 0) {
        return -1;
    }
    return 0;
}

static int create_listener(const char *socket_path)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(addr.sun_path, socket_path);

    unlink(socket_path);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 16) < 0) {
        int saved_errno = errno;

        close(fd);
        unlink(socket_path);
        errno = saved_errno;
        return -1;
    }

    return fd;
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

int main(int argc, char *argv[])
{
    char tempdir[] = "/tmp/landlockd-activation-XXXXXX";
    char policy_path[PATH_MAX];
    char socket_path[PATH_MAX];
    char command_dir[PATH_MAX];
    char listen_pid_str[32];
    char *serve_argv[4];
    char *run_argv[9];
    char *stop_argv[5];
    const char *true_binary;
    pid_t daemon_pid;
    int listen_fd;
    int daemon_status;
    int run_status;
    int stop_status;

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

    listen_fd = create_listener(socket_path);
    if (listen_fd < 0) {
        diag("cannot create listener: %s", strerror(errno));
        return 1;
    }

    daemon_pid = fork();
    if (daemon_pid < 0) {
        diag("fork failed: %s", strerror(errno));
        close(listen_fd);
        return 1;
    }
    if (daemon_pid == 0) {
        serve_argv[0] = argv[1];
        serve_argv[1] = "serve";
        serve_argv[2] = "--systemd";
        serve_argv[3] = NULL;

        if (listen_fd != 3) {
            if (dup2(listen_fd, 3) < 0) {
                _exit(127);
            }
            close(listen_fd);
        }
        snprintf(listen_pid_str, sizeof(listen_pid_str), "%d", (int)getpid());
        setenv("LISTEN_PID", listen_pid_str, 1);
        setenv("LISTEN_FDS", "1", 1);
        execv(argv[1], serve_argv);
        _exit(127);
    }
    close(listen_fd);

    plan(3);

    run_argv[0] = argv[1];
    run_argv[1] = "run";
    run_argv[2] = "--socket";
    run_argv[3] = socket_path;
    run_argv[4] = "--policy-file";
    run_argv[5] = policy_path;
    run_argv[6] = "--";
    run_argv[7] = (char *)true_binary;
    run_argv[8] = NULL;
    ok(run_landlockd(argv[1], run_argv, &run_status) == 0 &&
           WIFEXITED(run_status) && WEXITSTATUS(run_status) == 0,
       "run succeeds through a systemd-activated daemon listener");

    stop_argv[0] = argv[1];
    stop_argv[1] = "stop";
    stop_argv[2] = "--socket";
    stop_argv[3] = socket_path;
    stop_argv[4] = NULL;
    ok(run_landlockd(argv[1], stop_argv, &stop_status) == 0 &&
           WIFEXITED(stop_status) && WEXITSTATUS(stop_status) == 0,
       "stop succeeds against the activated listener");

    ok(waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
       "activated daemon exits cleanly after stop");

    unlink(socket_path);
    done_testing();
}
