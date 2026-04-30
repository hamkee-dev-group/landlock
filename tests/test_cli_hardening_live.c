#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/landlock.h"
#include "landlockd/seccomp.h"
#include "tap.h"

static int probe_user_notif_available(void)
{
    unsigned int action = SECCOMP_RET_USER_NOTIF;

    return syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0U, &action) == 0;
}

static int probe_user_notif_installable(void)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        return 0;
    }
    if (pid == 0) {
        struct landlockd_seccomp_plan plan;
        int listener_fd;

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            _exit(1);
        }
        if (landlockd_seccomp_plan_init(&plan) < 0) {
            _exit(1);
        }
        if (landlockd_seccomp_plan_add(&plan, (int)SYS_openat) < 0) {
            _exit(1);
        }
        listener_fd = landlockd_seccomp_install(&plan);
        if (listener_fd < 0) {
            _exit(1);
        }
        close(listener_fd);
        _exit(0);
    }

    if (waitpid(pid, &status, 0) < 0) {
        return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
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

static int write_policy(const char *policy_path, const char *helper_dir,
                        const char *read_target)
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
        emit_rule(fp, helper_dir,
                  "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/lib",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/lib64",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/usr/lib",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/usr/lib64",
                        "[\"execute\", \"read_file\", \"read_dir\"]") < 0 ||
        maybe_emit_rule(fp, "/etc", "[\"read_file\", \"read_dir\"]") < 0 ||
        fprintf(fp, "\n[broker]\nallow_read = [\"%s\"]\n", read_target) < 0) {
        fclose(fp);
        return -1;
    }

    return fclose(fp) < 0 ? -1 : 0;
}

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

static int read_file_buf(const char *path, char *buf, size_t buf_size)
{
    int fd;
    ssize_t nread;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    nread = read(fd, buf, buf_size - 1);
    close(fd);
    if (nread < 0) {
        return -1;
    }
    buf[nread] = '\0';
    return 0;
}

static int status_field_value(pid_t pid, const char *field_name, int *value_out)
{
    char path[PATH_MAX];
    char buf[8192];
    char *line;
    char *saveptr;
    size_t name_len;

    if (snprintf(path, sizeof(path), "/proc/%d/status", (int)pid) >=
        (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (read_file_buf(path, buf, sizeof(buf)) < 0) {
        return -1;
    }

    name_len = strlen(field_name);
    for (line = strtok_r(buf, "\n", &saveptr); line != NULL;
         line = strtok_r(NULL, "\n", &saveptr)) {
        if (strncmp(line, field_name, name_len) == 0 &&
            line[name_len] == ':') {
            *value_out = atoi(line + name_len + 1);
            return 0;
        }
    }
    errno = ENOENT;
    return -1;
}

static int read_cmdline(pid_t pid, char *buf, size_t buf_size)
{
    char path[PATH_MAX];
    int fd;
    ssize_t nread;
    size_t i;

    if (snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid) >=
        (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    nread = read(fd, buf, buf_size - 1);
    close(fd);
    if (nread < 0) {
        return -1;
    }
    buf[nread] = '\0';
    for (i = 0; i < (size_t)nread; i++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    return 0;
}

static int read_children(pid_t pid, pid_t *children_out, size_t max_children,
                         size_t *count_out)
{
    char path[PATH_MAX];
    char buf[1024];
    char *tok;
    char *saveptr;
    size_t count;

    if (snprintf(path, sizeof(path), "/proc/%d/task/%d/children", (int)pid,
                 (int)pid) >= (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (read_file_buf(path, buf, sizeof(buf)) < 0) {
        return -1;
    }

    count = 0;
    for (tok = strtok_r(buf, " \n", &saveptr); tok != NULL;
         tok = strtok_r(NULL, " \n", &saveptr)) {
        if (count >= max_children) {
            errno = ENOSPC;
            return -1;
        }
        children_out[count++] = (pid_t)atoi(tok);
    }
    *count_out = count;
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
        int devnull = open("/dev/null", O_WRONLY);
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

int main(int argc, char *argv[])
{
    char tempdir[] = "/tmp/landlockd-hardening-XXXXXX";
    char helper_dir[PATH_MAX];
    char read_target[PATH_MAX];
    char policy_path[PATH_MAX];
    char socket_path[PATH_MAX];
    char *serve_argv[5];
    char *run_argv[9];
    pid_t daemon_pid;
    pid_t run_pid;
    pid_t children[8];
    pid_t broker_pid;
    size_t child_count;
    int daemon_status;
    int run_status;
    int stop_status;
    int value;
    int i;

    if (argc < 3) {
        diag("usage: %s <landlockd> <broker-helper>", argv[0]);
        return 1;
    }

    if (landlock_abi_version() == 0 || !probe_user_notif_available() ||
        !probe_user_notif_installable()) {
        plan(SKIP_ALL,
             "Landlock or seccomp user-notify broker path is unavailable");
        done_testing();
    }

    if (mkdtemp(tempdir) == NULL) {
        diag("mkdtemp failed: %s", strerror(errno));
        return 1;
    }
    if (parent_dir_of(argv[2], helper_dir, sizeof(helper_dir)) < 0) {
        diag("cannot derive helper directory: %s", strerror(errno));
        return 1;
    }
    if (snprintf(read_target, sizeof(read_target), "%s/read.txt", tempdir) >=
            (int)sizeof(read_target) ||
        snprintf(policy_path, sizeof(policy_path), "%s/policy.toml", tempdir) >=
            (int)sizeof(policy_path) ||
        snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
            (int)sizeof(socket_path)) {
        diag("path too long");
        return 1;
    }
    {
        FILE *fp = fopen(read_target, "w");
        if (fp == NULL) {
            diag("cannot write read target: %s", strerror(errno));
            return 1;
        }
        fputs("hold\n", fp);
        fclose(fp);
    }
    if (write_policy(policy_path, helper_dir, read_target) < 0) {
        diag("cannot write policy: %s", strerror(errno));
        return 1;
    }

    plan(9);

    serve_argv[0] = argv[1];
    serve_argv[1] = "serve";
    serve_argv[2] = "--socket";
    serve_argv[3] = socket_path;
    serve_argv[4] = NULL;
    ok(spawn_quiet(argv[1], serve_argv, &daemon_pid) == 0 &&
           wait_for_socket(socket_path) == 0,
       "daemon starts for hardening inspection");
    ok(status_field_value(daemon_pid, "NoNewPrivs", &value) == 0 && value == 1,
       "daemon runs with NoNewPrivs=1");
    ok(status_field_value(daemon_pid, "Seccomp", &value) == 0 && value == 2,
       "daemon runs in seccomp filter mode");

    run_argv[0] = argv[1];
    run_argv[1] = "run";
    run_argv[2] = "--policy-file";
    run_argv[3] = policy_path;
    run_argv[4] = "--";
    run_argv[5] = argv[2];
    run_argv[6] = read_target;
    run_argv[7] = "hold";
    run_argv[8] = NULL;
    ok(spawn_quiet(argv[1], run_argv, &run_pid) == 0,
       "direct run starts for broker hardening inspection");

    broker_pid = -1;
    for (i = 0; i < 200; i++) {
        child_count = 0;
        if (read_children(run_pid, children, sizeof(children) / sizeof(children[0]),
                          &child_count) == 0 &&
            child_count >= 2) {
            size_t j;
            for (j = 0; j < child_count; j++) {
                char cmdline[512];
                if (read_cmdline(children[j], cmdline, sizeof(cmdline)) == 0 &&
                    strncmp(cmdline, argv[1], strlen(argv[1])) == 0) {
                    broker_pid = children[j];
                    break;
                }
            }
            if (broker_pid > 0) {
                break;
            }
        }
        usleep(10000);
    }
    ok(broker_pid > 0, "broker child becomes observable under the run supervisor");
    ok(broker_pid > 0 &&
           status_field_value(broker_pid, "NoNewPrivs", &value) == 0 &&
           value == 1,
       "broker runs with NoNewPrivs=1");
    ok(broker_pid > 0 && status_field_value(broker_pid, "Seccomp", &value) == 0 &&
           value == 2,
       "broker runs in seccomp filter mode");

    ok(waitpid(run_pid, &run_status, 0) == run_pid && WIFEXITED(run_status) &&
           WEXITSTATUS(run_status) == 0,
       "direct brokered run still exits cleanly after hardening");

    if (spawn_quiet(argv[1],
                    (char *const[]){(char *)argv[1], "stop", "--socket",
                                    socket_path, NULL},
                    &run_pid) < 0 ||
        waitpid(run_pid, &stop_status, 0) != run_pid ||
        !WIFEXITED(stop_status) || WEXITSTATUS(stop_status) != 0 ||
        waitpid(daemon_pid, &daemon_status, 0) != daemon_pid ||
        !WIFEXITED(daemon_status) || WEXITSTATUS(daemon_status) != 0) {
        ok(0, "daemon stops cleanly after hardening inspection");
    } else {
        ok(1, "daemon stops cleanly after hardening inspection");
    }

    done_testing();
}
