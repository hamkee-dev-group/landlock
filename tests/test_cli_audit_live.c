#define _GNU_SOURCE

#include <ctype.h>
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

static int run_landlockd_capture(const char *binary, char *const argv[],
                                 int *status, char *stderr_buf,
                                 size_t stderr_buf_size) {
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
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
        dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[1]);
        execv(binary, argv);
        _exit(127);
    }

    close(pipe_fds[1]);
    total = 0;
    while (total + 1 < stderr_buf_size &&
           (nread = read(pipe_fds[0], stderr_buf + total,
                         stderr_buf_size - 1 - total)) > 0) {
        total += (size_t)nread;
    }
    close(pipe_fds[0]);
    stderr_buf[total] = '\0';

    if (waitpid(pid, status, 0) < 0) {
        return -1;
    }
    return 0;
}

static int read_file_into_buffer(const char *path, char *buf, size_t buf_size)
{
    FILE *fp;
    size_t nread;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    nread = fread(buf, 1, buf_size - 1, fp);
    fclose(fp);
    buf[nread] = '\0';
    return 0;
}

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
                        const char *read_target, const char *write_target,
                        const char *scratch_root, int allow_read,
                        int allow_write, int allow_scratch,
                        const char *mount_tmpfs, const char *bind_source,
                        const char *bind_target)
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
        (mount_tmpfs != NULL &&
         emit_rule(fp, mount_tmpfs, "[\"read_file\", \"read_dir\"]") < 0) ||
        (bind_target != NULL &&
         emit_rule(fp, bind_target, "[\"read_file\", \"read_dir\"]") < 0) ||
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

    if (allow_read || allow_write || allow_scratch) {
        if (fprintf(fp, "\n[broker]\n") < 0) {
            fclose(fp);
            return -1;
        }
        if (allow_read &&
            (fprintf(fp, "allow_read = [\"%s\"]\n", read_target) < 0 ||
             fprintf(fp, "addfd = [\"%s\"]\n", read_target) < 0)) {
            fclose(fp);
            return -1;
        }
        if (allow_write &&
            (fprintf(fp, "allow_write = [\"%s\"]\n", write_target) < 0 ||
             fprintf(fp, "addfd = [\"%s\"]\n", write_target) < 0)) {
            fclose(fp);
            return -1;
        }
        if (allow_scratch &&
            (fprintf(fp, "scratch = [\"%s\"]\n", scratch_root) < 0 ||
             fprintf(fp, "addfd = [\"%s\"]\n", scratch_root) < 0)) {
            fclose(fp);
            return -1;
        }
    }

    if (mount_tmpfs != NULL || bind_target != NULL) {
        if (fprintf(fp, "\n[mount]\n") < 0) {
            fclose(fp);
            return -1;
        }
        if (mount_tmpfs != NULL &&
            fprintf(fp, "tmpfs = [\"%s\"]\n", mount_tmpfs) < 0) {
            fclose(fp);
            return -1;
        }
        if (bind_source != NULL && bind_target != NULL &&
            fprintf(fp,
                    "  [[mount.bind]]\n"
                    "  source = \"%s\"\n"
                    "  target = \"%s\"\n"
                    "  read_only = false\n",
                    bind_source, bind_target) < 0) {
            fclose(fp);
            return -1;
        }
    }

    if (fclose(fp) < 0) {
        return -1;
    }
    return 0;
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

static int audit_line_has_pid(const char *buf, const char *event)
{
    const char *line;

    line = buf;
    while (line != NULL && *line != '\0') {
        const char *next = strchr(line, '\n');
        const char *event_match = strstr(line, event);
        const char *pid_match = strstr(line, "\"pid\":");

        if (event_match != NULL && pid_match != NULL &&
            (next == NULL || (event_match < next && pid_match < next))) {
            const char *p = pid_match + strlen("\"pid\":");

            if (isdigit((unsigned char)*p)) {
                do {
                    p++;
                } while (isdigit((unsigned char)*p));
                if (next == NULL || p <= next) {
                    return 1;
                }
            }
        }
        if (next == NULL) {
            break;
        }
        line = next + 1;
    }
    return 0;
}

static int audit_line_has_field(const char *buf, const char *event,
                                const char *field)
{
    const char *line;

    line = buf;
    while (line != NULL && *line != '\0') {
        const char *next = strchr(line, '\n');
        const char *event_match = strstr(line, event);
        const char *field_match = strstr(line, field);

        if (event_match != NULL && field_match != NULL &&
            (next == NULL || (event_match < next && field_match < next))) {
            return 1;
        }
        if (next == NULL) {
            break;
        }
        line = next + 1;
    }
    return 0;
}

static int audit_timestamp_valid(const char *field)
{
    const char *ts = field + strlen("\"timestamp\":\"");

    return isdigit((unsigned char)ts[0]) &&
           isdigit((unsigned char)ts[1]) &&
           isdigit((unsigned char)ts[2]) &&
           isdigit((unsigned char)ts[3]) && ts[4] == '-' &&
           isdigit((unsigned char)ts[5]) &&
           isdigit((unsigned char)ts[6]) && ts[7] == '-' &&
           isdigit((unsigned char)ts[8]) &&
           isdigit((unsigned char)ts[9]) && ts[10] == 'T' &&
           isdigit((unsigned char)ts[11]) &&
           isdigit((unsigned char)ts[12]) && ts[13] == ':' &&
           isdigit((unsigned char)ts[14]) &&
           isdigit((unsigned char)ts[15]) && ts[16] == ':' &&
           isdigit((unsigned char)ts[17]) &&
           isdigit((unsigned char)ts[18]) && ts[19] == 'Z' &&
           ts[20] == '"';
}

static int audit_event_lines_have_timestamps(const char *buf)
{
    const char *line;

    line = buf;
    while (line != NULL && *line != '\0') {
        const char *next = strchr(line, '\n');
        const char *event = strstr(line, "\"event\":");

        if (event != NULL && (next == NULL || event < next)) {
            const char *timestamp = strstr(line, "\"timestamp\":\"");

            if (timestamp == NULL || (next != NULL && timestamp >= next) ||
                !audit_timestamp_valid(timestamp)) {
                return 0;
            }
        }
        if (next == NULL) {
            break;
        }
        line = next + 1;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    char tempdir[] = "/tmp/landlockd-audit-XXXXXX";
    char helper_dir[PATH_MAX];
    char read_target[PATH_MAX];
    char write_target[PATH_MAX];
    char scratch_root[PATH_MAX];
    char scratch_dir[PATH_MAX];
    char scratch_file[PATH_MAX];
    char policy_read[PATH_MAX];
    char policy_readonly[PATH_MAX];
    char policy_scratch[PATH_MAX];
    char policy_mount[PATH_MAX];
    char mount_tmpfs_dir[PATH_MAX];
    char bind_source_dir[PATH_MAX];
    char bind_target_dir[PATH_MAX];
    char socket_path[PATH_MAX];
    char daemon_stderr_path[PATH_MAX];
    char direct_stderr[16384];
    char daemon_stderr[16384];
    char *direct_read_argv[8];
    char *direct_write_fail_argv[9];
    char *direct_scratch_argv[9];
    char *direct_mount_argv[8];
    char *serve_argv[5];
    char *daemon_run_argv[10];
    char *stop_argv[5];
    char daemon_pid_field[64];
    pid_t daemon_pid;
    int daemon_status;
    int direct_status;
    int mount_run_ok;
    int stop_status;

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
        snprintf(write_target, sizeof(write_target), "%s/write.txt", tempdir) >=
            (int)sizeof(write_target) ||
        snprintf(scratch_root, sizeof(scratch_root), "%s/scratch", tempdir) >=
            (int)sizeof(scratch_root) ||
        snprintf(scratch_dir, sizeof(scratch_dir), "%s/nested", scratch_root) >=
            (int)sizeof(scratch_dir) ||
        snprintf(scratch_file, sizeof(scratch_file), "%s/out.txt", scratch_dir) >=
            (int)sizeof(scratch_file) ||
        snprintf(policy_read, sizeof(policy_read), "%s/read.toml", tempdir) >=
            (int)sizeof(policy_read) ||
        snprintf(policy_readonly, sizeof(policy_readonly), "%s/readonly.toml",
                 tempdir) >= (int)sizeof(policy_readonly) ||
        snprintf(policy_scratch, sizeof(policy_scratch), "%s/scratch.toml",
                 tempdir) >= (int)sizeof(policy_scratch) ||
        snprintf(policy_mount, sizeof(policy_mount), "%s/mount.toml",
                 tempdir) >= (int)sizeof(policy_mount) ||
        snprintf(mount_tmpfs_dir, sizeof(mount_tmpfs_dir), "%s/mount-tmpfs",
                 tempdir) >= (int)sizeof(mount_tmpfs_dir) ||
        snprintf(bind_source_dir, sizeof(bind_source_dir), "%s/bind-source",
                 tempdir) >= (int)sizeof(bind_source_dir) ||
        snprintf(bind_target_dir, sizeof(bind_target_dir), "%s/bind-target",
                 tempdir) >= (int)sizeof(bind_target_dir) ||
        snprintf(socket_path, sizeof(socket_path), "%s/landlockd.sock", tempdir) >=
            (int)sizeof(socket_path) ||
        snprintf(daemon_stderr_path, sizeof(daemon_stderr_path),
                 "%s/daemon.stderr", tempdir) >=
            (int)sizeof(daemon_stderr_path)) {
        diag("path too long");
        return 1;
    }

    {
        FILE *fp = fopen(read_target, "w");
        if (fp == NULL) {
            diag("fopen read target failed: %s", strerror(errno));
            return 1;
        }
        fputs("audit\n", fp);
        fclose(fp);
    }
    {
        FILE *fp = fopen(write_target, "w");
        if (fp == NULL) {
            diag("fopen write target failed: %s", strerror(errno));
            return 1;
        }
        fputs("seed", fp);
        fclose(fp);
    }
    if (mkdir(scratch_root, 0700) < 0) {
        diag("mkdir scratch root failed: %s", strerror(errno));
        return 1;
    }
    if (mkdir(mount_tmpfs_dir, 0700) < 0 ||
        mkdir(bind_source_dir, 0700) < 0 ||
        mkdir(bind_target_dir, 0700) < 0) {
        diag("mkdir mount dirs failed: %s", strerror(errno));
        return 1;
    }

    if (write_policy(policy_read, helper_dir, read_target, write_target,
                     scratch_root, 1, 0, 0, NULL, NULL, NULL) < 0 ||
        write_policy(policy_readonly, helper_dir, read_target, write_target,
                     scratch_root, 1, 0, 0, NULL, NULL, NULL) < 0 ||
        write_policy(policy_scratch, helper_dir, read_target, write_target,
                     scratch_root, 0, 0, 1, NULL, NULL, NULL) < 0 ||
        write_policy(policy_mount, helper_dir, read_target, write_target,
                     scratch_root, 1, 0, 0, mount_tmpfs_dir, bind_source_dir,
                     bind_target_dir) < 0) {
        diag("cannot write policy files: %s", strerror(errno));
        return 1;
    }

    if (setenv("LANDLOCKD_JOB_ID", "test-job-abc123", 1) < 0) {
        diag("setenv failed: %s", strerror(errno));
        return 1;
    }

    plan(23);

    direct_read_argv[0] = argv[1];
    direct_read_argv[1] = "run";
    direct_read_argv[2] = "--policy-file";
    direct_read_argv[3] = policy_read;
    direct_read_argv[4] = "--";
    direct_read_argv[5] = argv[2];
    direct_read_argv[6] = read_target;
    direct_read_argv[7] = NULL;
    ok(run_landlockd_capture(argv[1], direct_read_argv, &direct_status,
                             direct_stderr, sizeof(direct_stderr)) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0,
       "direct brokered read succeeds with audit capture");
    ok(strstr(direct_stderr, "\"event\":\"run.start\"") != NULL &&
           strstr(direct_stderr, "\"policy_file\":\"") != NULL,
       "direct run emits a structured run.start event");
    ok(strstr(direct_stderr, "\"event\":\"broker.open\"") != NULL &&
           strstr(direct_stderr, "\"decision\":\"allow\"") != NULL &&
           strstr(direct_stderr, "\"scope\":\"exception\"") != NULL &&
           strstr(direct_stderr, "\"operation\":\"read\"") != NULL &&
           strstr(direct_stderr, read_target) != NULL,
       "direct brokered read emits a structured allow audit event");
    ok(strstr(direct_stderr, "\"event\":\"run.exit\"") != NULL &&
           strstr(direct_stderr, "\"status\":0") != NULL,
       "direct run emits a structured exit event");
    ok(audit_line_has_pid(direct_stderr, "\"event\":\"run.start\"") &&
           audit_line_has_pid(direct_stderr, "\"event\":\"run.exit\""),
       "direct run emits matching pid fields on run.start and run.exit");
    ok(audit_line_has_field(direct_stderr, "\"event\":\"run.start\"",
                            "\"job_id\":\"test-job-abc123\"") &&
           audit_line_has_field(direct_stderr, "\"event\":\"broker.open\"",
                                "\"job_id\":\"test-job-abc123\"") &&
           audit_line_has_field(direct_stderr, "\"event\":\"run.exit\"",
                                "\"job_id\":\"test-job-abc123\""),
       "direct run correlates run and broker audit events with job_id");
    ok(audit_event_lines_have_timestamps(direct_stderr),
       "direct audit events include RFC3339 UTC timestamps");

    direct_write_fail_argv[0] = argv[1];
    direct_write_fail_argv[1] = "run";
    direct_write_fail_argv[2] = "--policy-file";
    direct_write_fail_argv[3] = policy_readonly;
    direct_write_fail_argv[4] = "--";
    direct_write_fail_argv[5] = argv[2];
    direct_write_fail_argv[6] = write_target;
    direct_write_fail_argv[7] = "append";
    direct_write_fail_argv[8] = NULL;
    ok(run_landlockd_capture(argv[1], direct_write_fail_argv, &direct_status,
                             direct_stderr, sizeof(direct_stderr)) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) != 0,
       "direct disallowed write fails with audit capture");
    ok(strstr(direct_stderr, "\"event\":\"broker.open\"") != NULL &&
           strstr(direct_stderr, "\"decision\":\"deny\"") != NULL &&
           strstr(direct_stderr, "\"operation\":\"write\"") != NULL &&
           strstr(direct_stderr, "\"errno\":13") != NULL &&
           strstr(direct_stderr, write_target) != NULL,
       "direct denied write emits a structured deny audit event");
    ok(audit_line_has_field(direct_stderr, "\"event\":\"broker.open\"",
                            "\"operation\":\"write\""),
       "direct denied write audit event includes write operation");

    direct_scratch_argv[0] = argv[1];
    direct_scratch_argv[1] = "run";
    direct_scratch_argv[2] = "--policy-file";
    direct_scratch_argv[3] = policy_scratch;
    direct_scratch_argv[4] = "--";
    direct_scratch_argv[5] = argv[2];
    direct_scratch_argv[6] = scratch_dir;
    direct_scratch_argv[7] = "mkdir";
    direct_scratch_argv[8] = NULL;
    ok(run_landlockd_capture(argv[1], direct_scratch_argv, &direct_status,
                             direct_stderr, sizeof(direct_stderr)) == 0 &&
           WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0,
       "direct scratch mkdir succeeds with audit capture");
    ok(strstr(direct_stderr, "\"event\":\"broker.mkdir\"") != NULL &&
           strstr(direct_stderr, "\"decision\":\"allow\"") != NULL &&
           strstr(direct_stderr, scratch_dir) != NULL,
       "scratch mkdir emits a structured allow audit event");
    ok(audit_line_has_field(direct_stderr, "\"event\":\"broker.mkdir\"",
                            "\"operation\":\"mkdir\""),
       "scratch mkdir audit event includes mkdir operation");

    direct_mount_argv[0] = argv[1];
    direct_mount_argv[1] = "run";
    direct_mount_argv[2] = "--policy-file";
    direct_mount_argv[3] = policy_mount;
    direct_mount_argv[4] = "--";
    direct_mount_argv[5] = argv[2];
    direct_mount_argv[6] = read_target;
    direct_mount_argv[7] = NULL;
    direct_stderr[0] = '\0';
    mount_run_ok = run_landlockd_capture(argv[1], direct_mount_argv,
                                         &direct_status, direct_stderr,
                                         sizeof(direct_stderr)) == 0 &&
                   WIFEXITED(direct_status) && WEXITSTATUS(direct_status) == 0;
    if (!mount_run_ok &&
        strstr(direct_stderr,
               "mount rules require unprivileged user namespaces") != NULL) {
        tap_skip(2, "unprivileged mounts are unavailable");
    } else {
        ok(mount_run_ok, "direct mount policy succeeds with audit capture");
        ok(audit_line_has_pid(direct_stderr, "\"event\":\"mount.tmpfs\"") &&
               audit_line_has_pid(direct_stderr, "\"event\":\"mount.bind\""),
           "mount audit events include pid fields");
    }

    daemon_pid = fork();
    if (daemon_pid < 0) {
        diag("fork failed: %s", strerror(errno));
        return 1;
    }
    if (daemon_pid == 0) {
        int fd = open(daemon_stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int devnull = open("/dev/null", O_WRONLY);

        if (fd >= 0) {
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
        serve_argv[0] = argv[1];
        serve_argv[1] = "serve";
        serve_argv[2] = "--socket";
        serve_argv[3] = socket_path;
        serve_argv[4] = NULL;
        execv(argv[1], serve_argv);
        _exit(127);
    }
    ok(wait_for_socket(socket_path) == 0, "daemon starts for audit capture");

    daemon_run_argv[0] = argv[1];
    daemon_run_argv[1] = "run";
    daemon_run_argv[2] = "--socket";
    daemon_run_argv[3] = socket_path;
    daemon_run_argv[4] = "--policy-file";
    daemon_run_argv[5] = policy_read;
    daemon_run_argv[6] = "--";
    daemon_run_argv[7] = argv[2];
    daemon_run_argv[8] = read_target;
    daemon_run_argv[9] = NULL;
    ok(run_landlockd_capture(argv[1], daemon_run_argv, &daemon_status,
                             direct_stderr, sizeof(direct_stderr)) == 0 &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
       "daemon run succeeds while the daemon captures audit events");

    stop_argv[0] = argv[1];
    stop_argv[1] = "stop";
    stop_argv[2] = "--socket";
    stop_argv[3] = socket_path;
    stop_argv[4] = NULL;
    ok(run_landlockd_capture(argv[1], stop_argv, &stop_status, direct_stderr,
                             sizeof(direct_stderr)) == 0 &&
           WIFEXITED(stop_status) && WEXITSTATUS(stop_status) == 0 &&
           waitpid(daemon_pid, &daemon_status, 0) == daemon_pid &&
           WIFEXITED(daemon_status) && WEXITSTATUS(daemon_status) == 0,
       "daemon stops cleanly after audit capture");

    ok(read_file_into_buffer(daemon_stderr_path, daemon_stderr,
                             sizeof(daemon_stderr)) == 0,
       "daemon audit log is readable");
    ok(strstr(daemon_stderr, "\"event\":\"daemon.listen\"") != NULL &&
           strstr(daemon_stderr, "\"event\":\"daemon.request\"") != NULL &&
           strstr(daemon_stderr, "\"command\":\"run\"") != NULL,
       "daemon emits structured listener and request audit events");
    ok(strstr(daemon_stderr, "\"event\":\"broker.open\"") != NULL &&
           strstr(daemon_stderr, read_target) != NULL &&
           strstr(daemon_stderr, "\"event\":\"daemon.exit\"") != NULL,
       "daemon stderr includes broker and shutdown audit events");
    ok(audit_event_lines_have_timestamps(daemon_stderr),
       "daemon audit events include RFC3339 UTC timestamps");
    snprintf(daemon_pid_field, sizeof(daemon_pid_field), "\"pid\":%ld",
             (long)daemon_pid);
    ok(audit_line_has_field(daemon_stderr, "\"event\":\"daemon.listen\"",
                            daemon_pid_field) &&
           audit_line_has_field(daemon_stderr, "\"event\":\"daemon.request\"",
                                daemon_pid_field) &&
           audit_line_has_field(daemon_stderr, "\"event\":\"daemon.exit\"",
                                daemon_pid_field),
       "daemon lifecycle audit events include the daemon pid");

    done_testing();
}
