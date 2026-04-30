#define _GNU_SOURCE

#include <errno.h>
#include <linux/seccomp.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "landlockd/seccomp.h"
#include "tap.h"

static int send_listener_fd(int sock, int fd)
{
    struct msghdr msg;
    struct iovec iov;
    char payload = 'X';
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    memset(&msg, 0, sizeof(msg));
    memset(cbuf, 0, sizeof(cbuf));
    iov.iov_base = &payload;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_listener_fd(int sock)
{
    struct msghdr msg;
    struct iovec iov;
    char payload;
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    int fd;

    memset(&msg, 0, sizeof(msg));
    memset(cbuf, 0, sizeof(cbuf));
    iov.iov_base = &payload;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    if (recvmsg(sock, &msg, 0) <= 0) {
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS) {
        return -1;
    }
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

static int probe_user_notif_available(void)
{
    unsigned int action = SECCOMP_RET_USER_NOTIF;
    long rc;

    rc = syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0U, &action);
    return rc == 0;
}

int main(void)
{
    int sv[2];
    pid_t pid;
    int listener_fd;
    struct seccomp_notif req;
    struct seccomp_notif_resp resp;
    int status;

    if (!probe_user_notif_available()) {
        plan(SKIP_ALL, "seccomp user-notify not available on this kernel");
        done_testing();
    }

    plan(4);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        diag("socketpair failed: %s", strerror(errno));
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        diag("fork failed: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        struct landlockd_seccomp_plan p;
        int lfd;
        long ppid;
        long uid;

        close(sv[0]);
        landlockd_seccomp_plan_init(&p);
        landlockd_seccomp_plan_add(&p, (int)SYS_getppid);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            _exit(10);
        }
        lfd = landlockd_seccomp_install(&p);
        if (lfd < 0) {
            _exit(11);
        }
        if (send_listener_fd(sv[1], lfd) < 0) {
            _exit(12);
        }
        close(lfd);

        ppid = syscall(SYS_getppid);
        if (ppid <= 0) {
            _exit(13);
        }

        uid = syscall(SYS_getuid);
        (void)uid;

        _exit(0);
    }

    close(sv[1]);
    listener_fd = recv_listener_fd(sv[0]);
    ok(listener_fd >= 0, "parent receives seccomp listener fd from child");

    memset(&req, 0, sizeof(req));
    ok(ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) == 0,
       "parent reads one notification via SECCOMP_IOCTL_NOTIF_RECV");
    ok(req.data.nr == (int)SYS_getppid,
       "declared syscall is routed to user-notify");

    memset(&resp, 0, sizeof(resp));
    resp.id = req.id;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        diag("SECCOMP_IOCTL_NOTIF_SEND failed: %s", strerror(errno));
    }

    if (waitpid(pid, &status, 0) < 0) {
        diag("waitpid failed: %s", strerror(errno));
    }
    ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "child completes; undeclared syscall handled entirely in-kernel");

    close(listener_fd);
    close(sv[0]);

    done_testing();
}
