#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

static int umount_quiet(const char *path)
{
    syscall(SYS_umount2, path, 0);
    return 0;
}

int main(int argc, char *argv[])
{
    char byte;
    int fd;

    if (argc != 2 && argc != 3 && argc != 4 && argc != 5) {
        return 2;
    }

    if (argc == 5) {
        if (strcmp(argv[4], "bind-read-cycle") == 0) {
            if (syscall(SYS_mount, argv[1], argv[2], NULL, MS_BIND, NULL) < 0) {
                perror("mount");
                return 14;
            }
            fd = open(argv[3], O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (read(fd, &byte, sizeof(byte)) < 0) {
                perror("read");
                close(fd);
                umount_quiet(argv[2]);
                return 15;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "bind-append-cycle") == 0) {
            if (syscall(SYS_mount, argv[1], argv[2], NULL, MS_BIND, NULL) < 0) {
                perror("mount");
                return 14;
            }
            fd = open(argv[3], O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (write(fd, "!", 1) != 1) {
                perror("write");
                close(fd);
                umount_quiet(argv[2]);
                return 15;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "bind-append-denied-cycle") == 0) {
            if (syscall(SYS_mount, argv[1], argv[2], NULL, MS_BIND, NULL) < 0) {
                perror("mount");
                return 14;
            }
            fd = open(argv[3], O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd >= 0) {
                if (write(fd, "!", 1) == 1) {
                    close(fd);
                    umount_quiet(argv[2]);
                    return 16;
                }
                if (errno != EROFS && errno != EACCES && errno != EPERM) {
                    perror("write");
                    close(fd);
                    umount_quiet(argv[2]);
                    return 15;
                }
                close(fd);
            } else if (errno != EROFS && errno != EACCES && errno != EPERM) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "move-mount-read-cycle") == 0) {
#ifdef SYS_move_mount
            if (syscall(SYS_move_mount, AT_FDCWD, argv[1], AT_FDCWD, argv[2], 0U) < 0) {
                perror("move_mount");
                return 17;
            }
#else
            return 17;
#endif
            fd = open(argv[3], O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (read(fd, &byte, sizeof(byte)) < 0) {
                perror("read");
                close(fd);
                umount_quiet(argv[2]);
                return 15;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "move-mount-append-cycle") == 0) {
#ifdef SYS_move_mount
            if (syscall(SYS_move_mount, AT_FDCWD, argv[1], AT_FDCWD, argv[2], 0U) < 0) {
                perror("move_mount");
                return 17;
            }
#else
            return 17;
#endif
            fd = open(argv[3], O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (write(fd, "!", 1) != 1) {
                perror("write");
                close(fd);
                umount_quiet(argv[2]);
                return 15;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "move-mount-append-denied-cycle") == 0) {
#ifdef SYS_move_mount
            if (syscall(SYS_move_mount, AT_FDCWD, argv[1], AT_FDCWD, argv[2], 0U) < 0) {
                perror("move_mount");
                return 17;
            }
#else
            return 17;
#endif
            fd = open(argv[3], O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd >= 0) {
                if (write(fd, "!", 1) == 1) {
                    close(fd);
                    umount_quiet(argv[2]);
                    return 16;
                }
                if (errno != EROFS && errno != EACCES && errno != EPERM) {
                    perror("write");
                    close(fd);
                    umount_quiet(argv[2]);
                    return 15;
                }
                close(fd);
            } else if (errno != EROFS && errno != EACCES && errno != EPERM) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "open-tree-move-read-cycle") == 0) {
#if defined(SYS_open_tree) && defined(SYS_move_mount)
            int tree_fd;
            tree_fd = syscall(SYS_open_tree, AT_FDCWD, argv[1],
                              OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
            if (tree_fd < 0) {
                perror("open_tree");
                return 18;
            }
            if (syscall(SYS_move_mount, tree_fd, "", AT_FDCWD, argv[2],
                        MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                perror("move_mount");
                close(tree_fd);
                return 17;
            }
            close(tree_fd);
#else
            return 18;
#endif
            fd = open(argv[3], O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (read(fd, &byte, sizeof(byte)) < 0) {
                perror("read");
                close(fd);
                umount_quiet(argv[2]);
                return 15;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "open-tree-move-append-cycle") == 0) {
#if defined(SYS_open_tree) && defined(SYS_move_mount)
            int tree_fd;
            tree_fd = syscall(SYS_open_tree, AT_FDCWD, argv[1],
                              OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
            if (tree_fd < 0) {
                perror("open_tree");
                return 18;
            }
            if (syscall(SYS_move_mount, tree_fd, "", AT_FDCWD, argv[2],
                        MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                perror("move_mount");
                close(tree_fd);
                return 17;
            }
            close(tree_fd);
#else
            return 18;
#endif
            fd = open(argv[3], O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (write(fd, "!", 1) != 1) {
                perror("write");
                close(fd);
                umount_quiet(argv[2]);
                return 15;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "open-tree-move-append-denied-cycle") == 0) {
#if defined(SYS_open_tree) && defined(SYS_move_mount)
            int tree_fd;
            tree_fd = syscall(SYS_open_tree, AT_FDCWD, argv[1],
                              OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
            if (tree_fd < 0) {
                perror("open_tree");
                return 18;
            }
            if (syscall(SYS_move_mount, tree_fd, "", AT_FDCWD, argv[2],
                        MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                perror("move_mount");
                close(tree_fd);
                return 17;
            }
            close(tree_fd);
#else
            return 18;
#endif
            fd = open(argv[3], O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd >= 0) {
                if (write(fd, "!", 1) == 1) {
                    close(fd);
                    umount_quiet(argv[2]);
                    return 16;
                }
                if (errno != EROFS && errno != EACCES && errno != EPERM) {
                    perror("write");
                    close(fd);
                    umount_quiet(argv[2]);
                    return 15;
                }
                close(fd);
            } else if (errno != EROFS && errno != EACCES && errno != EPERM) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "fsopen-fsmount-create-cycle") == 0) {
#if defined(SYS_fsopen) && defined(SYS_fsconfig) && defined(SYS_fsmount) && defined(SYS_move_mount)
            int fsfd;
            int mntfd;

            fsfd = syscall(SYS_fsopen, argv[1], FSOPEN_CLOEXEC);
            if (fsfd < 0) {
                perror("fsopen");
                return 19;
            }
            if (syscall(SYS_fsconfig, fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
                perror("fsconfig");
                close(fsfd);
                return 20;
            }
            mntfd = syscall(SYS_fsmount, fsfd, FSMOUNT_CLOEXEC, 0U);
            close(fsfd);
            if (mntfd < 0) {
                perror("fsmount");
                return 21;
            }
            if (syscall(SYS_move_mount, mntfd, "", AT_FDCWD, argv[2],
                        MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                perror("move_mount");
                close(mntfd);
                return 17;
            }
            close(mntfd);
#else
            return 19;
#endif
            fd = open(argv[3], O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd < 0) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (write(fd, "x", 1) != 1) {
                perror("write");
                close(fd);
                umount_quiet(argv[2]);
                return 15;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        if (strcmp(argv[4], "fsopen-fsmount-setattr-readonly-cycle") == 0) {
#if defined(SYS_fsopen) && defined(SYS_fsconfig) && defined(SYS_fsmount) && defined(SYS_move_mount)
            int fsfd;
            int mntfd;

            fsfd = syscall(SYS_fsopen, argv[1], FSOPEN_CLOEXEC);
            if (fsfd < 0) {
                perror("fsopen");
                return 19;
            }
            if (syscall(SYS_fsconfig, fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
                perror("fsconfig");
                close(fsfd);
                return 20;
            }
            mntfd = syscall(SYS_fsmount, fsfd, FSMOUNT_CLOEXEC, 0U);
            close(fsfd);
            if (mntfd < 0) {
                perror("fsmount");
                return 21;
            }
            if (syscall(SYS_move_mount, mntfd, "", AT_FDCWD, argv[2],
                        MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                perror("move_mount");
                close(mntfd);
                return 17;
            }
            close(mntfd);
#ifdef SYS_mount_setattr
            {
                struct mount_attr attr;

                memset(&attr, 0, sizeof(attr));
                attr.attr_set = MOUNT_ATTR_RDONLY;
                if (syscall(SYS_mount_setattr, AT_FDCWD, argv[2], 0U, &attr,
                            sizeof(attr)) < 0) {
                    perror("mount_setattr");
                    umount_quiet(argv[2]);
                    return 22;
                }
            }
#else
            umount_quiet(argv[2]);
            return 22;
#endif
#else
            return 19;
#endif
            fd = open(argv[3], O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd >= 0) {
                close(fd);
                umount_quiet(argv[2]);
                return 16;
            }
            if (errno != EROFS && errno != EACCES && errno != EPERM) {
                perror("open");
                umount_quiet(argv[2]);
                return 15;
            }
            if (syscall(SYS_umount2, argv[2], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        return 2;
    }

    if (argc == 4) {
        if (strcmp(argv[3], "rename") == 0) {
            if (syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], 0U) <
                0) {
                perror("renameat2");
                return 7;
            }
            return 0;
        }
        if (strcmp(argv[3], "symlink") == 0) {
            if (syscall(SYS_symlinkat, argv[1], AT_FDCWD, argv[2]) < 0) {
                perror("symlinkat");
                return 10;
            }
            return 0;
        }
        if (strcmp(argv[3], "link") == 0) {
            if (syscall(SYS_linkat, AT_FDCWD, argv[1], AT_FDCWD, argv[2], 0) < 0) {
                perror("linkat");
                return 9;
            }
            return 0;
        }
        if (strcmp(argv[3], "mount-cycle") == 0) {
            if (syscall(SYS_mount, "tmpfs", argv[1], "tmpfs", 0UL, NULL) < 0) {
                perror("mount");
                return 12;
            }
            fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd < 0) {
                perror("open");
                syscall(SYS_umount2, argv[1], 0);
                return 3;
            }
            if (write(fd, "mounted", 7) != 7) {
                perror("write");
                close(fd);
                syscall(SYS_umount2, argv[1], 0);
                return 5;
            }
            close(fd);
            if (syscall(SYS_umount2, argv[1], 0) < 0) {
                perror("umount2");
                return 13;
            }
            return 0;
        }
        return 2;
    }

    if (argc == 3) {
        if (strcmp(argv[2], "append") == 0) {
            fd = open(argv[1], O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                return 3;
            }
            if (write(fd, "!", 1) != 1) {
                perror("write");
                close(fd);
                return 5;
            }
            close(fd);
            return 0;
        }
        if (strcmp(argv[2], "create") == 0) {
            fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd < 0) {
                perror("open");
                return 3;
            }
            if (write(fd, "scratch", 7) != 7) {
                perror("write");
                close(fd);
                return 5;
            }
            close(fd);
            return 0;
        }
        if (strcmp(argv[2], "hold") == 0) {
            fd = open(argv[1], O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                perror("open");
                return 3;
            }
            sleep(2);
            close(fd);
            return 0;
        }
        if (strcmp(argv[2], "mkdir") == 0) {
            if (syscall(SYS_mkdirat, AT_FDCWD, argv[1], 0700) < 0) {
                perror("mkdirat");
                return 6;
            }
            return 0;
        }
        if (strcmp(argv[2], "unlink") == 0) {
            if (syscall(SYS_unlinkat, AT_FDCWD, argv[1], 0) < 0) {
                perror("unlinkat");
                return 8;
            }
            return 0;
        }
        if (strcmp(argv[2], "rmdir") == 0) {
            if (syscall(SYS_unlinkat, AT_FDCWD, argv[1], AT_REMOVEDIR) < 0) {
                perror("unlinkat-rmdir");
                return 11;
            }
            return 0;
        }
        return 2;
    }

    fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open");
        return 3;
    }
    if (read(fd, &byte, sizeof(byte)) < 0) {
        perror("read");
        close(fd);
        return 4;
    }
    close(fd);
    return 0;
}
