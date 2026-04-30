#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    DIR *dir;
    struct dirent *entry;
    int scan_fd;

    dir = opendir("/proc/self/fd");
    if (dir == NULL) {
        perror("opendir");
        return 1;
    }

    scan_fd = dirfd(dir);
    if (scan_fd < 0) {
        perror("dirfd");
        closedir(dir);
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char *endptr;
        long fd;
        char path[PATH_MAX];
        char target[PATH_MAX];
        ssize_t len;

        errno = 0;
        fd = strtol(entry->d_name, &endptr, 10);
        if (errno != 0 || endptr == entry->d_name || *endptr != '\0') {
            continue;
        }
        if (fd <= STDERR_FILENO || fd == scan_fd) {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        len = readlink(path, target, sizeof(target) - 1);
        if (len < 0) {
            perror("readlink");
            closedir(dir);
            return 1;
        }
        target[len] = '\0';

        if (strstr(target, "landlock") != NULL ||
            strstr(target, "seccomp") != NULL) {
            fprintf(stderr, "unexpected inherited fd %ld -> %s\n", fd, target);
            closedir(dir);
            return 1;
        }
    }

    closedir(dir);
    return 0;
}
