#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  long rc;

  if (argc != 2) {
    return 2;
  }

  if (strcmp(argv[1], "getpid") == 0) {
    errno = 0;
    rc = syscall(SYS_getpid);
    if (rc < 0) {
      return errno != 0 ? errno : 3;
    }
    return 0;
  }

  if (strcmp(argv[1], "getppid") == 0) {
    errno = 0;
    rc = syscall(SYS_getppid);
    if (rc < 0) {
      return errno != 0 ? errno : 3;
    }
    return 0;
  }

  fprintf(stderr, "unknown mode: %s\n", argv[1]);
  return 2;
}
