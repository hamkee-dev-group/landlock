#define _GNU_SOURCE

#include "landlockd_audit.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static FILE *landlockd_audit_current_diag;
static char *landlockd_audit_buf;
static size_t landlockd_audit_len;
static size_t landlockd_audit_cap;

static int landlockd_audit_append(const char *buf, size_t len) {
  char *new_buf;
  size_t new_cap;

  if (len == 0) {
    return 0;
  }

  if (landlockd_audit_len + len + 1 <= landlockd_audit_cap) {
    memcpy(landlockd_audit_buf + landlockd_audit_len, buf, len);
    landlockd_audit_len += len;
    landlockd_audit_buf[landlockd_audit_len] = '\0';
    return 0;
  }

  new_cap = landlockd_audit_cap == 0 ? 256 : landlockd_audit_cap;
  while (landlockd_audit_len + len + 1 > new_cap) {
    new_cap *= 2;
  }

  new_buf = realloc(landlockd_audit_buf, new_cap);
  if (new_buf == NULL) {
    return -1;
  }
  landlockd_audit_buf = new_buf;
  landlockd_audit_cap = new_cap;
  memcpy(landlockd_audit_buf + landlockd_audit_len, buf, len);
  landlockd_audit_len += len;
  landlockd_audit_buf[landlockd_audit_len] = '\0';
  return 0;
}

static int landlockd_audit_append_char(char ch) {
  return landlockd_audit_append(&ch, 1);
}

static void landlockd_audit_emit_escaped(const char *value) {
  const unsigned char *p;
  char escaped[7];

  if (value == NULL) {
    (void)landlockd_audit_append("null", 4);
    return;
  }

  (void)landlockd_audit_append_char('"');
  p = (const unsigned char *)value;
  while (*p != '\0') {
    switch (*p) {
    case '"':
      (void)landlockd_audit_append("\\\"", 2);
      break;
    case '\\':
      (void)landlockd_audit_append("\\\\", 2);
      break;
    case '\b':
      (void)landlockd_audit_append("\\b", 2);
      break;
    case '\f':
      (void)landlockd_audit_append("\\f", 2);
      break;
    case '\n':
      (void)landlockd_audit_append("\\n", 2);
      break;
    case '\r':
      (void)landlockd_audit_append("\\r", 2);
      break;
    case '\t':
      (void)landlockd_audit_append("\\t", 2);
      break;
    default:
      if (*p < 0x20U) {
        snprintf(escaped, sizeof(escaped), "\\u%04x", (unsigned int)*p);
        (void)landlockd_audit_append(escaped, strlen(escaped));
      } else {
        (void)landlockd_audit_append_char((char)*p);
      }
      break;
    }
    p++;
  }
  (void)landlockd_audit_append_char('"');
}

static void landlockd_audit_field_prefix(int *first_field, const char *key) {
  if (!*first_field) {
    (void)landlockd_audit_append_char(',');
  }
  *first_field = 0;
  landlockd_audit_emit_escaped(key);
  (void)landlockd_audit_append_char(':');
}

static void landlockd_audit_format_timestamp(char *buf, size_t buf_size) {
  struct timespec now;
  struct tm tm;

  now.tv_sec = 0;
  now.tv_nsec = 0;
  memset(&tm, 0, sizeof(tm));
  (void)clock_gettime(CLOCK_REALTIME, &now);
  (void)gmtime_r(&now.tv_sec, &tm);
  (void)strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void landlockd_audit_begin(FILE *diag, const char *event, int *first_field) {
  char timestamp[sizeof("YYYY-MM-DDTHH:MM:SSZ")];
  const char *job_id;

  if (diag == NULL || first_field == NULL) {
    return;
  }

  landlockd_audit_current_diag = diag;
  free(landlockd_audit_buf);
  landlockd_audit_buf = NULL;
  landlockd_audit_len = 0;
  landlockd_audit_cap = 0;
  *first_field = 1;
  (void)landlockd_audit_append_char('{');
  landlockd_audit_field_string(diag, first_field, "component", "landlockd");
  landlockd_audit_field_string(diag, first_field, "event", event);
  landlockd_audit_format_timestamp(timestamp, sizeof(timestamp));
  landlockd_audit_field_string(diag, first_field, "timestamp", timestamp);
  job_id = getenv("LANDLOCKD_JOB_ID");
  if (job_id != NULL) {
    landlockd_audit_field_string(diag, first_field, "job_id", job_id);
  }
}

void landlockd_audit_field_string(FILE *diag, int *first_field,
                                  const char *key, const char *value) {
  if (diag == NULL || first_field == NULL || key == NULL) {
    return;
  }

  (void)diag;
  landlockd_audit_field_prefix(first_field, key);
  landlockd_audit_emit_escaped(value);
}

void landlockd_audit_field_int(FILE *diag, int *first_field, const char *key,
                               long long value) {
  char buf[32];

  if (diag == NULL || first_field == NULL || key == NULL) {
    return;
  }

  (void)diag;
  landlockd_audit_field_prefix(first_field, key);
  snprintf(buf, sizeof(buf), "%lld", value);
  (void)landlockd_audit_append(buf, strlen(buf));
}

void landlockd_audit_field_uint(FILE *diag, int *first_field, const char *key,
                                unsigned long long value) {
  char buf[32];

  if (diag == NULL || first_field == NULL || key == NULL) {
    return;
  }

  (void)diag;
  landlockd_audit_field_prefix(first_field, key);
  snprintf(buf, sizeof(buf), "%llu", value);
  (void)landlockd_audit_append(buf, strlen(buf));
}

void landlockd_audit_end(FILE *diag) {
  int fd;

  if (diag == NULL) {
    return;
  }

  (void)diag;
  (void)landlockd_audit_append("}\n", 2);
  if (landlockd_audit_current_diag != NULL) {
    fd = fileno(landlockd_audit_current_diag);
    if (fd >= 0) {
      size_t off;

      off = 0;
      while (off < landlockd_audit_len) {
        ssize_t nwritten;

        nwritten = write(fd, landlockd_audit_buf + off,
                         landlockd_audit_len - off);
        if (nwritten < 0) {
          if (errno == EINTR) {
            continue;
          }
          break;
        }
        off += (size_t)nwritten;
      }
    }
  }
  free(landlockd_audit_buf);
  landlockd_audit_buf = NULL;
  landlockd_audit_len = 0;
  landlockd_audit_cap = 0;
  landlockd_audit_current_diag = NULL;
}
