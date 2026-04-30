#ifndef LANDLOCKD_AUDIT_H
#define LANDLOCKD_AUDIT_H

#include <stdio.h>

void landlockd_audit_begin(FILE *diag, const char *event, int *first_field);
void landlockd_audit_field_string(FILE *diag, int *first_field,
                                  const char *key, const char *value);
void landlockd_audit_field_int(FILE *diag, int *first_field, const char *key,
                               long long value);
void landlockd_audit_field_uint(FILE *diag, int *first_field, const char *key,
                                unsigned long long value);
void landlockd_audit_end(FILE *diag);

#endif
