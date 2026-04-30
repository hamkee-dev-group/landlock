#ifndef LANDLOCKD_EXEC_H
#define LANDLOCKD_EXEC_H

#include <stdio.h>

struct landlockd_policy_ir;

int landlockd_run_policy_ir_loaded(const struct landlockd_policy_ir *ir,
                                   const char *policy_label,
                                   char *const argv[], FILE *diag);
int landlockd_run_policy_file(const char *policy_file, char *const argv[],
                              FILE *diag);
int landlockd_run_policy_file_wait_status(const char *policy_file,
                                          char *const argv[], FILE *diag,
                                          int *wait_status_out);

#endif
