#ifndef LANDLOCKD_POLICY_LOADER_H
#define LANDLOCKD_POLICY_LOADER_H

#include <stdio.h>

#include "landlock_policy_ir.h"

int landlockd_policy_load_file(const char *file_path,
                               struct landlockd_policy_ir *out_ir,
                               FILE *err_stream);
int landlockd_policy_load_file_in_process(const char *file_path,
                                          struct landlockd_policy_ir *out_ir,
                                          FILE *err_stream);
int landlockd_policy_loader_uses_helper(void);
int landlockd_policy_helper_main(int argc, char *argv[]);

#endif
