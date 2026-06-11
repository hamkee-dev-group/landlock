#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "landlock_policy_ir.h"
#include "landlock_policy_loader.h"
#include "tap.h"

static void check_addfd_rule(const struct landlockd_policy_ir *ir, size_t index,
                             const char *action, const char *target,
                             const char *mode)
{
    ok(ir->broker_addfd_count > index &&
           strcmp(ir->broker_addfd_rules[index].action, action) == 0 &&
           strcmp(ir->broker_addfd_rules[index].target, target) == 0 &&
           ir->broker_addfd_rules[index].mode != NULL &&
           strcmp(ir->broker_addfd_rules[index].mode, mode) == 0,
       "Rust policy helper round-trips broker.addfd[%zu] action=%s", index,
       action);
}

static int load_capturing(const char *file_path,
                          struct landlockd_policy_ir *out,
                          char *errbuf, size_t errbufsz)
{
    FILE *mem;
    int rc;

    mem = fmemopen(errbuf, errbufsz, "w");
    if (mem == NULL) {
        return -1;
    }
    rc = landlockd_policy_load_file(file_path, out, mem);
    fclose(mem);
    return rc;
}

int main(int argc, char *argv[])
{
    struct landlockd_policy_ir ir;
    char errbuf[512];
    int rc;

    if (argc < 4) {
        diag("usage: %s <rust-helper|none> <valid-policy> <invalid-policy>", argv[0]);
        return 1;
    }

    if (!landlockd_policy_loader_uses_helper()) {
        plan(SKIP_ALL, "policy loader helper build mode is disabled");
        done_testing();
        return 0;
    }
    if (strcmp(argv[1], "none") == 0) {
        plan(SKIP_ALL, "Rust policy helper was not built");
        done_testing();
        return 0;
    }

    if (setenv("LANDLOCKD_POLICY_HELPER", argv[1], 1) < 0) {
        diag("setenv LANDLOCKD_POLICY_HELPER failed");
        return 1;
    }
    unsetenv("LANDLOCKD_POLICY_HELPER_BACKEND");

    plan(8);

    landlockd_policy_ir_init(&ir);
    memset(errbuf, 0, sizeof(errbuf));
    rc = load_capturing(argv[2], &ir, errbuf, sizeof(errbuf));
    ok(rc == 0 && ir.broker_addfd_count == 5,
       "Rust policy helper loads broker.addfd rules through the standard helper path");
    check_addfd_rule(&ir, 0, "open", "/tmp/landlockd-addfd-read", "read");
    check_addfd_rule(&ir, 1, "open_tree", "/tmp/landlockd-addfd-write",
                     "write");
    check_addfd_rule(&ir, 2, "scratch_open", "/tmp/landlockd-addfd-scratch",
                     "write");
    check_addfd_rule(&ir, 3, "fsopen", "/tmp/landlockd-addfd-fsopen", "read");
    check_addfd_rule(&ir, 4, "fsmount", "/tmp/landlockd-addfd-fsmount",
                     "write");
    landlockd_policy_ir_reset(&ir);

    landlockd_policy_ir_init(&ir);
    memset(errbuf, 0, sizeof(errbuf));
    rc = load_capturing(argv[3], &ir, errbuf, sizeof(errbuf));
    ok(rc == -1 && strstr(errbuf, argv[3]) != NULL,
       "Rust policy helper reports invalid policies through stderr");
    ok(ir.fs_layer_count == 0 && ir.fs_layers == NULL &&
           ir.net_enabled == 0 && ir.net_rules == NULL &&
           ir.broker_addfd_count == 0 && ir.broker_addfd_rules == NULL,
       "Rust policy helper leaves the destination IR empty on parse failure");
    landlockd_policy_ir_reset(&ir);

    done_testing();
}
