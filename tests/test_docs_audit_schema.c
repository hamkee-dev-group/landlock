#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tap.h"

static char *read_text_file(const char *path)
{
    FILE *fp;
    long size;
    size_t nread;
    char *buf;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) < 0) {
        fclose(fp);
        return NULL;
    }
    size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) < 0) {
        fclose(fp);
        return NULL;
    }
    buf = calloc((size_t)size + 1, 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    nread = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    buf[nread] = '\0';
    return buf;
}

int main(int argc, char *argv[])
{
    static const char *const headings[] = {
        "## run.start",
        "## run.exit",
        "## run.signal",
        "## broker.open",
        "## broker.mkdir",
        "## broker.unlink",
        "## broker.rmdir",
        "## broker.rename",
        "## broker.symlink",
        "## broker.link",
        "## broker.fsopen",
        "## broker.fsconfig",
        "## broker.fsmount",
        "## broker.open_tree",
        "## broker.mount",
        "## broker.move_mount",
        "## broker.mount_setattr",
        "## broker.umount",
        "## mount.tmpfs",
        "## mount.proc",
        "## mount.bind",
        "## daemon.listen",
        "## daemon.request",
        "## daemon.peer",
        "## daemon.exit",
    };
    char *readme;
    char *docs;
    int i;
    int all_headings_present;

    if (argc < 3) {
        diag("usage: %s <README> <audit-schema>", argv[0]);
        return 1;
    }

    plan(3);

    readme = read_text_file(argv[1]);
    docs = read_text_file(argv[2]);
    ok(readme != NULL && docs != NULL, "README and audit schema docs are readable");
    ok(readme != NULL && strstr(readme, "docs/audit-schema.md") != NULL,
       "README links to the audit schema reference");

    all_headings_present = docs != NULL &&
                           strstr(docs, "## Common Fields") != NULL &&
                           strstr(docs, "`component`") != NULL &&
                           strstr(docs, "`timestamp`") != NULL;
    for (i = 0; all_headings_present &&
                i < (int)(sizeof(headings) / sizeof(headings[0]));
         i++) {
        all_headings_present = strstr(docs, headings[i]) != NULL;
    }
    ok(all_headings_present,
       "audit schema docs cover common fields and every emitted event heading");

    free(readme);
    free(docs);
    done_testing();
}
