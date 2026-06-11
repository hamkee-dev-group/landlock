#!/usr/bin/env python3

import json
import sys


SUPPORTED_ACTIONS = ["open", "open_tree", "scratch_open", "fsopen", "fsmount"]


def load_addfd_schema(schema_path):
    with open(schema_path, "r", encoding="utf-8") as fp:
        schema = json.load(fp)
    return schema["$defs"]["broker"]["properties"]["addfd"]["items"]


def accepts(addfd_schema, entry):
    props = addfd_schema["properties"]
    required = addfd_schema["required"]
    if any(key not in entry for key in required):
        return False
    if set(entry) - set(props):
        return False
    if entry["action"] not in props["action"]["enum"]:
        return False
    if not isinstance(entry["target"], str) or entry["target"] == "":
        return False
    if props["target"].get("pattern") == "^/" and not entry["target"].startswith("/"):
        return False
    if "mode" in entry and entry["mode"] not in props["mode"]["enum"]:
        return False
    return True


def main():
    addfd_schema = load_addfd_schema(sys.argv[1])
    actions = addfd_schema["properties"]["action"]["enum"]
    assert actions == SUPPORTED_ACTIONS

    for action in SUPPORTED_ACTIONS:
        assert accepts(
            addfd_schema,
            {"action": action, "target": f"/tmp/landlockd-{action}", "mode": "read"},
        )

    assert not accepts(
        addfd_schema,
        {"action": "frobnicate", "target": "/tmp/landlockd-frobnicate", "mode": "read"},
    )


if __name__ == "__main__":
    main()
