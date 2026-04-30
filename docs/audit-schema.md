# Audit Schema

`landlockd` writes one JSON object per line to the diagnostic stream. The
encoder lives in `src/landlockd_audit.c::landlockd_audit_begin`,
`landlockd_audit_field_string`, `landlockd_audit_field_int`, and
`landlockd_audit_end`.

## Common Fields

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `component` | string | Always `"landlockd"`. | `src/landlockd_audit.c::landlockd_audit_begin` |
| `event` | string | Event name for the record type documented below. | `src/landlockd_audit.c::landlockd_audit_begin` |
| `timestamp` | string | UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` form. | `src/landlockd_audit.c::landlockd_audit_format_timestamp` |
| `job_id` | string | Optional correlation id copied from `LANDLOCKD_JOB_ID` when present. | `src/landlockd_audit.c::landlockd_audit_begin` |

`pid` semantics depend on the event family:

- `run.*` emits the supervised workload pid.
- `broker.*` emits the pid that triggered the seccomp notify request.
- `mount.*` emits the launcher pid performing static mount setup.
- `daemon.listen`, `daemon.request`, and `daemon.exit` emit the daemon pid.
- `daemon.peer` emits the connecting peer pid from socket credentials.

## run.start

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Child pid after fork, before the parent waits. | `src/landlockd_exec.c::landlockd_audit_run_start` |
| `policy_file` | string | Policy file path or daemon-provided label. | `src/landlockd_exec.c::landlockd_audit_run_start` |
| `argv0` | string | Executable path passed to the workload. | `src/landlockd_exec.c::landlockd_audit_run_start` |

## run.exit

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Workload pid. | `src/landlockd_exec.c::landlockd_audit_run_exit` |
| `status` | integer | Exit status from `WEXITSTATUS`. | `src/landlockd_exec.c::landlockd_audit_run_exit` |

## run.signal

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Workload pid. | `src/landlockd_exec.c::landlockd_audit_run_exit` |
| `signal` | integer | Terminating signal from `WTERMSIG`. | `src/landlockd_exec.c::landlockd_audit_run_exit` |

## broker.open

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_open` |
| `syscall` | string | Brokered syscall name such as `openat` or `openat2`. | `src/landlockd_exec.c::landlockd_audit_broker_open` |
| `scope` | string | Decision scope such as `exception` or `scratch`. | `src/landlockd_exec.c::landlockd_audit_broker_open` |
| `operation` | string | Open intent such as `read`, `write`, or `read_write`. | `src/landlockd_exec.c::landlockd_audit_broker_open` |
| `path` | string or null | Canonical path when resolution succeeded. | `src/landlockd_exec.c::landlockd_audit_broker_open` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_open` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_open` |

## broker.mkdir

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `operation` | string | Always `mkdir`. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `path` | string | Canonical or requested target path. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_path` |

## broker.unlink

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `operation` | string | Always `unlink`. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `path` | string | Canonical or requested target path. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_path` |

## broker.rmdir

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `operation` | string | Always `rmdir`. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `path` | string | Canonical or requested target path. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_path` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_path` |

## broker.rename

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `operation` | string | Always `rename`. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `old_path` | string | Source path for the rename. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `new_path` | string | Destination path for the rename. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |

## broker.symlink

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_symlink` |
| `operation` | string | Always `symlink`. | `src/landlockd_exec.c::landlockd_audit_broker_symlink` |
| `target` | string | Symlink target string. | `src/landlockd_exec.c::landlockd_audit_broker_symlink` |
| `path` | string | Symlink path created in scratch or export space. | `src/landlockd_exec.c::landlockd_audit_broker_symlink` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_symlink` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_symlink` |

## broker.link

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `operation` | string | Always `link`. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `old_path` | string | Existing source path. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `new_path` | string | New link path. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_paths` |

## broker.fsopen

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `fsopen`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Mount object name when known. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## broker.fsconfig

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `fsconfig`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Mount object name when known. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## broker.fsmount

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `fsmount`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Mount object name when known. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## broker.open_tree

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `open_tree`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Source path or canonical source tree. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## broker.mount

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `mount`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Mount target path. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## broker.move_mount

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `move_mount`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Destination attach path. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## broker.mount_setattr

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `mount_setattr`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Target path whose attributes are changed. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## broker.umount

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Requesting sandbox pid. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `operation` | string | Always `umount`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `path` | string or null | Canonical mount target path. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |
| `errno` | integer | Optional errno for denied or failed requests. | `src/landlockd_exec.c::landlockd_audit_broker_mount` |

## mount.tmpfs

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Launcher pid applying static mount setup. | `src/landlockd_exec.c::landlockd_audit_mount_event` |
| `path` | string | Target path for the tmpfs mount. | `src/landlockd_exec.c::landlockd_audit_mount_event` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_mount_event` |
| `errno` | integer | Optional errno for denied or failed mount setup. | `src/landlockd_exec.c::landlockd_audit_mount_event` |

## mount.proc

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Launcher pid applying static mount setup. | `src/landlockd_exec.c::landlockd_audit_mount_event` |
| `path` | string | Target path for the proc mount. | `src/landlockd_exec.c::landlockd_audit_mount_event` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_mount_event` |
| `errno` | integer | Optional errno for denied or failed mount setup. | `src/landlockd_exec.c::landlockd_audit_mount_event` |

## mount.bind

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Launcher pid applying static mount setup. | `src/landlockd_exec.c::landlockd_audit_bind_mount` |
| `source` | string | Source path on the host. | `src/landlockd_exec.c::landlockd_audit_bind_mount` |
| `target` | string | Bind target path in the runtime namespace. | `src/landlockd_exec.c::landlockd_audit_bind_mount` |
| `read_only` | integer | `1` for read-only remount, `0` otherwise. | `src/landlockd_exec.c::landlockd_audit_bind_mount` |
| `decision` | string | `allow`, `deny`, or `error`. | `src/landlockd_exec.c::landlockd_audit_bind_mount` |
| `errno` | integer | Optional errno for denied or failed mount setup. | `src/landlockd_exec.c::landlockd_audit_bind_mount` |

## daemon.listen

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Daemon pid. | `src/landlockd_daemon.c::landlockd_daemon_audit_listener` |
| `socket` | string | Socket path or systemd label. | `src/landlockd_daemon.c::landlockd_daemon_audit_listener` |
| `mode` | string | Listener mode, currently `socket` or `systemd`. | `src/landlockd_daemon.c::landlockd_daemon_audit_listener` |

## daemon.request

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Daemon pid handling the request. | `src/landlockd_daemon.c::landlockd_daemon_audit_request` |
| `command` | string | Protocol verb such as `run`, `stop`, or `status`. | `src/landlockd_daemon.c::landlockd_daemon_audit_request` |
| `policy_file` | string | Policy file when the request carries one. | `src/landlockd_daemon.c::landlockd_daemon_audit_request` |
| `argc` | integer | Argument count forwarded to the workload. | `src/landlockd_daemon.c::landlockd_daemon_audit_request` |

## daemon.peer

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `uid` | integer | Peer uid from Unix socket credentials. | `src/landlockd_daemon.c::landlockd_daemon_audit_peer` |
| `pid` | integer | Peer pid from Unix socket credentials. | `src/landlockd_daemon.c::landlockd_daemon_audit_peer` |
| `decision` | string | Authorization result such as `allow` or `deny`. | `src/landlockd_daemon.c::landlockd_daemon_audit_peer` |

## daemon.exit

| Key | JSON Type | Semantics | Source |
| --- | --- | --- | --- |
| `pid` | integer | Daemon pid. | `src/landlockd_daemon.c::landlockd_daemon_audit_listener` |
| `socket` | string | Socket path or systemd label. | `src/landlockd_daemon.c::landlockd_daemon_audit_listener` |

