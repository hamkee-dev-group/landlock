# landlockd

`landlockd` is a minimal Linux sandbox daemon and runner built around two kernel
mechanisms:

- **Landlock LSM** for filesystem and network restrictions
- **seccomp user notification** for a narrow broker path when a sandboxed process
  needs a declared exception

This is a small, auditable, kernel-native sandbox for developer workstations
and CI jobs: lighter than a full container runtime, more structured than ad hoc
wrapper scripts, and easier to reason about than a large setuid sandbox.

## Why this exists

`bubblewrap` and `firejail` are useful tools, but they solve a broader problem
than many CI and developer sandbox use cases need.

`landlockd` is trying to be narrower:

- **policy-first** instead of long shell command lines
- **kernel-enforced on the hot path**
- **brokered only for declared exceptions**
- **usable as either a one-shot runner or a daemon**
- **small enough to audit**

Audit event fields and coverage are documented in `docs/audit-schema.md`.

## What it can do

- enforce filesystem allowlists with stacked Landlock layers
- enforce network allowlists where the host Landlock ABI supports it
- deny selected syscalls with seccomp and a fixed errno
- broker explicit host-file opens through seccomp notify
- broker scratch-root create / rename / link / symlink / delete operations
- publish artifacts from declared scratch roots into declared export roots
- create per-run tmpfs mounts and static bind mounts
- broker runtime `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`,
  and constrained `mount_setattr` on declared targets
- pivot into a prepared rootfs with `runtime.root`

## What it is not

- not a full OCI/container runtime
- not a general-purpose mount graph engine yet
- not a distro-packaged product yet
- not a finished replacement for every `bubblewrap` or `firejail` workflow

## Build

Requirements:

- Linux
- a C toolchain
- Meson and Ninja
- optionally `cargo` for the Rust policy helper

Build and test:

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

Install:

```sh
meson install -C build
```

Optional build knobs:

- `meson -Dpolicy_helper=disabled` keeps a minimal in-process parser build
- `cargo` enables the optional installed Rust helper
- installed starter policies include `policies/ci-default.toml`,
  `policies/net-fetch.toml`, `policies/hermetic-build.toml`,
  `policies/prepared-root.toml`, and `policies/prepared-root-net.toml`

## Quick start

Lint a policy:

```sh
landlockd lint --policy-file policy.toml
```

Run a command directly:

```sh
landlockd run --policy-file policy.toml -- /usr/bin/curl https://example.com
```

Run through the daemon:

```sh
landlockd serve --socket /tmp/landlockd.sock
landlockd run --socket /tmp/landlockd.sock --policy-file policy.toml -- /usr/bin/curl https://example.com
landlockd status --socket /tmp/landlockd.sock
landlockd stop --socket /tmp/landlockd.sock
```

Run with systemd user socket activation:

```sh
systemctl --user enable --now landlockd.socket
landlockd run --socket "${XDG_RUNTIME_DIR}/landlockd.sock" --policy-file policy.toml -- /usr/bin/curl https://example.com
```

## Example policy

```toml
version = 1

[[fs_layer]]
handled_access_fs = ["execute", "read_file", "read_dir"]

  [[fs_layer.rule]]
  path = "/usr"
  allowed_access = ["execute", "read_file", "read_dir"]

  [[fs_layer.rule]]
  path = "/lib"
  allowed_access = ["execute", "read_file", "read_dir"]

[[fs_layer]]
handled_access_fs = ["read_file", "read_dir"]

  [[fs_layer.rule]]
  path = "/etc/ssl"
  allowed_access = ["read_file", "read_dir"]

[net]
handled_access_net = ["connect_tcp"]

  [[net.rule]]
  port = 443
  allowed_access = ["connect_tcp"]

[broker]
allow_read = ["/etc/resolv.conf"]
allow_write = ["/tmp/ci-artifact.log"]
scratch = ["/tmp/ci-scratch"]
export = ["/tmp/ci-export"]

[mount]
tmpfs = ["/tmp/ci-work"]
proc = ["/proc"]

[runtime]
root = "/srv/landlockd/rootfs"
cwd = "/workspace"

[seccomp]
deny = ["ptrace", "bpf", "perf_event_open"]
errno = 13
```

That policy gives the process a restricted rootfs view, a small filesystem and
network allowlist, a seccomp deny list, and a broker path for explicit read,
write, scratch, and export exceptions.

### Prepared Rootfs Example

Use `policies/prepared-root.toml` when another stage has already built the
rootfs under a host path such as `/run/jobs/J/root`:

```sh
landlockd run --policy-file policies/prepared-root.toml -- /usr/bin/<basename>
```

For `runtime.root` policies, the command path is evaluated inside the pivoted
rootfs, but every `fs_layer.rule.path` is still a host path under
`/run/jobs/J/root`. For example, `/usr/bin/<basename>` is the workload path
after pivot, while `/run/jobs/J/root/usr/bin` is the matching host path that
must appear in the policy. Use `policies/prepared-root-net.toml` for the same
layout plus explicit outbound `connect_tcp` rules for ports `80` and `443`.

## Performance

Local benchmark results are included here because a GitHub project page should
show real numbers, not only the existence of benchmark scripts.

Host used for these numbers:

- kernel: `Linux 6.12.74-amd64`
- `bubblewrap 0.11.0`
- `firejail 0.9.74`
- `hyperfine 1.19.0`

### Spawn latency (`/bin/true`)

| Tool | Mean |
|:--|--:|
| `landlockd-daemon` | `1.576 ms` |
| `landlockd-direct` | `2.476 ms` |
| `bubblewrap` | `4.283 ms` |
| `firejail` | `33.135 ms` |

### Broker RTT-style microbenchmarks

| Operation | Direct | Daemon |
|:--|--:|--:|
| brokered read open | `2.7 ms` | `1.7 ms` |
| brokered write open | `2.6 ms` | `1.8 ms` |
| brokered scratch create | `2.8 ms` | `1.8 ms` |

### End-to-end workloads

| Workload | `landlockd-daemon` | `bubblewrap` | `firejail` |
|:--|--:|--:|--:|
| `/bin/sh -c true` | `1.8 ms` | `5.1 ms` | `33.2 ms` |
| `python3 -c 'import json, ssl, pathlib'` | `40.7 ms` | `46.2 ms` | `55.4 ms` |
| tiny C compile | `36.8 ms` | `40.2 ms` | `48.6 ms` |

Notes:

- these are local measurements, not a universal guarantee
- the benchmark scripts live under `bench/`
- `bubblewrap` and `firejail` are reasonable end-to-end baselines
- only `landlockd` exposes the seccomp user-notify broker path, so broker RTT
  is not directly comparable across tools
- the mount round-trip benchmark is host-capability-dependent and was not
  available on this host

## Project layout

- `src/` — core daemon, CLI, policy loader, sandbox runtime, broker logic
- `include/` — public headers
- `policy/` — JSON Schema
- `policies/` — starter policies
- `systemd/` — user service and socket units
