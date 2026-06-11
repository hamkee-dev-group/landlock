use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process;

const LANDLOCKD_POLICY_WIRE_MAGIC: u32 = 0x4c50_4c44;
const LANDLOCKD_POLICY_WIRE_VERSION: u32 = 15;
const DEFAULT_SECCOMP_ERRNO: u16 = 1;

const ACCESS_EXECUTE: u64 = 1u64 << 0;
const ACCESS_WRITE_FILE: u64 = 1u64 << 1;
const ACCESS_READ_FILE: u64 = 1u64 << 2;
const ACCESS_READ_DIR: u64 = 1u64 << 3;
const ACCESS_REMOVE_DIR: u64 = 1u64 << 4;
const ACCESS_REMOVE_FILE: u64 = 1u64 << 5;
const ACCESS_MAKE_CHAR: u64 = 1u64 << 6;
const ACCESS_MAKE_DIR: u64 = 1u64 << 7;
const ACCESS_MAKE_REG: u64 = 1u64 << 8;
const ACCESS_MAKE_SOCK: u64 = 1u64 << 9;
const ACCESS_MAKE_FIFO: u64 = 1u64 << 10;
const ACCESS_MAKE_BLOCK: u64 = 1u64 << 11;
const ACCESS_MAKE_SYM: u64 = 1u64 << 12;
const ACCESS_REFER: u64 = 1u64 << 13;
const ACCESS_TRUNCATE: u64 = 1u64 << 14;
const ACCESS_IOCTL_DEV: u64 = 1u64 << 15;
const ACCESS_BIND_TCP: u64 = 1u64 << 0;
const ACCESS_CONNECT_TCP: u64 = 1u64 << 1;
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
const BROKER_ADDFD_ACTIONS: [&str; 5] = [
    "open",
    "open_tree",
    "scratch_open",
    "fsopen",
    "fsmount",
];

#[derive(Default)]
struct PolicyIr {
    fs_layers: Vec<FsLayerIr>,
    net_enabled: bool,
    net_handled_access: u64,
    net_rules: Vec<NetRuleIr>,
    broker_open_read: Vec<String>,
    broker_open_write: Vec<String>,
    broker_scratch: Vec<String>,
    broker_export: Vec<String>,
    broker_mount_tmpfs: Vec<String>,
    broker_mount_bind: Vec<BindMountIr>,
    broker_mount_object: Vec<MountObjectIr>,
    broker_addfd: Vec<AddfdRuleIr>,
    mount_tmpfs: Vec<String>,
    mount_bind: Vec<BindMountIr>,
    mount_proc: Vec<String>,
    runtime_root: Option<String>,
    runtime_cwd: Option<String>,
    seccomp_enabled: bool,
    seccomp_errno: u16,
    seccomp_deny: Vec<i32>,
}

struct FsLayerIr {
    handled_access: u64,
    rules: Vec<FsRuleIr>,
}

struct FsRuleIr {
    path: String,
    allowed_access: u64,
}

struct NetRuleIr {
    port: u16,
    allowed_access: u64,
}

struct BindMountIr {
    source: String,
    target: String,
    read_only: bool,
}

struct MountObjectIr {
    name: String,
    fs_type: String,
    attach: Vec<String>,
    attrs: u64,
}

struct AddfdRuleIr {
    action: String,
    target: String,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDoc {
    version: u32,
    #[serde(default)]
    fs_layer: Vec<FsLayerDoc>,
    net: Option<NetDoc>,
    broker: Option<BrokerDoc>,
    mount: Option<MountDoc>,
    runtime: Option<RuntimeDoc>,
    seccomp: Option<SeccompDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FsLayerDoc {
    handled_access_fs: Vec<String>,
    #[serde(default)]
    rule: Vec<FsRuleDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FsRuleDoc {
    path: String,
    allowed_access: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetDoc {
    handled_access_net: Vec<String>,
    #[serde(default)]
    rule: Vec<NetRuleDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetRuleDoc {
    port: i64,
    allowed_access: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerDoc {
    allow_read: Option<Vec<String>>,
    allow_write: Option<Vec<String>>,
    scratch: Option<Vec<String>>,
    export: Option<Vec<String>>,
    mount_tmpfs: Option<Vec<String>>,
    mount_bind: Option<Vec<BindMountDoc>>,
    mount_object: Option<Vec<MountObjectDoc>>,
    addfd: Option<Vec<AddfdDoc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddfdDoc {
    action: String,
    target: String,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MountDoc {
    tmpfs: Option<Vec<String>>,
    bind: Option<Vec<BindMountDoc>>,
    proc: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindMountDoc {
    source: String,
    target: String,
    read_only: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MountObjectDoc {
    name: String,
    fs_type: String,
    attach: Vec<String>,
    attrs: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDoc {
    root: Option<String>,
    cwd: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeccompDoc {
    deny: Vec<String>,
    errno: Option<i64>,
}

fn report(file_path: &str, msg: &str) {
    eprintln!("landlockd: policy {}: {}", file_path, msg);
}

fn require_non_empty(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{}: expected a non-empty string", field))
    } else {
        Ok(())
    }
}

fn require_absolute(field: &str, value: &str) -> Result<(), String> {
    require_non_empty(field, value)?;
    if !value.starts_with('/') {
        return Err(format!("{}: expected an absolute path", field));
    }
    Ok(())
}

fn parse_access_list(items: &[String], field: &str, table: &[(&str, u64)]) -> Result<u64, String> {
    if items.is_empty() {
        return Err(format!("{}: must contain at least one entry", field));
    }

    let mut mask = 0u64;
    for (index, item) in items.iter().enumerate() {
        if item.is_empty() {
            return Err(format!("{}[{}]: expected a non-empty string", field, index));
        }
        let bit = table
            .iter()
            .find_map(|(name, bit)| (*name == item).then_some(*bit))
            .ok_or_else(|| format!("{}[{}]: unknown access \"{}\"", field, index, item))?;
        mask |= bit;
    }
    Ok(mask)
}

fn parse_path_list(items: Option<Vec<String>>, field: &str, absolute: bool) -> Result<Vec<String>, String> {
    let Some(items) = items else {
        return Ok(Vec::new());
    };
    if items.is_empty() {
        return Err(format!("{}: must contain at least one entry", field));
    }
    for (index, item) in items.iter().enumerate() {
        let item_field = format!("{}[{}]", field, index);
        if absolute {
            require_absolute(&item_field, item)?;
        } else {
            require_non_empty(&item_field, item)?;
        }
    }
    Ok(items)
}

fn parse_bind_list(items: Option<Vec<BindMountDoc>>, field: &str) -> Result<Vec<BindMountIr>, String> {
    let Some(items) = items else {
        return Ok(Vec::new());
    };
    if items.is_empty() {
        return Err(format!("{}: must contain at least one entry", field));
    }

    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        require_absolute(&format!("{}[{}].source", field, index), &item.source)?;
        require_absolute(&format!("{}[{}].target", field, index), &item.target)?;
        out.push(BindMountIr {
            source: item.source,
            target: item.target,
            read_only: item.read_only.unwrap_or(true),
        });
    }
    Ok(out)
}

fn parse_addfd_list(
    items: Option<Vec<AddfdDoc>>,
    field: &str,
) -> Result<Vec<AddfdRuleIr>, String> {
    let Some(items) = items else {
        return Ok(Vec::new());
    };
    if items.is_empty() {
        return Err(format!("{}: must contain at least one entry", field));
    }
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        require_non_empty(&format!("{}[{}].action", field, index), &item.action)?;
        if !BROKER_ADDFD_ACTIONS.contains(&item.action.as_str()) {
            return Err(format!(
                "{}[{}].action: unknown action \"{}\"",
                field, index, item.action
            ));
        }
        require_absolute(&format!("{}[{}].target", field, index), &item.target)?;
        if let Some(mode) = item.mode.as_deref() {
            require_non_empty(&format!("{}[{}].mode", field, index), mode)?;
            if mode != "read" && mode != "write" {
                return Err(format!(
                    "{}[{}].mode: unknown mode \"{}\"",
                    field, index, mode
                ));
            }
        }
        out.push(AddfdRuleIr {
            action: item.action,
            target: item.target,
            mode: item.mode,
        });
    }
    Ok(out)
}

fn parse_mount_attrs(items: &[String], field: &str) -> Result<u64, String> {
    let table = [
        ("readonly", MOUNT_ATTR_RDONLY),
        ("nosuid", MOUNT_ATTR_NOSUID),
        ("nodev", MOUNT_ATTR_NODEV),
        ("noexec", MOUNT_ATTR_NOEXEC),
    ];
    parse_access_list(items, field, &table)
}

fn parse_mount_object_list(
    items: Option<Vec<MountObjectDoc>>,
    field: &str,
) -> Result<Vec<MountObjectIr>, String> {
    let Some(items) = items else {
        return Ok(Vec::new());
    };
    if items.is_empty() {
        return Err(format!("{}: must contain at least one entry", field));
    }

    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        require_non_empty(&format!("{}[{}].name", field, index), &item.name)?;
        if item.name.contains('/') {
            return Err(format!("{}[{}].name: must not contain '/'", field, index));
        }
        require_non_empty(&format!("{}[{}].fs_type", field, index), &item.fs_type)?;
        if item.fs_type != "tmpfs" && item.fs_type != "proc" {
            return Err(format!(
                "{}[{}].fs_type: expected one of tmpfs or proc",
                field, index
            ));
        }
        if item.attach.is_empty() {
            return Err(format!("{}[{}].attach: must contain at least one entry", field, index));
        }
        for (attach_index, path) in item.attach.iter().enumerate() {
            require_absolute(&format!("{}[{}].attach[{}]", field, index, attach_index), path)?;
        }
        let attrs = match item.attrs {
            Some(attrs) => parse_mount_attrs(&attrs, &format!("{}[{}].attrs", field, index))?,
            None => 0,
        };
        out.push(MountObjectIr {
            name: item.name,
            fs_type: item.fs_type,
            attach: item.attach,
            attrs,
        });
    }
    Ok(out)
}

fn syscall_by_name(name: &str) -> Option<i32> {
    match name {
        "getpid" => Some(libc::SYS_getpid as i32),
        "getppid" => Some(libc::SYS_getppid as i32),
        "openat" => Some(libc::SYS_openat as i32),
        "openat2" => Some(libc::SYS_openat2 as i32),
        "mkdirat" => Some(libc::SYS_mkdirat as i32),
        "unlinkat" => Some(libc::SYS_unlinkat as i32),
        "renameat2" => Some(libc::SYS_renameat2 as i32),
        "symlinkat" => Some(libc::SYS_symlinkat as i32),
        "linkat" => Some(libc::SYS_linkat as i32),
        "socket" => Some(libc::SYS_socket as i32),
        "connect" => Some(libc::SYS_connect as i32),
        "mount" => Some(libc::SYS_mount as i32),
        "umount2" => Some(libc::SYS_umount2 as i32),
        "pivot_root" => Some(libc::SYS_pivot_root as i32),
        "open_tree" => Some(libc::SYS_open_tree as i32),
        "move_mount" => Some(libc::SYS_move_mount as i32),
        "fsopen" => Some(libc::SYS_fsopen as i32),
        "fsconfig" => Some(libc::SYS_fsconfig as i32),
        "fsmount" => Some(libc::SYS_fsmount as i32),
        "mount_setattr" => Some(libc::SYS_mount_setattr as i32),
        "unshare" => Some(libc::SYS_unshare as i32),
        "setns" => Some(libc::SYS_setns as i32),
        "clone3" => Some(libc::SYS_clone3 as i32),
        "ptrace" => Some(libc::SYS_ptrace as i32),
        "bpf" => Some(libc::SYS_bpf as i32),
        "perf_event_open" => Some(libc::SYS_perf_event_open as i32),
        "kexec_load" => Some(libc::SYS_kexec_load as i32),
        "init_module" => Some(libc::SYS_init_module as i32),
        "finit_module" => Some(libc::SYS_finit_module as i32),
        "delete_module" => Some(libc::SYS_delete_module as i32),
        "open_by_handle_at" => Some(libc::SYS_open_by_handle_at as i32),
        "swapon" => Some(libc::SYS_swapon as i32),
        "swapoff" => Some(libc::SYS_swapoff as i32),
        "reboot" => Some(libc::SYS_reboot as i32),
        _ => None,
    }
}

fn build_ir(doc: PolicyDoc) -> Result<PolicyIr, String> {
    let fs_table = [
        ("execute", ACCESS_EXECUTE),
        ("write_file", ACCESS_WRITE_FILE),
        ("read_file", ACCESS_READ_FILE),
        ("read_dir", ACCESS_READ_DIR),
        ("remove_dir", ACCESS_REMOVE_DIR),
        ("remove_file", ACCESS_REMOVE_FILE),
        ("make_char", ACCESS_MAKE_CHAR),
        ("make_dir", ACCESS_MAKE_DIR),
        ("make_reg", ACCESS_MAKE_REG),
        ("make_sock", ACCESS_MAKE_SOCK),
        ("make_fifo", ACCESS_MAKE_FIFO),
        ("make_block", ACCESS_MAKE_BLOCK),
        ("make_sym", ACCESS_MAKE_SYM),
        ("refer", ACCESS_REFER),
        ("truncate", ACCESS_TRUNCATE),
        ("ioctl_dev", ACCESS_IOCTL_DEV),
    ];
    let net_table = [
        ("bind_tcp", ACCESS_BIND_TCP),
        ("connect_tcp", ACCESS_CONNECT_TCP),
    ];
    let mut ir = PolicyIr {
        seccomp_errno: DEFAULT_SECCOMP_ERRNO,
        ..PolicyIr::default()
    };

    if doc.version != 1 {
        return Err(format!("version: expected 1, got {}", doc.version));
    }

    for (layer_index, layer) in doc.fs_layer.into_iter().enumerate() {
        let handled_access = parse_access_list(
            &layer.handled_access_fs,
            &format!("fs_layer[{}].handled_access_fs", layer_index),
            &fs_table,
        )?;
        let mut rules = Vec::with_capacity(layer.rule.len());
        for (rule_index, rule) in layer.rule.into_iter().enumerate() {
            require_non_empty(&format!("fs_layer[{}].rule[{}].path", layer_index, rule_index), &rule.path)?;
            let allowed_access = parse_access_list(
                &rule.allowed_access,
                &format!("fs_layer[{}].rule[{}].allowed_access", layer_index, rule_index),
                &fs_table,
            )?;
            rules.push(FsRuleIr {
                path: rule.path,
                allowed_access,
            });
        }
        ir.fs_layers.push(FsLayerIr {
            handled_access,
            rules,
        });
    }

    if let Some(net) = doc.net {
        ir.net_enabled = true;
        ir.net_handled_access = parse_access_list(&net.handled_access_net, "net.handled_access_net", &net_table)?;
        for (rule_index, rule) in net.rule.into_iter().enumerate() {
            if !(0..=65535).contains(&rule.port) {
                return Err(format!(
                    "net.rule[{}].port: value {} out of range [0..65535]",
                    rule_index, rule.port
                ));
            }
            let allowed_access = parse_access_list(
                &rule.allowed_access,
                &format!("net.rule[{}].allowed_access", rule_index),
                &net_table,
            )?;
            ir.net_rules.push(NetRuleIr {
                port: rule.port as u16,
                allowed_access,
            });
        }
    }

    if let Some(broker) = doc.broker {
        ir.broker_open_read = parse_path_list(broker.allow_read, "broker.allow_read", false)?;
        ir.broker_open_write = parse_path_list(broker.allow_write, "broker.allow_write", false)?;
        ir.broker_scratch = parse_path_list(broker.scratch, "broker.scratch", false)?;
        ir.broker_export = parse_path_list(broker.export, "broker.export", false)?;
        ir.broker_mount_tmpfs = parse_path_list(broker.mount_tmpfs, "broker.mount_tmpfs", false)?;
        ir.broker_mount_bind = parse_bind_list(broker.mount_bind, "broker.mount_bind")?;
        ir.broker_mount_object =
            parse_mount_object_list(broker.mount_object, "broker.mount_object")?;
        ir.broker_addfd = parse_addfd_list(broker.addfd, "broker.addfd")?;
    }

    if let Some(mount) = doc.mount {
        ir.mount_tmpfs = parse_path_list(mount.tmpfs, "mount.tmpfs", true)?;
        ir.mount_bind = parse_bind_list(mount.bind, "mount.bind")?;
        ir.mount_proc = parse_path_list(mount.proc, "mount.proc", true)?;
        if ir.mount_tmpfs.is_empty() && ir.mount_bind.is_empty() && ir.mount_proc.is_empty() {
            return Err("mount: expected at least one of mount.tmpfs, mount.bind, or mount.proc".to_string());
        }
    }

    if let Some(runtime) = doc.runtime {
        if let Some(root) = runtime.root {
            require_absolute("runtime.root", &root)?;
            ir.runtime_root = Some(root);
        }
        if let Some(cwd) = runtime.cwd {
            require_absolute("runtime.cwd", &cwd)?;
            ir.runtime_cwd = Some(cwd);
        }
        if ir.runtime_root.is_none() && ir.runtime_cwd.is_none() {
            return Err("runtime: expected at least one of runtime.root or runtime.cwd".to_string());
        }
    }

    if let Some(seccomp) = doc.seccomp {
        ir.seccomp_enabled = true;
        if let Some(errno_ret) = seccomp.errno {
            if !(1..=4095).contains(&errno_ret) {
                return Err(format!(
                    "seccomp.errno: value {} out of range [1..4095]",
                    errno_ret
                ));
            }
            ir.seccomp_errno = errno_ret as u16;
        }
        if seccomp.deny.is_empty() {
            return Err("seccomp.deny: must contain at least one entry".to_string());
        }
        for (index, name) in seccomp.deny.iter().enumerate() {
            if name.is_empty() {
                return Err(format!(
                    "seccomp.deny[{}]: expected a non-empty string",
                    index
                ));
            }
            let syscall_nr = syscall_by_name(name)
                .ok_or_else(|| format!("seccomp.deny[{}]: unknown syscall \"{}\"", index, name))?;
            ir.seccomp_deny.push(syscall_nr);
        }
    }

    Ok(ir)
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_ne_bytes())
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_ne_bytes())
}

fn write_len_prefixed_string<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    let len = u32::try_from(value.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "string too large"))?;
    write_u32(writer, len)?;
    writer.write_all(value.as_bytes())
}

fn write_ir<W: Write>(writer: &mut W, ir: &PolicyIr) -> io::Result<()> {
    write_u32(writer, LANDLOCKD_POLICY_WIRE_MAGIC)?;
    write_u32(writer, LANDLOCKD_POLICY_WIRE_VERSION)?;
    write_u32(writer, ir.fs_layers.len() as u32)?;
    write_u32(writer, ir.net_enabled as u32)?;
    write_u64(writer, ir.net_handled_access)?;
    write_u32(writer, ir.net_rules.len() as u32)?;
    write_u32(writer, ir.broker_open_read.len() as u32)?;
    write_u32(writer, ir.broker_open_write.len() as u32)?;
    write_u32(writer, ir.broker_scratch.len() as u32)?;
    write_u32(writer, ir.broker_export.len() as u32)?;
    write_u32(writer, ir.broker_mount_tmpfs.len() as u32)?;
    write_u32(writer, ir.broker_mount_bind.len() as u32)?;
    write_u32(writer, ir.broker_mount_object.len() as u32)?;
    write_u32(writer, ir.broker_addfd.len() as u32)?;
    write_u32(writer, ir.mount_tmpfs.len() as u32)?;
    write_u32(writer, ir.mount_bind.len() as u32)?;
    write_u32(writer, ir.mount_proc.len() as u32)?;
    write_u32(
        writer,
        ir.runtime_root
            .as_ref()
            .map(|value| value.len() as u32)
            .unwrap_or(0),
    )?;
    write_u32(
        writer,
        ir.runtime_cwd
            .as_ref()
            .map(|value| value.len() as u32)
            .unwrap_or(0),
    )?;
    write_u32(writer, ir.seccomp_enabled as u32)?;
    write_u32(writer, ir.seccomp_errno as u32)?;
    write_u32(writer, ir.seccomp_deny.len() as u32)?;

    for layer in &ir.fs_layers {
        write_u64(writer, layer.handled_access)?;
        write_u32(writer, layer.rules.len() as u32)?;
        for rule in &layer.rules {
            write_u64(writer, rule.allowed_access)?;
            write_len_prefixed_string(writer, &rule.path)?;
        }
    }

    for rule in &ir.net_rules {
        write_u32(writer, rule.port as u32)?;
        write_u64(writer, rule.allowed_access)?;
    }

    for path in &ir.broker_open_read {
        write_len_prefixed_string(writer, path)?;
    }
    for path in &ir.broker_open_write {
        write_len_prefixed_string(writer, path)?;
    }
    for path in &ir.broker_scratch {
        write_len_prefixed_string(writer, path)?;
    }
    for path in &ir.broker_export {
        write_len_prefixed_string(writer, path)?;
    }
    for path in &ir.broker_mount_tmpfs {
        write_len_prefixed_string(writer, path)?;
    }
    for bind in &ir.broker_mount_bind {
        write_len_prefixed_string(writer, &bind.source)?;
        write_len_prefixed_string(writer, &bind.target)?;
        write_u32(writer, bind.read_only as u32)?;
    }
    for obj in &ir.broker_mount_object {
        write_len_prefixed_string(writer, &obj.name)?;
        write_len_prefixed_string(writer, &obj.fs_type)?;
        write_u32(writer, obj.attach.len() as u32)?;
        write_u32(writer, (obj.attrs & 0xffff_ffff) as u32)?;
        write_u32(writer, (obj.attrs >> 32) as u32)?;
        for path in &obj.attach {
            write_len_prefixed_string(writer, path)?;
        }
    }
    for entry in &ir.broker_addfd {
        write_len_prefixed_string(writer, &entry.action)?;
        write_len_prefixed_string(writer, &entry.target)?;
        match &entry.mode {
            Some(mode) => write_len_prefixed_string(writer, mode)?,
            None => write_u32(writer, 0)?,
        }
    }
    for path in &ir.mount_tmpfs {
        write_len_prefixed_string(writer, path)?;
    }
    for bind in &ir.mount_bind {
        write_len_prefixed_string(writer, &bind.source)?;
        write_len_prefixed_string(writer, &bind.target)?;
        write_u32(writer, bind.read_only as u32)?;
    }
    for path in &ir.mount_proc {
        write_len_prefixed_string(writer, path)?;
    }
    if let Some(path) = &ir.runtime_root {
        writer.write_all(path.as_bytes())?;
    }
    if let Some(path) = &ir.runtime_cwd {
        writer.write_all(path.as_bytes())?;
    }
    for syscall_nr in &ir.seccomp_deny {
        write_u32(writer, *syscall_nr as u32)?;
    }

    Ok(())
}

fn main() {
    let mut args = env::args();
    let _program = args.next();
    let Some(file_path) = args.next() else {
        eprintln!("usage: landlockd-policy-helper-rs <policy.toml>");
        process::exit(1);
    };
    if args.next().is_some() {
        eprintln!("usage: landlockd-policy-helper-rs <policy.toml>");
        process::exit(1);
    }

    let content = match fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(err) => {
            report(&file_path, &format!("open failed: {}", err));
            process::exit(1);
        }
    };

    let doc: PolicyDoc = match toml::from_str(&content) {
        Ok(doc) => doc,
        Err(err) => {
            report(&file_path, &err.to_string());
            process::exit(1);
        }
    };

    let ir = match build_ir(doc) {
        Ok(ir) => ir,
        Err(err) => {
            report(&file_path, &err);
            process::exit(1);
        }
    };

    let mut stdout = io::stdout().lock();
    if let Err(err) = write_ir(&mut stdout, &ir) {
        report(&file_path, &format!("wire encode failed: {}", err));
        process::exit(1);
    }
}
