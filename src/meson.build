policy_loader_helper_opt = get_option('policy_helper')
policy_loader_helper_enabled = policy_loader_helper_opt.enabled() or policy_loader_helper_opt.auto()
rust_policy_helper_opt = get_option('policy_helper_rust')
cargo = find_program('cargo', required : false)
rust_policy_helper_enabled = false
policy_loader_helper_path = join_paths(get_option('prefix'),
                                       get_option('bindir'),
                                       'landlockd-policy-helper')
policy_loader_rust_helper_path = join_paths(get_option('prefix'),
                                            get_option('bindir'),
                                            'landlockd-policy-helper-rs')
policy_system_dir = join_paths(get_option('prefix'),
                               get_option('datadir'),
                               'landlockd',
                               'policies')
policy_loader_c_args = [
  '-DLANDLOCKD_POLICY_HELPER_PATH="@0@"'.format(policy_loader_helper_path),
  '-DLANDLOCKD_POLICY_HELPER_RUST_PATH="@0@"'.format(policy_loader_rust_helper_path),
  '-DLANDLOCKD_POLICY_SHARE_DIR="@0@"'.format(policy_system_dir),
]

if not rust_policy_helper_opt.disabled()
  if cargo.found()
    rust_policy_helper_enabled = policy_loader_helper_enabled
  elif rust_policy_helper_opt.enabled()
    error('policy_helper_rust is enabled but cargo was not found')
  endif
endif

if policy_loader_helper_enabled
  policy_loader_c_args += [
    '-DLANDLOCKD_POLICY_LOADER_USE_HELPER=1',
  ]
endif

liblandlock_sources = files(
  'landlock.c',
  'landlock_fs_ruleset.c',
  'landlock_policy.c',
  'landlock_policy_ir.c',
  'policy_compiler.c',
  'policy_ir.c',
  'landlock_policy_loader.c',
  'landlock_policy_loader_in_process.c',
  'landlockd_preflight.c',
  'landlockd_preflight_seccomp.c',
  'landlockd_seccomp.c',
  'seccomp_notify_probe.c',
  'landlock_net_ruleset.c',
  'landlock_no_new_privs.c',
  'landlock_restrict_self_require_nnp.c',
  'landlock_sandbox.c',
  'landlock_sandbox_seccomp.c')

tomlc99_dep = dependency('tomlc99', fallback : ['tomlc99', 'tomlc99_dep'])

landlockd_cli_sources = files(
  'cli_parse.c',
  'landlockd_cli.c',
  'landlockd_runtime_stubs.c')

landlockd_runtime_sources = files(
  'landlockd_audit.c',
  'landlockd_exec.c',
  'landlockd_daemon.c')

landlockd_main_source = files(
  'landlockd_main.c')

liblandlock = static_library('landlock',
  liblandlock_sources,
  include_directories : inc,
  c_args : policy_loader_c_args,
  dependencies : tomlc99_dep,
  install : true)

landlock_dep = declare_dependency(
  link_with : liblandlock,
  dependencies : tomlc99_dep,
  include_directories : inc)

if policy_loader_helper_enabled
  landlockd_policy_helper_exe = executable('landlockd-policy-helper',
    files(
      'landlock_policy_ir.c',
      'landlock_policy_loader.c',
      'landlock_policy_loader_in_process.c',
      'landlock_no_new_privs.c',
      'landlockd_seccomp.c',
      'landlockd_policy_helper_main.c'),
    include_directories : [inc, src_inc],
    c_args : policy_loader_c_args,
    dependencies : tomlc99_dep,
    install : true)
endif

if rust_policy_helper_enabled
  rust_policy_helper_builder = find_program(
    meson.project_source_root() / 'tools' / 'build-rust-policy-helper.sh')
  rust_policy_helper_input = files(
    '..' / 'tools' / 'landlockd-policy-helper-rs' / 'Cargo.toml',
    '..' / 'tools' / 'landlockd-policy-helper-rs' / 'Cargo.lock',
    '..' / 'tools' / 'landlockd-policy-helper-rs' / 'src' / 'main.rs')
  landlockd_policy_helper_rust_exe = custom_target('landlockd-policy-helper-rs',
    input : rust_policy_helper_input,
    output : 'landlockd-policy-helper-rs',
    command : [rust_policy_helper_builder,
               cargo,
               meson.project_source_root() / 'tools' / 'landlockd-policy-helper-rs',
               '@OUTPUT@'],
    build_by_default : true,
    install : true,
    install_dir : get_option('bindir'))
endif

landlockd_exe = executable('landlockd',
  landlockd_cli_sources + landlockd_runtime_sources + landlockd_main_source,
  include_directories : [inc, src_inc],
  c_args : policy_loader_c_args,
  dependencies : tomlc99_dep,
  link_with : liblandlock,
  install : true)
