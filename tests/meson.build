libtap_dep = dependency('libtap', fallback : ['libtap', 'libtap_dep'])

landlock_test_sources = files(
  'test_abi_version.c',
  'test_landlock_create_ruleset.c',
  'test_landlock_create_ruleset_for_abi.c',
  'test_add_rule.c',
  'test_landlock_restrict_self.c',
  'test_create_fs_ruleset.c',
  'test_create_net_ruleset.c')

test_probe_abi_source = files(
  'test_probe_abi.c')

test_seccomp_probe_user_notif_source = files(
  'test_seccomp_probe_user_notif.c')

test_seccomp_notify_probe_source = files(
  'test_seccomp_notify_probe.c')

test_add_rule_fs_delegate_source = files(
  'test_add_rule_fs_delegate.c')

test_add_rule_fs_empty_access_source = files(
  'test_add_rule_fs_empty_access.c')

test_add_net_rule_contract_source = files(
  'test_add_net_rule_contract.c')

test_add_rule_fs_parent_fd_zero_source = files(
  'test_add_rule_fs_parent_fd_zero.c')

test_add_rule_fs_high_bits_source = files(
  'test_add_rule_fs_high_bits.c')

test_add_rule_fs_eacces_source = files(
  'test_add_rule_fs_eacces.c')

test_add_rule_fs_enomem_source = files(
  'test_add_rule_fs_enomem.c')

test_add_fs_rule_live_source = files(
  'test_add_fs_rule_live.c')

test_create_fs_ruleset_live_source = files(
  'test_create_fs_ruleset_live.c')

test_create_net_ruleset_live_source = files(
  'test_create_net_ruleset_live.c')

test_restrict_self_with_no_new_privs_source = files(
  'test_restrict_self_with_no_new_privs.c')

test_set_no_new_privs_source = files(
  'test_set_no_new_privs.c')

test_restrict_self_invalid_flags_source = files(
  'test_restrict_self_invalid_flags.c')

test_restrict_self_require_nnp_source = files(
  'test_restrict_self_require_nnp.c')

test_restrict_self_warn_e2big_source = files(
  'test_restrict_self_warn_e2big.c')

test_cli_parse_source = files(
  'test_cli_parse.c')

test_cli_policy_parse_source = files(
  'test_cli_policy_parse.c')

test_cli_named_policy_source = files(
  'test_cli_named_policy.c')

test_cli_build_fs_ruleset_source = files(
  'test_cli_build_fs_ruleset.c')

test_cli_smoke_source = files(
  'test_cli_smoke.c')

test_docs_audit_schema_source = files(
  'test_docs_audit_schema.c')

test_cli_exec_live_source = files(
  'test_cli_exec_live.c')

test_cli_e2e_source = files(
  'test_cli_e2e.c')

test_cli_ir_deterministic_source = files(
  'test_cli_ir_deterministic.c')

test_cli_dry_run_source = files(
  'test_cli_dry_run.c')

test_cli_dry_run_stable_source = files(
  'test_cli_dry_run_stable.c')

test_cli_dry_run_abi_source = files(
  'test_cli_dry_run_abi.c')

test_cli_dry_run_net_unsupported_source = files(
  'test_cli_dry_run_net_unsupported.c')

test_cli_preflight_negatives_source = files(
  'test_cli_preflight_negatives.c')

test_cli_preflight_diag_source = files(
  'test_cli_preflight_diag.c')

test_cli_launch_status_source = files(
  'test_cli_launch_status.c')

test_cli_notify_supervise_live_source = files(
  'test_cli_notify_supervise_live.c')

test_cli_notify_fd_helper_source = files(
  'test_cli_notify_fd_helper.c')

test_cli_broker_live_source = files(
  'test_cli_broker_live.c')

test_cli_broker_mount_live_source = files(
  'test_cli_broker_mount_live.c')

test_cli_broker_bind_live_source = files(
  'test_cli_broker_bind_live.c')

test_cli_broker_move_mount_live_source = files(
  'test_cli_broker_move_mount_live.c')

test_cli_broker_mount_fd_live_source = files(
  'test_cli_broker_mount_fd_live.c')

test_cli_broker_mount_object_live_source = files(
  'test_cli_broker_mount_object_live.c')

test_cli_hardening_live_source = files(
  'test_cli_hardening_live.c')

test_cli_audit_live_source = files(
  'test_cli_audit_live.c')

test_cli_broker_open_helper_source = files(
  'test_cli_broker_open_helper.c')

test_cli_seccomp_helper_source = files(
  'test_cli_seccomp_helper.c')

test_cli_seccomp_live_source = files(
  'test_cli_seccomp_live.c')

test_cli_tmpfs_live_source = files(
  'test_cli_tmpfs_live.c')

test_cli_mount_hardening_live_source = files(
  'test_cli_mount_hardening_live.c')

test_cli_bind_mount_live_source = files(
  'test_cli_bind_mount_live.c')

test_cli_root_pivot_live_source = files(
  'test_cli_root_pivot_live.c')

test_cli_daemon_socket_activation_live_source = files(
  'test_cli_daemon_socket_activation_live.c')

test_cli_daemon_status_live_source = files(
  'test_cli_daemon_status_live.c')

test_cli_kernel_unsupported_source = files(
  'test_cli_kernel_unsupported.c')

test_cli_notify_preflight_diag_source = files(
  'test_cli_notify_preflight_diag.c')

test_cli_notify_preflight_einval_source = files(
  'test_cli_notify_preflight_einval.c')

test_cli_signal_live_source = files(
  'test_cli_signal_live.c')

test_cli_prepared_root_lint_source = files(
  'test_cli_prepared_root_lint.c')

test_preflight_source = files(
  'test_preflight.c')

test_preflight_seccomp_source = files(
  'test_preflight_seccomp.c')

test_landlock_policy_source = files(
  'test_landlock_policy.c')

test_policy_ir_source = files(
  'test_policy_ir.c')

test_policy_compile_source = files(
  'test_policy_compile.c')

test_policy_compiler_source = files(
  'test_policy_compiler.c')

test_policy_compiler_exceptions_source = files(
  'test_policy_compiler_exceptions.c')

test_seccomp_plan_source = files(
  'test_seccomp_plan.c')

test_seccomp_hardening_source = files(
  'test_seccomp_hardening.c')

test_seccomp_install_failclosed_source = files(
  'test_seccomp_install_failclosed.c')

test_seccomp_notify_live_source = files(
  'test_seccomp_notify_live.c')

test_apply_sandbox_with_seccomp_source = files(
  'test_apply_sandbox_with_seccomp.c')

test_policy_loader_source = files(
  'test_policy_loader.c')

test_policy_loader_mode_source = files(
  'test_policy_loader_mode.c')

test_policy_loader_rust_helper_source = files(
  'test_policy_loader_rust_helper.c')

test_cli_policy_helper_exec_failure_source = files(
  'test_cli_policy_helper_exec_failure.c')

test_cli_policy_file_failclosed_source = files(
  'test_cli_policy_file_failclosed.c')

test_cli_policy_run_net_unsupported_source = files(
  'test_cli_policy_run_net_unsupported.c')

test_cli_policy_run_fs_only_source = files(
  'test_cli_policy_run_fs_only.c')

test_cli_policy_file_run_fs_only_source = files(
  'test_cli_policy_file_run_fs_only.c')

lint_test_sources = landlock_test_sources + test_probe_abi_source + test_seccomp_probe_user_notif_source + test_seccomp_notify_probe_source + test_add_rule_fs_delegate_source + test_add_rule_fs_empty_access_source + test_add_net_rule_contract_source + test_add_rule_fs_parent_fd_zero_source + test_add_rule_fs_high_bits_source + test_add_rule_fs_eacces_source + test_add_rule_fs_enomem_source + test_add_fs_rule_live_source + test_create_fs_ruleset_live_source + test_create_net_ruleset_live_source + test_restrict_self_with_no_new_privs_source + test_set_no_new_privs_source + test_restrict_self_invalid_flags_source + test_restrict_self_require_nnp_source + test_restrict_self_warn_e2big_source + test_cli_parse_source + test_cli_policy_parse_source + test_cli_named_policy_source + test_cli_build_fs_ruleset_source + test_cli_smoke_source + test_docs_audit_schema_source + test_cli_exec_live_source + test_cli_e2e_source + test_cli_ir_deterministic_source + test_cli_dry_run_source + test_cli_dry_run_stable_source + test_cli_dry_run_abi_source + test_cli_dry_run_net_unsupported_source + test_cli_preflight_negatives_source + test_cli_preflight_diag_source + test_cli_launch_status_source + test_cli_broker_live_source + test_cli_broker_mount_live_source + test_cli_broker_bind_live_source + test_cli_broker_move_mount_live_source + test_cli_broker_mount_fd_live_source + test_cli_broker_mount_object_live_source + test_cli_hardening_live_source + test_cli_audit_live_source + test_cli_seccomp_live_source + test_cli_tmpfs_live_source + test_cli_mount_hardening_live_source + test_cli_bind_mount_live_source + test_cli_root_pivot_live_source + test_cli_daemon_socket_activation_live_source + test_cli_daemon_status_live_source + test_cli_kernel_unsupported_source + test_cli_notify_preflight_diag_source + test_cli_notify_preflight_einval_source + test_cli_signal_live_source + test_cli_prepared_root_lint_source + test_preflight_source + test_preflight_seccomp_source + test_landlock_policy_source + test_policy_ir_source + test_policy_compile_source + test_policy_compiler_source + test_policy_compiler_exceptions_source + test_seccomp_plan_source + test_seccomp_hardening_source + test_seccomp_install_failclosed_source + test_seccomp_notify_live_source + test_apply_sandbox_with_seccomp_source + test_policy_loader_source + test_policy_loader_mode_source + test_policy_loader_rust_helper_source + test_cli_policy_helper_exec_failure_source + test_cli_policy_file_failclosed_source + test_cli_policy_run_net_unsupported_source + test_cli_policy_run_fs_only_source + test_cli_policy_file_run_fs_only_source

test_abi_version = executable('test_abi_version',
  landlock_test_sources[0],
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('abi_version', test_abi_version, protocol : 'tap', suite : 'smoke')

test_probe_abi = executable('test_probe_abi',
  test_probe_abi_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('probe_abi', test_probe_abi, protocol : 'tap', suite : 'smoke')

test_seccomp_probe_user_notif = executable('test_seccomp_probe_user_notif',
  test_seccomp_probe_user_notif_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('seccomp_probe_user_notif', test_seccomp_probe_user_notif, protocol : 'tap', suite : 'smoke')

test_seccomp_notify_probe = executable('test_seccomp_notify_probe',
  test_seccomp_notify_probe_source,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('seccomp_notify_probe', test_seccomp_notify_probe, protocol : 'tap', suite : 'smoke')

test_landlock_create_ruleset = executable('test_landlock_create_ruleset',
  landlock_test_sources[1],
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('landlock_create_ruleset', test_landlock_create_ruleset, protocol : 'tap', suite : 'smoke')

test_landlock_create_ruleset_for_abi = executable('test_landlock_create_ruleset_for_abi',
  landlock_test_sources[2],
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('landlock_create_ruleset_for_abi', test_landlock_create_ruleset_for_abi, protocol : 'tap', suite : 'smoke')

test_add_rule = executable('test_add_rule',
  landlock_test_sources[3],
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_rule', test_add_rule, protocol : 'tap', suite : 'smoke')

test_add_rule_fs_delegate = executable('test_add_rule_fs_delegate',
  test_add_rule_fs_delegate_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_rule_fs_delegate', test_add_rule_fs_delegate, protocol : 'tap', suite : 'smoke')

test_add_rule_fs_empty_access = executable('test_add_rule_fs_empty_access',
  test_add_rule_fs_empty_access_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_rule_fs_empty_access', test_add_rule_fs_empty_access, protocol : 'tap', suite : 'smoke')

test_add_net_rule_contract = executable('test_add_net_rule_contract',
  test_add_net_rule_contract_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_net_rule_contract', test_add_net_rule_contract, protocol : 'tap', suite : 'smoke')

test_add_rule_fs_parent_fd_zero = executable('test_add_rule_fs_parent_fd_zero',
  test_add_rule_fs_parent_fd_zero_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_rule_fs_parent_fd_zero', test_add_rule_fs_parent_fd_zero, protocol : 'tap', suite : 'smoke')

test_add_rule_fs_high_bits = executable('test_add_rule_fs_high_bits',
  test_add_rule_fs_high_bits_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_rule_fs_high_bits', test_add_rule_fs_high_bits, protocol : 'tap', suite : 'smoke')

test_add_rule_fs_eacces = executable('test_add_rule_fs_eacces',
  test_add_rule_fs_eacces_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_rule_fs_eacces', test_add_rule_fs_eacces, protocol : 'tap', suite : 'smoke')

test_add_rule_fs_enomem = executable('test_add_rule_fs_enomem',
  test_add_rule_fs_enomem_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_rule_fs_enomem', test_add_rule_fs_enomem, protocol : 'tap', suite : 'smoke')

test_landlock_restrict_self = executable('test_landlock_restrict_self',
  landlock_test_sources[4],
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('landlock_restrict_self', test_landlock_restrict_self, protocol : 'tap', suite : 'smoke')

test_create_fs_ruleset = executable('test_create_fs_ruleset',
  landlock_test_sources[5],
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('create_fs_ruleset', test_create_fs_ruleset, protocol : 'tap', suite : 'smoke')

test_create_net_ruleset = executable('test_create_net_ruleset',
  landlock_test_sources[6],
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('create_net_ruleset', test_create_net_ruleset, protocol : 'tap', suite : 'smoke')

test_restrict_self_with_no_new_privs = executable('test_restrict_self_with_no_new_privs',
  test_restrict_self_with_no_new_privs_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('restrict_self_with_no_new_privs', test_restrict_self_with_no_new_privs, protocol : 'tap', suite : 'smoke')

test_set_no_new_privs = executable('test_set_no_new_privs',
  test_set_no_new_privs_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('set_no_new_privs', test_set_no_new_privs, protocol : 'tap', suite : 'smoke')

test_restrict_self_invalid_flags = executable('test_restrict_self_invalid_flags',
  test_restrict_self_invalid_flags_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('restrict_self_invalid_flags', test_restrict_self_invalid_flags, protocol : 'tap', suite : 'smoke')

test_restrict_self_require_nnp = executable('test_restrict_self_require_nnp',
  test_restrict_self_require_nnp_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('restrict_self_require_nnp', test_restrict_self_require_nnp, protocol : 'tap', suite : 'smoke')

test_restrict_self_warn_e2big = executable('test_restrict_self_warn_e2big',
  test_restrict_self_warn_e2big_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('restrict_self_warn_e2big', test_restrict_self_warn_e2big, protocol : 'tap', suite : 'smoke')

test_cli_parse = executable('test_cli_parse',
  test_cli_parse_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_parse', test_cli_parse, protocol : 'tap', suite : 'smoke')

test_cli_policy_parse = executable('test_cli_policy_parse',
  test_cli_policy_parse_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_policy_parse', test_cli_policy_parse, protocol : 'tap', suite : 'smoke')

test_cli_named_policy = executable('test_cli_named_policy',
  test_cli_named_policy_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_named_policy', test_cli_named_policy, protocol : 'tap', suite : 'smoke')

test_cli_build_fs_ruleset = executable('test_cli_build_fs_ruleset',
  test_cli_build_fs_ruleset_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_build_fs_ruleset', test_cli_build_fs_ruleset, protocol : 'tap', suite : 'smoke')

test_cli_smoke = executable('test_cli_smoke',
  test_cli_smoke_source,
  include_directories : inc,
  dependencies : libtap_dep)

test('cli_smoke', test_cli_smoke,
  args : [landlockd_exe,
          meson.current_source_dir() / 'policies' / 'valid_minimal.toml',
          meson.project_source_root() / 'policies' / 'ci-default.toml',
          meson.project_source_root() / 'policies' / 'net-fetch.toml',
          meson.project_source_root() / 'policies' / 'hermetic-build.toml',
          meson.project_source_root() / 'policies' / 'prepared-root.toml',
          meson.project_source_root() / 'policies' / 'prepared-root-net.toml'],
  protocol : 'tap', suite : 'smoke')

test_docs_audit_schema = executable('test_docs_audit_schema',
  test_docs_audit_schema_source,
  dependencies : libtap_dep)

test('docs_audit_schema', test_docs_audit_schema,
  args : [meson.project_source_root() / 'README.md',
          meson.project_source_root() / 'docs' / 'audit-schema.md'],
  protocol : 'tap', suite : 'smoke')

test_cli_exec_live = executable('test_cli_exec_live',
  test_cli_exec_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_exec_live', test_cli_exec_live, args : [landlockd_exe], protocol : 'tap', suite : 'live')

test_cli_e2e = executable('test_cli_e2e',
  test_cli_e2e_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_e2e', test_cli_e2e, args : [landlockd_exe], protocol : 'tap', suite : 'smoke')

test_cli_ir_deterministic = executable('test_cli_ir_deterministic',
  test_cli_ir_deterministic_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_ir_deterministic', test_cli_ir_deterministic,
  args : [landlockd_exe],
  protocol : 'tap', suite : 'smoke')

test_cli_dry_run = executable('test_cli_dry_run',
  test_cli_dry_run_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_dry_run', test_cli_dry_run, protocol : 'tap', suite : 'smoke')

test_cli_dry_run_stable = executable('test_cli_dry_run_stable',
  test_cli_dry_run_stable_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_dry_run_stable', test_cli_dry_run_stable,
  args : [landlockd_exe, meson.current_source_dir() / 'policies' / 'valid_minimal.toml'],
  protocol : 'tap', suite : 'smoke')

test_cli_dry_run_abi = executable('test_cli_dry_run_abi',
  test_cli_dry_run_abi_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_dry_run_abi', test_cli_dry_run_abi,
  args : [meson.current_source_dir() / 'policies' / 'valid_minimal.toml'],
  protocol : 'tap', suite : 'smoke')

test_cli_dry_run_net_unsupported = executable('test_cli_dry_run_net_unsupported',
  test_cli_dry_run_net_unsupported_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_dry_run_net_unsupported', test_cli_dry_run_net_unsupported,
  protocol : 'tap', suite : 'smoke')

test_cli_preflight_negatives = executable('test_cli_preflight_negatives',
  test_cli_preflight_negatives_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_preflight_negatives', test_cli_preflight_negatives, args : [landlockd_exe], protocol : 'tap', suite : 'live')

test_cli_preflight_diag_preload = shared_library('test_cli_preflight_diag_preload',
  test_cli_preflight_diag_source,
  c_args : ['-DLANDLOCKD_TEST_PRELOAD'],
  install : false)

test_cli_preflight_diag = executable('test_cli_preflight_diag',
  test_cli_preflight_diag_source,
  include_directories : inc,
  dependencies : libtap_dep)

test('cli_preflight_diag', test_cli_preflight_diag, args : [landlockd_exe, test_cli_preflight_diag_preload], protocol : 'tap', suite : 'live')

test_cli_launch_status = executable('test_cli_launch_status',
  test_cli_launch_status_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_launch_status', test_cli_launch_status, args : [landlockd_exe], protocol : 'tap', suite : 'live')

test_cli_notify_fd_helper = executable('test_cli_notify_fd_helper',
  test_cli_notify_fd_helper_source)

test_cli_notify_supervise_live = executable('test_cli_notify_supervise_live',
  test_cli_notify_supervise_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_notify_supervise_live', test_cli_notify_supervise_live,
  args : [landlockd_exe, test_cli_notify_fd_helper],
  protocol : 'tap', suite : 'live')

test_cli_broker_open_helper = executable('test_cli_broker_open_helper',
  test_cli_broker_open_helper_source,
  link_args : ['-static'])

test_cli_seccomp_helper = executable('test_cli_seccomp_helper',
  test_cli_seccomp_helper_source,
  link_args : ['-static'])

test_cli_broker_live = executable('test_cli_broker_live',
  test_cli_broker_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_broker_live', test_cli_broker_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_broker_mount_live = executable('test_cli_broker_mount_live',
  test_cli_broker_mount_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_broker_mount_live', test_cli_broker_mount_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_broker_bind_live = executable('test_cli_broker_bind_live',
  test_cli_broker_bind_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_broker_bind_live', test_cli_broker_bind_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_broker_move_mount_live = executable('test_cli_broker_move_mount_live',
  test_cli_broker_move_mount_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_broker_move_mount_live', test_cli_broker_move_mount_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_broker_mount_fd_live = executable('test_cli_broker_mount_fd_live',
  test_cli_broker_mount_fd_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_broker_mount_fd_live', test_cli_broker_mount_fd_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_broker_mount_object_live = executable('test_cli_broker_mount_object_live',
  test_cli_broker_mount_object_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_broker_mount_object_live', test_cli_broker_mount_object_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_hardening_live = executable('test_cli_hardening_live',
  test_cli_hardening_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_hardening_live', test_cli_hardening_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_seccomp_live = executable('test_cli_seccomp_live',
  test_cli_seccomp_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_seccomp_live', test_cli_seccomp_live,
  args : [landlockd_exe, test_cli_seccomp_helper],
  protocol : 'tap', suite : 'live')

test_cli_tmpfs_live = executable('test_cli_tmpfs_live',
  test_cli_tmpfs_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_tmpfs_live', test_cli_tmpfs_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_mount_hardening_live = executable('test_cli_mount_hardening_live',
  test_cli_mount_hardening_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_mount_hardening_live', test_cli_mount_hardening_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_bind_mount_live = executable('test_cli_bind_mount_live',
  test_cli_bind_mount_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_bind_mount_live', test_cli_bind_mount_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_root_pivot_live = executable('test_cli_root_pivot_live',
  test_cli_root_pivot_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_root_pivot_live', test_cli_root_pivot_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_audit_live = executable('test_cli_audit_live',
  test_cli_audit_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_audit_live', test_cli_audit_live,
  args : [landlockd_exe, test_cli_broker_open_helper],
  protocol : 'tap', suite : 'live')

test_cli_daemon_socket_activation_live = executable('test_cli_daemon_socket_activation_live',
  test_cli_daemon_socket_activation_live_source,
  include_directories : inc,
  dependencies : libtap_dep)

test('cli_daemon_socket_activation_live', test_cli_daemon_socket_activation_live,
  args : [landlockd_exe],
  protocol : 'tap', suite : 'live')

test_cli_daemon_status_live = executable('test_cli_daemon_status_live',
  test_cli_daemon_status_live_source,
  include_directories : inc,
  dependencies : libtap_dep)

test('cli_daemon_status_live', test_cli_daemon_status_live,
  args : [landlockd_exe],
  protocol : 'tap', suite : 'live')

test_cli_kernel_unsupported = executable('test_cli_kernel_unsupported',
  test_cli_kernel_unsupported_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_kernel_unsupported', test_cli_kernel_unsupported, protocol : 'tap', suite : 'smoke')

test_cli_notify_preflight_diag = executable('test_cli_notify_preflight_diag',
  test_cli_notify_preflight_diag_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_notify_preflight_diag', test_cli_notify_preflight_diag, protocol : 'tap', suite : 'smoke')

test_cli_notify_preflight_einval = executable('test_cli_notify_preflight_einval',
  test_cli_notify_preflight_einval_source + landlockd_cli_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_notify_preflight_einval', test_cli_notify_preflight_einval, protocol : 'tap', suite : 'smoke')

test_add_fs_rule_live = executable('test_add_fs_rule_live',
  test_add_fs_rule_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('add_fs_rule_live', test_add_fs_rule_live, protocol : 'tap', suite : 'live')

test_create_fs_ruleset_live = executable('test_create_fs_ruleset_live',
  test_create_fs_ruleset_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('create_fs_ruleset_live', test_create_fs_ruleset_live, protocol : 'tap', suite : 'live')

test_create_net_ruleset_live = executable('test_create_net_ruleset_live',
  test_create_net_ruleset_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('create_net_ruleset_live', test_create_net_ruleset_live, protocol : 'tap', suite : 'live')

test_cli_signal_live = executable('test_cli_signal_live',
  test_cli_signal_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_signal_live', test_cli_signal_live,
  args : [landlockd_exe,
          meson.current_source_dir() / 'policies' / 'valid_minimal.toml'],
  protocol : 'tap', suite : 'live')

test_cli_prepared_root_lint = executable('test_cli_prepared_root_lint',
  test_cli_prepared_root_lint_source,
  dependencies : libtap_dep)

test('cli_prepared_root_lint', test_cli_prepared_root_lint,
  args : [landlockd_exe,
          meson.current_source_dir() / 'policies' / 'prepared-root.toml'],
  protocol : 'tap', suite : 'smoke')

test_preflight = executable('test_preflight',
  test_preflight_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('preflight', test_preflight, protocol : 'tap', suite : 'smoke')

test_preflight_seccomp = executable('test_preflight_seccomp',
  test_preflight_seccomp_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('preflight_seccomp', test_preflight_seccomp, protocol : 'tap', suite : 'smoke')

test_landlock_policy = executable('test_landlock_policy',
  test_landlock_policy_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('landlock_policy', test_landlock_policy, protocol : 'tap', suite : 'smoke')

test_policy_ir = executable('test_policy_ir',
  test_policy_ir_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('policy_ir', test_policy_ir, protocol : 'tap', suite : 'smoke')

test_policy_compile = executable('test_policy_compile',
  test_policy_compile_source,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('policy_compile', test_policy_compile, protocol : 'tap', suite : 'smoke')

test_policy_compiler = executable('test_policy_compiler',
  test_policy_compiler_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('policy_compiler', test_policy_compiler, protocol : 'tap', suite : 'smoke')

test_policy_compiler_exceptions = executable('test_policy_compiler_exceptions',
  test_policy_compiler_exceptions_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('policy_compiler_exceptions', test_policy_compiler_exceptions, protocol : 'tap', suite : 'smoke')

test_seccomp_plan = executable('test_seccomp_plan',
  test_seccomp_plan_source + files('../src/cli_parse.c'),
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('seccomp_plan', test_seccomp_plan, protocol : 'tap', suite : 'smoke')

test_seccomp_hardening = executable('test_seccomp_hardening',
  test_seccomp_hardening_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('seccomp_hardening', test_seccomp_hardening, protocol : 'tap', suite : 'smoke')

test_seccomp_install_failclosed = executable('test_seccomp_install_failclosed',
  test_seccomp_install_failclosed_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('seccomp_install_failclosed', test_seccomp_install_failclosed, protocol : 'tap', suite : 'smoke')

test_seccomp_notify_live = executable('test_seccomp_notify_live',
  test_seccomp_notify_live_source,
  include_directories : inc,
  link_with : liblandlock,
  dependencies : libtap_dep)

test('seccomp_notify_live', test_seccomp_notify_live, protocol : 'tap', suite : 'live')

test_apply_sandbox_with_seccomp = executable('test_apply_sandbox_with_seccomp',
  test_apply_sandbox_with_seccomp_source + files('../src/landlock_sandbox_seccomp.c'),
  include_directories : inc,
  dependencies : libtap_dep)

test('apply_sandbox_with_seccomp', test_apply_sandbox_with_seccomp, protocol : 'tap', suite : 'smoke')

test_policy_loader = executable('test_policy_loader',
  test_policy_loader_source,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : [libtap_dep, tomlc99_dep])

test('policy_loader', test_policy_loader,
  args : [meson.current_source_dir() / 'policies'],
  protocol : 'tap', suite : 'smoke')

test_policy_loader_mode = executable('test_policy_loader_mode',
  test_policy_loader_mode_source,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('policy_loader_mode', test_policy_loader_mode,
  args : [policy_loader_helper_enabled ? 'helper' : 'fallback'],
  protocol : 'tap', suite : 'smoke')

test_policy_loader_rust_helper = executable('test_policy_loader_rust_helper',
  test_policy_loader_rust_helper_source,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('policy_loader_rust_helper', test_policy_loader_rust_helper,
  args : [rust_policy_helper_enabled ? landlockd_policy_helper_rust_exe : 'none',
          meson.current_source_dir() / 'policies' / 'valid_minimal.toml',
          meson.current_source_dir() / 'policies' / 'seccomp_unknown_syscall.toml'],
  protocol : 'tap', suite : 'live')

test_cli_policy_helper_exec_failure = executable('test_cli_policy_helper_exec_failure',
  test_cli_policy_helper_exec_failure_source,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_policy_helper_exec_failure', test_cli_policy_helper_exec_failure,
  args : [landlockd_exe, meson.current_source_dir() / 'policies' / 'valid_minimal.toml'],
  protocol : 'tap', suite : 'live')

test_cli_policy_file_failclosed = executable('test_cli_policy_file_failclosed',
  test_cli_policy_file_failclosed_source + landlockd_cli_sources +
    landlockd_runtime_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_policy_file_failclosed', test_cli_policy_file_failclosed,
  protocol : 'tap', suite : 'smoke')

test_cli_policy_run_net_unsupported = executable('test_cli_policy_run_net_unsupported',
  test_cli_policy_run_net_unsupported_source + landlockd_cli_sources +
    landlockd_runtime_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_policy_run_net_unsupported', test_cli_policy_run_net_unsupported,
  protocol : 'tap', suite : 'smoke')

test_cli_policy_run_fs_only = executable('test_cli_policy_run_fs_only',
  test_cli_policy_run_fs_only_source + landlockd_cli_sources +
    landlockd_runtime_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_policy_run_fs_only', test_cli_policy_run_fs_only,
  protocol : 'tap', suite : 'smoke')

test_cli_policy_file_run_fs_only = executable('test_cli_policy_file_run_fs_only',
  test_cli_policy_file_run_fs_only_source + landlockd_cli_sources +
    landlockd_runtime_sources,
  include_directories : [inc, src_inc],
  link_with : liblandlock,
  dependencies : libtap_dep)

test('cli_policy_file_run_fs_only', test_cli_policy_file_run_fs_only,
  protocol : 'tap', suite : 'smoke')
