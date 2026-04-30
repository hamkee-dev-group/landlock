project('landlockd', 'c',
  version : '0.1.0',
  default_options : ['c_std=c11', 'warning_level=2'])

inc = include_directories('include')
src_inc = include_directories('src')
system_policy_dir = join_paths(get_option('prefix'),
                               get_option('datadir'),
                               'landlockd',
                               'policies')
install_headers(
  'include/landlockd/landlock.h',
  'include/landlockd/landlock_policy.h',
  'include/landlockd/landlock_compat.h',
  'include/landlockd/policy_compiler.h',
  'include/landlockd/policy_ir.h',
  'include/landlockd/preflight.h',
  subdir : 'landlockd')

systemd_user_unit_dir = join_paths(get_option('prefix'),
                                   get_option('libdir'),
                                   'systemd',
                                   'user')
systemd_unit_conf = configuration_data()
systemd_unit_conf.set('LANDLOCKD_EXECUTABLE',
                      join_paths(get_option('prefix'),
                                 get_option('bindir'),
                                 'landlockd'))
configure_file(
  input : 'systemd/landlockd.service.in',
  output : 'landlockd.service',
  configuration : systemd_unit_conf,
  install : true,
  install_dir : systemd_user_unit_dir)
install_data('systemd/landlockd.socket',
  install_dir : systemd_user_unit_dir)
install_data(
  'policies/ci-default.toml',
  'policies/net-fetch.toml',
  'policies/hermetic-build.toml',
  'policies/prepared-root.toml',
  'policies/prepared-root-net.toml',
  install_dir : system_policy_dir)

subdir('src')
subdir('tests')

cc = meson.get_compiler('c')
run_target('lint',
  command : [cc.cmd_array(),
             '-fsyntax-only',
             '-Wall', '-Wextra', '-Wpedantic', '-Werror',
             '-I' + meson.current_source_dir() / 'include',
             '-I' + meson.current_source_dir() / 'subprojects/libtap',
             '-I' + meson.current_source_dir() / 'subprojects/tomlc99',
             '-I' + meson.current_source_dir() / 'src',
             liblandlock_sources + lint_test_sources])
