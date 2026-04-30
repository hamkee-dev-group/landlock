project('tomlc99', 'c', default_options : ['c_std=c11', 'warning_level=0'])

tomlc99_lib = static_library('tomlc99',
  'toml.c',
  c_args : ['-w'])

tomlc99_dep = declare_dependency(
  include_directories : include_directories('.'),
  link_with : tomlc99_lib)
