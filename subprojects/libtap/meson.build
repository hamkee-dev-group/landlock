project('libtap', 'c')

libtap = static_library('tap', 'tap.c')

libtap_dep = declare_dependency(
  link_with : libtap,
  include_directories : include_directories('.'))
