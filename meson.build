project('utcp', 'c', version : '0.1.0',
  default_options : ['c_std=c11', 'warning_level=3', 'werror=true', 'buildtype=release',
                     'b_ndebug=if-release'])

cc = meson.get_compiler('c')
add_project_arguments('-D_GNU_SOURCE', '-Wno-pedantic', '-Wshadow', '-Wstrict-prototypes',
                      '-Wno-unused-parameter', language : 'c')
m = cc.find_library('m', required : false)

inc = include_directories('include')
utcp_src = files('src/core.c', 'src/net.c', 'src/tcp_in.c', 'src/tcp_out.c', 'src/tcp_cc.c',
                 'src/tcp_sock.c')
libutcp = library('utcp', utcp_src, include_directories : inc, dependencies : m,
                  install : true)
utcp_dep = declare_dependency(link_with : libutcp, include_directories : inc)
install_headers('include/utcp.h')

subdir('tests')
if host_machine.system() == 'linux'
  subdir('app')
endif
