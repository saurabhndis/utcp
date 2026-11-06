app_args = []
app_deps = [utcp_dep]
bpf = cc.find_library('bpf', required : false)
clang = find_program('clang', required : false)
if bpf.found() and clang.found()
  app_args += '-DHAVE_BPF'
  app_deps += bpf
  custom_target('steer.bpf.o', input : 'steer.bpf.c', output : 'steer.bpf.o',
                command : [clang, '-O2', '-g', '-target', 'bpf',
                           '-I/usr/include/' + host_machine.cpu_family() + '-linux-gnu',
                           '-c', '@INPUT@', '-o', '@OUTPUT@'],
                build_by_default : true, install : true,
                install_dir : get_option('bindir'))
endif
executable('utcp-app', ['main.c', 'workload.c', 'shm.c', 'link.c', 'be_utcp.c', 'be_kernel.c'],
           c_args : app_args, dependencies : app_deps, install : true)
