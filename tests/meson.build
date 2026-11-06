sim = files('sim.c')
test_wire = executable('test_wire', ['test_wire.c', sim], dependencies : utcp_dep)
test_unit = executable('test_unit', 'test_unit.c', dependencies : utcp_dep,
                       link_with : libutcp, include_directories : include_directories('../src'))
# The tests account for sockets and packet buffers themselves; regions are
# intentionally not torn down, so LeakSanitizer is disabled.
asan_env = ['ASAN_OPTIONS=detect_leaks=0']
test('unit', test_unit, env : asan_env)
test('wire', test_wire, env : asan_env, timeout : 1200)
