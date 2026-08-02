generate_sbat = [python3, files('generate_sbat.py')]
generate_binary = [python3, files('generate_binary.py')]
probe_objcopy_efi = [python3, files('probe-objcopy-efi.py')]

# get source version, falling back
git = find_program('git', required : false)
if git.found()
  source_version = run_command(git, 'describe', check: false).stdout().strip()
else
  source_version = 'unknown'
endif

if uswid.found()
  con2 = configuration_data()
  con2.set('project_version', meson.project_version())
  con2.set('source_version', source_version)
  swid_xml = configure_file(
    input : 'swid.xml.in',
    output : 'swid.xml',
    configuration : con2,
  )
endif

efi_ldsdir = get_option('efi-ldsdir')
efi_incdir = get_option('efi-includedir')

gnu_efi_path_arch = ''
foreach name : [gnu_efi_arch, EFI_MACHINE_TYPE_NAME]
  if (gnu_efi_path_arch == '' and name != '' and
    cc.has_header('@0@/@1@/efibind.h'.format(efi_incdir, name)))
    gnu_efi_path_arch = name
  endif
endforeach

if gnu_efi_path_arch != '' and EFI_MACHINE_TYPE_NAME == ''
  error('gnu-efi is available, but EFI_MACHINE_TYPE_NAME is unknown')
endif

efi_libdir = get_option('efi-libdir')
if efi_libdir == ''
  efi_libdir_default = '/usr/lib'
  multi_result = run_command(
    cc.cmd_array(),
    '-print-multi-os-directory',
    check: false,
  )
  if multi_result.returncode() == 0
    multi = multi_result.stdout().strip()
    if multi != ''
      efi_libdir_multi = join_paths(efi_libdir_default, multi)
      if (fs.is_dir(join_paths(efi_libdir_multi, 'gnuefi')) or
          fs.is_file(join_paths(efi_libdir_multi, 'libgnuefi.a')) )
        efi_libdir = efi_libdir_multi
      else
        efi_libdir = gnuefi.get_variable('libdir', default_value: efi_libdir_default)
      endif
    endif
  else
    warning('Compiler does not support -print-multi-os-directory, using default efi-libdir path')
    efi_libdir = efi_libdir_default
  endif
endif
message('efi_libdir:', efi_libdir)

# The name we need to look for on this arch and OS: elf_x86_64_fbsd_efi.lds
lds_os = ''
if host_cpu == 'x86_64' and host_machine.system() == 'freebsd'
  lds_os = '_fbsd'
endif

arch_lds = 'efi.lds'
arch_crt = 'crt0.o'
arch_lds_efi    = 'elf_@0@@1@_efi.lds'.format(gnu_efi_path_arch, lds_os)
arch_lds_local  = 'elf_@0@@1@_efi.lds'.format(gnu_efi_arch, lds_os)
arch_lds_system = 'elf_@0@@1@_efi_system.lds'.format(gnu_efi_arch, lds_os)
arch_crt_efi    = 'crt0-efi-@0@.o'.format(gnu_efi_path_arch)
arch_crt_local  = 'crt0-efi-@0@.o'.format(gnu_efi_arch)

if efi_ldsdir == ''
  efi_ldsdir = join_paths(efi_libdir, 'gnuefi', gnu_efi_path_arch)
  if not fs.is_file(efi_ldsdir / arch_lds)
    arch_lds = arch_lds_efi
    arch_crt = arch_crt_efi
    efi_ldsdir = join_paths(efi_libdir, 'gnuefi')
  endif
  if not fs.is_file(efi_ldsdir / arch_lds)
    efi_ldsdir = efi_libdir
  endif
else
  if not fs.is_file(efi_ldsdir / arch_lds)
    arch_lds = arch_lds_efi
    arch_crt = arch_crt_efi
  endif
endif
if not fs.is_file(efi_ldsdir / arch_lds)
  error('Cannot find @0@'.format(arch_lds))
endif
efi_crtdir = efi_ldsdir

# If using objcopy, crt0 must not include the PE/COFF header
if run_command('grep', '-q', 'coff_header', join_paths(efi_crtdir, arch_crt), check: false).returncode() == 0
        coff_header_in_crt0 = true
else
        coff_header_in_crt0 = false
endif

# older gnu-objcopy for Aarch64, ARM32 and RISC-V are not EFI capable.
# llvm-objcopy is not EFI capable (https://github.com/llvm/llvm-project/issues/108609)
efi_app_target = 'efi-app-@0@'.format(gnu_efi_arch)

# probe if objcopy supports efi-app
cmd = run_command(
  probe_objcopy_efi,
  '--cc', ' '.join(cc.cmd_array()),
  '--objcopy', objcopy,
  '--target', efi_app_target,
  '--lds', efi_ldsdir / arch_lds,
  '--crt0', efi_ldsdir / arch_crt,
  check: false,
)
have_objcopy_efi = cmd.returncode() == 0
message('objcopy @0@: @1@'.format(efi_app_target, have_objcopy_efi))

local_crt = false
local_lds = false

if have_objcopy_efi
  objcopy_manualsymbols = false
  generate_binary_extra = []
  efi_format = ['--output-target=@0@'.format(efi_app_target)]
else
  # Use 'binary' instead, and add required symbols manually.
  objcopy_manualsymbols = true
  generate_binary_extra = ['--objcopy-manualsymbols']
  efi_format = ['-O', 'binary']

  # probe if crt0 provides pe-header
  cmd = run_command(
    probe_objcopy_efi,
    '--cc', ' '.join(cc.cmd_array()),
    '--objcopy', objcopy,
    '--target', 'binary',
    '--lds', efi_ldsdir / arch_lds,
    '--crt0', efi_ldsdir / arch_crt,
    check: false,
  )
  have_crt0_pefile = cmd.returncode() == 0
  message('@0@ pefile: @1@'.format(arch_crt, have_crt0_pefile))

  if not have_crt0_pefile
    warning('Switching to local copy of crt0 for pefile')
    local_crt = true
    local_lds = true
  endif

endif


# is the system linker script new enough to know about SBAT?
# i.e. gnu-efi with https://github.com/vathpela/gnu-efi/pull/14 has been installed
if get_option('efi_sbat_distro_id') != ''
  cmd = run_command('grep', '-q', 'sbat', join_paths(efi_ldsdir, arch_lds), check: false)
  if cmd.returncode() != 0
    warning('Cannot find SBAT section in @0@, using local copy'.format(join_paths(efi_ldsdir, arch_lds)))
    local_lds = true
  endif
endif

# SBOM is never in system lds
if uswid.found()
  warning('Switching to local copy of linker script as using SBOM')
  local_lds = true
endif

# is the system crt0 for arm and aarch64 new enough to know about SBAT?
if objcopy_manualsymbols
  if get_option('efi_sbat_distro_id') != ''
    cmd = run_command('grep', '-q', 'sbat', join_paths(efi_crtdir, arch_crt), check: false)
    if cmd.returncode() != 0
      warning('Cannot find SBAT section in @0@, using local copy'.format(join_paths(efi_crtdir, arch_crt)))
      # The gnuefi libraries are still needed
      efi_libdir = efi_crtdir
      local_crt = true
      local_lds = true
    endif
  endif
endif

# SBOM not in system crt0
if objcopy_manualsymbols
  if uswid.found()
    warning('Switching to local copy of crt0 as using SBOM')
    local_crt = true
    local_lds = true
  endif
endif

if local_crt
  efi_crtdir = join_paths(meson.current_build_dir(), 'crt0')
  arch_crt   = arch_crt_local
endif
if local_lds
  efi_ldsdir = join_paths(meson.current_source_dir(), 'lds')
  arch_lds   = arch_lds_local
endif

# Check system aligned lds and crt0
if not objcopy_manualsymbols and local_lds
  cmd = run_command('test', '-f', join_paths(efi_ldsdir, arch_lds_system), check: false)
  if cmd.returncode() == 0
    arch_lds = arch_lds_system
  endif
endif

message('efi-crt: @0@'.format(arch_crt))
message('efi-lds: @0@'.format(arch_lds))
message('efi-libdir: "@0@"'.format(efi_libdir))
message('efi-ldsdir: "@0@"'.format(efi_ldsdir))
message('efi-crtdir: "@0@"'.format(efi_crtdir))
message('efi-includedir: "@0@"'.format(efi_incdir))

debugdir = join_paths (libdir, 'debug')
compile_args = ['-Og',
                '-g3',
                '--param=ssp-buffer-size=4',
                '-fexceptions',
                '-Wall',
                '-Wextra',
                '-Wvla',
                '-std=gnu11',
                '-fno-pie',
                '-fPIC',
                '-funsigned-char',
                '-fshort-wchar',
                '-ffreestanding',
                '-fno-strict-aliasing',
                '-fno-stack-protector',
                '-fno-stack-check',
                '-fno-merge-all-constants',
                '-Wsign-compare',
                '-Wno-missing-field-initializers',
                '-Wno-address-of-packed-member',
                '-grecord-gcc-switches',
                '-DDEBUGDIR="@0@"'.format(debugdir),
                '-I.',
                '-isystem', efi_incdir,
                '-isystem', join_paths(efi_incdir, gnu_efi_path_arch)]
# clang only has fno-merge-all-constants
compile_args += cc.first_supported_argument('-fno-merge-constants')
if get_option('werror')
    compile_args += '-Werror'
endif
if host_cpu == 'x86_64'
  compile_args += ['-mno-red-zone',
                   '-mno-sse',
                   '-mno-mmx',
                   '-DEFI_FUNCTION_WRAPPER',
                   '-DGNU_EFI_USE_MS_ABI']
elif host_cpu == 'x86'
  compile_args += ['-mno-sse',
                   '-mno-mmx',
                   '-mno-red-zone',
                   '-mfpmath=387',
                   '-m32']
elif host_cpu == 'loongarch64'
  compile_args += ['-mno-lsx',
                   '-mno-lasx']
# no special cases for aarch64 or arm
endif

efi_ldflags = ['-T',
               join_paths(efi_ldsdir, arch_lds),
               '-shared',
               '-no-pie',
               '-Bsymbolic',
               '-nostdlib',
               '-znocombreloc',
               '-znorelro',
               '-L', efi_crtdir,
               '-L', efi_libdir,
               join_paths(efi_crtdir, arch_crt)]

if host_cpu == 'aarch64' or host_cpu == 'arm'
# Don't use 64KiB pages
  efi_ldflags += ['-z', 'common-page-size=4096']
  efi_ldflags += ['-z', 'max-page-size=4096']
endif

# Using system so without crt0 generator
if objcopy_manualsymbols and not local_crt
    efi_ldflags += ['--defsym=EFI_SUBSYSTEM=0xa']
endif

libgcc_file_name = run_command(cc.cmd_array(), get_option('c_link_args'),
                               '-print-libgcc-file-name', check: true).stdout().strip()
message('libgcc_file_name:', libgcc_file_name)
efi_name = 'fwupd@0@.efi'.format(EFI_MACHINE_TYPE_NAME)

# GNU-EFI 4.0 changed how CompareGuid works (to align with EDK2)
# Keep GNU-EFI 3.0 support for a while
if gnuefi.version().version_compare('>=4.0.0')
  compile_args += ['-DGNU_EFI_3_0_COMPAT']
endif


o_files = []
o_files += custom_target('fwupdate.o',
                        input : 'fwupdate.c',
                        output : 'fwupdate.o',
                        command : [cc.cmd_array(), '-c', '@INPUT@', '-o', '@OUTPUT@']
                                  + compile_args)
o_files += custom_target('fwup-debug.o',
                        input : 'fwup-debug.c',
                        output : 'fwup-debug.o',
                        command : [cc.cmd_array(), '-c', '@INPUT@', '-o', '@OUTPUT@']
                                  + compile_args)
o_files += custom_target('fwup-efi.o',
                        input : 'fwup-efi.c',
                        output : 'fwup-efi.o',
                        command : [cc.cmd_array(), '-c', '@INPUT@', '-o', '@OUTPUT@']
                                  + compile_args)
o_files += custom_target('fwup-common.o',
                        input : 'fwup-common.c',
                        output : 'fwup-common.o',
                        command : [cc.cmd_array(), '-c', '@INPUT@', '-o', '@OUTPUT@']
                                  + compile_args)

o_files += custom_target('fwup-sbat.o',
                        output : 'fwup-sbat.o',
                        command : [
                          generate_sbat,
                          '@OUTPUT@',
                          '--cc', ' '.join(cc.cmd_array()),
                          '--cflags', ' '.join(compile_args),
                          '--objcopy', objcopy,
                          '--project-name', meson.project_name(),
                          '--project-version', meson.project_version(),
                          '--sbat-version', '1',
                          '--sbat-generation', '@0@'.format(get_option('efi_sbat_fwupd_generation')),
                          '--sbat-distro-id', get_option('efi_sbat_distro_id'),
                          '--sbat-distro-generation', '0',
                          '--sbat-distro-summary', get_option('efi_sbat_distro_summary'),
                          '--sbat-distro-pkgname', get_option('efi_sbat_distro_pkgname'),
                          '--sbat-distro-version', get_option('efi_sbat_distro_version'),
                          '--sbat-distro-url', get_option('efi_sbat_distro_url'),
                        ])

if uswid.found()
  if uswid.version().version_compare('>=0.4.3')
    uswid_cflags = ['--cflags', ' '.join(compile_args)]
  else
    uswid_cflags = []
  endif
  o_files += custom_target('fwup-sbom.o',
                          output : 'fwup-sbom.o',
                          command : [
                            'uswid',
                            '--cc', cc.cmd_array()[-1],
                            '--objcopy', objcopy,
                            '--load', swid_xml,
                            '--save', '@OUTPUT@',
                          ] + uswid_cflags)
endif

fwupd_so_deps = []
if efi_crtdir == join_paths(meson.current_build_dir(), 'crt0')
  # A custom crt0 is needed
  subdir('crt0')
  fwupd_so_deps += [o_crt0]
endif

so = custom_target('fwup.so',
                   input : o_files,
                   output : 'fwup.so',
                   command : [cc_ld, '-nostdlib', '-o', '@OUTPUT@'] +
                             efi_ldflags + ['@INPUT@'] +
                             ['-lefi', '-lgnuefi', libgcc_file_name],
                   depends: fwupd_so_deps)

app = custom_target(efi_name,
                    input : so,
                    output : efi_name,
                    command : [
                      generate_binary,
                      '@INPUT@', '@OUTPUT@',
                      '--arch', gnu_efi_arch,
                      '--os', host_machine.system(),
                      '--objcopy', objcopy,
                      '--pkgnote', get_option('pkgnote'),
                      '--genpeimg', genpeimg.found() ? genpeimg : ''
                    ]
                    + generate_binary_extra,
                    install : true,
                    install_dir : efi_app_location)

dbg = custom_target('efi_debug',
                    input : so,
                    output : efi_name + '.debug',
                    command : [objcopy,
                               '-j', '.text',
                               '-j', '.sdata',
                               '-j', '.data',
                               '-j', '.dynamic',
                               '-j', '.dynstr',
                               '-j', '.dynsym',
                               '-j', '.rodata',
                               '-j', '.rel*',
                               '-j', '.rela*',
                               '-j', '.reloc',
                               '-j', '.eh_frame',
                               '-j', '.debug*',
                               '-j', '.note.gnu.build-id']
                               + efi_format +
                               ['@INPUT@', '@OUTPUT@'],
                    install : false,
                    install_dir : debugdir)

selftest = executable('fwup-selftest',
  'fwup-selftest.c',
  c_args: [
    '-DDEBUGDIR="/mock/"',
    '-Wno-unused-function',
    '-Wno-unused-variable',
    '-Wno-unused-parameter',
    '-Wno-address-of-packed-member',
  ],
  include_directories: include_directories('mock-include', '.'),
  native: true,
)
test('fwup-selftest', selftest)

if get_option('fuzzing')
  fuzz_c_args = [
    '-DDEBUGDIR="/mock/"',
    '-Wno-unused-function',
    '-Wno-unused-variable',
    '-Wno-unused-parameter',
    '-Wno-address-of-packed-member',
    '-fsanitize=fuzzer,address,undefined',
    '-fno-sanitize-recover=all',
  ]
  fuzz_link_args = ['-fsanitize=fuzzer,address,undefined']
  fuzz_incdirs = include_directories('mock-include', '.')

  executable('fwup-fuzz-update-info',
    'fwup-fuzz-update-info.c',
    c_args: fuzz_c_args,
    link_args: fuzz_link_args,
    include_directories: fuzz_incdirs,
    native: true,
  )

  executable('fwup-fuzz-capsule',
    'fwup-fuzz-capsule.c',
    c_args: fuzz_c_args,
    link_args: fuzz_link_args,
    include_directories: fuzz_incdirs,
    native: true,
  )
endif
