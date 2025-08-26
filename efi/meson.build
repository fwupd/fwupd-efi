generate_sbat = [python3, files('generate_sbat.py')]
generate_binary = [python3, files('generate_binary.py')]

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
  efi_libdir = '/usr/lib'
  if meson.get_compiler('c').has_argument('-print-multi-os-directory')
    fs = import('fs')
    multi = run_command(cc.cmd_array(), '-print-multi-os-directory', check: true).stdout().strip()
    efi_libdir_multi = join_paths(efi_libdir, multi)
    if fs.is_dir(join_paths(efi_libdir_multi, 'gnuefi'))
      efi_libdir = efi_libdir_multi
    endif
  else
    warning('Compiler does not support -print-multi-os-directory, using default efi-libdir path')
  endif
endif

# The name we need to look for on this arch and OS: elf_x86_64_fbsd_efi.lds
lds_os = ''
if host_cpu == 'x86_64' and host_machine.system() == 'freebsd'
  lds_os = '_fbsd'
endif

arch_lds = 'efi.lds'
arch_crt = 'crt0.o'
if efi_ldsdir == ''
  efi_ldsdir = join_paths(efi_libdir, 'gnuefi', gnu_efi_path_arch)
  cmd = run_command('test', '-f', join_paths(efi_ldsdir, arch_lds), check: false)
  if cmd.returncode() != 0
    arch_lds = 'elf_@0@@1@_efi.lds'.format(gnu_efi_path_arch, lds_os)
    arch_crt = 'crt0-efi-@0@.o'.format(gnu_efi_path_arch)
    efi_ldsdir = join_paths(efi_libdir, 'gnuefi')
    cmd = run_command('test', '-f', join_paths(efi_ldsdir, arch_lds), check: false)
  endif
  if cmd.returncode() != 0
    efi_ldsdir = efi_libdir
    cmd = run_command('test', '-f', join_paths(efi_ldsdir, arch_lds), check: false)
    if cmd.returncode() != 0
      error('Cannot find @0@'.format(arch_lds))
    endif
  endif
else
  cmd = run_command('test', '-f', join_paths(efi_ldsdir, arch_lds), check: false)
  if cmd.returncode() != 0
    arch_lds = 'elf_@0@@1@_efi.lds'.format(gnu_efi_path_arch, lds_os)
    arch_crt = 'crt0-efi-@0@.o'.format(gnu_efi_path_arch)
    cmd = run_command('test', '-f', join_paths(efi_ldsdir, arch_lds), check: false)
  endif
  if cmd.returncode() != 0
    error('Cannot find @0@'.format(arch_lds))
  endif
endif
efi_crtdir = efi_ldsdir

# If using objcopy, crt0 must not include the PE/COFF header
if run_command('grep', '-q', 'coff_header', join_paths(efi_crtdir, arch_crt), check: false).returncode() == 0
        coff_header_in_crt0 = true
else
        coff_header_in_crt0 = false
endif

# older objcopy for Aarch64, ARM32 and RISC-V are not EFI capable.
# Use 'binary' instead, and add required symbols manually.
if ( host_cpu == 'arm'
  or (host_cpu == 'riscv64'     and (objcopy_version.version_compare ('< 2.42') or coff_header_in_crt0))
  or (host_cpu == 'aarch64'     and (objcopy_version.version_compare ('< 2.38') or coff_header_in_crt0 or uswid.found()))
  or (host_cpu == 'loongarch64' and (objcopy_version.version_compare ('< 2.41') or coff_header_in_crt0)) )
  objcopy_manualsymbols = true
  generate_binary_extra = ['--objcopy-manualsymbols']
else
  objcopy_manualsymbols = false
  generate_binary_extra = []
endif

# is the system linker script new enough to know about SBAT?
# i.e. gnu-efi with https://github.com/vathpela/gnu-efi/pull/14 has been installed
if get_option('efi_sbat_distro_id') != ''
  cmd = run_command('grep', '-q', 'sbat', join_paths(efi_ldsdir, arch_lds), check: false)
  if cmd.returncode() != 0
    warning('Cannot find SBAT section in @0@, using local copy'.format(join_paths(efi_ldsdir, arch_lds)))
    efi_ldsdir = join_paths(meson.current_source_dir(), 'lds')
    arch_lds = 'elf_@0@@1@_efi.lds'.format(gnu_efi_arch, lds_os)
  endif
endif

# SBOM is never in system lds
if uswid.found()
  warning('Switching to local copy of linker script as using SBOM')
  efi_ldsdir = join_paths(meson.current_source_dir(), 'lds')
  arch_lds = 'elf_@0@@1@_efi.lds'.format(gnu_efi_arch, lds_os)
endif

# is the system crt0 for arm and aarch64 new enough to know about SBAT?
if objcopy_manualsymbols
  if get_option('efi_sbat_distro_id') != ''
    cmd = run_command('grep', '-q', 'sbat', join_paths(efi_crtdir, arch_crt), check: false)
    if cmd.returncode() != 0
      warning('Cannot find SBAT section in @0@, using local copy'.format(join_paths(efi_crtdir, arch_crt)))
      # The gnuefi libraries are still needed
      efi_libdir = efi_crtdir
      efi_crtdir = join_paths(meson.current_build_dir(), 'crt0')
      efi_ldsdir = join_paths(meson.current_source_dir(), 'lds')
    endif
  endif
endif

# SBOM not in system crt0
if objcopy_manualsymbols
  if uswid.found()
    warning('Switching to local copy of crt0 as using SBOM')
    efi_crtdir = join_paths(meson.current_build_dir(), 'crt0')
    efi_ldsdir = join_paths(meson.current_source_dir(), 'lds')
  endif
endif

# Check aligned lds and crt0 on ARM64 this breaks otherwise
if host_cpu == 'aarch64' and not objcopy_manualsymbols
  if efi_ldsdir == join_paths(meson.current_source_dir(), 'lds')
      arch_lds = 'elf_@0@@1@_efi_system.lds'.format(gnu_efi_arch, lds_os)
  endif
endif


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
                '-fpic',
                '-fno-pie',
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
                   '-m32']
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

if objcopy_manualsymbols
  # older objcopy for Aarch64, ARM32 and RISC-V are not EFI capable.
  # Use 'binary' instead, and add required symbols manually.
  if efi_crtdir != join_paths(meson.current_build_dir(), 'crt0')
    # Using system so without crt0 generator
    efi_ldflags += ['--defsym=EFI_SUBSYSTEM=0xa']
  endif
  efi_format = ['-O', 'binary']
else
  efi_format = ['--target=efi-app-@0@'.format(gnu_efi_arch)]
endif

libgcc_file_name = run_command(cc.cmd_array(), '-print-libgcc-file-name', check: true).stdout().strip()
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
