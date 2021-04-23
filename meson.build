project('fwupd-efi', 'c',
  version : '1.1',
  license : 'LGPL-2.1+',
  meson_version : '>=0.53.0',
  default_options : ['warning_level=2', 'c_std=c99'],
)

# get supported warning flags
warning_flags = [
  '-Waggregate-return',
  '-Wunused',
  '-Warray-bounds',
  '-Wcast-align',
  '-Wclobbered',
  '-Wdeclaration-after-statement',
  '-Wdiscarded-qualifiers',
  '-Wduplicated-branches',
  '-Wduplicated-cond',
  '-Wempty-body',
  '-Wformat=2',
  '-Wformat-nonliteral',
  '-Wformat-security',
  '-Wformat-signedness',
  '-Wignored-qualifiers',
  '-Wimplicit-function-declaration',
  '-Winit-self',
  '-Wlogical-op',
  '-Wmaybe-uninitialized',
  '-Wmissing-declarations',
  '-Wmissing-format-attribute',
  '-Wmissing-include-dirs',
  '-Wmissing-noreturn',
  '-Wmissing-parameter-type',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wno-cast-function-type',
  '-Wno-address-of-packed-member',  # incompatible with g_autoptr()
  '-Wno-unknown-pragmas',
  '-Wno-missing-field-initializers',
  '-Wno-strict-aliasing',
  '-Wno-suggest-attribute=format',
  '-Wno-unused-parameter',
  '-Wold-style-definition',
  '-Woverride-init',
  '-Wpointer-arith',
  '-Wredundant-decls',
  '-Wreturn-type',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-aliasing',
  '-Wstrict-prototypes',
  '-Wswitch-default',
  '-Wtype-limits',
  '-Wundef',
  '-Wuninitialized',
  '-Wunused-but-set-variable',
  '-Wunused-variable',
  '-Wvla',
  '-Wwrite-strings'
]
cc = meson.get_compiler('c')
add_project_arguments(cc.get_supported_arguments(warning_flags), language : 'c')

if not meson.is_cross_build()
  add_project_arguments('-fstack-protector-strong', language : 'c')
endif

# enable full RELRO where possible
# FIXME: until https://github.com/mesonbuild/meson/issues/1140 is fixed
global_link_args = []
test_link_args = [
  '-Wl,-z,relro',
  '-Wl,-z,defs',
  '-Wl,-z,now',
  '-Wl,-z,ibt,-z,shstk',
]
foreach arg: test_link_args
  if cc.has_link_argument(arg)
    global_link_args += arg
  endif
endforeach
add_project_link_arguments(
  global_link_args,
  language: 'c'
)

prefix = get_option('prefix')
libdir = join_paths(prefix, get_option('libdir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))

objcopy = find_program ('objcopy')
genpeimg = find_program ('genpeimg', required: false)

efi_app_location = join_paths(libexecdir, 'fwupd', 'efi')
host_cpu = host_machine.cpu_family()
if host_cpu == 'x86'
        EFI_MACHINE_TYPE_NAME = 'ia32'
        gnu_efi_arch = 'ia32'
elif host_cpu == 'x86_64'
        EFI_MACHINE_TYPE_NAME = 'x64'
        gnu_efi_arch = 'x86_64'
elif host_cpu == 'arm'
        EFI_MACHINE_TYPE_NAME = 'arm'
        gnu_efi_arch = 'arm'
elif host_cpu == 'aarch64'
        EFI_MACHINE_TYPE_NAME = 'aa64'
        gnu_efi_arch = 'aarch64'
else
        EFI_MACHINE_TYPE_NAME = ''
        gnu_efi_arch = ''
endif

# sanity check the packager set this to *SOMETHING*
if get_option('efi_sbat_distro_id') == ''
    warning('-Defi_sbat_distro_id is unset, see README.md')
endif

pkgg = import('pkgconfig')
pkgg.generate(
  version : meson.project_version(),
  name : meson.project_name(),
  filebase : 'fwupd-efi',
  description : 'fwupd-efi is the UEFI binary used with fwupd for installing UEFI firmware updates',
)

fwupd_efi_dep = declare_dependency()

subdir('efi')
