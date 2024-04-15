project('fwupd-efi', 'c',
  version : '1.7',
  license : 'LGPL-2.1+',
  meson_version : '>=0.62.0',
  default_options : ['warning_level=2', 'c_std=c99'],
)

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())

cc = meson.get_compiler('c')
objcopy = find_program('objcopy')
objcopy_version = run_command(objcopy, '--version', check: true).stdout().split('\n')[0].split(' ')[-1]

gnuefi = dependency('gnu-efi', version: '>= 3.0.18')
prefix = get_option('prefix')
libdir = join_paths(prefix, get_option('libdir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))

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
elif host_cpu == 'loongarch64'
        EFI_MACHINE_TYPE_NAME = 'loongarch64'
        gnu_efi_arch = 'loongarch64'
elif host_cpu == 'riscv64'
        EFI_MACHINE_TYPE_NAME = 'riscv64'
        gnu_efi_arch = 'riscv64'
else
        error('Unknown host_cpu ' + host_cpu)
endif

# sanity check the packager set this to *SOMETHING*
if get_option('efi_sbat_distro_id') == ''
    warning('-Defi_sbat_distro_id is unset, see README.md')
endif

configure_file(
  output : 'config.h',
  configuration : conf
)

pkgg = import('pkgconfig')
pkgg.generate(
  version : meson.project_version(),
  name : meson.project_name(),
  filebase : 'fwupd-efi',
  description : 'fwupd-efi is the UEFI binary used with fwupd for installing UEFI firmware updates',
)

fwupd_efi_dep = declare_dependency()

# SBOM support
uswid = find_program('uswid', required: false)
if not uswid.found()
  warning('uswid is unfound, so not embedding uSWID metadata')
endif

subdir('efi')
