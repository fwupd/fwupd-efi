project('fwupd-efi', 'c',
  version : '1.1',
  license : 'LGPL-2.1+',
  meson_version : '>=0.53.0',
  default_options : ['warning_level=2', 'c_std=c99'],
)

cc = meson.get_compiler('c')

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
else
        error('Unknown host_cpu ' + host_cpu)
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
