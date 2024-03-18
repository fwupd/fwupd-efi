arch_crt_source = 'crt0-efi-@0@.S'.format(gnu_efi_arch)

crt0_compile_args = compile_args

# Subsystem
crt0_compile_args += ['-DEFI_SUBSYSTEM=10']

# Section data
nr_sections = 4
if get_option('efi_sbat_distro_id') != ''
  crt0_compile_args += ['-DUSING_SBAT']
  nr_sections = nr_sections + 1
endif
if uswid.found()
  crt0_compile_args += ['-DUSING_SBOM']
  nr_sections = nr_sections + 1
endif
crt0_compile_args += ['-DNR_SECTIONS=@0@'.format(nr_sections)]


o_crt0 = custom_target('efi_crt0',
                       input : arch_crt_source,
                       output : arch_crt,
                       command : [cc.cmd_array(), '-c', '@INPUT@', '-o', '@OUTPUT@']
                       + crt0_compile_args)

