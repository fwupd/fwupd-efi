# EFI executable for fwupd
This repository contains the source used for the fwupd project to generate a UEFI binary for installing updates using the `UpdateCapsule` runtime service.

It was imported from the combined fwupd project, but is maintained separately to allow fwupd userspace releases and fwupd-efi UEFI executable releases at a different candence.

UEFI SBAT Support
-----------------

The packager should also specify the SBAT metadata required for the secure boot
revocation support. See the specification for more information: https://github.com/rhboot/shim/blob/sbat/SBAT.md

Typically, this will be set as part of the package build script, e.g.

    -Defi_sbat_distro_id="fedora" \
    -Defi_sbat_distro_summary="The Fedora Project" \
    -Defi_sbat_distro_pkgname="%{name}" \
    -Defi_sbat_distro_version="%{version}" \
    -Defi_sbat_distro_url="https://src.fedoraproject.org/rpms/%{name}" \
