# EFI executable for fwupd

This repository contains the source used for the fwupd project to generate a
UEFI binary for installing updates using the `UpdateCapsule` runtime service.

It was originally imported from the combined fwupd project, and is now maintained
separately to allow fwupd userspace releases and fwupd-efi UEFI executable releases
to follow a different cadence.

## Compatibility

### 1.1.x through 1.5.x

This UEFI executable is compatible will all fwupd releases from `1_1_X` and newer.
In these fwupd sustaining releases, the EFI source continues to be distributed,
but a new *fwupd* meson build option `-Defi_binary=false` is introduced which
will allow disabling the compilation of built-in fwupd EFI binary.

### 1.6.x and newer

The fwupd EFI source has been removed from the releases and is now distributed
by this repository.

Hand-building fwupd will perform a subproject checkout of *fwupd-efi* and build
the binary at the same time.

All packagers should generate separate source packages for *fwupd* and
*fwupd-efi*. In the *fwupd* package, the subproject behavior should be explicitly
disabled using `-Defi_binary=false`.

## Standalone compilation

`fwupd-efi` uses the `meson` system to build EFI executables.  Install `gnu-efi`
and then follow these instructions to build and install locally:

```bash
meson build
ninja -C build
ninja -C build install
```

## UEFI SBAT Support

The packager should also specify the SBAT metadata required for the secure boot
revocation support. See the [specification](https://github.com/rhboot/shim/blob/main/SBAT.md)
for more information.

Typically, this will be set as part of the packager build script, e.g.

```meson
    -Defi_sbat_distro_id="fedora" \
    -Defi_sbat_distro_summary="The Fedora Project" \
    -Defi_sbat_distro_pkgname="%{name}" \
    -Defi_sbat_distro_version="%{version}" \
    -Defi_sbat_distro_url="https://src.fedoraproject.org/rpms/%{name}" \
```
