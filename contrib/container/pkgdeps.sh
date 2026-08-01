#!/usr/bin/env sh
set -eu

if [ $# -lt 1 ]; then
    echo "usage DISTRO= $0 <features...>" >&2
    exit 1
fi

features="$*"
distro="${DISTRO:-}"

echo "Installer started:"
echo "- features: $features"

if [ -z "$distro" ]; then
  echo "Guessing distro by package manager"
  if   command -v apt    > /dev/null 2>&1; then distro='debian';
  elif command -v dnf    > /dev/null 2>&1; then distro='fedora';
  elif command -v pacman > /dev/null 2>&1; then distro='archlinux';
  elif command -v apk    > /dev/null 2>&1; then distro='alpine';
  fi
fi
case "$distro" in
  ubuntu*|debian*|fedora*|archlinux*|alpine*) ;;
  *) echo "$0: unsupported distribution '$distro'" >&2
     exit 1
  ;;
esac
echo "- distro  : $distro"

case "$distro" in
  "ubuntu"*|\
  "debian"*)  update="apt update -y"; pkgadd="apt install -y" ;;
  "fedora"*)  update="dnf -y update"; pkgadd="dnf -y install" ;;
  "arch"*)    update="";              pkgadd="pacman -Sy --noconfirm" ;;
  "alpine"*)  update="";              pkgadd="apk add --no-cache" ;;
  *)
    echo "$0: unsupported distribution '$distro'" >&2
    exit 1
    ;;
esac

packages=""
packages2=""
extra_command=""

## build dependencies
for f in $features; do
  case "$f" in

    # toolchain
    "base") case "$distro" in
        "ubuntu"*|\
        "debian"*) packages="$packages pkg-config python3 meson ninja-build" ;;
        "fedora"*) packages="$packages pkg-config python3 meson ninja-build" ;;
        "arch"*)   packages="$packages pkg-config python3 meson ninja"       ;;
        "alpine"*) packages="$packages pkgconfig  python3 meson ninja"       ;;
      esac ;;

    "gnu") case "$distro" in
        "alpine"*) packages="$packages gcc musl-dev binutils" ;;
        *)         packages="$packages gcc binutils" ;;
      esac ;;

    "llvm")        packages="$packages llvm clang lld compiler-rt"
      case "$distro" in
        "alpine"*) packages="$packages build-base" ;;
      esac ;;

    # deps
    "gnuefi") case "$distro" in
        "fedora"*) packages="$packages gnu-efi-devel"  ;;
        "alpine"*) packages="$packages gnu-efi-dev"  ;;
        *)         packages="$packages gnu-efi" ;;
      esac ;;

    "py3pe") case "$distro" in
        "arch"*)   packages="$packages python-pefile"  ;;
        "alpine"*) packages="$packages py3-pefile"  ;;
        *)         packages="$packages python3-pefile" ;;
      esac ;;

    # optional deps
    "genpeimg") case "$distro" in
        "fedora"*|\
        "ubuntu"*|\
        "debian"*) packages="$packages mingw-w64-tools" ;;
        *) echo "$f is not packaged for $distro"; exit 1 ;;
      esac ;;

    "uswid") case "$distro" in
        "fedora"*) packages="$packages python-uswid"  ;;
        *) extra_command="$extra_command && pip install uswid" ;;
      esac ;;

    *)  echo "$0: unknown feature '$f'" >&2;
        exit 1
    ;;
  esac
done

install_cmd="${pkgadd} ${packages}"
if [ -n "$update" ];        then install_cmd="${update} && ${install_cmd}"; fi
if [ -n "$extra_command" ]; then install_cmd="${install_cmd} ${extra_command}"; fi
echo "$install_cmd"

echo "- command : $install_cmd"
eval "$install_cmd"
