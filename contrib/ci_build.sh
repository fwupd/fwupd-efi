#!/usr/bin/env sh
set -eu

if command -v git >/dev/null 2>&1; then
    # disable the safe directory feature
    git config --global safe.directory "*"
fi

MESON_ARGS=""

case "${TARGET:-}" in
    gnu)
        export CC=gcc
        export OBJCOPY=objcopy
        export AR=ar
        export STRIP=strip
    ;;
    llvm)
        export CC=clang
        export CC_LD=lld
        export OBJCOPY=llvm-objcopy
        export AR=llvm-ar
        export STRIP=llvm-strip
        MESON_ARGS="-Dc_link_args=--rtlib=compiler-rt"
    ;;
    none)
        unset CC
        unset CC_LD
        unset OBJCOPY
        unset AR
        unset STRIP
    ;;
    *)
    ;;
esac

echo "Running on: $(uname -m)"

rm -rf build/

meson setup build $MESON_ARGS || {
    status=$?
    cat ./build/meson-logs/meson-log.txt
    exit "$status"
}
ninja -C build
