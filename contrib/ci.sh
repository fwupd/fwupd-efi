#!/bin/bash
set -e
set -x
shopt -s extglob
rm -rf build/

if [ "$OS" = "fedora" ]; then
    meson build
    VERSION=`meson introspect build --projectinfo | jq -r .version`
    RPMVERSION=${VERSION//-/.}
    sed "s,#VERSION#,$RPMVERSION,;
         s,#BUILD#,1,;
         s,#LONGDATE#,`date '+%a %b %d %Y'`,;
         s,#ALPHATAG#,alpha,;
         s,Source0.*,Source0:\tfwupd-efi-$VERSION.tar.xz," \
        contrib/fwupd-efi.spec.in > build/fwupd-efi.spec
    if [ -n "$CI" ]; then
        sed -i "s,enable_ci 0,enable_ci 1,;" build/fwupd-efi.spec
    fi
    ninja -C build dist
    mkdir -p $HOME/rpmbuild/SOURCES/
    mv build/meson-dist/fwupd-efi-$VERSION.tar.xz $HOME/rpmbuild/SOURCES/
    rpmbuild -ba build/fwupd-efi.spec
    mkdir -p dist
    cp $HOME/rpmbuild/RPMS/*/*.rpm dist
elif [ "$OS" = "debian-x86_64" ] || [ "$OS" = "debian-i386" ]; then
    export DEBFULLNAME="CI Builder"
    export DEBEMAIL="ci@travis-ci.org"
    VERSION=`head meson.build | grep ' version :' | cut -d \' -f2`
    mkdir -p build
    cp -lR !(build|dist|venv) build/
    pushd build
    mv contrib/debian .
    sed s/quilt/native/ debian/source/format -i
    #build the package
    EDITOR=/bin/true dch --create --package fwupd-efi -v $VERSION "CI Build"
    debuild --no-lintian --preserve-envvar CI --preserve-envvar CC \
        --preserve-envvar QUBES_OPTION
else
    meson build
    ninja -C build
fi
