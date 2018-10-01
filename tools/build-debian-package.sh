#!/bin/sh
#
# Written by Daniil Baturin, 2018
# This file is public domain

git diff-index --quiet HEAD || echo "Warning: git working directory is not clean!"

# Set the defaults
if [ "$EXTRA_VERSION" = "" ]; then
    EXTRA_VERSION="-MyDebPkgVersion"
fi

if [ "$WANT_SNMP" = "" ]; then
    WANT_SNMP=0
fi

if [ "$WANT_CUMULUS_MODE" = "" ]; then
    WANT_CUMULUS_MODE=0
fi

echo "Preparing the build"
./bootstrap.sh
./configure --with-pkg-extra-version=$EXTRA_VERSION
make dist

echo "Preparing Debian source package"
mv debianpkg debian
make -f debian/rules backports

echo "Unpacking the source to frrpkg/"
mkdir frrpkg
cd frrpkg
tar xf ../frr_*.orig.tar.gz
cd frr*
. /etc/os-release
tar xf ../../frr_*${ID}${VERSION_ID}*.debian.tar.xz

echo "Building the Debian package"
debuild --no-lintian --set-envvar=WANT_SNMP=$WANT_SNMP --set-envvar=WANT_CUMULUS_MODE=$WANT_CUMULUS_MODE -b -uc -us

