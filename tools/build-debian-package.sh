#!/bin/sh
#
# Written by Daniil Baturin, 2018
# This file is public domain
set -e

cd "`dirname $0`"
cd ..

if [ "`id -u`" = 0 ]; then
	echo "Running as root - installing dependencies"
	apt-get install fakeroot debhelper devscripts
	mk-build-deps --install debian/control
	exit 0
fi

git diff-index --quiet HEAD || echo "Warning: git working directory is not clean!"

echo "Preparing the build"
tools/tarsource.sh -V

echo "Building the Debian package"
if test $# -eq 0; then
	dpkg-buildpackage -b -uc -us
else
	dpkg-buildpackage "$@"
fi
