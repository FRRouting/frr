#!/bin/sh
# SPDX-License-Identifier: NONE
#
# Written by Daniil Baturin, 2018
# Rewritten by Ondřej Surý, 2020
# This file is public domain
set -e

cd "$(dirname "$0")/.."

#
# Checking requirements
#

if [ "$(id -u)" = 0 ]; then
	echo "Running as root - installing dependencies"
	apt-get install fakeroot debhelper devscripts git-buildpackage lsb-release
	mk-build-deps --install debian/control
	exit 0
fi

git diff-index --quiet HEAD || echo "Warning: git working directory is not clean!"

############################
# Build the Debian package #
############################

#
# Now we will construct an "upstream" version out of:
# 1. version in AC_INIT
# 2. the unix time from the last commit (HEAD)
#    (alternatively %Y%m%d%H%M%S could be used here)
# 4. Debian version (always -1)
#

UPSTREAM_VERSION=$(sed -ne 's/AC_INIT(\[frr\],\s\[\([^]]*\)\],.*/\1/p' configure.ac | sed -e 's/-\(\(dev\|alpha\|beta\)\d*\)/~\1/')
LAST_TIMESTAMP=$(git log --format=format:%ad --date=format:%s -1 "HEAD")
DEBIAN_VERSION="$UPSTREAM_VERSION-$LAST_TIMESTAMP-1"
DEBIAN_BRANCH=$(git rev-parse --abbrev-ref HEAD)

#
# We add a Debian changelog entry, and use artifical "since commit"
# so there's not a whole git history in the debian/changelog.
#
# The --snapshot option appends ~1.<shorthash> to the debian version, so for the
# release build, this needs to be replaces with --release
#

echo "Adding new snapshot debian/changelog entry for $DEBIAN_VERSION..."

gbp dch \
    --debian-branch="$DEBIAN_BRANCH" \
    --new-version="$DEBIAN_VERSION" \
    --dch-opt="--force-bad-version" \
    --since="HEAD~" \
    --snapshot \
    --commit \
    --git-author

echo "Building package..."

#
# git-buildpackage will use $BUILDER command to just build new binary package
#

BUILDER="dpkg-buildpackage -uc -us --build=binary --no-check-builddeps --no-pre-clean -sa"
UPSTREAM_COMPRESSION=xz

gbp buildpackage \
    --git-export-dir="$WORKDIR" \
    --git-builder="$BUILDER" \
    --git-debian-branch="$DEBIAN_BRANCH" \
    --git-force-create \
    --git-compression=$UPSTREAM_COMPRESSION \
    --git-no-pristine-tar \
    --git-ignore-new
