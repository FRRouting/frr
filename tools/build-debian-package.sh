#!/bin/sh
#
# Written by Daniil Baturin, 2018
# Rewritten by Ondřej Surý, 2020
# This file is public domain
set -e

cd "$(dirname "$(dirname "$0")")"

if [ "$(id -u)" = 0 ]; then
	echo "Running as root - installing dependencies"
	apt-get install fakeroot debhelper devscripts git-buildpackage
	mk-build-deps --install debian/control
	exit 0
fi

git diff-index --quiet HEAD || { echo "ERROR: git working directory is not clean!" ; exit 1; }

HEAD_COMMIT=$(git rev-parse --short HEAD)
HEAD_BRANCH=$(git rev-parse --abbrev-ref HEAD)
BUILD_BRANCH="debian/$HEAD_BRANCH-$(date +%s)"

echo "Switching to a '$BUILD_BRANCH' build branch"

git checkout -b "$BUILD_BRANCH" "$HEAD_BRANCH"

UPSTREAM_VERSION=$(sed -ne 's/AC_INIT(\[frr\],\s\[\([^]]*\)\],.*/\1/p' configure.ac | sed -e 's/-\(\(dev\|alpha\|beta\)\d*\)/~\1/')
LAST_TIMESTAMP=$(git log --format=format:%ad --date=format:%Y%m%d -1 "$HEAD_COMMIT")
SINCE_COMMIT=$(git log --since="00:00:00" --format=format:%H | tail -1)
DEBIAN_VERSION="$UPSTREAM_VERSION-$LAST_TIMESTAMP-git.$HEAD_COMMIT-1"

echo "Adding new snapshot debian/changelog entry for $DEBIAN_VERSION"

gbp dch \
    --debian-branch="$BUILD_BRANCH" \
    --new-version "$DEBIAN_VERSION" \
    --since="$SINCE_COMMIT~" \
    --snapshot \
    --commit

echo "Building package"

gbp buildpackage \
    --git-builder=debuild \
    --git-debian-branch="$BUILD_BRANCH" \
    --git-force-create \
    --git-no-pristine-tar

echo "Switching back to '$HEAD_BRANCH' branch"

git checkout "$HEAD_BRANCH"

echo "Deleting the '$BUILD_BRANCH' build branch"

git branch -D "$BUILD_BRANCH"
