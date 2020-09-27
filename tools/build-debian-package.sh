#!/bin/sh
#
# Written by Daniil Baturin, 2018
# Rewritten by Ondřej Surý, 2020
# This file is public domain
set -e

BASEDIR="$(realpath -e "$(dirname "$(dirname "$0")")")"
cd "$BASEDIR"

#
# Directory where the git-buildpackage does the work
#
WORKDIR=$(mktemp -d /tmp/debwork-XXXXXXXX) || exit 1
trap '( rm -rf "$WORKDIR" )' EXIT

#
# Checking requirements
#

if [ "$(id -u)" = 0 ]; then
	echo "Running as root - installing dependencies"
	apt-get install fakeroot debhelper devscripts git-buildpackage lsb-release
	mk-build-deps --install debian/control
	exit 0
fi

git diff-index --quiet HEAD || { echo "ERROR: git working directory is not clean!" ; exit 1; }

#
# We switch to a separate branch to not mangle the actual branch, this is
# not needed in the CI
#

CLONEDIR="$WORKDIR/$(basename "$BASEDIR")"

echo "Creating shallow clone from $BASEDIR to $CLONEDIR..."

git clone --depth=2 "file://$BASEDIR" "$CLONEDIR"
cd "$CLONEDIR"

####################################
# Build the Debian package sources #
####################################

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

#
# We add a Debian changelog entry, and use artifical "since commit"
# so there's not a whole git history in the debian/changelog.
#
# The --snapshot option appends ~1.<shorthash> to the debian version, so for the
# release build, this needs to be replaces with --release
#

echo "Adding new snapshot debian/changelog entry for $DEBIAN_VERSION..."

gbp dch \
    --ignore-branch \
    --new-version "$DEBIAN_VERSION" \
    --dch-opt="--force-bad-version" \
    --since="HEAD~" \
    --snapshot \
    --commit

echo "Building package..."

#
# git-buildpackage will use $BUILDER command to just build new source package
#

BUILDER="dpkg-buildpackage -uc -us --build=source --no-check-builddeps --no-pre-clean -sa"
UPSTREAM_COMPRESSION=xz

gbp buildpackage \
    --git-export-dir="$WORKDIR" \
    --git-builder="$BUILDER" \
    --git-ignore-branch \
    --git-force-create \
    --git-compression=$UPSTREAM_COMPRESSION \
    --git-no-pristine-tar

DEB_SOURCE="$(dpkg-parsechangelog -SSource)"
DEB_VERSION="$(dpkg-parsechangelog -SVersion)"
DEB_VERSION_UPSTREAM_REVISION="$(echo "${DEB_VERSION}" | sed -e 's/^[0-9]*://')"
DEB_VERSION_UPSTREAM="$(echo "${DEB_VERSION_UPSTREAM_REVISION}" | sed -e 's/-[^-]*$//')"

#
# Now the source package has been built and it is stored in following files:
#

echo "Running lintian on the source package"

lintian "${WORKDIR}/${DEB_SOURCE}_${DEB_VERSION_UPSTREAM_REVISION}_source.changes"

####################
# Backporting part #
####################

#
# Now we determine what should be the suffix for the system we are backporting
# for.
#

DIST=$(lsb_release --codename --short)
PATCH=${PATCH:-1}

case "$DIST" in
    jessie)  EXTRA_VERSION="deb8u${PATCH}" ;;
    stretch) EXTRA_VERSION="deb9u${PATCH}" ;;
    buster)  EXTRA_VERSION="deb10u${PATCH}" ;;
    sid)     EXTRA_VERSION="sid+${PATCH}" ;;
    xenial)  EXTRA_VERSION="ubuntu16.04+${PATCH}" ;;
    bionic)  EXTRA_VERSION="ubuntu16.04+${PATCH}" ;;
    focal)   EXTRA_VERSION="ubuntu20.04+${PATCH}" ;;
    groovy)  EXTRA_VERSION="ubuntu20.10+${PATCH}" ;;
    *) echo "Unknown distribution '$DIST'" ; exit 1 ;;
esac

#
# Now the actual backport, we:
#
# 1. Unpack the sources
# 2. Append the EXTRA_VERSION
# 3. Use debuild to build the package (don't sign
#

(cd "$WORKDIR" && dpkg-source -x "${DEB_SOURCE}_${DEB_VERSION_UPSTREAM_REVISION}.dsc")
(cd "$WORKDIR/${DEB_SOURCE}-${DEB_VERSION_UPSTREAM}/" && dch -b -m -t -l "~$EXTRA_VERSION" "No change backport build for $DIST")
(cd "$WORKDIR/${DEB_SOURCE}-${DEB_VERSION_UPSTREAM}/" && debuild -uc -us)

#
# Copy back the result
#

cp -a "$WORKDIR"/*.build "$WORKDIR"/*.buildinfo "$WORKDIR"/*.changes "$WORKDIR"/*.dsc "$WORKDIR"/*.deb "$WORKDIR"/*.debian.* "$WORKDIR"/*.orig.tar.* "${BASEDIR}/"
