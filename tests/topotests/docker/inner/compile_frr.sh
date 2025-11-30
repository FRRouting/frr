#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")

set -e

# Load shared functions
CDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. $CDIR/funcs.sh

#
# Script begin
#

# Check if FRR packages are already installed and skip build if requested
if [ "${TOPOTEST_SKIP_BUILD}" = "1" ]; then
	# Find packages directory - check multiple locations
	# The host home directory is mounted at the same path, so check:
	# 1. Container's $HOME/packages (usually /root/packages for root user)
	# 2. All /home/*/packages directories (for non-root host users)
	# 3. Check if TOPOTEST_PACKAGES_DIR is explicitly set
	PACKAGES_DIR=""
	
	# First check if explicitly set via environment variable
	if [ -n "${TOPOTEST_PACKAGES_DIR}" ] && [ -d "${TOPOTEST_PACKAGES_DIR}" ] && [ -n "$(ls -A "${TOPOTEST_PACKAGES_DIR}"/*.deb 2>/dev/null)" ]; then
		PACKAGES_DIR="${TOPOTEST_PACKAGES_DIR}"
	else
		# Check common locations
		for dir in "$HOME/packages" /home/*/packages; do
			# Expand glob patterns
			for expanded_dir in $dir; do
				if [ -d "$expanded_dir" ] && [ -n "$(ls -A "$expanded_dir"/*.deb 2>/dev/null)" ]; then
					PACKAGES_DIR="$expanded_dir"
					break 2
				fi
			done
		done
	fi
	
	# If found, install packages
	if [ -n "$PACKAGES_DIR" ]; then
		log_info "Found packages in $PACKAGES_DIR, installing..."
		# Copy packages to a writable location since the source is read-only
		mkdir -p /tmp/packages
		cp "$PACKAGES_DIR"/*.deb /tmp/packages/ 2>/dev/null || true
		if [ -n "$(ls -A /tmp/packages/*.deb 2>/dev/null)" ]; then
			# The package's postinst script now handles existing groups/users gracefully
			dpkg -i /tmp/packages/*.deb || apt-get install -f -y
			log_info "Packages installed from $PACKAGES_DIR"
		fi
	fi
	
	# Check if FRR packages are now installed
	if command -v zebra >/dev/null 2>&1 || \
	   [ -f /usr/lib/frr/zebra ] || \
	   dpkg -l | grep -q "^ii.*frr "; then
		log_info "FRR packages detected, skipping build (TOPOTEST_SKIP_BUILD=1)"
		# Still need to sync source for tests, even if we skip the build
		if [ "${TOPOTEST_CLEAN}" != "0" ]; then
			log_info "Cleaning FRR builddir..."
			rm -rf $FRR_BUILD_DIR &> /dev/null
		fi
		log_info "Syncing FRR source with host (needed for tests)..."
		mkdir -p $FRR_BUILD_DIR
		rsync -a --info=progress2 \
			--from0 --files-from=/tmp/git-ls-files \
			--chown root:root \
			$FRR_HOST_DIR/. $FRR_BUILD_DIR/
		exit 0
	fi
	log_warning "TOPOTEST_SKIP_BUILD=1 but no FRR packages found, building from source..."
fi

if [ "${TOPOTEST_CLEAN}" != "0" ]; then
	log_info "Cleaning FRR builddir..."
	rm -rf $FRR_BUILD_DIR &> /dev/null
fi

log_info "Syncing FRR source with host..."
mkdir -p $FRR_BUILD_DIR
rsync -a --info=progress2 \
	--from0 --files-from=/tmp/git-ls-files \
	--chown root:root \
	$FRR_HOST_DIR/. $FRR_BUILD_DIR/

cd "$FRR_BUILD_DIR" || \
	log_fatal "failed to find frr directory"

if [ "${TOPOTEST_VERBOSE}" != "0" ]; then
	exec 3>&1
else
	exec 3>/dev/null
fi

log_info "Building FRR..."

if [ ! -e configure ]; then
	bash bootstrap.sh >&3 || \
		log_fatal "failed to bootstrap configuration"
fi

if [ "${TOPOTEST_DOC}" != "0" ]; then
	EXTRA_CONFIGURE+=" --enable-doc "
else
	EXTRA_CONFIGURE+=" --disable-doc "
fi

if [ ! -e Makefile ]; then
	if [ "${TOPOTEST_SANITIZER}" != "0" ]; then
		export CC="gcc"
		export CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer"
		export LDFLAGS="-g -fsanitize=address -ldl"
		touch .address_sanitizer
	else
		rm -f .address_sanitizer
	fi

	bash configure >&3 \
		--enable-dev-build \
		--with-moduledir=/usr/lib/frr/modules \
		--prefix=/usr \
		--sysconfdir=/etc \
		--localstatedir=/var \
		--sbindir=/usr/lib/frr \
		--enable-multipath=0 \
		--enable-fpm \
		--enable-grpc \
		--enable-scripting \
		--enable-sharpd \
		$EXTRA_CONFIGURE \
		--with-pkg-extra-version=-topotests \
		|| log_fatal "failed to configure the sources"
fi

# if '.address_sanitizer' file exists it means we are using address sanitizer.
if [ -f .address_sanitizer ]; then
	make -C lib CFLAGS="-g -O2" LDFLAGS="-g" clippy >&3
fi

make -j$(cpu_count) >&3 || \
	log_fatal "failed to build the sources"

make install >/dev/null || \
	log_fatal "failed to install frr"
