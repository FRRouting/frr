#!/bin/sh

exec 3>&1
exec 1>/dev/null

#
# I/O & interfacing & reporting bits
#

# steal the parent's stdout, since ours is redirected
if test -e "/proc/${PPID}/fd/1"; then
	test -e "$(readlink /proc/${PPID}/fd/1)" \
		&& exec 1>>"/proc/${PPID}/fd/1"
fi

ok() {
	echo "frr-format: $@"
	printf "%s" "-fplugin=tools/gcc-plugins/frr-format-${fullver}.so" >&3
	exit 0
}

weakfail() {
	echo "frr-format: $@"
	exit 1
}

strongfail() {
	if test -t 2 -a -z "$NO_COLOR" -a "$COLORTERM"; then
		C0="$(printf '\033[33m')"
		C1="$(printf '\033[m')"
	fi
	cat >&2 <<EOF
$C0=================================================================
frr-format: $@

Somewhere on earth, a panda is sad now.
Please make it happy by installing GCC plugin development files.

Debian/Ubuntu: sudo apt install gcc-$shortver-plugin-dev
Fedora: part of main GCC package, is your GCC install broken?
=================================================================$C1
EOF
	exit 1
}

#
# actual core - detect & try to build GCC plugin
#

test "$CC" || weakfail "CC not set?"
# clang has no "-dumpfullversion"
$CC -dumpfullversion >/dev/null 2>/dev/null \
	|| weakfail "disabled, compiler doesn't seem to be GCC"

# unfortunately even "-dumpfullversion" isn't enough to ensure compatibility
# "micro-minor" GCC changes also require a rebuild
#  => hash the configure args too
infohash="-$($CC -v 2>&1 | grep -E '^(Configured with:|gcc version)' | sha1sum | cut -c 1-16)"
# 15.2.0
fullver="$($CC -dumpfullversion)$infohash"
# 15
shortver="$($CC -dumpversion)"

# lots of situations possible with paths, unfortunately...

if test "${top_builddir}"; then
	outdir="${top_builddir%/}/tools/gcc-plugins"
else
	outdir="$(dirname "$0")"
fi

test -f "$outdir/frr-format-${fullver}.so" \
	&& ok "enabled (gcc-${fullver})"

# NB: "srcdir" is relative to the output directory (used for symlink and VPATH)
if test -z "${top_srcdir}"; then
	srcdir="$(realpath "$(dirname "$0")")"
elif test "${top_srcdir}" = "${top_srcdir#/}"; then
	# top_srcdir not absolute path; but we're going down 2 dirs
	srcdir="../../${top_srcdir%/}/tools/gcc-plugins"
else
	srcdir="${top_srcdir%/}/tools/gcc-plugins"
fi

mkdir -p "$outdir"
test -e "$outdir/Makefile" \
	|| ln -s "${srcdir}/Makefile" "$outdir/Makefile"
make VPATH="${srcdir}" CC=gcc-${shortver} CXX=g++-${shortver} VERSUFFIX="$infohash" -C "$outdir" \
	|| strongfail "build for gcc ${fullver} failed"
ok "enabled (gcc-${fullver}, freshly built)"
