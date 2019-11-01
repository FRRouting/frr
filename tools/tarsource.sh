#!/bin/bash
# 2018 by David Lamparter, placed in the Public Domain

help() {
	cat <<EOF
FRR tarball/dsc helper, intended to run from a git checkout

Usage:
	./tarsource.sh [-dDn] [-i GITPATH] [-o OUTDIR] [-S KEYID]
			[-C COMMIT] [-e EXTRAVERSION] [-z gz|xz]

options:
    -i GITPATH		path to git working tree or bare repository.
			- default: parent directory containing this script
    -o OUTDIR		path to place the generated output files in.
			- default: current directory
    -C COMMIT		build tarball for specified git commit
			- default: current HEAD
    -e EXTRAVERSION	override automatic package extraversion
			- default "-YYYYMMDD-NN-gGGGGGGGGGGGG", but the script
			  autodetects if a release tag is checked out
    -z gz|xz		compression format to use
			- default: xz
    -S KEYID		sign the output with gpg key
    -d			use dirty git tree with local changes
    -D			generate Debian .dsc and .debian.tar.xz too
			(note: output files are moved to parent directory)
    -l			remove Debian auto-build changelog entry
			(always done for releases)
    -V			write version information to config.version and exit
    -n			allow executing from non-git source (NOT RECOMMENDED)
    -h			show this help text

Note(1) that this script tries very hard to generate a deterministic,
reproducible tarball by eliminating timestamps and similar things.  However,
since the tarball includes autoconf/automake files, the versions of these
tools need to be _exactly_ identical to get the same tarball.

Note(2) the debian ".orig" tarball is always identical to the "plain" tarball
generated without the -D option.

Note(3) if you want the tool to identify github PRs, you need to edit your
.git/config to fetch PRs from github like this:

	[remote "origin"]
		url = git@github.com:frrouting/frr.git
		fetch = +refs/heads/*:refs/remotes/origin/*
ADD:		fetch = +refs/pull/*/head:refs/remotes/origin/pull/*
EOF
}

set -e

options=`getopt -o 'hi:o:C:S:e:z:DdnlV' -l help -- "$@"`
debian=false
dirty=false
nongit=false
zip=xz
adjchangelog=false
writeversion=false
extraset=false
set - $options
while test $# -gt 0; do
	arg="$1"; shift; optarg=$1
	case "$arg" in
	-h|--help)	help; exit 0;;
	-d)		dirty=true;;
	-D)		debian=true;;
	-n)		nongit=true;;
	-i)		eval src=$optarg; shift;;
	-C)		eval commit=$optarg; shift;;
	-o)		eval outdir=$optarg; shift;;
	-e)		eval extraver=$optarg; extraset=true; shift;;
	-z)		eval zip=$optarg; shift;;
	-S)		eval keyid=$optarg; shift;;
	-l)		adjchangelog=true;;
	-V)		writeversion=true;;
	--)		break;;
	*)		echo something went wrong with getopt >&2
			exit 1
			;;
	esac
done

cwd="`pwd`"
outdir="${outdir:-$cwd}"

if test -e "$outdir" -a \! -d "$outdir"; then
	echo "output $outdir must be a directory" >&2
	exit 1
elif test \! -d "$outdir"; then
	mkdir -p "$outdir"
fi

cd "$outdir"
outdir="`pwd`"
cd "$cwd"
cd "`dirname $0`/.."
selfdir="`pwd`"
src="${src:-$selfdir}"

if $writeversion; then
	if $nongit; then
		echo "The -V option cannot be used without a git tree" >&2
		exit 1
	fi
	dirty=true
fi

case "$zip" in
gz)	ziptarget=dist-gzip; ziptool="gzip -n -9"; unzip="gzip -k -c";;
xz)	ziptarget=dist-xz;   ziptool="xz -z -e";   unzip="xz -d -k -c";;
*)	echo "unknown compression format $zip" >&2
	exit 1
esac

# always overwrite file ownership in tars
taropt="--owner=root --group=root"

onexit() {
	rv="$?"
	set +e
	test -n "$tmpdir" -a -d "$tmpdir" && rm -rf "$tmpdir"

	if test "$rv" -ne 0; then
		echo -e "\n\033[31;1mfailed\n" >&2
		if test "$dirty" = true; then
			echo please try running the script without the -d option.>&2
		fi
	fi
	exit $rv
}
trap onexit EXIT
tmpdir="`mktemp -d -t frrtar.XXXXXX`"

if test -e "$src/.git"; then
	commit="`git -C \"$src\" rev-parse \"${commit:-HEAD}\"`"

	if $dirty; then
		cd "$src"
		echo -e "\033[31;1mgit: using dirty worktree in $src\033[m" >&2
	else
		echo -e "\033[33;1mgit: preparing a clean clone of $src\033[m"
		branch="${tmpdir##*/}"
		cd "$tmpdir"

		git -C "$src" branch "$branch" "$commit"
		git clone --single-branch -s -b "$branch" "$src" source
		git -C "$src" branch -D "$branch"
		cd source
	fi

	# if we're creating a tarball from git, force the timestamps inside
	# the tar to match the commit date - this makes the tarball itself
	# reproducible
	gitts="`TZ=UTC git show -s --format=%cd --date=local $commit`"
	gitts="`TZ=UTC date -d "$gitts" '+%Y-%m-%dT%H:%M:%SZ'`"
	taropt="--mtime=$gitts $taropt"

	# check if we're on a release tag
	gittag="`git -C \"$src\" describe --tags --match 'frr-*' --first-parent --long $commit`"
	gittag="${gittag%-g*}"
	gittag="${gittag%-*}"

	# if there have been changes to packaging or tests, it's still the
	# same release
	changes="`git diff --name-only "$gittag" $commit | \
		egrep -v '\.git|^m4/|^config|^README|^alpine/|^debian/|^pkgsrc/|^ports/|^redhat/|^snapcraft/|^solaris/|^tests/|^tools/|^gdb/|^docker/|^\.' | \
		wc -l`"
	if test "$changes" -eq 0; then
		adjchangelog=true
		echo "detected release build for tag $gittag" >&2
		$extraset || extraver=""
	elif ! $adjchangelog; then
		gitdate="`TZ=UTC date -d "$gitts" '+%Y%m%d'`"
		gitrev="`git rev-parse --short $commit`"
		dayseq="`git rev-list --since \"${gitts%T*} 00:00:00 +0000\" $commit | wc -l`"
		dayseq="`printf '%02d' $(( $dayseq - 1 ))`"

		$extraset || extraver="-$gitdate-$dayseq-g$gitrev"

		git -C "$src" remote -v | grep fetch | sed -e 's% (fetch)$%%' \
			| egrep -i '\b(git@github\.com:frrouting/frr\.git|https://github\.com/FRRouting/frr\.git)$' \
			| while read remote; do
			remote="${remote%%	*}"

			git -C "$src" var -l | egrep "^remote.$remote.fetch=" \
				| while read fetch; do
				fetch="${fetch#*=}"
				from="${fetch%:*}"
				to="${fetch#*:}"
				if test "$from" = "+refs/pull/*/head"; then
					name="`git -C \"$src\" name-rev --name-only --refs \"$to\" $commit`"
					test "$name" = "undefined" && continue
					realname="${name%~*}"
					realname="${realname%%^*}"
					realname="${realname%%@*}"
					if test "$realname" = "$name"; then
						echo "${name##*/}" > "$tmpdir/.gitpr"
						break
					fi
				fi
			done || true
			test -n "$gitpr" && break
		done || true
		test $extraset = false -a -f "$tmpdir/.gitpr" && extraver="-PR`cat \"$tmpdir/.gitpr\"`$extraver"
	fi

	debsrc="git ls-files debian/"
else
	if $nongit; then
		echo -e "\033[31;1mWARNING: this script should be executed from a git tree\033[m" >&2
	else
		echo -e "\033[31;1mERROR: this script should be executed from a git tree\033[m" >&2
		exit 1
	fi
	debsrc="echo debian"
fi

if $writeversion; then
	pkgver="`egrep ^AC_INIT configure.ac`"
	pkgver="${pkgver#*,}"
	pkgver="${pkgver%,*}"
	pkgver="`echo $pkgver`" # strip whitespace
	pkgver="${pkgver#[}"
	pkgver="${pkgver%]}"

	echo -e "\033[32;1mwriting version ID \033[36;1mfrr-$pkgver$extraver\033[m"

	cat > config.version <<EOF
# config.version override by tarsource.sh
EXTRAVERSION="$extraver"
DIST_PACKAGE_VERSION="$pkgver$extraver"
gitts="$gitts"
taropt="$taropt"
EOF
	sed -e "s%@VERSION@%$pkgver$extraver%" \
		< changelog-auto.in \
		> changelog-auto
	exit 0
fi

echo -e "\033[33;1mpreparing source tree\033[m"

# config.version will also overwrite gitts and taropt when tarsource.sh
# was used to write the config.version file before - but configure will
# overwrite config.version down below!
if test -f config.version; then
	# never executed for clean git build
	. ./config.version
	if $nongit; then
		$extraset || extraver="$EXTRAVERSION"
	fi
fi
if test \! -f configure; then
	# always executed for clean git build
	./bootstrap.sh
fi
if test "$EXTRAVERSION" != "$extraver" -o \! -f config.status; then
	# always executed for clean git build
	# options don't matter really - we just want to make a dist tarball
	./configure --with-pkg-extra-version=$extraver
fi

. ./config.version
PACKAGE_VERSION="$DIST_PACKAGE_VERSION"

echo -e "\033[33;1mpacking up \033[36;1mfrr-$PACKAGE_VERSION\033[m"

make GZIP_ENV="-n9" am__tar="tar -chof - $taropt \"\$\$tardir\"" $ziptarget
mv frr-${PACKAGE_VERSION}.tar.$zip "$outdir" || true
lsfiles="frr-${PACKAGE_VERSION}.tar.$zip"

if $debian; then
	mkdir -p "$tmpdir/debian/source"
	cat debian/changelog > "$tmpdir/debian/changelog"
	if $adjchangelog; then
		if grep -q 'autoconf changelog entry' debian/changelog; then
			tail -n +9 debian/changelog > "$tmpdir/debian/changelog"
		fi
	fi
	echo '3.0 (quilt)' > "$tmpdir/debian/source/format"
	DEBVER="`dpkg-parsechangelog -l\"$tmpdir/debian/changelog\" -SVersion`"

	eval $debsrc | tar -cho $taropt \
		--exclude-vcs --exclude debian/source/format \
		--exclude debian/changelog \
		--exclude debian/changelog-auto \
		--exclude debian/changelog-auto.in \
		--exclude debian/subdir.am \
		-T - -f ../frr_${DEBVER}.debian.tar
	# add specially prepared files from above
	tar -uf ../frr_${DEBVER}.debian.tar $taropt -C "$tmpdir" debian/source/format debian/changelog

	test -f ../frr_${DEBVER}.debian.tar.$zip && rm -f ../frr_${DEBVER}.debian.tar.$zip
	$ziptool ../frr_${DEBVER}.debian.tar

	# pack up debian files proper
	ln -s "$outdir/frr-${PACKAGE_VERSION}.tar.$zip" ../frr_${PACKAGE_VERSION}.orig.tar.$zip
	dpkg-source -l"$tmpdir/debian/changelog" \
		--format='3.0 (custom)' --target-format='3.0 (quilt)' \
		-b . frr_${PACKAGE_VERSION}.orig.tar.$zip frr_${DEBVER}.debian.tar.$zip

	dpkg-genchanges -sa -S > ../frr_${DEBVER}_source.changes

	test -n "$keyid" && debsign ../frr_${DEBVER}_source.changes  -k"$keyid"

	mv ../frr_${DEBVER}_source.changes "$outdir" || true
	mv ../frr_${DEBVER}.dsc "$outdir" || true
	mv ../frr_${DEBVER}.debian.tar.$zip "$outdir" || true
	if test -h ../frr_${PACKAGE_VERSION}.orig.tar.$zip; then
		rm ../frr_${PACKAGE_VERSION}.orig.tar.$zip || true
	fi
	ln -s frr-${PACKAGE_VERSION}.tar.$zip "$outdir/frr_${PACKAGE_VERSION}.orig.tar.$zip" || true

	cd "$outdir"

	lsfiles="$lsfiles \
		frr_${DEBVER}.dsc \
		frr_${DEBVER}.debian.tar.$zip \
		frr_${PACKAGE_VERSION}.orig.tar.$zip \
		frr_${DEBVER}_source.changes"
fi

cd "$outdir"
if test -n "$keyid"; then
	$unzip frr-${PACKAGE_VERSION}.tar.$zip > frr-${PACKAGE_VERSION}.tar
	test -f frr-${PACKAGE_VERSION}.tar.asc && rm frr-${PACKAGE_VERSION}.tar.asc
	if gpg -a --detach-sign -u "$keyid" frr-${PACKAGE_VERSION}.tar; then
		lsfiles="$lsfiles frr-${PACKAGE_VERSION}.tar.asc"
	fi
	rm frr-${PACKAGE_VERSION}.tar
fi

echo -e "\n\033[32;1mdone: \033[36;1mfrr-$PACKAGE_VERSION\033[m\n"
ls -l $lsfiles
