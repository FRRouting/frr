#!/bin/bash
# written 2012-2013 by David Lamparter, placed in Public Domain.
#
# builds some git commit of Quagga in some different configurations
# usage: buildtest.sh [commit [configurations...]]

basecfg="--prefix=/usr --enable-user=quagga --enable-group=quagga --enable-vty-group=quagga --enable-configfile-mask=0660 --enable-logfile-mask=0640 --enable-vtysh --sysconfdir=/etc/quagga --enable-exampledir=/etc/quagga/samples --localstatedir=/var/run/quagga --libdir=/usr/lib64/quagga --enable-ipv6 --enable-ripngd --enable-ospf6d --enable-rtadv --disable-static --enable-isisd --enable-multipath=0 --enable-babeld"

configs_base="gcc|$basecfg"

configs_nov6="gcc|$basecfg"
configs_nov6="${configs_nov6/enable-ipv6/disable-ipv6}"
configs_nov6="${configs_nov6/enable-ospf6d/disable-ospf6d}"
configs_nov6="${configs_nov6/enable-ripngd/disable-ripngd}"
configs_nov6="${configs_nov6/enable-babeld/disable-babeld}"

configs_ext="gcc|$basecfg --enable-opaque-lsa --enable-ospf-te --enable-ospfclient --enable-isis-topology"
configs_snmp="gcc|$basecfg --enable-opaque-lsa --enable-ospf-te --enable-ospfclient --enable-isis-topology --enable-snmp"
configs_clang="clang|$basecfg --enable-opaque-lsa --enable-ospf-te --enable-ospfclient --enable-isis-topology"
configs_icc="icc|$basecfg --enable-opaque-lsa --enable-ospf-te --enable-ospfclient --enable-isis-topology"

defconfigs="base nov6 ext"
net-snmp-config --version	&> /dev/null && defconfigs="$defconfigs snmp"
clang --version			&> /dev/null && defconfigs="$defconfigs clang"
icc --version			&> /dev/null && defconfigs="$defconfigs icc"

echo "enabled configurations: $defconfigs"

cc_gcc="CC=gcc; export CC"
cc_clang="CC=clang; export CC"
cc_icc="CC=icc; export CC"

###############################

errfunc() {
	echo "something went wrong! check $TEMP"
	exit 1
}

set -e
trap errfunc ERR

COMMITREF="$1"
COMMITISH="`git rev-list --max-count=1 ${COMMITREF:-HEAD}`"
TEMP="`mktemp -t -d quaggabuild.XXXXXX`"
BASE="`pwd`"
CONFIGS="$2"

echo using temporary directory: $TEMP
echo git commit used:
git --no-pager log -n 1 --pretty=oneline "$COMMITISH"

cd "$TEMP"
git clone "$BASE" "source"
cd "source"
git checkout -b build "$COMMITISH"
git clean -d -f -x
sh bootstrap.sh

cd ..

echo -e "\n\n\n\n\033[33;1mmaking dist tarball\033[m"

mkdir build_dist
cd build_dist
../source/configure
make distdir=sdist dist-gzip
cd ..
tar zxvf build_dist/sdist.tar.gz

for cfg in ${CONFIGS:-$defconfigs}; do
	echo -e "\n\n\n\n\033[33;1mbuilding configuration $cfg\033[m"
	config="\${configs_$cfg}"
	eval "config=$config"

	cc="${config%%|*}"
	args="${config#*|}"

	ccset="\${cc_$cc}"
	eval "ccset=$ccset"
	eval "$ccset"

	bdir="build_$cfg"
	mkdir "$bdir"
	cd "$bdir"
	../sdist/configure $args
	make -j5
	make check
	make DESTDIR="$TEMP/inst_$cfg" install
	cd ..
done

echo -e "\n\n\n\neverything seems ok. you may now\n\trm -rf $TEMP"
