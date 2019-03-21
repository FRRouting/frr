#!/bin/bash
./bootstrap.sh
export LD_LIBRARY_PATH=/usr/local/lib:/lib:/usr/lib
./configure \
    --prefix=$(pwd)/docker/debian \
    --sysconfdir=/etc/frr \
    --with-yangmodelsdir=/usr/share/yang \
    --localstatedir=/var/run/frr \
    --enable-multipath=64 \
    --enable-user=frr \
    --enable-group=frr \
    --enable-vty-group=frrvty \
    --enable-systemd=no\
    --disable-exampledir \
    --disable-ldpd \
    --enable-fpm \
    --with-pkg-git-version \
    --with-pkg-extra-version=-MyOwnFRRVersion
make -j4
make install
make check
cp ../libyang/build/libyang.so* docker/debian/lib
mkdir -p docker/debian/libyang/user_types docker/debian/libyang/extensions
cp ../libyang/build/src/user_types/*.so docker/debian/libyang/user_types/
cp ../libyang/build/src/extensions/*.so docker/debian/libyang/extensions/
#./configure \
#    --enable-exampledir=/usr/share/doc/frr/examples/ \
#    --localstatedir=/var/opt/frr \
#    --sbindir=/usr/lib/frr \
#    --sysconfdir=/etc/frr \
#    --enable-multipath=64 \
#    --enable-user=frr \
#    --enable-group=frr \
#    --enable-vty-group=frrvty \
#    --enable-configfile-mask=0640 \
#    --enable-logfile-mask=0640 \
#    --enable-fpm \
#    --with-pkg-git-version \
#    --with-pkg-extra-version=-6.0.2
