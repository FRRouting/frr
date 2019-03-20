#!/bin/bash
./bootstrap.sh
export LD_LIBRARY_PATH=/usr/local/lib:/lib:/usr/lib
./configure \
    --prefix=$(pwd)/docker/debian \
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
