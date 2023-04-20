#!/bin/bash

sudo apt update
sudo apt-get install \
   git autoconf automake libtool make libreadline-dev texinfo \
   pkg-config libpam0g-dev libjson-c-dev bison flex \
   libc-ares-dev python3-dev python3-sphinx \
   python3-pytest python3-scapy python3-exabgp \
   install-info build-essential libsnmp-dev perl linux-modules-extra-`uname -r` \
   libcap-dev python2 libelf-dev libunwind-dev cmake libpcre2-dev \
   protobuf-c-compiler libprotobuf-c-dev libzmq5 libzmq3-dev -y

cd /tmp
git clone https://github.com/CESNET/libyang.git
cd libyang
git checkout v2.0.0
mkdir build; cd build
cmake -D CMAKE_INSTALL_PREFIX:PATH=/usr \
      -D CMAKE_BUILD_TYPE:String="Release" ..
make
sudo make install


sudo groupadd -r -g 92 frr
sudo groupadd -r -g 85 frrvty
sudo adduser --system --ingroup frr --home /var/run/frr/ \
   --gecos "FRR suite" --shell /sbin/nologin frr
sudo usermod -a -G frrvty frr

cd /home/vagrant
git clone https://github.com/frrouting/frr.git --single-branch frr
cd frr
./bootstrap.sh
./configure \
    --prefix=/usr \
    --includedir=\${prefix}/include \
    --bindir=\${prefix}/bin \
    --sbindir=\${prefix}/lib/frr \
    --libdir=\${prefix}/lib/frr \
    --libexecdir=\${prefix}/lib/frr \
    --localstatedir=/var/run/frr \
    --sysconfdir=/etc/frr \
    --with-moduledir=\${prefix}/lib/frr/modules \
    --with-libyang-pluginsdir=\${prefix}/lib/frr/libyang_plugins \
    --enable-configfile-mask=0640 \
    --enable-logfile-mask=0640 \
    --enable-snmp=agentx \
    --enable-multipath=64 \
    --enable-user=frr \
    --enable-group=frr \
    --enable-vty-group=frrvty \
    --with-pkg-git-version \
    --with-pkg-extra-version=-MyOwnFRRVersion
make

sudo install -m 775 -o frr -g frrvty -d /etc/frr
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak

sudo sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sed -i 's/^#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
sudo sysctl -p

sudo cp /etc/modules-load.d/modules.conf /etc/modules-load.d/modules.conf.bak
sudo bash -c 'cat << EOF >> /etc/modules-load.d/modules.conf
# Load MPLS Kernel Modules
mpls_router
mpls_iptunnel
EOF'

sudo modprobe mpls-router mpls-iptunnel

sudo bash -c 'cat << EOF >> /etc/sysctl.conf
# Enable MPLS Label processing on all interfaces
net.mpls.conf.eth0.input=1
net.mpls.conf.eth1.input=1
net.mpls.conf.eth2.input=1
net.mpls.platform_labels=100000
EOF'
