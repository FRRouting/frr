Building FRR on Fedora 24 from Git Source
=========================================

Install required packages
-------------------------

Add packages:

    sudo dnf install git autoconf automake libtool make gawk \
       readline-devel texinfo net-snmp-devel groff pkgconfig \
       json-c-devel pam-devel perl-XML-LibXML pytest

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not 
using any packages**

### Add frr groups and user

    sudo groupadd -g 92 frr
    sudo groupadd -r -g 85 frrvt
    sudo useradd -u 92 -g 92 -M -r -G frrvt -s /sbin/nologin \
      -c "FRR FreeRangeRouting suite" -d /var/run/frr frr

### Download Source, configure and compile it
(You may prefer different options on configure statement. These are just 
an example.)

You may want to pay special attention to `/usr/lib64` paths and change 
them if you are not building on a x86_64 architecture

    git clone https://github.com/freerangerouting/frr.git frr
    cd frr
    git checkout stable/2.0
    ./bootstrap.sh
    ./configure \
        --sysconfdir=/etc/frr \
        --libdir=/usr/lib64/frr \
        --libexecdir=/usr/lib64/frr \
        --localstatedir=/var/run/frr \
        --enable-pimd \
        --enable-snmp=agentx \
        --enable-multipath=64 \
        --enable-ospfclient=yes \
        --enable-ospfapi=yes \
        --enable-user=frr \
        --enable-group=frr \
        --enable-vty-group=frrvt \
        --enable-rtadv \
        --disable-exampledir \
        --enable-watchfrr \
        --enable-tcp-zebra \
        --enable-fpm \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion    
    make
    make check
    sudo make install

### Create empty FRR configuration files
    sudo mkdir /var/log/frr
    sudo mkdir /etc/frr
    sudo touch /etc/frr/zebra.conf
    sudo touch /etc/frr/bgpd.conf
    sudo touch /etc/frr/ospfd.conf
    sudo touch /etc/frr/ospf6d.conf
    sudo touch /etc/frr/isisd.conf
    sudo touch /etc/frr/ripd.conf
    sudo touch /etc/frr/ripngd.conf
    sudo touch /etc/frr/pimd.conf
    sudo touch /etc/frr/ldpd.conf
    sudo chown -R frr:frr /etc/frr/
    sudo touch /etc/frr/vtysh.conf
    sudo chown frr:frrvt /etc/frr/vtysh.conf
    sudo chmod 640 /etc/frr/*.conf

### Enable IP & IPv6 forwarding (and MPLS)

Create a new file `/etc/sysctl.d/90-routing-sysctl.conf` with the 
following content:
(Please make sure to list all interfaces with required MPLS similar 
to `net.mpls.conf.eth0.input=1`)

    # Sysctl for routing
    #
    # Routing: We need to forward packets
    net.ipv4.conf.all.forwarding=1
    net.ipv6.conf.all.forwarding=1
    #
    # Enable MPLS Label processing on all interfaces
    net.mpls.conf.eth0.input=1
    net.mpls.conf.eth1.input=1
    net.mpls.conf.eth2.input=1
    net.mpls.platform_labels=100000

Create a new file `/etc/modules-load.d/mpls.conf` with the following content:

    # Load MPLS Kernel Modules
    mpls-router
    mpls-iptunnel

**Reboot** or use `sysctl` to apply the same config to the running system

### Install Service files 
    install -p -m 644 redhat/zebra.service /usr/lib/systemd/system/zebra.service
    install -p -m 644 redhat/isisd.service /usr/lib/systemd/system/isisd.service
    install -p -m 644 redhat/ripd.service /usr/lib/systemd/system/ripd.service
    install -p -m 644 redhat/ospfd.service /usr/lib/systemd/system/ospfd.service
    install -p -m 644 redhat/bgpd.service /usr/lib/systemd/system/bgpd.service
    install -p -m 644 redhat/ospf6d.service /usr/lib/systemd/system/ospf6d.service
    install -p -m 644 redhat/ripngd.service /usr/lib/systemd/system/ripngd.service
    install -p -m 644 redhat/pimd.service /usr/lib/systemd/system/pimd.service
    install -p -m 644 redhat/pimd.service /usr/lib/systemd/system/ldpd.service
    install -p -m 644 redhat/frr.sysconfig /etc/sysconfig/frr
    install -p -m 644 redhat/frr.logrotate /etc/logrotate.d/frr

### Register the systemd files
    systemctl preset zebra.service
    systemctl preset ripd.service
    systemctl preset ospfd.service
    systemctl preset bgpd.service
    systemctl preset ospf6d.service
    systemctl preset ripngd.service
    systemctl preset pimd.service
    systemctl preset ldpd.service

### Enable required daemons at startup
Only enable zebra and the daemons which are needed for your setup

    systemctl enable zebra
    systemctl enable ospfd
    systemctl enable bgpd
    [...] etc (as needed)
