Building FRR on Ubuntu 16.04LTS from Git Source
===============================================

- MPLS is not supported on `Ubuntu 16.04` with default kernel. MPLS requires 
  Linux Kernel 4.5 or higher (LDP can be built, but may have limited use 
  without MPLS)
  For an updated Ubuntu Kernel, see 
    http://kernel.ubuntu.com/~kernel-ppa/mainline/

Install required packages
-------------------------

Add packages:

    apt-get install git autoconf automake libtool make gawk libreadline-dev \
       texinfo dejagnu pkg-config libpam0g-dev libjson-c-dev bison flex \
       python-pytest

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not using 
any packages**

### Add frr groups and user

    sudo groupadd -g 92 frr
    sudo groupadd -r -g 85 frrvty
    sudo adduser --system --ingroup frr --groups frrvty --home /var/run/frr/ \
       --gecos "FRR suite" --shell /sbin/nologin frr

### Download Source, configure and compile it
(You may prefer different options on configure statement. These are just 
an example.)

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    git checkout stable/2.0
    ./bootstrap.sh
    ./configure \
        --enable-exampledir=/usr/share/doc/frr/examples/ \
        --localstatedir=/var/run/frr \
        --sbindir=/usr/lib/frr \
        --sysconfdir=/etc/frr \
        --enable-pimd \
        --enable-watchfrr \
        --enable-ospfclient=yes \
        --enable-ospfapi=yes \
        --enable-multipath=64 \
        --enable-user=frr \
        --enable-group=frr \
        --enable-vty-group=frrvty \
        --enable-configfile-mask=0640 \
        --enable-logfile-mask=0640 \
        --enable-rtadv \
        --enable-tcp-zebra \
        --enable-fpm \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion   
    make
    make check
    sudo make install

### Create empty FRR configuration files

    sudo mkdir /var/log/frr
    sudo chown frr:fee /var/log/frr
    sudo mkdir /etc/frr
    sudo touch /etc/frr/etc/zebra.conf
    sudo touch /etc/frr/etc/bgpd.conf
    sudo touch /etc/frr/etc/ospfd.conf
    sudo touch /etc/frr/etc/ospf6d.conf
    sudo touch /etc/frr/etc/isisd.conf
    sudo touch /etc/frr/etc/ripd.conf
    sudo touch /etc/frr/etc/ripngd.conf
    sudo touch /etc/frr/etc/pimd.conf
    sudo touch /etc/frr/etc/ldpd.conf
    sudo chown frr:frr /etc/frr/
    sudo touch /etc/frr/etc/vtysh.conf
    sudo chown frr:frrvty /etc/frr/etc/vtysh.conf
    sudo chmod 640 /etc/frr/*.conf

### Enable IP & IPv6 forwarding

Edit `/etc/sysctl.conf` and uncomment the following values (ignore the 
other settings)

    # Uncomment the next line to enable packet forwarding for IPv4
    net.ipv4.ip_forward=1

    # Uncomment the next line to enable packet forwarding for IPv6
    #  Enabling this option disables Stateless Address Autoconfiguration
    #  based on Router Advertisements for this host
    net.ipv6.conf.all.forwarding=1

### Enable MPLS Forwarding (with Linux Kernel >= 4.5)

Edit `/etc/sysctl.conf` and the following lines. Make sure to add a line 
equal to `net.mpls.conf.eth0.input` or each interface used with MPLS

    # Enable MPLS Label processing on all interfaces
    net.mpls.conf.eth0.input=1
    net.mpls.conf.eth1.input=1
    net.mpls.conf.eth2.input=1
    net.mpls.platform_labels=100000

### Add MPLS kernel modules

Add the following lines to `/etc/modules-load.d/modules.conf`:

    # Load MPLS Kernel Modules
    mpls-router
    mpls-iptunnel

**Reboot** or use `sysctl` to apply the same config to the running system
