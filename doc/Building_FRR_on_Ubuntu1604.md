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
       python-pytest libc-ares-dev python3-dev libsystemd-dev python-ipaddr

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not using 
any packages**

### Add frr groups and user

    sudo groupadd -g 92 frr
    sudo groupadd -r -g 85 frrvty
    sudo adduser --system --ingroup frr --home /var/run/frr/ \
       --gecos "FRR suite" --shell /sbin/nologin frr
    sudo usermod -a -G frrvty frr

### Download Source, configure and compile it
(You may prefer different options on configure statement. These are just 
an example.)

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    ./bootstrap.sh
    ./configure \
        --prefix=/usr \
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
        --enable-fpm \
        --enable-systemd=yes \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion   
    make
    make check
    sudo make install

### Create empty FRR configuration files

    sudo install -m 755 -o frr -g frr -d /var/log/frr
    sudo install -m 775 -o frr -g frrvty -d /etc/frr
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/zebra.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/bgpd.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/ospfd.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/ospf6d.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/isisd.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/ripd.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/ripngd.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/pimd.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/ldpd.conf
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/nhrpd.conf    
    sudo install -m 640 -o frr -g frrvty /dev/null /etc/frr/vtysh.conf

### Enable IPv4 & IPv6 forwarding

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

**Reboot** or use `sysctl -p` to apply the same config to the running system


### Install the systemd service (if rebooted from last step, change directory back to frr directory)

    sudo install -m 644 tools/frr.service /etc/systemd/system/frr.service
    sudo install -m 644 tools/etc/default/frr /etc/default/frr
    sudo install -m 644 tools/etc/frr/daemons /etc/frr/daemons
    sudo install -m 644 tools/etc/frr/daemons.conf /etc/frr/daemons.conf
    sudo install -m 644 tools/etc/frr/frr.conf /etc/frr/frr.conf
    sudo install -m 644 -o frr -g frr tools/etc/frr/vtysh.conf /etc/frr/vtysh.conf

### Enable daemons 

Edit `/etc/frr/daemons` and change the value from "no" to "yes" for those daemons you want to start by systemd.  
For example.

    zebra=yes
    bgpd=yes
    ospfd=yes
    ospf6d=yes
    ripd=yes
    ripngd=yes
    isisd=yes

### Enable the systemd service
 - systemctl enable frr

### Start the systemd service
- systemctl start frr
- use `systemctl status frr` to check its status.
