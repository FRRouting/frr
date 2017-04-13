Building FRR on Ubuntu 12.04LTS from Git Source
===============================================

- MPLS is not supported on `Ubuntu 12.04` with default kernel. MPLS requires 
  Linux Kernel 4.5 or higher (LDP can be built, but may have limited use 
  without MPLS)
  For an updated Ubuntu Kernel, see http://kernel.ubuntu.com/~kernel-ppa/mainline/

Install required packages
-------------------------

Add packages:

    apt-get install git autoconf automake libtool make gawk libreadline-dev \
       texinfo libpam0g-dev dejagnu libjson0-dev pkg-config libpam0g-dev \
       libjson0-dev flex python-pip libc-ares-dev python3-dev

Install newer bison from 14.04 package source (Ubuntu 12.04 package source
is too old)

    mkdir builddir
    cd builddir
    wget http://archive.ubuntu.com/ubuntu/pool/main/b/bison/bison_3.0.2.dfsg-2.dsc
    wget http://archive.ubuntu.com/ubuntu/pool/main/b/bison/bison_3.0.2.dfsg.orig.tar.bz2
    wget http://archive.ubuntu.com/ubuntu/pool/main/b/bison/bison_3.0.2.dfsg-2.debian.tar.gz
    tar -jxvf bison_3.0.2.dfsg.orig.tar.bz2 
    cd bison-3.0.2.dfsg/
    tar xzf ../bison_3.0.2.dfsg-2.debian.tar.gz 
    sudo apt-get build-dep bison
    debuild -b -uc -us
    cd ..
    sudo dpkg -i ./libbison-dev_3.0.2.dfsg-2_amd64.deb ./bison_3.0.2.dfsg-2_amd64.deb 
    cd ..
    rm -rf builddir

Install newer version of autoconf and automake:

    wget http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
    tar xvf autoconf-2.69.tar.gz
    cd autoconf-2.69
    ./configure --prefix=/usr
    make
    sudo make install
    cd ..
    
    wget http://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz
    tar xvf automake-1.15.tar.gz
    cd automake-1.15
    ./configure --prefix=/usr
    make
    sudo make install
    cd ..

Install pytest:

    pip install pytest

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

**Reboot** or use `sysctl -p` to apply the same config to the running system
