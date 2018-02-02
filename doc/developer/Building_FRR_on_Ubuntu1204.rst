Ubuntu 12.04LTS
===============================================

-  MPLS is not supported on ``Ubuntu 12.04`` with default kernel. MPLS
   requires Linux Kernel 4.5 or higher (LDP can be built, but may have
   limited use without MPLS) For an updated Ubuntu Kernel, see
   http://kernel.ubuntu.com/~kernel-ppa/mainline/

Install required packages
-------------------------

Add packages:

::

    apt-get install git autoconf automake libtool make gawk libreadline-dev \
       texinfo libpam0g-dev dejagnu libjson0-dev pkg-config libpam0g-dev \
       libjson0-dev flex python-pip libc-ares-dev python3-dev

Install newer bison from 14.04 package source (Ubuntu 12.04 package
source is too old)

::

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

::

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

::

    pip install pytest

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr groups and user
~~~~~~~~~~~~~~~~~~~~~~~

::

    sudo groupadd -g 92 frr
    sudo groupadd -r -g 85 frrvty
    sudo adduser --system --ingroup frr --home /var/run/frr/ \
       --gecos "FRR suite" --shell /sbin/nologin frr
    sudo usermod -a -G frrvty frr

Download Source, configure and compile it
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

(You may prefer different options on configure statement. These are just
an example.)

::

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
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion   
    make
    make check
    sudo make install

Create empty FRR configuration files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

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

Enable IP & IPv6 forwarding
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Edit ``/etc/sysctl.conf`` and uncomment the following values (ignore the
other settings)

::

    # Uncomment the next line to enable packet forwarding for IPv4
    net.ipv4.ip_forward=1

    # Uncomment the next line to enable packet forwarding for IPv6
    #  Enabling this option disables Stateless Address Autoconfiguration
    #  based on Router Advertisements for this host
    net.ipv6.conf.all.forwarding=1

**Reboot** or use ``sysctl -p`` to apply the same config to the running
system

Install the init.d service
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    sudo install -m 755 tools/frr /etc/init.d/frr
    sudo install -m 644 tools/etc/frr/daemons /etc/frr/daemons
    sudo install -m 644 tools/etc/frr/daemons.conf /etc/frr/daemons.conf
    sudo install -m 644 -o frr -g frr tools/etc/frr/vtysh.conf /etc/frr/vtysh.conf

Enable daemons
~~~~~~~~~~~~~~

| Edit ``/etc/frr/daemons`` and change the value from "no" to "yes" for
  those daemons you want to start by systemd.
| For example.

::

    zebra=yes  
    bgpd=yes  
    ospfd=yes  
    ospf6d=yes  
    ripd=yes  
    ripngd=yes  
    isisd=yes 

Start the init.d service
~~~~~~~~~~~~~~~~~~~~~~~~

-  /etc/init.d/frr start
-  use ``/etc/init.d/frr status`` to check its status.
