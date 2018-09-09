NetBSD 6
========================================

NetBSD 6 restrictions:
----------------------

-  MPLS is not supported on ``NetBSD``. MPLS requires a Linux Kernel
   (4.5 or higher). LDP can be built, but may have limited use without
   MPLS

Install required packages
-------------------------

Configure Package location:

::

    PKG_PATH="ftp://ftp.NetBSD.org/pub/pkgsrc/packages/NetBSD/`uname -m`/`uname -r`/All"
    export PKG_PATH

Add packages:

::

    sudo pkg_add git autoconf automake libtool gmake gawk openssl \
       pkg-config json-c python27 py27-test python35 py-sphinx

Install SSL Root Certificates (for git https access):

::

    sudo pkg_add mozilla-rootcerts
    sudo touch /etc/openssl/openssl.cnf
    sudo mozilla-rootcerts install

Select default Python and py.test

::

    sudo ln -s /usr/pkg/bin/python2.7 /usr/bin/python
    sudo ln -s /usr/pkg/bin/py.test-2.7 /usr/bin/py.test

Get FRR, compile it and install it (from Git)
---------------------------------------------

Add frr groups and user
^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo groupadd -g 92 frr
    sudo groupadd -g 93 frrvty
    sudo useradd -g 92 -u 92 -G frrvty -c "FRR suite" \
        -d /nonexistent -s /sbin/nologin frr

Download Source, configure and compile it
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(You may prefer different options on configure statement. These are just
an example)

::

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    ./bootstrap.sh
    MAKE=gmake
    export LDFLAGS="-L/usr/pkg/lib -R/usr/pkg/lib"
    export CPPFLAGS="-I/usr/pkg/include"
    ./configure \
        --sysconfdir=/usr/pkg/etc/frr \
        --enable-exampledir=/usr/pkg/share/examples/frr \
        --enable-pkgsrcrcdir=/usr/pkg/share/examples/rc.d \
        --localstatedir=/var/run/frr \
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
    gmake
    gmake check
    sudo gmake install

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo mkdir /var/log/frr
    sudo mkdir /usr/pkg/etc/frr
    sudo touch /usr/pkg/etc/frr/zebra.conf
    sudo touch /usr/pkg/etc/frr/bgpd.conf
    sudo touch /usr/pkg/etc/frr/ospfd.conf
    sudo touch /usr/pkg/etc/frr/ospf6d.conf
    sudo touch /usr/pkg/etc/frr/isisd.conf
    sudo touch /usr/pkg/etc/frr/ripd.conf
    sudo touch /usr/pkg/etc/frr/ripngd.conf
    sudo touch /usr/pkg/etc/frr/pimd.conf
    sudo chown -R frr:frr /usr/pkg/etc/frr
    sudo touch /usr/local/etc/frr/vtysh.conf
    sudo chown frr:frrvty /usr/pkg/etc/frr/*.conf
    sudo chmod 640 /usr/pkg/etc/frr/*.conf

Enable IP & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add the following lines to the end of ``/etc/sysctl.conf``:

::

    # Routing: We need to forward packets
    net.inet.ip.forwarding=1
    net.inet6.ip6.forwarding=1

**Reboot** or use ``sysctl`` to apply the same config to the running
system

Install rc.d init files
^^^^^^^^^^^^^^^^^^^^^^^

::

    cp pkgsrc/*.sh /etc/rc.d/
    chmod 555 /etc/rc.d/*.sh

Enable FRR processes
^^^^^^^^^^^^^^^^^^^^

(Enable the required processes only)

::

    echo "zebra=YES" >> /etc/rc.conf
    echo "bgpd=YES" >> /etc/rc.conf
    echo "ospfd=YES" >> /etc/rc.conf
    echo "ospf6d=YES" >> /etc/rc.conf
    echo "isisd=YES" >> /etc/rc.conf
    echo "ripngd=YES" >> /etc/rc.conf
    echo "ripd=YES" >> /etc/rc.conf
    echo "pimd=YES" >> /etc/rc.conf
