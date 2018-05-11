OpenBSD 6
=========================================

Install required packages
-------------------------

Configure PKG\_PATH

::

    export PKG_PATH=http://ftp5.usa.openbsd.org/pub/OpenBSD/$(uname -r)/packages/$(machine -a)/

Add packages:

::

    pkg_add git autoconf-2.69p2 automake-1.15.1 libtool bison
    pkg_add gmake gawk dejagnu openssl json-c py-test py-sphinx

Select Python2.7 as default (required for pytest)

::

    ln -s /usr/local/bin/python2.7 /usr/local/bin/python

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr group and user
^^^^^^^^^^^^^^^^^^^^^^

::

    groupadd -g 525 _frr
    groupadd -g 526 _frrvty
    useradd -g 525 -u 525 -c "FRR suite" -G _frrvty \
        -d /nonexistent -s /sbin/nologin _frr

Download Source, configure and compile it
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(You may prefer different options on configure statement. These are just
an example)

::

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    export AUTOCONF_VERSION="2.69"
    export AUTOMAKE_VERSION="1.15"
    ./bootstrap.sh
    export LDFLAGS="-L/usr/local/lib"
    export CPPFLAGS="-I/usr/local/include"
    ./configure \
        --sysconfdir=/etc/frr \
        --localstatedir=/var/frr \
        --enable-pimd \
        --enable-ospfclient=yes \
        --enable-ospfapi=yes \
        --enable-multipath=64 \
        --enable-user=_frr \
        --enable-group=_frr \
        --enable-vty-group=_frrvty \
        --enable-configfile-mask=0640 \
        --enable-logfile-mask=0640 \
        --enable-rtadv \
        --enable-fpm \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    gmake
    gmake check
    doas gmake install

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    doas mkdir /var/frr
    doas chown _frr:_frr /var/frr
    doas chmod 755 /var/frr
    doas mkdir /etc/frr
    doas touch /etc/frr/zebra.conf
    doas touch /etc/frr/bgpd.conf
    doas touch /etc/frr/ospfd.conf
    doas touch /etc/frr/ospf6d.conf
    doas touch /etc/frr/isisd.conf
    doas touch /etc/frr/ripd.conf
    doas touch /etc/frr/ripngd.conf
    doas touch /etc/frr/pimd.conf
    doas touch /etc/frr/ldpd.conf
    doas touch /etc/frr/nhrpd.conf
    doas chown -R _frr:_frr /etc/frr
    doas touch /etc/frr/vtysh.conf
    doas chown -R _frr:_frrvty /etc/frr/vtysh.conf
    doas chmod 750 /etc/frr
    doas chmod 640 /etc/frr/*.conf

Enable IP & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add the following lines to the end of ``/etc/rc.conf``:

::

    net.inet6.ip6.forwarding=1      # 1=Permit forwarding of IPv6 packets
    net.inet6.ip6.mforwarding=1     # 1=Permit forwarding of IPv6 multicast packets
    net.inet6.ip6.multipath=1       # 1=Enable IPv6 multipath routing

**Reboot** to apply the config to the system

Enable MPLS Forwarding
^^^^^^^^^^^^^^^^^^^^^^

To enable MPLS forwarding on a given interface, use the following
command:

::

    doas ifconfig em0 mpls

Alternatively, to make MPLS forwarding persistent across reboots, add
the "mpls" keyword in the hostname.\* files of the desired interfaces.
Example:

::

    cat /etc/hostname.em0
    inet 10.0.1.1 255.255.255.0 mpls

Install rc.d init files
^^^^^^^^^^^^^^^^^^^^^^^

(create them in /etc/rc.d - no example are included at this time with
FRR source)

Example (for zebra - store as ``/etc/rc.d/frr_zebra.sh``)

::

    #!/bin/sh
    #
    # $OpenBSD: frr_zebra.rc,v 1.1 2013/04/18 20:29:08 sthen Exp $

    daemon="/usr/local/sbin/zebra -d"

    . /etc/rc.d/rc.subr

    rc_cmd $1

Enable FRR processes
^^^^^^^^^^^^^^^^^^^^

(Enable the required processes only)

::

    echo "frr_zebra=YES" >> /etc/rc.conf
    echo "frr_bgpd=YES" >> /etc/rc.conf
    echo "frr_ospfd=YES" >> /etc/rc.conf
    echo "frr_ospf6d=YES" >> /etc/rc.conf
    echo "frr_isisd=YES" >> /etc/rc.conf
    echo "frr_ripngd=YES" >> /etc/rc.conf
    echo "frr_ripd=YES" >> /etc/rc.conf
    echo "frr_pimd=YES" >> /etc/rc.conf
    echo "frr_ldpd=YES" >> /etc/rc.conf
