NetBSD 7
========================================

NetBSD 7 restrictions:
----------------------

-  MPLS is not supported on ``NetBSD``. MPLS requires a Linux Kernel
   (4.5 or higher). LDP can be built, but may have limited use without
   MPLS

Install required packages
-------------------------

::

    sudo pkgin install git autoconf automake libtool gmake openssl \
       pkg-config json-c python36 py36-test py36-sphinx \
       protobuf-c

Install SSL Root Certificates (for git https access):

::

    sudo pkgin install mozilla-rootcerts
    sudo touch /etc/openssl/openssl.cnf
    sudo mozilla-rootcerts install

.. include:: building-libyang.rst

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
        --enable-pkgsrcrcdir=/usr/pkg/share/examples/rc.d \
        --localstatedir=/var/run/frr \
        --enable-multipath=64 \
        --enable-user=frr \
        --enable-group=frr \
        --enable-vty-group=frrvty \
        --enable-configfile-mask=0640 \
        --enable-logfile-mask=0640 \
        --enable-fpm \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    gmake
    gmake check
    sudo gmake install

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

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
