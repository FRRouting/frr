NetBSD 10
=========

NetBSD 10 restrictions:
-----------------------

-  While NetBSD supports MPLS, FRRouting does not have a backend suitable for
   use with it.  MPLS is therefore not supported on NetBSD.  It may be possible
   to adapt FRR's OpenBSD MPLS backend but noone has currently committed the
   resources to do this.  LDP can be built, but will be of limited use.

-  Similarly, multicast routing is not supported on NetBSD; ``pimd`` and
   ``pim6d`` cannot be built.

Install required packages
-------------------------

::

    sudo pkgin install \
        git openssl \
        autoconf automake libtool gmake gtexinfo pkg-config \
        json-c protobuf-c libyang2 libcares \
        bison flex python313 py313-test py313-sphinx

Install SSL Root Certificates (for git https access):

::

    sudo pkgin install mozilla-rootcerts
    sudo touch /etc/openssl/openssl.cnf
    sudo mozilla-rootcerts install


A source build of libyang is not currently necessary on NetBSD, the packaged
version is sufficiently new and can be used.


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
    export MAKE=gmake
    export LDFLAGS="-L/usr/pkg/lib -R/usr/pkg/lib"
    export CPPFLAGS="-I/usr/pkg/include"
    ./configure \
        --prefix=/usr/pkg \
        --localstatedir=/var \
        --enable-pkgsrcrcdir=/usr/pkg/share/examples/rc.d \
        --enable-multipath=64 \
        --enable-user=frr \
        --enable-group=frr \
        --enable-vty-group=frrvty \
        --enable-configfile-mask=0640 \
        --enable-logfile-mask=0640 \
        --enable-fpm \
        --disable-pimd \
        --disable-pim6d \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    gmake
    gmake check
    sudo gmake install

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo mkdir /usr/pkg/etc/frr
    sudo touch /usr/pkg/etc/frr/frr.conf
    sudo chown -R frr:frr /usr/pkg/etc/frr
    sudo touch /usr/local/etc/frr/vtysh.conf
    sudo chown frr:frrvty /usr/pkg/etc/frr/vtysh.conf
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
