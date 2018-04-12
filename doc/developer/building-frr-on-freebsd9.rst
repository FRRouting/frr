FreeBSD 9
=========================================

FreeBSD 9 restrictions:
-----------------------

-  MPLS is not supported on ``FreeBSD``. MPLS requires a Linux Kernel
   (4.5 or higher). LDP can be built, but may have limited use without
   MPLS

Install required packages
-------------------------

Add packages: (Allow the install of the package managment tool if this
is first package install and asked)

::

    pkg install -y git autoconf automake libtool gmake gawk \
        pkgconf texinfo json-c bison flex py27-pytest c-ares \
        python3 py-sphinx

Make sure there is no /usr/bin/flex preinstalled (and use the newly
installed in /usr/local/bin): (FreeBSD frequently provides a older flex
as part of the base OS which takes preference in path)

::

    rm -f /usr/bin/flex

For building with clang (instead of gcc), upgrade clang from 3.4 default
to 3.6 *This is needed to build FreeBSD packages as well - for packages
clang is default* (Clang 3.4 as shipped with FreeBSD 9 crashes during
compile)

::

    pkg install clang36
    pkg delete clang34
    mv /usr/bin/clang /usr/bin/clang34
    ln -s /usr/local/bin/clang36 /usr/bin/clang

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr group and user
^^^^^^^^^^^^^^^^^^^^^^

::

    pw groupadd frr -g 101
    pw groupadd frrvty -g 102
    pw adduser frr -g 101 -u 101 -G 102 -c "FRR suite" \
        -d /usr/local/etc/frr -s /usr/sbin/nologin

(You may prefer different options on configure statement. These are just
an example)

::

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    ./bootstrap.sh
    export MAKE=gmake
    export LDFLAGS="-L/usr/local/lib"
    export CPPFLAGS="-I/usr/local/include"
    ./configure \
        --sysconfdir=/usr/local/etc/frr \
        --enable-pkgsrcrcdir=/usr/pkg/share/examples/rc.d \
        --localstatedir=/var/run/frr \
        --prefix=/usr/local \
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

    sudo mkdir /usr/local/etc/frr
    sudo touch /usr/local/etc/frr/zebra.conf
    sudo touch /usr/local/etc/frr/bgpd.conf
    sudo touch /usr/local/etc/frr/ospfd.conf
    sudo touch /usr/local/etc/frr/ospf6d.conf
    sudo touch /usr/local/etc/frr/isisd.conf
    sudo touch /usr/local/etc/frr/ripd.conf
    sudo touch /usr/local/etc/frr/ripngd.conf
    sudo touch /usr/local/etc/frr/pimd.conf
    sudo chown -R frr:frr /usr/local/etc/frr
    sudo touch /usr/local/etc/frr/vtysh.conf
    sudo chown frr:frrvty /usr/local/etc/frr/vtysh.conf
    sudo chmod 640 /usr/local/etc/frr/*.conf

Enable IP & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add the following lines to the end of ``/etc/sysctl.conf``:

::

    # Routing: We need to forward packets
    net.inet.ip.forwarding=1
    net.inet6.ip6.forwarding=1

**Reboot** or use ``sysctl`` to apply the same config to the running
system
