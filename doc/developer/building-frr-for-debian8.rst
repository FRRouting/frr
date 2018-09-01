Debian 8
========================================

Debian 8 restrictions:
----------------------

-  MPLS is not supported on ``Debian 8`` with default kernel. MPLS
   requires Linux Kernel 4.5 or higher (LDP can be built, but may have
   limited use without MPLS)

Install required packages
-------------------------

Add packages:

::

    sudo apt-get install git autoconf automake libtool make gawk \
       libreadline-dev texinfo libjson-c-dev pkg-config bison flex \
       python-pip libc-ares-dev python3-dev python3-sphinx

Install newer pytest (>3.0) from pip

::

    sudo pip install pytest

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr groups and user
^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo addgroup --system --gid 92 frr
    sudo addgroup --system --gid 85 frrvty
    sudo adduser --system --ingroup frr --home /var/run/frr/ \
       --gecos "FRR suite" --shell /bin/false frr
    sudo usermod -a -G frrvty frr

Download Source, configure and compile it
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(You may prefer different options on configure statement. These are just
an example.)

::

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    ./bootstrap.sh
    ./configure \
        --enable-exampledir=/usr/share/doc/frr/examples/ \
        --localstatedir=/var/run/frr \
        --sbindir=/usr/lib/frr \
        --sysconfdir=/etc/frr \
        --enable-vtysh \
        --enable-isisd \
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
        --enable-ldpd \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    make
    make check
    sudo make install

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^

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

Troubleshooting
^^^^^^^^^^^^^^^

**Local state directory**

The local state directory must exist and have the correct permissions
applied for the frrouting daemons to start. In the above ./configure
example the local state directory is set to /var/run/frr
(--localstatedir=/var/run/frr) Debian considers /var/run/frr to be
temporary and this is removed after a reboot.

When using a different local state directory you need to create the new
directory and change the ownership to the frr user, for example:

::

    mkdir /var/opt/frr
    chown frr /var/opt/frr

**Shared library error**

If you try and start any of the frrouting daemons you may see the below
error due to the frrouting shared library directory not being found:

::

    ./zebra: error while loading shared libraries: libfrr.so.0: cannot open shared object file: No such file or directory

The fix is to add the following line to /etc/ld.so.conf which will
continue to reference the library directory after the system reboots. To
load the library directory path immediately run the ldconfig command
after adding the line to the file eg:

::

    echo include /usr/local/lib >> /etc/ld.so.conf
    ldconfig
