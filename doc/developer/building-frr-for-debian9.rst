Debian 9
========================================

Install required packages
-------------------------

Add packages:

::

    sudo apt-get install git autoconf automake libtool make \
      libreadline-dev texinfo libjson-c-dev pkg-config bison flex \
      python-pip libc-ares-dev python3-dev python-pytest python3-sphinx

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr groups and user
^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo addgroup --system --gid 92 frr
    sudo addgroup --system --gid 85 frrvty
    sudo adduser --system --ingroup frr --home /var/opt/frr/ \
       --gecos "FRR suite" --shell /bin/false frr
    sudo usermod -a -G frrvty frr

Download Source, configure and compile it
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(You may prefer different options on configure statement. These are just
an example.)

::

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    git checkout stable/3.0
    ./bootstrap.sh
    ./configure \
        --enable-exampledir=/usr/share/doc/frr/examples/ \
        --localstatedir=/var/opt/frr \
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
    sudo install -m 755 -o frr -g frr -d /var/opt/frr
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
---------------

Shared library error
^^^^^^^^^^^^^^^^^^^^

If you try and start any of the frrouting daemons you may see the below
error due to the frrouting shared library directory not being found:

::

   ./zebra: error while loading shared libraries: libfrr.so.0: cannot open
   shared object file: No such file or directory

The fix is to add the following line to /etc/ld.so.conf which will
continue to reference the library directory after the system reboots. To
load the library directory path immediately run the ldconfig command
after adding the line to the file eg:

::

   echo include /usr/local/lib >> /etc/ld.so.conf
   ldconfig
