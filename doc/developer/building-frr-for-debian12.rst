Debian 12
=========

Install required packages
-------------------------

Add packages:

::

   sudo apt-get install git autoconf automake libtool make \
      libprotobuf-c-dev protobuf-c-compiler build-essential \
      python3-dev python3-pytest python3-sphinx libjson-c-dev \
      libelf-dev libreadline-dev cmake libcap-dev bison flex \
      pkg-config texinfo gdb libgrpc-dev python3-grpc-tools

.. include:: building-libunwind-note.rst

.. include:: building-libyang.rst

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
    ./bootstrap.sh
    ./configure \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --sbindir=/usr/lib/frr \
        --enable-multipath=64 \
        --enable-user=frr \
        --enable-group=frr \
        --enable-vty-group=frrvty \
        --enable-configfile-mask=0640 \
        --enable-logfile-mask=0640 \
        --enable-fpm \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    make
    make check
    sudo make install

For more compile options, see ``./configure --help``

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/frr.conf
    sudo install -m 640 -o frr -g frr tools/etc/frr/daemons /etc/frr/daemons

Edit ``/etc/frr/daemons`` and enable the FRR daemons for the protocols you need

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
