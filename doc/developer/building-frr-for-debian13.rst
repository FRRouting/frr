Debian 13
=========

Install required packages
-------------------------

Add packages:

::

   sudo apt-get install git autoconf automake libtool make \
      build-essential python3-dev python3-pytest python3-sphinx \
      libjson-c-dev libelf-dev libreadline-dev cmake libcap-dev \
      bison flex pkg-config texinfo gdb

.. include:: building-libunwind-note.rst


Debian 13 (Trixie) ships libyang-dev version 3.12, so we can install it using:

::

   sudo apt-get install libyang-dev


For gRPC support the following packages are required:

:: 

   sudo apt-get install libprotobuf-c-dev protobuf-c-compiler libgrpc-dev \
      libgrpc++-dev python3-grpc-tools libprotoc-dev protobuf-compiler \
      libprotobuf-dev protobuf-compiler-grpc


Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr groups and user
^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo addgroup --system frr
    sudo addgroup --system frrvty
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

    sudo mkdir /var/log/frr
    sudo mkdir /etc/frr
    sudo install -m 640 -o frr -g frr /dev/null /etc/frr/frr.conf
    sudo install -m 640 -o frr -g frr tools/etc/frr/daemons /etc/frr/daemons
    sudo install -m 640 -o frr -g frr tools/etc/frr/support_bundle_commands.conf /etc/frr/support_bundle_commands.conf

Edit ``/etc/frr/daemons`` and enable the FRR daemons for the protocols you need

Enable IP & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If ``systemd-sysctl`` is used, create a ``/etc/sysctl.d/frr.conf`` file and enable the
following sysctl variables:

::

    # Uncomment the next line to enable packet forwarding for IPv4
    net.ipv4.ip_forward=1

    # Uncomment the next line to enable packet forwarding for IPv6
    #  Enabling this option disables Stateless Address Autoconfiguration
    #  based on Router Advertisements for this host
    net.ipv6.conf.all.forwarding=1

**Reboot** or use ``systemctl restart systemd-sysctl`` to apply the same config to the running
system

Install service files
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo install -m 644 tools/frr.service /etc/systemd/system/frr.service
   sudo systemctl enable frr

Enable daemons
^^^^^^^^^^^^^^

Open :file:`/etc/frr/daemons` with your text editor of choice. Look for the
section with ``watchfrr_enable=...`` and ``zebra=...`` etc.  Enable the daemons
as required by changing the value to ``yes``.

Start FRR
^^^^^^^^^

.. code-block:: shell

   systemctl start frr


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
