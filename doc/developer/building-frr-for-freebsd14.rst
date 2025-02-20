FreeBSD 14
==========

FreeBSD 14 restrictions:
------------------------

-  MPLS is not supported on ``FreeBSD``. MPLS requires a Linux Kernel
   (4.5 or higher). LDP can be built, but may have limited use without
   MPLS
-  PIM for IPv6 is not currently supported on ``FreeBSD``.

Install required packages
-------------------------

Add packages: (Allow the install of the package management tool if this
is first package install and asked)

.. code-block:: shell

   pkg install autoconf automake bison c-ares git gmake json-c libtool \
        libunwind libyang2 pkgconf protobuf-c py39-pytest py39-sphinx texinfo

.. include:: building-libunwind-note.rst

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not using any
packages**

Add frr group and user
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

   pw groupadd frr -g 101
   pw groupadd frrvty -g 102
   pw adduser frr -g 101 -u 101 -G 102 -c "FRR suite" \
      -d /usr/local/etc/frr -s /usr/sbin/nologin


Download Source, configure and compile it
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(You may prefer different options on configure statement. These are just
an example)

.. code-block:: shell

   git clone https://github.com/frrouting/frr.git frr
   cd frr
   ./bootstrap.sh
   export MAKE=gmake LDFLAGS=-L/usr/local/lib CPPFLAGS=-I/usr/local/include
   ./configure \
       --sysconfdir=/usr/local/etc \
       --localstatedir=/var \
       --enable-pkgsrcrcdir=/usr/pkg/share/examples/rc.d \
       --prefix=/usr/local \
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

.. code-block:: shell

   sudo mkdir /usr/local/etc/frr

For integrated config file:

.. code-block:: shell

   sudo touch /usr/local/etc/frr/frr.conf

For individual config files:

.. note:: Integrated config is preferred to individual config.

.. code-block:: shell

   sudo touch /usr/local/etc/frr/babeld.conf
   sudo touch /usr/local/etc/frr/bfdd.conf
   sudo touch /usr/local/etc/frr/bgpd.conf
   sudo touch /usr/local/etc/frr/eigrpd.conf
   sudo touch /usr/local/etc/frr/isisd.conf
   sudo touch /usr/local/etc/frr/ldpd.conf
   sudo touch /usr/local/etc/frr/nhrpd.conf
   sudo touch /usr/local/etc/frr/ospf6d.conf
   sudo touch /usr/local/etc/frr/ospfd.conf
   sudo touch /usr/local/etc/frr/pbrd.conf
   sudo touch /usr/local/etc/frr/pimd.conf
   sudo touch /usr/local/etc/frr/ripd.conf
   sudo touch /usr/local/etc/frr/ripngd.conf
   sudo touch /usr/local/etc/frr/staticd.conf
   sudo touch /usr/local/etc/frr/zebra.conf
   sudo chown -R frr:frr /usr/local/etc/frr/
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

**Reboot** or use ``sysctl`` to apply the same config to the running system.
