Ubuntu 18.04 LTS
================

Install dependencies
--------------------

Required packages
^^^^^^^^^^^^^^^^^

::

   sudo apt-get install \
      git autoconf automake libtool make gawk libreadline-dev texinfo \
      pkg-config libpam0g-dev libjson-c-dev bison flex python-pytest \
      libc-ares-dev python3-dev libsystemd-dev python-ipaddr python3-sphinx \
      install-info

Optional packages
^^^^^^^^^^^^^^^^^

Dependencies for additional functionality can be installed as-desired.

Protobuf
~~~~~~~~

::

   sudo apt-get install \
       protobuf-c-compiler \
       libprotobuf-c-dev

ZeroMQ
~~~~~~

::

   sudo apt-get install \
       libzmq5 \
       libzmq3-dev

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr groups and user
^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo groupadd -r -g 92 frr
   sudo groupadd -r -g 85 frrvty
   sudo adduser --system --ingroup frr --home /var/run/frr/ \
      --gecos "FRR suite" --shell /sbin/nologin frr
   sudo usermod -a -G frrvty frr

Download source
^^^^^^^^^^^^^^^

::

   git clone https://github.com/frrouting/frr.git frr

Configure
^^^^^^^^^
Options below are provided as an example.

.. seealso:: *Installation* section of user guide

.. code-block:: shell

   cd frr
   ./bootstrap.sh
   ./configure \
       --prefix=/usr \
       --enable-exampledir=/usr/share/doc/frr/examples/ \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
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
       --enable-systemd=yes \
       --with-pkg-git-version \
       --with-pkg-extra-version=-MyOwnFRRVersion

If optional packages were installed, the associated feature may now be
enabled.

.. option:: --enable-protobuf

Enable support for protobuf transport

.. option:: --enable-zeromq

Enable support for ZeroMQ transport

Compile
^^^^^^^

::

   make
   make check
   sudo make install

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Although not strictly necessary, it's good practice to create empty
configuration files _before_ starting FRR. This assures that the permissions 
are correct. If the files are not already present, FRR will create them.

It's also important to consider _which_ files to create. FRR supports writing
configuration to a monolithic file, :file:`/etc/frr/frr.conf`.

.. seealso:: *VTYSH* section of user guide

The presence of :file:`/etc/frr/frr.conf` on startup implicitly configures FRR
to ignore daemon-specific configuration files.

Daemon-specific configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

Monolithic configuration
~~~~~~~~~~~~~~~~~~~~~~~~

::

   sudo install -m 755 -o frr -g frr -d /var/log/frr
   sudo install -m 775 -o frr -g frrvty -d /etc/frr
   sudo install -m 640 -o frr -g frr /dev/null /etc/frr/frr.conf

Enable IPv4 & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Edit :file:`/etc/sysctl.conf` and uncomment the following values (ignore the
other settings):

::

   # Uncomment the next line to enable packet forwarding for IPv4
   net.ipv4.ip_forward=1

   # Uncomment the next line to enable packet forwarding for IPv6
   #  Enabling this option disables Stateless Address Autoconfiguration
   #  based on Router Advertisements for this host
   net.ipv6.conf.all.forwarding=1

Add MPLS kernel modules
^^^^^^^^^^^^^^^^^^^^^^^

Ubuntu 18.04 ships with kernel 4.15. MPLS modules are present by default.  To
enable, add the following lines to :file:`/etc/modules-load.d/modules.conf`:

::

   # Load MPLS Kernel Modules
   mpls_router
   mpls_iptunnel

Reboot or use ``sysctl -p`` to apply the same config to the running system.

Enable MPLS Forwarding
^^^^^^^^^^^^^^^^^^^^^^

Edit :file:`/etc/sysctl.conf` and the following lines. Make sure to add a line
equal to :file:`net.mpls.conf.eth0.input` for each interface used with MPLS.

::

   # Enable MPLS Label processing on all interfaces
   net.mpls.conf.eth0.input=1
   net.mpls.conf.eth1.input=1
   net.mpls.conf.eth2.input=1
   net.mpls.platform_labels=100000

Install the systemd service
^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo install -m 644 tools/frr.service /etc/systemd/system/frr.service
   sudo install -m 644 tools/etc/default/frr /etc/default/frr
   sudo install -m 644 tools/etc/frr/daemons /etc/frr/daemons
   sudo install -m 644 tools/etc/frr/daemons.conf /etc/frr/daemons.conf
   sudo install -m 644 tools/etc/frr/frr.conf /etc/frr/frr.conf
   sudo install -m 644 -o frr -g frr tools/etc/frr/vtysh.conf /etc/frr/vtysh.conf

Enable daemons
^^^^^^^^^^^^^^

Edit ``/etc/frr/daemons`` and change the value from "no" to "yes" for those
daemons you want to start by systemd.  For example:

::

   zebra=yes
   bgpd=yes
   ospfd=yes
   ospf6d=yes
   ripd=yes
   ripngd=yes
   isisd=yes

Enable the systemd service
^^^^^^^^^^^^^^^^^^^^^^^^^^

Enabling the systemd service causes FRR to be started upon boot. To enable it,
use the following command:

.. code-block:: shell

   systemctl enable frr

Start the systemd service
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

   systemctl start frr

After starting the service, you can use ``systemctl status frr`` to check its
status.
