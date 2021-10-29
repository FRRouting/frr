Ubuntu 16.04 LTS
================

This document describes installation from source. If you want to build a
``deb``, see :ref:`packaging-debian`.

Installing Dependencies
-----------------------

.. code-block:: console

   apt-get update
   apt-get install \
      git autoconf automake libtool make libreadline-dev texinfo \
      pkg-config libpam0g-dev libjson-c-dev bison flex python3-pytest \
      libc-ares-dev python3-dev python-ipaddress python3-sphinx \
      install-info build-essential libsnmp-dev perl libcap-dev \
      libelf-dev libprotobuf-c-dev protobuf-c-compiler

.. include:: building-libyang.rst

Protobuf
^^^^^^^^

.. code-block:: console

   sudo apt-get install protobuf-c-compiler libprotobuf-c-dev

Building & Installing FRR
-------------------------

Add FRR user and groups
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo groupadd -r -g 92 frr
   sudo groupadd -r -g 85 frrvty
   sudo adduser --system --ingroup frr --home /var/run/frr/ \
      --gecos "FRR suite" --shell /sbin/nologin frr
   sudo usermod -a -G frrvty frr

Compile
^^^^^^^

.. include:: include-compile.rst

Install FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo install -m 775 -o frr -g frr -d /var/log/frr
   sudo install -m 775 -o frr -g frrvty -d /etc/frr
   sudo install -m 640 -o frr -g frrvty tools/etc/frr/vtysh.conf /etc/frr/vtysh.conf
   sudo install -m 640 -o frr -g frr tools/etc/frr/frr.conf /etc/frr/frr.conf
   sudo install -m 640 -o frr -g frr tools/etc/frr/daemons.conf /etc/frr/daemons.conf
   sudo install -m 640 -o frr -g frr tools/etc/frr/daemons /etc/frr/daemons

Tweak sysctls
^^^^^^^^^^^^^

Some sysctls need to be changed in order to enable IPv4/IPv6 forwarding and
MPLS (if supported by your platform). If your platform does not support MPLS,
skip the MPLS related configuration in this section.

Edit :file:`/etc/sysctl.conf` and uncomment the following values (ignore the
other settings):

::

   # Uncomment the next line to enable packet forwarding for IPv4
   net.ipv4.ip_forward=1

   # Uncomment the next line to enable packet forwarding for IPv6
   #  Enabling this option disables Stateless Address Autoconfiguration
   #  based on Router Advertisements for this host
   net.ipv6.conf.all.forwarding=1

Reboot or use ``sysctl -p`` to apply the same config to the running system.

Add MPLS kernel modules
"""""""""""""""""""""""

.. warning::

   MPLS is not supported on Ubuntu 16.04 with the default kernel. MPLS requires
   kernel 4.5 or higher. LDPD can be built, but may have limited use without
   MPLS. For an updated Ubuntu Kernel, see
   http://kernel.ubuntu.com/~kernel-ppa/mainline/

Ubuntu 18.04 ships with kernel 4.15. MPLS modules are present by default.  To
enable, add the following lines to :file:`/etc/modules-load.d/modules.conf`:

::

   # Load MPLS Kernel Modules
   mpls_router
   mpls_iptunnel


And load the kernel modules on the running system:

.. code-block:: console

   sudo modprobe mpls-router mpls-iptunnel

Enable MPLS Forwarding
""""""""""""""""""""""

Edit :file:`/etc/sysctl.conf` and the following lines. Make sure to add a line
equal to :file:`net.mpls.conf.eth0.input` for each interface used with MPLS.

::

   # Enable MPLS Label processing on all interfaces
   net.mpls.conf.eth0.input=1
   net.mpls.conf.eth1.input=1
   net.mpls.conf.eth2.input=1
   net.mpls.platform_labels=100000

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

.. code-block:: console

   systemctl start frr
