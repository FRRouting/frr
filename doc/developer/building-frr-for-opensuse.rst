openSUSE
========

This document describes installation from source.

These instructions have been tested on openSUSE Tumbleweed in a Raspberry Pi 400.

Installing Dependencies
-----------------------

.. code-block:: console

   zypper in  git autoconf automake libtool make   \
     readline-devel texinfo net-snmp-devel groff pkgconfig libjson-c-devel\
     pam-devel python3-pytest bison flex c-ares-devel python3-devel\
     python3-Sphinx perl patch libcap-devel libyang-devel \
     libelf-devel libunwind-devel protobuf-c

.. include:: building-libunwind-note.rst

Building & Installing FRR
-------------------------

Add FRR user and groups
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo groupadd -g 92 frr
   sudo groupadd -r -g 85 frrvty
   sudo useradd -u 92 -g 92 -M -r -G frrvty -s /sbin/nologin \
     -c "FRR FRRouting suite" -d /var/run/frr frr

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

.. note::

        In some platforms like raspberry for performance reasons
        some directories are in file systems (/var/run, ...) mounted with tempfs 
        so will disapear after every reboot.
        In frr the /var/run/frr is used to store pid files for every daemon.

Tweak sysctls
^^^^^^^^^^^^^

Some sysctls need to be changed in order to enable IPv4/IPv6 forwarding and
MPLS (if supported by your platform). If your platform does not support MPLS,
skip the MPLS related configuration in this section.

Create a new file ``/etc/sysctl.d/90-routing-sysctl.conf`` with the following
content:

::

   #
   # Enable packet forwarding
   #
   net.ipv4.conf.all.forwarding=1
   net.ipv6.conf.all.forwarding=1
   #
   # Enable MPLS Label processing on all interfaces
   #
   #net.mpls.conf.eth0.input=1
   #net.mpls.conf.eth1.input=1
   #net.mpls.conf.eth2.input=1
   #net.mpls.platform_labels=100000

.. note::

   MPLS must be invidividually enabled on each interface that requires it. See
   the example in the config block above.

Load the modified sysctls on the system:

.. code-block:: console

   sudo sysctl -p /etc/sysctl.d/90-routing-sysctl.conf

Create a new file ``/etc/modules-load.d/mpls.conf`` with the following content:

::

   # Load MPLS Kernel Modules
   mpls-router
   mpls-iptunnel

And load the kernel modules on the running system:

.. code-block:: console

   sudo modprobe mpls-router mpls-iptunnel


.. note::
   The ``firewalld`` service could be enabled. You may run into some
   issues with the iptables rules it installs by default. If you wish to just
   stop the service and clear `ALL` rules do these commands:

   .. code-block:: console

      sudo systemctl disable firewalld.service
      sudo systemctl stop firewalld.service
      sudo iptables -F

Install frr Service
^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo install -p -m 644 tools/frr.service /usr/lib/systemd/system/frr.service
   sudo systemctl enable frr

Enable daemons
^^^^^^^^^^^^^^

Open :file:`/etc/frr/daemons` with your text editor of choice. Look for the
section with ``bgpd=no`` etc.  Enable the daemons
as required by changing the value to ``yes``.

Start FRR
^^^^^^^^^

.. code-block:: console

   sudo systemctl start frr

Check the starting messages of frr with

.. code-block:: console

   journalctl -u frr --follow
