Fedora 24
=========

This document describes installation from source. If you want to build an RPM,
see :ref:`packaging-redhat`.

Installing Dependencies
-----------------------

.. code-block:: console

   sudo dnf install git autoconf automake libtool make gawk \
     readline-devel texinfo net-snmp-devel groff pkgconfig json-c-devel \
     pam-devel pytest bison flex c-ares-devel python3-devel python3-sphinx

.. include:: building-libyang.rst

Building & Installing FRR
-------------------------

Compilation
^^^^^^^^^^^

Clone the FRR git repo and use the included ``configure`` script to configure
FRR's build time options to your liking. The full option listing can be
obtained by running ``./configure -h``. The options shown below are examples.

.. code-block:: console

   git clone https://github.com/frrouting/frr.git frr
   cd frr
   ./bootstrap.sh
   ./configure \
       --bindir=/usr/bin \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --libdir=/usr/lib/frr \
       --libexecdir=/usr/lib/frr \
       --localstatedir=/var/run/frr \
       --with-moduledir=/usr/lib/frr/modules \
       --enable-snmp=agentx \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --disable-exampledir \
       --enable-fpm \
       --with-pkg-git-version \
       --with-pkg-extra-version=-MyOwnFRRVersion
   make
   sudo make install

Add FRR groups and user
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo groupadd -g 92 frr
   sudo groupadd -r -g 85 frrvty
   sudo useradd -u 92 -g 92 -M -r -G frrvty -s /sbin/nologin \
     -c "FRR FRRouting suite" -d /var/run/frr frr


Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo mkdir /var/log/frr
   sudo mkdir /etc/frr
   sudo touch /etc/frr/zebra.conf
   sudo touch /etc/frr/bgpd.conf
   sudo touch /etc/frr/ospfd.conf
   sudo touch /etc/frr/ospf6d.conf
   sudo touch /etc/frr/isisd.conf
   sudo touch /etc/frr/ripd.conf
   sudo touch /etc/frr/ripngd.conf
   sudo touch /etc/frr/pimd.conf
   sudo touch /etc/frr/ldpd.conf
   sudo touch /etc/frr/nhrpd.conf
   sudo touch /etc/frr/eigrpd.conf
   sudo touch /etc/frr/babeld.conf
   sudo chown -R frr:frr /etc/frr/
   sudo touch /etc/frr/vtysh.conf
   sudo chown frr:frrvty /etc/frr/vtysh.conf
   sudo chmod 640 /etc/frr/*.conf

Install daemon config file
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo install -p -m 644 redhat/daemons /etc/frr/
   sudo chown frr:frr /etc/frr/daemons

Edit /etc/frr/daemons
^^^^^^^^^^^^^^^^^^^^^

Look for the section with ``watchfrr_enable=...`` and ``zebra=...`` etc.
Enable the daemons as required by changing the value to ``yes``.

Enable IP & IPv6 forwarding (and MPLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create a new file ``/etc/sysctl.d/90-routing-sysctl.conf`` with the following
content (please make sure to list all interfaces with required MPLS similar to
``net.mpls.conf.eth0.input=1``):

.. code-block:: console

   # Sysctl for routing
   #
   # Routing: We need to forward packets
   net.ipv4.conf.all.forwarding=1
   net.ipv6.conf.all.forwarding=1
   #
   # Enable MPLS Label processing on all interfaces
   net.mpls.conf.eth0.input=1
   net.mpls.conf.eth1.input=1
   net.mpls.conf.eth2.input=1
   net.mpls.platform_labels=100000

Load the modified sysctl's on the system:

.. code-block:: console

   sudo sysctl -p /etc/sysctl.d/90-routing-sysctl.conf

Create a new file ``/etc/modules-load.d/mpls.conf`` with the following
content:

.. code-block:: console

   # Load MPLS Kernel Modules
   mpls-router
   mpls-iptunnel

And load the kernel modules on the running system:

.. code-block:: console

   sudo modprobe mpls-router mpls-iptunnel

Install system service files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo install -p -m 644 redhat/frr.service /usr/lib/systemd/system/frr.service
   sudo install -p -m 755 redhat/frr.init /usr/lib/frr/frr
   sudo systemctl enable frr

Start FRR
^^^^^^^^^

.. code-block:: frr

   sudo systemctl start frr
