Arch Linux
================

Installing Dependencies
-----------------------

.. code-block:: console

   sudo pacman -Syu
   sudo pacman -S \
      git autoconf automake libtool make cmake pcre readline texinfo \
      pkg-config pam json-c bison flex python-pytest \
      c-ares python python2-ipaddress python-sphinx \
      net-snmp perl libcap libelf libunwind protobuf-c

.. include:: building-libunwind-note.rst

.. include:: building-libyang.rst


ZeroMQ
^^^^^^

.. code-block:: console

   sudo pacman -S zeromq

Building & Installing FRR
-------------------------

Add FRR user and groups
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   sudo groupadd -r -g 92 frr
   sudo groupadd -r -g 85 frrvty
   sudo useradd --system -g frr --home-dir /var/run/frr/ \
   -c "FRR suite" --shell /sbin/nologin frr
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

Edit :file:`/etc/sysctl.conf` [*Create the file if it doesn't exist*] and
append the following values (ignore the other settings):

::

   # Enable packet forwarding for IPv4
   net.ipv4.ip_forward=1

   #  Enable packet forwarding for IPv6
   net.ipv6.conf.all.forwarding=1

Reboot or use ``sysctl -p`` to apply the same config to the running system.

Add MPLS kernel modules
"""""""""""""""""""""""

To
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

Start FRR
^^^^^^^^^

.. code-block:: shell

   systemctl start frr
