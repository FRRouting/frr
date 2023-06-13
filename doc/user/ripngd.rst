.. _ripng:

*****
RIPng
*****

*ripngd* supports the RIPng protocol as described in :rfc:`2080`. It's an IPv6
reincarnation of the RIP protocol.

.. _invoking-ripngd:

Invoking ripngd
===============

There are no `ripngd` specific invocation options. Common options can be
specified (:ref:`common-invocation-options`).

.. _ripngd-configuration:

ripngd Configuration
====================

Currently ripngd supports the following commands:

.. clicmd:: router ripng [vrf NAME]

   Enable RIPng.

.. clicmd:: network NETWORK

   Set RIPng enabled interface by NETWORK.

.. clicmd:: network IFNAME

   Set RIPng enabled interface by IFNAME.

.. clicmd:: route NETWORK

   Set RIPng static routing announcement of NETWORK.

.. clicmd:: allow-ecmp [1-MULTIPATH_NUM]

   Control how many ECMP paths RIPng can inject for the same prefix. If specified
   without a number, a maximum is taken (compiled with ``--enable-multipath``).

.. _ripngd-terminal-mode-commands:

ripngd Terminal Mode Commands
=============================

.. clicmd:: show ipv6 ripng [vrf NAME] status

.. clicmd:: show debugging ripng

.. clicmd:: debug ripng events

.. clicmd:: debug ripng packet

.. clicmd:: debug ripng zebra


ripngd Filtering Commands
=========================

RIPng routes can be filtered by a distribute-list.

.. clicmd:: distribute-list [prefix] LIST <in|out> IFNAME

   You can apply access lists to the interface with a `distribute-list` command.
   If prefix is specified LIST is a prefix-list.  If prefix is not specified
   then LIST is the access list name.  `in` specifies packets being received,
   and `out` specifies outgoing packets.  Finally if an interface is specified
   it will be applied against a specific interface.

   The ``distribute-list`` command can be used to filter the RIPNG path.
   ``distribute-list`` can apply access-lists to a chosen interface.  First, one
   should specify the access-list. Next, the name of the access-list is used in
   the distribute-list command. For example, in the following configuration
   ``eth0`` will permit only the paths that match the route 10.0.0.0/8

   .. code-block:: frr

      !
      router ripng
       distribute-list private in eth0
      !
      access-list private permit 10 10.0.0.0/8
      access-list private deny any
      !


   `distribute-list` can be applied to both incoming and outgoing data.


Sample configuration
====================

.. code-block:: frr

   debug ripng events
   debug ripng packet

   router ripng
    network sit1
    route 3ffe:506::0/32
    distribute-list local-only out sit1

   ipv6 access-list local-only permit 3ffe:506::0/32
   ipv6 access-list local-only deny any
