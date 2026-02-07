.. _ripng:

*****
RIPng
*****

*ripngd* supports the RIPng protocol as described in :rfc:`2080`. It's an IPv6
reincarnation of the RIP protocol.

.. _invoking-ripngd:

Invoking ripngd
===============

.. include:: config-include.rst

There are no `ripngd` specific invocation options. Common options can be
specified (:ref:`common-invocation-options`).

.. _ripngd-configuration:

ripngd Configuration
====================

Currently ripngd supports the following commands:

.. clicmd:: router ripng [vrf NAME]

   Enable RIPng.

.. clicmd:: network NETWORK
   :daemon: ripngd

   Set RIPng enabled interface by NETWORK.

.. clicmd:: network IFNAME
   :daemon: ripngd

   Set RIPng enabled interface by IFNAME.

.. clicmd:: route NETWORK

   Set RIPng static routing announcement of NETWORK.

.. clicmd:: allow-ecmp [1-MULTIPATH_NUM]
   :daemon: ripngd

   Control how many ECMP paths RIPng can inject for the same prefix. If specified
   without a number, a maximum is taken (compiled with ``--enable-multipath``).

.. clicmd:: default-information originate
   :daemon: ripngd

   Distribute default route information.

.. clicmd:: default-metric (1-16)
   :daemon: ripngd

   Set a metric of redistribute routes.

.. clicmd:: offset-list ACCESSLIST6_NAME <in|out> (0-16) [IFNAME]

   Modify RIPng metric based on access-list. The access-list is applied to
   incoming or outgoing updates, optionally on a specific interface.

.. clicmd:: passive-interface IFNAME

   Suppress routing updates on an interface.

.. clicmd:: redistribute PROTOCOL [{metric (0-16)|route-map RMAP_NAME}]

   Redistribute routes from other protocols into RIPng. Optionally specify
   metric or route-map for the redistributed routes.

.. clicmd:: aggregate-address X:X::X:X/M
   :daemon: ripngd

   Set aggregate RIPng route announcement.

.. clicmd:: timers basic (1-65535) (1-65535) (1-65535)

   Set RIPng timers for update, timeout, and garbage collection intervals.

.. clicmd:: ipv6 distribute-list ACCESSLIST6_NAME <in|out> [IFNAME]

   Filter networks in routing updates using access-list. Can be applied to
   incoming or outgoing updates, optionally on a specific interface.

.. clicmd:: ipv6 distribute-list prefix PREFIXLIST6_NAME <in|out> [IFNAME]

   Filter networks in routing updates using prefix-list. Can be applied to
   incoming or outgoing updates, optionally on a specific interface.

.. _ripngd-terminal-mode-commands:

ripngd Terminal Mode Commands
=============================

.. clicmd:: show ipv6 ripng [vrf NAME]

   Show RIPng routes.

.. clicmd:: show ipv6 ripng [vrf NAME] status

   Show RIPng status and configuration.

.. clicmd:: show debugging ripng

   Show debugging status for RIPng.

.. clicmd:: debug ripng events

   Debug RIPng events.

.. clicmd:: debug ripng packet

   Debug RIPng packet processing.

.. clicmd:: debug ripng packet <recv|send>

   Debug specific packet direction (receive or send).

.. clicmd:: debug ripng zebra

   Debug RIPng and zebra communication.

.. clicmd:: clear ipv6 ripng [vrf WORD]

   Clear RIPng routes.

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


.. _ripng-route-map:

RIPng route-map
===============

Usage of *ripngd*'s route-map support.

Route-map statement (:ref:`route-map`) is needed to use route-map
functionality.

.. clicmd:: match interface WORD
   :daemon: ripngd

   This command match to incoming interface. Notation of this match is
   different from Cisco. Cisco uses a list of interfaces - NAME1 NAME2 ...
   NAMEN. Ripngd allows only one name (maybe will change in the future). Next -
   Cisco means interface which includes next-hop of routes (it is somewhat
   similar to "ipv6 next-hop" statement). Ripngd means interface where this route
   will be sent. This difference is because "next-hop" of same routes which
   sends to different interfaces must be different.

.. clicmd:: match ipv6 address WORD

.. clicmd:: match ipv6 address prefix-list WORD

   Match if route destination is permitted by access-list/prefix-list.

.. clicmd:: match metric (0-4294967295)
   :daemon: ripngd

   This command match to the metric value of RIPng updates. For other protocol
   compatibility metric range is shown as (0-4294967295). But for RIPng protocol
   only the value range (0-16) make sense.

.. clicmd:: set ipv6 next-hop local IPV6_ADDRESS
   :daemon: ripngd

   Set the link-local IPv6 nexthop address.

.. clicmd:: set metric (1-16)

   Set a metric for matched route when sending announcement. The metric value
   range is very large for compatibility with other protocols. For RIPng, valid
   metric values are from 1 to 16.

.. clicmd:: set tag <untagged|(1-4294967295)>
   :daemon: ripngd

   Set a tag on the matched route.

.. _ripng-interface-commands:

RIPng Interface Commands
========================

.. clicmd:: ipv6 ripng split-horizon [poisoned-reverse]

   Configure split horizon on the interface. The optional `poisoned-reverse`
   parameter enables poisoned reverse split horizon.

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
