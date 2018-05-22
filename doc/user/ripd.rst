.. _rip:

***
RIP
***

RIP -- Routing Information Protocol is widely deployed interior gateway
protocol. RIP was developed in the 1970s at Xerox Labs as part of the
XNS routing protocol. RIP is a :term:`distance-vector` protocol and is
based on the :term:`Bellman-Ford` algorithms. As a distance-vector
protocol, RIP router send updates to its neighbors periodically, thus
allowing the convergence to a known topology. In each update, the
distance to any given network will be broadcast to its neighboring
router.

*ripd* supports RIP version 2 as described in RFC2453 and RIP
version 1 as described in RFC1058.

.. _starting-and-stopping-ripd:

Starting and Stopping ripd
==========================

The default configuration file name of *ripd*'s is :file:`ripd.conf`. When
invocation *ripd* searches directory |INSTALL_PREFIX_ETC|. If :file:`ripd.conf`
is not there next search current directory.

RIP uses UDP port 520 to send and receive RIP packets. So the user must have
the capability to bind the port, generally this means that the user must have
superuser privileges. RIP protocol requires interface information maintained by
*zebra* daemon. So running *zebra* is mandatory to run *ripd*. Thus minimum
sequence for running RIP is like below:

::

  # zebra -d
  # ripd -d


Please note that *zebra* must be invoked before *ripd*.

To stop *ripd*. Please use::
   kill `cat /var/run/ripd.pid`

Certain signals have special meanings to *ripd*.

 +-------------+------------------------------------------------------+
 | Signal      | Action                                               |
 +=============+======================================================+
 | ``SIGHUP``  | Reload configuration file :file:`ripd.conf`.         |
 |             | All configurations are reset. All routes learned     |
 |             | so far are cleared and removed from routing table.   |
 +-------------+------------------------------------------------------+
 | ``SIGUSR1`` | Rotate the *ripd* logfile.                           |
 +-------------+------------------------------------------------------+
 | ``SIGINT``  |                                                      |
 | ``SIGTERM`` | Sweep all installed routes and gracefully terminate. |
 +-------------+------------------------------------------------------+

*ripd* invocation options. Common options that can be specified
(:ref:`common-invocation-options`).


.. _rip-netmask:

RIP netmask
-----------

The netmask features of *ripd* support both version 1 and version 2 of RIP.
Version 1 of RIP originally contained no netmask information. In RIP version 1,
network classes were originally used to determine the size of the netmask.
Class A networks use 8 bits of mask, Class B networks use 16 bits of masks,
while Class C networks use 24 bits of mask. Today, the most widely used method
of a network mask is assigned to the packet on the basis of the interface that
received the packet.  Version 2 of RIP supports a variable length subnet mask
(VLSM). By extending the subnet mask, the mask can be divided and reused. Each
subnet can be used for different purposes such as large to middle size LANs and
WAN links. FRR *ripd* does not support the non-sequential netmasks that are
included in RIP Version 2.

In a case of similar information with the same prefix and metric, the old
information will be suppressed. Ripd does not currently support equal cost
multipath routing.

.. _rip-configuration:

RIP Configuration
=================

.. index:: router rip
.. clicmd:: router rip

   The `router rip` command is necessary to enable RIP. To disable RIP, use the
   `no router rip` command. RIP must be enabled before carrying out any of the
   RIP commands.

.. index:: no router rip
.. clicmd:: no router rip

   Disable RIP.

.. index:: network NETWORK
.. clicmd:: network NETWORK

.. index:: no network NETWORK
.. clicmd:: no network NETWORK

   Set the RIP enable interface by NETWORK. The interfaces which have addresses
   matching with NETWORK are enabled.

   This group of commands either enables or disables RIP interfaces between
   certain numbers of a specified network address. For example, if the network
   for 10.0.0.0/24 is RIP enabled, this would result in all the addresses from
   10.0.0.0 to 10.0.0.255 being enabled for RIP. The `no network` command will
   disable RIP for the specified network.

.. index:: network IFNAME
.. clicmd:: network IFNAME

.. index:: no network IFNAME
.. clicmd:: no network IFNAME

   Set a RIP enabled interface by IFNAME. Both the sending and
   receiving of RIP packets will be enabled on the port specified in the
   `network ifname` command. The `no network ifname` command will disable
   RIP on the specified interface.

.. index:: neighbor A.B.C.D
.. clicmd:: neighbor A.B.C.D

.. index:: no neighbor A.B.C.D
.. clicmd:: no neighbor A.B.C.D

   Specify RIP neighbor. When a neighbor doesn't understand multicast, this
   command is used to specify neighbors. In some cases, not all routers will be
   able to understand multicasting, where packets are sent to a network or a
   group of addresses. In a situation where a neighbor cannot process multicast
   packets, it is necessary to establish a direct link between routers. The
   neighbor command allows the network administrator to specify a router as a
   RIP neighbor. The `no neighbor a.b.c.d` command will disable the RIP
   neighbor.

   Below is very simple RIP configuration. Interface `eth0` and interface which
   address match to `10.0.0.0/8` are RIP enabled.

   .. code-block:: frr

      !
      router rip
       network 10.0.0.0/8
       network eth0
      !


.. index:: passive-interface (IFNAME|default)
.. clicmd:: passive-interface (IFNAME|default)

.. index:: no passive-interface IFNAME
.. clicmd:: no passive-interface IFNAME

   This command sets the specified interface to passive mode. On passive mode
   interface, all receiving packets are processed as normal and ripd does not
   send either multicast or unicast RIP packets except to RIP neighbors
   specified with `neighbor` command. The interface may be specified as
   `default` to make ripd default to passive on all interfaces.

   The default is to be passive on all interfaces.

.. index:: ip split-horizon
.. clicmd:: ip split-horizon

.. index:: no ip split-horizon
.. clicmd:: no ip split-horizon

   Control split-horizon on the interface. Default is `ip split-horizon`. If
   you don't perform split-horizon on the interface, please specify `no ip
   split-horizon`.

.. _rip-version-control:

RIP Version Control
===================

RIP can be configured to send either Version 1 or Version 2 packets.  The
default is to send RIPv2 while accepting both RIPv1 and RIPv2 (and replying
with packets of the appropriate version for REQUESTS / triggered updates). The
version to receive and send can be specified globally, and further overridden on
a per-interface basis if needs be for send and receive separately (see below).

It is important to note that RIPv1 cannot be authenticated. Further, if RIPv1
is enabled then RIP will reply to REQUEST packets, sending the state of its RIP
routing table to any remote routers that ask on demand. For a more detailed
discussion on the security implications of RIPv1 see :ref:`rip-authentication`.

.. index:: version VERSION
.. clicmd:: version VERSION

   Set RIP version to accept for reads and send. ``VERSION`` can be either 1 or
   1.

   Disabling RIPv1 by specifying version 2 is STRONGLY encouraged,
   :ref:`rip-authentication`. This may become the default in a future release.

   Default: Send Version 2, and accept either version.

.. index:: no version
.. clicmd:: no version

   Reset the global version setting back to the default.

.. index:: ip rip send version VERSION
.. clicmd:: ip rip send version VERSION

   VERSION can be ``1``, ``2``, or ``1 2``.

   This interface command overrides the global rip version setting, and selects
   which version of RIP to send packets with, for this interface specifically.
   Choice of RIP Version 1, RIP Version 2, or both versions. In the latter
   case, where ``1 2`` is specified, packets will be both broadcast and
   multicast.

   Default: Send packets according to the global version (version 2)

.. index:: ip rip receive version VERSION
.. clicmd:: ip rip receive version VERSION

   VERSION can be ``1``, ``2``, or ``1 2``.

   This interface command overrides the global rip version setting, and selects
   which versions of RIP packets will be accepted on this interface. Choice of
   RIP Version 1, RIP Version 2, or both.

   Default: Accept packets according to the global setting (both 1 and 2).

.. _how-to-announce-rip-route:

How to Announce RIP route
=========================

.. index:: redistribute kernel
.. clicmd:: redistribute kernel

.. index:: redistribute kernel metric (0-16)
.. clicmd:: redistribute kernel metric (0-16)

.. index:: redistribute kernel route-map ROUTE-MAP
.. clicmd:: redistribute kernel route-map ROUTE-MAP

.. index:: no redistribute kernel
.. clicmd:: no redistribute kernel

   `redistribute kernel` redistributes routing information from kernel route
   entries into the RIP tables. `no redistribute kernel` disables the routes.

.. index:: redistribute static
.. clicmd:: redistribute static

.. index:: redistribute static metric (0-16)
.. clicmd:: redistribute static metric (0-16)

.. index:: redistribute static route-map ROUTE-MAP
.. clicmd:: redistribute static route-map ROUTE-MAP

.. index:: no redistribute static
.. clicmd:: no redistribute static

   `redistribute static` redistributes routing information from static route
   entries into the RIP tables. `no redistribute static` disables the routes.

.. index:: redistribute connected
.. clicmd:: redistribute connected

.. index:: redistribute connected metric (0-16)
.. clicmd:: redistribute connected metric (0-16)

.. index:: redistribute connected route-map ROUTE-MAP
.. clicmd:: redistribute connected route-map ROUTE-MAP

.. index:: no redistribute connected
.. clicmd:: no redistribute connected

   Redistribute connected routes into the RIP tables. `no redistribute
   connected` disables the connected routes in the RIP tables.  This command
   redistribute connected of the interface which RIP disabled.  The connected
   route on RIP enabled interface is announced by default.

.. index:: redistribute ospf
.. clicmd:: redistribute ospf

.. index:: redistribute ospf metric (0-16)
.. clicmd:: redistribute ospf metric (0-16)

.. index:: redistribute ospf route-map ROUTE-MAP
.. clicmd:: redistribute ospf route-map ROUTE-MAP

.. index:: no redistribute ospf
.. clicmd:: no redistribute ospf

   `redistribute ospf` redistributes routing information from ospf route
   entries into the RIP tables. `no redistribute ospf` disables the routes.

.. index:: redistribute bgp
.. clicmd:: redistribute bgp

.. index:: redistribute bgp metric (0-16)
.. clicmd:: redistribute bgp metric (0-16)

.. index:: redistribute bgp route-map ROUTE-MAP
.. clicmd:: redistribute bgp route-map ROUTE-MAP

.. index:: no redistribute bgp
.. clicmd:: no redistribute bgp

   `redistribute bgp` redistributes routing information from bgp route entries
   into the RIP tables. `no redistribute bgp` disables the routes.

   If you want to specify RIP only static routes:

.. index:: default-information originate
.. clicmd:: default-information originate

.. index:: route A.B.C.D/M
.. clicmd:: route A.B.C.D/M

.. index:: no route A.B.C.D/M
.. clicmd:: no route A.B.C.D/M

   This command is specific to FRR. The `route` command makes a static route
   only inside RIP. This command should be used only by advanced users who are
   particularly knowledgeable about the RIP protocol. In most cases, we
   recommend creating a static route in FRR and redistributing it in RIP using
   `redistribute static`.

.. _filtering-rip-routes:

Filtering RIP Routes
====================

RIP routes can be filtered by a distribute-list.

.. index:: distribute-list ACCESS_LIST DIRECT IFNAME
.. clicmd:: distribute-list ACCESS_LIST DIRECT IFNAME

   You can apply access lists to the interface with a `distribute-list` command.
   ACCESS_LIST is the access list name. DIRECT is ``in`` or ``out``. If DIRECT
   is ``in`` the access list is applied to input packets.

   The `distribute-list` command can be used to filter the RIP path.
   `distribute-list` can apply access-lists to a chosen interface.  First, one
   should specify the access-list. Next, the name of the access-list is used in
   the distribute-list command. For example, in the following configuration
   ``eth0`` will permit only the paths that match the route 10.0.0.0/8

   .. code-block:: frr

       !
       router rip
        distribute-list private in eth0
       !
       access-list private permit 10 10.0.0.0/8
       access-list private deny any
       !


   `distribute-list` can be applied to both incoming and outgoing data.

.. index:: distribute-list prefix PREFIX_LIST (in|out) IFNAME
.. clicmd:: distribute-list prefix PREFIX_LIST (in|out) IFNAME

   You can apply prefix lists to the interface with a `distribute-list`
   command. PREFIX_LIST is the prefix list name. Next is the direction of
   ``in`` or ``out``. If DIRECT is ``in`` the access list is applied to input
   packets.

.. _rip-metric-manipulation:

RIP Metric Manipulation
=======================

RIP metric is a value for distance for the network. Usually
*ripd* increment the metric when the network information is
received. Redistributed routes' metric is set to 1.

.. index:: default-metric (1-16)
.. clicmd:: default-metric (1-16)

.. index:: no default-metric (1-16)
.. clicmd:: no default-metric (1-16)

   This command modifies the default metric value for redistributed routes.
   The default value is 1. This command does not affect connected route even if
   it is redistributed by *redistribute connected*. To modify connected route's
   metric value, please use ``redistribute connected metric`` or *route-map*.
   *offset-list* also affects connected routes.

.. index:: offset-list ACCESS-LIST (in|out)
.. clicmd:: offset-list ACCESS-LIST (in|out)

.. index:: offset-list ACCESS-LIST (in|out) IFNAME
.. clicmd:: offset-list ACCESS-LIST (in|out) IFNAME


.. _rip-distance:

RIP distance
============

Distance value is used in zebra daemon. Default RIP distance is 120.

.. index:: distance (1-255)
.. clicmd:: distance (1-255)

.. index:: no distance (1-255)
.. clicmd:: no distance (1-255)

   Set default RIP distance to specified value.

.. index:: distance (1-255) A.B.C.D/M
.. clicmd:: distance (1-255) A.B.C.D/M

.. index:: no distance (1-255) A.B.C.D/M
.. clicmd:: no distance (1-255) A.B.C.D/M

   Set default RIP distance to specified value when the route's source IP
   address matches the specified prefix.

.. index:: distance (1-255) A.B.C.D/M ACCESS-LIST
.. clicmd:: distance (1-255) A.B.C.D/M ACCESS-LIST

.. index:: no distance (1-255) A.B.C.D/M ACCESS-LIST
.. clicmd:: no distance (1-255) A.B.C.D/M ACCESS-LIST

   Set default RIP distance to specified value when the route's source IP
   address matches the specified prefix and the specified access-list.

.. _rip-route-map:

RIP route-map
=============

Usage of *ripd*'s route-map support.

Optional argument route-map MAP_NAME can be added to each `redistribute`
statement.

.. code-block:: frr

   redistribute static [route-map MAP_NAME]
   redistribute connected [route-map MAP_NAME]
   .....


Cisco applies route-map _before_ routes will exported to rip route table.  In
current FRR's test implementation, *ripd* applies route-map after routes are
listed in the route table and before routes will be announced to an interface
(something like output filter). I think it is not so clear, but it is draft and
it may be changed at future.

Route-map statement (:ref:`route-map`) is needed to use route-map
functionality.

.. index:: match interface WORD
.. clicmd:: match interface WORD

   This command match to incoming interface. Notation of this match is
   different from Cisco. Cisco uses a list of interfaces - NAME1 NAME2 ...
   NAMEN. Ripd allows only one name (maybe will change in the future). Next -
   Cisco means interface which includes next-hop of routes (it is somewhat
   similar to "ip next-hop" statement). Ripd means interface where this route
   will be sent. This difference is because "next-hop" of same routes which
   sends to different interfaces must be different. Maybe it'd be better to
   made new matches - say "match interface-out NAME" or something like that.

.. index:: match ip address WORD
.. clicmd:: match ip address WORD

.. index:: match ip address prefix-list WORD
.. clicmd:: match ip address prefix-list WORD

   Match if route destination is permitted by access-list.

.. index:: match ip next-hop WORD
.. clicmd:: match ip next-hop WORD

.. index:: match ip next-hop prefix-list WORD
.. clicmd:: match ip next-hop prefix-list WORD

   Match if route next-hop (meaning next-hop listed in the rip route-table as
   displayed by "show ip rip") is permitted by access-list.

.. index:: match metric (0-4294967295)
.. clicmd:: match metric (0-4294967295)

   This command match to the metric value of RIP updates. For other protocol
   compatibility metric range is shown as (0-4294967295). But for RIP protocol
   only the value range (0-16) make sense.

.. index:: set ip next-hop A.B.C.D
.. clicmd:: set ip next-hop A.B.C.D

   This command set next hop value in RIPv2 protocol. This command does not
   affect RIPv1 because there is no next hop field in the packet.

.. index:: set metric (0-4294967295)
.. clicmd:: set metric (0-4294967295)

   Set a metric for matched route when sending announcement. The metric value
   range is very large for compatibility with other protocols. For RIP, valid
   metric values are from 1 to 16.

.. _rip-authentication:

RIP Authentication
==================

RIPv2 allows packets to be authenticated via either an insecure plain
text password, included with the packet, or via a more secure MD5 based
:abbr:`HMAC (keyed-Hashing for Message AuthentiCation)`,
RIPv1 can not be authenticated at all, thus when authentication is
configured `ripd` will discard routing updates received via RIPv1
packets.

However, unless RIPv1 reception is disabled entirely,
:ref:`rip-version-control`, RIPv1 REQUEST packets which are received,
which query the router for routing information, will still be honoured
by `ripd`, and `ripd` WILL reply to such packets. This allows
`ripd` to honour such REQUESTs (which sometimes is used by old
equipment and very simple devices to bootstrap their default route),
while still providing security for route updates which are received.

In short: Enabling authentication prevents routes being updated by
unauthenticated remote routers, but still can allow routes (I.e. the
entire RIP routing table) to be queried remotely, potentially by anyone
on the internet, via RIPv1.

To prevent such unauthenticated querying of routes disable RIPv1,
:ref:`rip-version-control`.

.. index:: ip rip authentication mode md5
.. clicmd:: ip rip authentication mode md5

.. index:: no ip rip authentication mode md5
.. clicmd:: no ip rip authentication mode md5

   Set the interface with RIPv2 MD5 authentication.

.. index:: ip rip authentication mode text
.. clicmd:: ip rip authentication mode text

.. index:: no ip rip authentication mode text
.. clicmd:: no ip rip authentication mode text

   Set the interface with RIPv2 simple password authentication.

.. index:: ip rip authentication string STRING
.. clicmd:: ip rip authentication string STRING

.. index:: no ip rip authentication string STRING
.. clicmd:: no ip rip authentication string STRING

   RIP version 2 has simple text authentication. This command sets
   authentication string. The string must be shorter than 16 characters.

.. index:: ip rip authentication key-chain KEY-CHAIN
.. clicmd:: ip rip authentication key-chain KEY-CHAIN

.. index:: no ip rip authentication key-chain KEY-CHAIN
.. clicmd:: no ip rip authentication key-chain KEY-CHAIN

   Specify Keyed MD5 chain.

   .. code-block:: frr

      !
      key chain test
       key 1
        key-string test
      !
      interface eth1
       ip rip authentication mode md5
       ip rip authentication key-chain test
      !


.. _rip-timers:

RIP Timers
==========

.. index:: timers basic UPDATE TIMEOUT GARBAGE
.. clicmd:: timers basic UPDATE TIMEOUT GARBAGE


   RIP protocol has several timers. User can configure those timers' values
   by `timers basic` command.

   The default settings for the timers are as follows:

   - The update timer is 30 seconds. Every update timer seconds, the RIP
     process is awakened to send an unsolicited Response message containing
     the complete routing table to all neighboring RIP routers.
   - The timeout timer is 180 seconds. Upon expiration of the timeout, the
     route is no longer valid; however, it is retained in the routing table
     for a short time so that neighbors can be notified that the route has
     been dropped.
   - The garbage collect timer is 120 seconds. Upon expiration of the
     garbage-collection timer, the route is finally removed from the routing
     table.

   The ``timers basic`` command allows the the default values of the timers
   listed above to be changed.

.. index:: no timers basic
.. clicmd:: no timers basic

   The `no timers basic` command will reset the timers to the default settings
   listed above.

.. _show-rip-information:

Show RIP Information
====================

To display RIP routes.

.. index:: show ip rip
.. clicmd:: show ip rip

   Show RIP routes.

The command displays all RIP routes. For routes that are received
through RIP, this command will display the time the packet was sent and
the tag information. This command will also display this information
for routes redistributed into RIP.

.. index:: show ip rip status
.. clicmd:: show ip rip status

   The command displays current RIP status. It includes RIP timer,
   filtering, version, RIP enabled interface and RIP peer information.

::

   ripd> **show ip rip status**
   Routing Protocol is "rip"
     Sending updates every 30 seconds with +/-50%, next due in 35 seconds
     Timeout after 180 seconds, garbage collect after 120 seconds
     Outgoing update filter list for all interface is not set
     Incoming update filter list for all interface is not set
     Default redistribution metric is 1
     Redistributing: kernel connected
     Default version control: send version 2, receive version 2
       Interface  Send  Recv
     Routing for Networks:
       eth0
       eth1
       1.1.1.1
       203.181.89.241
     Routing Information Sources:
       Gateway    BadPackets BadRoutes  Distance Last Update


RIP Debug Commands
==================

Debug for RIP protocol.

.. index:: debug rip events
.. clicmd:: debug rip events

   Shows RIP events. Sending and receiving packets, timers, and changes in
   interfaces are events shown with *ripd*.

.. index:: debug rip packet
.. clicmd:: debug rip packet

   Shows display detailed information about the RIP packets. The origin and
   port number of the packet as well as a packet dump is shown.

.. index:: debug rip zebra
.. clicmd:: debug rip zebra

   This command will show the communication between *ripd* and *zebra*. The
   main information will include addition and deletion of paths to the kernel
   and the sending and receiving of interface information.

.. index:: show debugging rip
.. clicmd:: show debugging rip

   Shows all information currently set for ripd debug.

