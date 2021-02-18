.. _ospfv3:

******
OSPFv3
******

*ospf6d* is a daemon support OSPF version 3 for IPv6 network. OSPF for IPv6 is
described in :rfc:`2740`.

.. _ospf6-router:

OSPF6 router
============

.. index:: router ospf6
.. clicmd:: router ospf6

.. index:: ospf6 router-id A.B.C.D
.. clicmd:: ospf6 router-id A.B.C.D

   Set router's Router-ID.

.. index:: interface IFNAME area (0-4294967295)
.. clicmd:: interface IFNAME area (0-4294967295)

.. index:: interface IFNAME area A.B.C.D
.. clicmd:: interface IFNAME area A.B.C.D

   Bind interface to specified area, and start sending OSPF packets. `area` can
   be specified as 0.

.. index:: timers throttle spf (0-600000) (0-600000) (0-600000)
.. clicmd:: timers throttle spf (0-600000) (0-600000) (0-600000)

   This command sets the initial `delay`, the `initial-holdtime`
   and the `maximum-holdtime` between when SPF is calculated and the
   event which triggered the calculation. The times are specified in
   milliseconds and must be in the range of 0 to 600000 milliseconds.

   The `delay` specifies the minimum amount of time to delay SPF
   calculation (hence it affects how long SPF calculation is delayed after
   an event which occurs outside of the holdtime of any previous SPF
   calculation, and also serves as a minimum holdtime).

   Consecutive SPF calculations will always be separated by at least
   'hold-time' milliseconds. The hold-time is adaptive and initially is
   set to the `initial-holdtime` configured with the above command.
   Events which occur within the holdtime of the previous SPF calculation
   will cause the holdtime to be increased by `initial-holdtime`, bounded
   by the `maximum-holdtime` configured with this command. If the adaptive
   hold-time elapses without any SPF-triggering event occurring then
   the current holdtime is reset to the `initial-holdtime`.

   .. code-block:: frr

      router ospf6
       timers throttle spf 200 400 10000


   In this example, the `delay` is set to 200ms, the initial holdtime is set
   to 400ms and the `maximum holdtime` to 10s. Hence there will always be at
   least 200ms between an event which requires SPF calculation and the actual
   SPF calculation. Further consecutive SPF calculations will always be
   separated by between 400ms to 10s, the hold-time increasing by 400ms each
   time an SPF-triggering event occurs within the hold-time of the previous
   SPF calculation.

.. index:: auto-cost reference-bandwidth COST
.. clicmd:: auto-cost reference-bandwidth COST

.. index:: auto-cost reference-bandwidth
.. clicmd:: no auto-cost reference-bandwidth

   This sets the reference bandwidth for cost calculations, where this
   bandwidth is considered equivalent to an OSPF cost of 1, specified in
   Mbits/s. The default is 100Mbit/s (i.e. a link of bandwidth 100Mbit/s
   or higher will have a cost of 1. Cost of lower bandwidth links will be
   scaled with reference to this cost).

   This configuration setting MUST be consistent across all routers
   within the OSPF domain.

.. index:: maximum-paths (1-64)
.. clicmd::[no] maximum-paths (1-64)

   Use this command to control the maximum number of parallel routes that
   OSPFv3 can support. The default is 64.

.. _ospf6-area:

OSPF6 area
==========

Area support for OSPFv3 is not yet implemented.

.. _ospf6-interface:

OSPF6 interface
===============

.. index:: ipv6 ospf6 cost COST
.. clicmd:: ipv6 ospf6 cost COST

   Sets interface's output cost. Default value depends on the interface
   bandwidth and on the auto-cost reference bandwidth.

.. index:: ipv6 ospf6 hello-interval HELLOINTERVAL
.. clicmd:: ipv6 ospf6 hello-interval HELLOINTERVAL

   Sets interface's Hello Interval. Default 10

.. index:: ipv6 ospf6 dead-interval DEADINTERVAL
.. clicmd:: ipv6 ospf6 dead-interval DEADINTERVAL

   Sets interface's Router Dead Interval. Default value is 40.

.. index:: ipv6 ospf6 retransmit-interval RETRANSMITINTERVAL
.. clicmd:: ipv6 ospf6 retransmit-interval RETRANSMITINTERVAL

   Sets interface's Rxmt Interval. Default value is 5.

.. index:: ipv6 ospf6 priority PRIORITY
.. clicmd:: ipv6 ospf6 priority PRIORITY

   Sets interface's Router Priority. Default value is 1.

.. index:: ipv6 ospf6 transmit-delay TRANSMITDELAY
.. clicmd:: ipv6 ospf6 transmit-delay TRANSMITDELAY

   Sets interface's Inf-Trans-Delay. Default value is 1.

.. index:: ipv6 ospf6 network (broadcast|point-to-point)
.. clicmd:: ipv6 ospf6 network (broadcast|point-to-point)

   Set explicitly network type for specified interface.

OSPF6 route-map
===============

Usage of *ospfd6*'s route-map support.

.. index:: set metric [+|-](0-4294967295)
.. clicmd:: set metric [+|-](0-4294967295)

   Set a metric for matched route when sending announcement. Use plus (+) sign
   to add a metric value to an existing metric. Use minus (-) sign to
   substract a metric value from an existing metric.

.. _redistribute-routes-to-ospf6:

Redistribute routes to OSPF6
============================

.. index:: redistribute <babel|bgp|connected|isis|kernel|openfabric|ripng|sharp|static|table> [route-map WORD]
.. clicmd:: redistribute <babel|bgp|connected|isis|kernel|openfabric|ripng|sharp|static|table> [route-map WORD]

   Redistribute routes from other protocols into OSPFv3.


.. _showing-ospf6-information:

Showing OSPF6 information
=========================

.. index:: show ipv6 ospf6 [INSTANCE_ID] [json]
.. clicmd:: show ipv6 ospf6 [INSTANCE_ID] [json]

   INSTANCE_ID is an optional OSPF instance ID. To see router ID and OSPF
   instance ID, simply type "show ipv6 ospf6 <cr>". JSON output can be
   obtained by appending 'json' to the end of command.

.. index:: show ipv6 ospf6 database [<detail|dump|internal>] [json]
.. clicmd:: show ipv6 ospf6 database [<detail|dump|internal>] [json]

   This command shows LSAs present in the LSDB. There are three view options.
   These options helps in viewing all the parameters of the LSAs. JSON output
   can be obtained by appending 'json' to the end of command. JSON option is
   not applicable with 'dump' option.

.. index:: show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> [json]
.. clicmd:: show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> [json]

   These options filters out the LSA based on its type. The three views options
   works here as well. JSON output can be obtained by appending 'json' to the
   end of command.

.. index:: show ipv6 ospf6 database adv-router A.B.C.D linkstate-id A.B.C.D [json]
.. clicmd:: show ipv6 ospf6 database adv-router A.B.C.D linkstate-id A.B.C.D [json]

   The LSAs additinally can also be filtered with the linkstate-id and
   advertising-router fields. We can use the LSA type filter and views with
   this command as well and visa-versa. JSON output can be obtained by
   appending 'json' to the end of command.

.. index:: show ipv6 ospf6 database self-originated [json]
.. clicmd:: show ipv6 ospf6 database self-originated [json]

   This command is used to filter the LSAs which are originated by the present
   router. All the other filters are applicable here as well.

.. index:: show ipv6 ospf6 interface [json]
.. clicmd:: show ipv6 ospf6 interface [json]

   To see OSPF interface configuration like costs. JSON output can be
   obtained by appending "json" in the end.

.. index:: show ipv6 ospf6 neighbor [json]
.. clicmd:: show ipv6 ospf6 neighbor [json]

   Shows state and chosen (Backup) DR of neighbor. JSON output can be
   obtained by appending 'json' at the end.

.. index:: show ipv6 ospf6 interface traffic [json]
.. clicmd:: show ipv6 ospf6 interface traffic [json]

   Shows counts of different packets that have been recieved and transmitted
   by the interfaces. JSON output can be obtained by appending "json" at the
   end.

.. index:: show ipv6 ospf6 request-list A.B.C.D
.. clicmd:: show ipv6 ospf6 request-list A.B.C.D

   Shows requestlist of neighbor.

.. index:: show ipv6 route ospf6
.. clicmd:: show ipv6 route ospf6

   This command shows internal routing table.

.. index:: show ipv6 ospf6 zebra [json]
.. clicmd:: show ipv6 ospf6 zebra [json]

   Shows state about what is being redistributed between zebra and OSPF6.
   JSON output can be obtained by appending "json" at the end.

.. index:: show ipv6 ospf6 redistribute [json]
.. clicmd:: show ipv6 ospf6 redistribute [json]

   Shows the routes which are redistributed by the router. JSON output can
   be obtained by appending 'json' at the end.

.. index:: show ipv6 ospf6 route [<intra-area|inter-area|external-1|external-2|X:X::X:X|X:X::X:X/M|detail|summary>] [json]
.. clicmd:: show ipv6 ospf6 route [<intra-area|inter-area|external-1|external-2|X:X::X:X|X:X::X:X/M|detail|summary>] [json]

   This command displays the ospfv3 routing table as determined by the most
   recent SPF calculations. Options are provided to view the different types
   of routes. Other than the standard view there are two other options, detail
   and summary. JSON output can be obtained by appending 'json' to the end of
   command.

.. index:: show ipv6 ospf6 route X:X::X:X/M match [detail] [json]
.. clicmd:: show ipv6 ospf6 route X:X::X:X/M match [detail] [json]

   The additional match option will match the given address to the destination
   of the routes, and return the result accordingly.

.. index:: show ipv6 ospf6 interface [IFNAME] prefix [detail|<X:X::X:X|X:X::X:X/M> [<match|detail>]] [json]
.. clicmd:: show ipv6 ospf6 interface [IFNAME] prefix [detail|<X:X::X:X|X:X::X:X/M> [<match|detail>]] [json]

   This command shows the prefixes present in the interface routing table.
   Interface name can also be given. JSON output can be obtained by appending
   'json' to the end of command.

OSPF6 Configuration Examples
============================

Example of ospf6d configured on one interface and area:

.. code-block:: frr

   interface eth0
    ipv6 ospf6 instance-id 0
   !
   router ospf6
    ospf6 router-id 212.17.55.53
    area 0.0.0.0 range 2001:770:105:2::/64
    interface eth0 area 0.0.0.0
   !
