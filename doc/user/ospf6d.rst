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

.. index:: router-id A.B.C.D
.. clicmd:: router-id A.B.C.D

   Set router's Router-ID.

.. index:: interface IFNAME area AREA
.. clicmd:: interface IFNAME area AREA

   Bind interface to specified area, and start sending OSPF packets. `area` can
   be specified as 0.

.. index:: timers throttle spf DELAY INITIAL-HOLDTIME MAX-HOLDTIME
.. clicmd:: timers throttle spf DELAY INITIAL-HOLDTIME MAX-HOLDTIME

.. index:: no timers throttle spf
.. clicmd:: no timers throttle spf

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

.. index:: no auto-cost reference-bandwidth
.. clicmd:: no auto-cost reference-bandwidth

   This sets the reference bandwidth for cost calculations, where this
   bandwidth is considered equivalent to an OSPF cost of 1, specified in
   Mbits/s. The default is 100Mbit/s (i.e. a link of bandwidth 100Mbit/s
   or higher will have a cost of 1. Cost of lower bandwidth links will be
   scaled with reference to this cost).

   This configuration setting MUST be consistent across all routers
   within the OSPF domain.

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

.. _redistribute-routes-to-ospf6:

Redistribute routes to OSPF6
============================

.. index:: redistribute static
.. clicmd:: redistribute static

.. index:: redistribute connected
.. clicmd:: redistribute connected

.. index:: redistribute ripng
.. clicmd:: redistribute ripng


.. _showing-ospf6-information:

Showing OSPF6 information
=========================

.. index:: show ipv6 ospf6 [INSTANCE_ID]
.. clicmd:: show ipv6 ospf6 [INSTANCE_ID]

   INSTANCE_ID is an optional OSPF instance ID. To see router ID and OSPF
   instance ID, simply type "show ipv6 ospf6 <cr>".

.. index:: show ipv6 ospf6 database
.. clicmd:: show ipv6 ospf6 database

   This command shows LSA database summary. You can specify the type of LSA.

.. index:: show ipv6 ospf6 interface
.. clicmd:: show ipv6 ospf6 interface

   To see OSPF interface configuration like costs.

.. index:: show ipv6 ospf6 neighbor
.. clicmd:: show ipv6 ospf6 neighbor

   Shows state and chosen (Backup) DR of neighbor.

.. index:: show ipv6 ospf6 request-list A.B.C.D
.. clicmd:: show ipv6 ospf6 request-list A.B.C.D

   Shows requestlist of neighbor.

.. index:: show ipv6 route ospf6
.. clicmd:: show ipv6 route ospf6

   This command shows internal routing table.

.. index:: show ipv6 ospf6 zebra
.. clicmd:: show ipv6 ospf6 zebra

   Shows state about what is being redistributed between zebra and OSPF6

OSPF6 Configuration Examples
============================

Example of ospf6d configured on one interface and area:

.. code-block:: frr

   interface eth0
    ipv6 ospf6 instance-id 0
   !
   router ospf6
    router-id 212.17.55.53
    area 0.0.0.0 range 2001:770:105:2::/64
    interface eth0 area 0.0.0.0
   !
