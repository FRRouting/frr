.. _OSPFv3:

******
OSPFv3
******

*ospf6d* is a daemon support OSPF version 3 for IPv6 network.
OSPF for IPv6 is described in RFC2740.

.. _OSPF6_router:

OSPF6 router
============

.. index:: {Command} {router ospf6} {}

{Command} {router ospf6} {}

.. index:: {OSPF6 Command} {router-id `a.b.c.d`} {}

{OSPF6 Command} {router-id `a.b.c.d`} {}
  Set router's Router-ID.

.. index:: {OSPF6 Command} {interface `ifname` area `area`} {}

{OSPF6 Command} {interface `ifname` area `area`} {}
  Bind interface to specified area, and start sending OSPF packets.  `area` can
  be specified as 0.

.. index:: {OSPF6 Command} {timers throttle spf `delay` `initial-holdtime` `max-holdtime`} {}

{OSPF6 Command} {timers throttle spf `delay` `initial-holdtime` `max-holdtime`} {}
.. index:: {OSPF6 Command} {no timers throttle spf} {}

{OSPF6 Command} {no timers throttle spf} {}
    This command sets the initial `delay`, the `initial-holdtime`
    and the `maximum-holdtime` between when SPF is calculated and the
    event which triggered the calculation. The times are specified in
    milliseconds and must be in the range of 0 to 600000 milliseconds.

    The `delay` specifies the minimum amount of time to delay SPF
    calculation (hence it affects how long SPF calculation is delayed after
    an event which occurs outside of the holdtime of any previous SPF
    calculation, and also serves as a minimum holdtime).

    Consecutive SPF calculations will always be seperated by at least
    'hold-time' milliseconds. The hold-time is adaptive and initially is
    set to the `initial-holdtime` configured with the above command.
    Events which occur within the holdtime of the previous SPF calculation
    will cause the holdtime to be increased by `initial-holdtime`, bounded
    by the `maximum-holdtime` configured with this command. If the adaptive
    hold-time elapses without any SPF-triggering event occuring then
    the current holdtime is reset to the `initial-holdtime`.

::

      router ospf6
       timers throttle spf 200 400 10000
      

    In this example, the `delay` is set to 200ms, the @var{initial
    holdtime} is set to 400ms and the `maximum holdtime` to 10s. Hence
    there will always be at least 200ms between an event which requires SPF
    calculation and the actual SPF calculation. Further consecutive SPF
    calculations will always be seperated by between 400ms to 10s, the
    hold-time increasing by 400ms each time an SPF-triggering event occurs
    within the hold-time of the previous SPF calculation.

.. index:: {OSPF6 Command} {auto-cost reference-bandwidth `cost`} {}

{OSPF6 Command} {auto-cost reference-bandwidth `cost`} {}
.. index:: {OSPF6 Command} {no auto-cost reference-bandwidth} {}

{OSPF6 Command} {no auto-cost reference-bandwidth} {}
      This sets the reference bandwidth for cost calculations, where this
      bandwidth is considered equivalent to an OSPF cost of 1, specified in
      Mbits/s. The default is 100Mbit/s (i.e. a link of bandwidth 100Mbit/s
      or higher will have a cost of 1. Cost of lower bandwidth links will be
      scaled with reference to this cost).

      This configuration setting MUST be consistent across all routers
      within the OSPF domain.

.. _OSPF6_area:

OSPF6 area
==========

Area support for OSPFv3 is not yet implemented.

.. _OSPF6_interface:

OSPF6 interface
===============

.. index:: {Interface Command} {ipv6 ospf6 cost COST} {}

{Interface Command} {ipv6 ospf6 cost COST} {}
  Sets interface's output cost.  Default value depends on the interface
  bandwidth and on the auto-cost reference bandwidth.

.. index:: {Interface Command} {ipv6 ospf6 hello-interval HELLOINTERVAL} {}

{Interface Command} {ipv6 ospf6 hello-interval HELLOINTERVAL} {}
  Sets interface's Hello Interval.  Default 40

.. index:: {Interface Command} {ipv6 ospf6 dead-interval DEADINTERVAL} {}

{Interface Command} {ipv6 ospf6 dead-interval DEADINTERVAL} {}
  Sets interface's Router Dead Interval.  Default value is 40.

.. index:: {Interface Command} {ipv6 ospf6 retransmit-interval RETRANSMITINTERVAL} {}

{Interface Command} {ipv6 ospf6 retransmit-interval RETRANSMITINTERVAL} {}
  Sets interface's Rxmt Interval.  Default value is 5.

.. index:: {Interface Command} {ipv6 ospf6 priority PRIORITY} {}

{Interface Command} {ipv6 ospf6 priority PRIORITY} {}
  Sets interface's Router Priority.  Default value is 1.

.. index:: {Interface Command} {ipv6 ospf6 transmit-delay TRANSMITDELAY} {}

{Interface Command} {ipv6 ospf6 transmit-delay TRANSMITDELAY} {}
  Sets interface's Inf-Trans-Delay.  Default value is 1.

.. index:: {Interface Command} {ipv6 ospf6 network (broadcast|point-to-point)} {}

{Interface Command} {ipv6 ospf6 network (broadcast|point-to-point)} {}
  Set explicitly network type for specifed interface.

.. _Redistribute_routes_to_OSPF6:

Redistribute routes to OSPF6
============================

.. index:: {OSPF6 Command} {redistribute static} {}

{OSPF6 Command} {redistribute static} {}
.. index:: {OSPF6 Command} {redistribute connected} {}

{OSPF6 Command} {redistribute connected} {}
.. index:: {OSPF6 Command} {redistribute ripng} {}

{OSPF6 Command} {redistribute ripng} {}

.. _Showing_OSPF6_information:

Showing OSPF6 information
=========================

.. index:: {Command} {show ipv6 ospf6 [INSTANCE_ID]} {}

{Command} {show ipv6 ospf6 [INSTANCE_ID]} {}
  INSTANCE_ID is an optional OSPF instance ID. To see router ID and OSPF
  instance ID, simply type "show ipv6 ospf6 <cr>".

.. index:: {Command} {show ipv6 ospf6 database} {}

{Command} {show ipv6 ospf6 database} {}
  This command shows LSA database summary.  You can specify the type of LSA.

.. index:: {Command} {show ipv6 ospf6 interface} {}

{Command} {show ipv6 ospf6 interface} {}
  To see OSPF interface configuration like costs.

.. index:: {Command} {show ipv6 ospf6 neighbor} {}

{Command} {show ipv6 ospf6 neighbor} {}
  Shows state and chosen (Backup) DR of neighbor.

.. index:: {Command} {show ipv6 ospf6 request-list A.B.C.D} {}

{Command} {show ipv6 ospf6 request-list A.B.C.D} {}
  Shows requestlist of neighbor.

.. index:: {Command} {show ipv6 route ospf6} {}

{Command} {show ipv6 route ospf6} {}
  This command shows internal routing table.

.. index:: {Command} {show ipv6 ospf6 zebra} {}

{Command} {show ipv6 ospf6 zebra} {}
  Shows state about what is being redistributed between zebra and OSPF6

OSPF6 Configuration Examples
============================

Example of ospf6d configured on one interface and area:

::

  interface eth0
   ipv6 ospf6 instance-id 0
  !
  router ospf6
   router-id 212.17.55.53
   area 0.0.0.0 range 2001:770:105:2::/64
   interface eth0 area 0.0.0.0
  !
  

