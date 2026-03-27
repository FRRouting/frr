=======================
OSPF Dead Timer Reset
=======================

Overview
--------

RFC 4222 Recommendation 2 advises that when packet prioritization is not
feasible, an OSPF implementation should refresh the neighbor inactivity
(dead) timer upon receipt of *any* valid OSPF unicast packet, or any OSPF
packet sent to AllSPFRouters on a point-to-point link. This prevents
unnecessary adjacency loss when Hello packets are delayed or dropped due to
congestion.

Behavior
--------

When ``ip ospf dead-timer-reset any-control`` is enabled, OSPF resets the
neighbor inactivity timer upon receipt of:

- Any valid unicast OSPF control packet

This extends adjacency lifetime even when Hello packets are delayed by
low-speed links or control-plane congestion. The default behavior is to
reset the dead timer only upon receipt of Hello packets.

Implementation Notes
--------------------

- The logic is implemented in the neighbor receive path.
- Only packets that pass basic validation reset the timer.
- The feature is enabled globally under the OSPF daemon.
- The ``no`` form restores the default Hello-only behavior.
- Note RFC 4222 Cautions this may interact with RFC 4222
  recommendation 1 see the RFC for details.

References
----------

- RFC 4222 <https://datatracker.ietf.org/doc/html/rfc4222>
