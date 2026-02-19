===============================
OSPF DSCP Control Packet Marking
===============================

OSPF allows operators to mark control packets with a specific Differentiated
Services Code Point (DSCP) value. This feature is useful on networks where
traffic prioritization is required to ensure timely delivery of routing
protocol packets, especially under congestion. See
RFC 4222 <https://datatracker.ietf.org/doc/html/rfc4222> for additional
guidance on OSPF control‑plane robustness.

Behavior
--------

When configured, OSPF applies the specified DSCP value to outgoing control
packets according to the selected mode. This allows OSPF traffic to be
classified and prioritized by QoS mechanisms in the network. By default,
OSPF sends all control packets without modifying the DSCP field.

Low‑priority control packets include LSA Updates, Database Description packets,
and Link State Requests. High‑priority packets such as Hellos and Link State
Acknowledgments typically retain their default DSCP unless the ``all`` option
is used.

This feature provides flexibility: operators may assign a DSCP value to all
control packets and then selectively adjust the DSCP for low‑priority traffic.
The ``no`` form of the command restores the default DSCP behavior.
