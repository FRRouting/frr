# OSPFv3 (IPv6) Topology Test (point-to-multipoint)

## Topology
	                                                  -----\
	  SW1 - Stub Net 1            SW2 - Stub Net 2          \
	  fc00:1:1:1::/64             fc00:2:2:2::/64            \
	\___________________/      \___________________/          |
	          |                          |                    |
	          |                          |                    |
	          | ::1                      | ::2                |
	+---------+---------+      +---------+---------+          |
	|        R1         |      |        R2         |          |
	|     FRRouting     |      |     FRRouting     |          |
	| Rtr-ID: 10.0.0.1  |      | Rtr-ID: 10.0.0.2  |          |
	+---------+---------+      +---------+---------+          |
	          | ::1                      | ::2                 \
	           \______        ___________/                      OSPFv3
	                  \      /                               Area 0.0.0.0
	                   \    /                                  /
	             ~~~~~~~~~~~~~~~~~~                           |
	           ~~       SW5        ~~                         |
	         ~~       Switch         ~~                       |
	           ~~  fc00:A:A:A::/64 ~~                         |
	             ~~~~~~~~~~~~~~~~~~                           |
	                     |                 /----              |
	                     | ::3            | SW3 - Stub Net 3  |
	           +---------+---------+    /-+ fc00:3:3:3::/64   |
	           |        R3         |   /  |                  /
	           |     FRRouting     +--/    \----            /
	           | Rtr-ID: 10.0.0.3  | ::3        ___________/
	           +---------+---------+                       \
	                     | ::3                              \
	                     |                                   \
	             ~~~~~~~~~~~~~~~~~~                           |
	           ~~       SW6        ~~                         |
	         ~~       Switch         ~~                       |
	           ~~  fc00:B:B:B::/64 ~~                          \
	             ~~~~~~~~~~~~~~~~~~                             OSPFv3
	                     |                                   Area 0.0.0.1
	                     | ::4                                 /
	           +---------+---------+       /----              |
	           |        R4         |      | SW4 - Stub Net 4  |
	           |     FRRouting     +------+ fc00:4:4:4::/64   |
	           | Rtr-ID: 10.0.0.4  | ::4  |                   /
	           +-------------------+       \----             /
	                                                   -----/

## FRR Configuration

Full config as used is in r1 / r2 / r3 / r4 / r5 subdirectories

Simplified `R1` config (R1 is similar)

	hostname r1
	!
	interface r1-stubnet
	 ipv6 address fc00:1:1:1::1/64
	 ipv6 ospf6 passive
	 ipv6 ospf6 area 0.0.0.0
	!
	interface r1-sw5
	 ipv6 address fc00:a:a:a::1/64
	 ipv6 ospf6 network point-to-multipoint
	 ipv6 ospf6 area 0.0.0.0
	!
	router ospf6
	 router-id 10.0.0.1
	 log-adjacency-changes detail
	 redistribute static
	!
	ipv6 route fc00:1111:1111:1111::/64 fc00:1:1:1::1234

Simplified `R3` config

	hostname r3
	!
	interface r3-stubnet
	 ipv6 address fc00:3:3:3::3/64
	 ipv6 ospf6 passive
	 ipv6 ospf6 area 0.0.0.0
	!
	interface r3-sw5
	 ipv6 address fc00:a:a:a::3/64
	 ipv6 ospf6 network point-to-multipoint
	 ipv6 ospf6 area 0.0.0.0
	 ipv6 ospf6 p2p-p2mp connected-prefixes include
	!
	interface r3-sw6
	 ipv6 address fc00:b:b:b::3/64
	 ipv6 ospf6 network point-to-multipoint
	 ipv6 ospf6 area 0.0.0.1
	 ipv6 ospf6 p2p-p2mp connected-prefixes include
	!
	router ospf6
	 router-id 10.0.0.3
	 log-adjacency-changes detail
	 redistribute static
	!
	ipv6 route fc00:3333:3333:3333::/64 fc00:3:3:3::1234

## Tests executed

### Check if FRR is running

Test is executed by running

	vtysh -c "show logging" | grep "Logging configuration for"

on each FRR router. This should return the logging information for all daemons registered
to Zebra and the list of running daemons is compared to the daemons started for this test (`zebra` and `ospf6d`)

### Check if OSPFv3 to converge

OSPFv3 is expected to converge on each view within 60s total time. Convergence is verified by executing (on each node)

	vtysh -c "show ipv6 ospf neigh"

and checking for "Full" neighbor status in the output. An additional 15 seconds after the full converge is waited for
routes to populate before the following routing table checks are executed

### Check OSPFv3 Routing Tables

Routing table is verified by running

	vtysh -c "show ipv6 route"

on each node and comparing the result to the stored example config (see `show_ipv6_route.ref` in r1 / r2 / r3 / r4 directories).
Link-Local addresses are masked out before the compare.

### Check Linux Kernel Routing Table

Linux Kernel IPv6 Routing table is verified on each FRR node with

	ip -6 route

Tables are compared with reference routing table (see `ip_6_address.ref` in r1 / r2 / r3 / r4 directories).
Link-Local addresses are translated after getting collected on each node with interface name to make them consistent
