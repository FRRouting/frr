IS-IS PPR Basic
===============

.. contents:: Table of contents
    :local:
    :backlinks: entry
    :depth: 2

Software
~~~~~~~~

The FRR PPR implementation for IS-IS is available here:
https://github.com/opensourcerouting/frr/tree/isisd-ppr

Topology
~~~~~~~~

In this topology we have an IS-IS network consisting of 12 routers. CE1
and CE2 are the consumer edges, connected to R11 and R14, respectively.
Three hosts are connected to the CEs using only static routes.

Router R11 advertises 6 PPR TLVs, which corresponds to three
bi-directional GRE tunnels: \* **6000:1::1 <-> 6000:2::1:** {R11 - R21 -
R22 - R23 - R14} (IPv6 Node Addresses only) \* **6000:1::2 <->
6000:2::2:** {R11 - R21 - R32 - R41 - R33 - R23 - R14} (IPv6 Node and
Interface Addresses) \* **6000:1::3 <-> 6000:2::3:** {R11 - R21 - R99 -
R23 - R14} (misconfigured path)

PBR rules are configured on R11 and R14 to route the traffic between
Host 1 and Host 3 using the first PPR tunnel. Traffic between Host 2 and
Host 3 uses the regular IS-IS shortest path.

Additional information: \* Addresses in the 4000::/16 range refer to
interface addresses, where the last hextet corresponds to the node ID.
\* Addresses in the 5000::/16 range refer to loopback addresses, where
the last hextet corresponds to the node ID. \* Addresses in the
6000::/16 range refer to PPR-ID addresses.

::

   +-------+       +-------+                                                 +-------+
   |       |       |       |                                                 |       |
   | HOST1 |       | HOST2 |                                                 | HOST3 |
   |       |       |       |                                                 |       |
   +---+---+       +---+---+                                                 +---+---+
       |               |                                                         |
       |fd00:10:1::/64 |                                                         |
       +-----+  +------+                                           fd00:20:1::/64|
             |  |fd00:10:2::/64                                                  |
             |  |                                                                |
           +-+--+--+                                                         +---+---+
           |       |                                                         |       |
           |  CE1  |                                                         |  CE2  |
           |       |                                                         |       |
           +---+---+                                                         +---+---+
               |                                                                 |
               |                                                                 |
               |fd00:10:0::/64                                     fd00:20:0::/64|
               |                                                                 |
               |                                                                 |
           +---+---+             +-------+             +-------+             +---+---+
           |       |4000:101::/64|       |4000:102::/64|       |4000:103::/64|       |
           |  R11  +-------------+  R12  +-------------+  R13  +-------------+  R14  |
           |       |             |       |             |       |             |       |
           +---+---+             +--+-+--+             +--+-+--+             +---+---+
               |                    | |                   | |                    |
               |4000:104::/64       | |4000:106::/64      | |4000:108::/64       |
               +---------+ +--------+ +--------+ +--------+ +--------+ +---------+
                         | |4000:105::/64      | |4000:107::/64      | |4000:109::/64
                         | |                   | |                   | |
                      +--+-+--+             +--+-+--+             +--+-+--+
                      |       |4000:110::/64|       |4000:111::/64|       |
                      |  R21  +-------------+  R22  +-------------+  R23  |
                      |       |             |       |             |       |
                      +--+-+--+             +--+-+--+             +--+-+--+
                         | |                   | |                   | |
                         | |4000:113::/64      | |4000:115::/64      | |4000:117::/64
               +---------+ +--------+ +--------+ +--------+ +--------+ +---------+
               |4000:112::/64       | |4000:114::/64      | |4000:116::/64       |
               |                    | |                   | |                    |
           +---+---+             +--+-+--+             +--+-+--+             +---+---+
           |       |4000:118::/64|       |4000:119::/64|       |4000:120::/64|       |
           |  R31  +-------------+  R32  +-------------+  R33  +-------------+  R34  |
           |       |             |       |             |       |             |       |
           +-------+             +---+---+             +---+---+             +-------+
                                     |                     |
                                     |4000:121::/64        |
                                     +----------+----------+
                                                |
                                                |
                                            +---+---+
                                            |       |
                                            |  R41  |
                                            |       |
                                            +-------+

Configuration
~~~~~~~~~~~~~

PPR TLV processing needs to be enabled on all IS-IS routers using the
``ppr on`` command. The advertisements of all PPR TLVs is done by router
R11.

CLI configuration
^^^^^^^^^^^^^^^^^

.. code:: yaml

   ---

   routers:

     host1:
       links:
         eth-ce1:
           peer: [ce1, eth-host1]
       frr:
         zebra:
         staticd:
         config: |
           interface eth-ce1
            ipv6 address fd00:10:1::1/64
           !
           ipv6 route ::/0 fd00:10:1::100

     host2:
       links:
         eth-ce1:
           peer: [ce1, eth-host2]
       frr:
         zebra:
         staticd:
         config: |
           interface eth-ce1
            ipv6 address fd00:10:2::1/64
           !
           ipv6 route ::/0 fd00:10:2::100

     host3:
       links:
         eth-ce2:
           peer: [ce2, eth-host3]
       frr:
         zebra:
         staticd:
         config: |
           interface eth-ce2
            ipv6 address fd00:20:1::1/64
           !
           ipv6 route ::/0 fd00:20:1::100

     ce1:
       links:
         eth-host1:
           peer: [host1, eth-ce1]
         eth-host2:
           peer: [host2, eth-ce1]
         eth-rt11:
           peer: [rt11, eth-ce1]
       frr:
         zebra:
         staticd:
         config: |
           interface eth-host1
            ipv6 address fd00:10:1::100/64
           !
           interface eth-host2
            ipv6 address fd00:10:2::100/64
           !
           interface eth-rt11
            ipv6 address fd00:10:0::100/64
           !
           ipv6 route ::/0 fd00:10:0::11

     ce2:
       links:
         eth-host3:
           peer: [host3, eth-ce2]
         eth-rt14:
           peer: [rt14, eth-ce2]
       frr:
         zebra:
         staticd:
         config: |
           interface eth-host3
            ipv6 address fd00:20:1::100/64
           !
           interface eth-rt14
            ipv6 address fd00:20:0::100/64
           !
           ipv6 route ::/0 fd00:20:0::14

     rt11:
       links:
         lo-ppr:
         eth-ce1:
           peer: [ce1, eth-rt11]
         eth-rt12:
           peer: [rt12, eth-rt11]
         eth-rt21:
           peer: [rt21, eth-rt11]
       shell: |
         # GRE tunnel for preferred packets (PPR)
         ip -6 tunnel add tun-ppr mode ip6gre remote 6000:2::1 local 6000:1::1 ttl 64
         ip link set dev tun-ppr up
         # PBR rules
         ip -6 rule add from fd00:10:1::/64 to fd00:20:1::/64 iif eth-ce1 lookup 10000
         ip -6 route add default dev tun-ppr table 10000
       frr:
         zebra:
         staticd:
         isisd:
         config: |
           interface lo-ppr
            ipv6 address 6000:1::1/128
            ipv6 address 6000:1::2/128
            ipv6 address 6000:1::3/128
           !
           interface lo
            ipv6 address 5000::11/128
            ipv6 router isis 1
           !
           interface eth-ce1
            ipv6 address fd00:10:0::11/64
           !
           interface eth-rt12
            ipv6 address 4000:101::11/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt21
            ipv6 address 4000:104::11/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           ipv6 route fd00:10::/32 fd00:10:0::100
           !
           ppr group VOIP
            ppr ipv6 6000:1::1/128 prefix 5000::11/128 metric 50
             pde ipv6-node 5000::14/128
             pde ipv6-node 5000::23/128
             pde ipv6-node 5000::22/128
             pde ipv6-node 5000::21/128
             pde ipv6-node 5000::11/128
            !
            ppr ipv6 6000:2::1/128 prefix 5000::14/128 metric 50
             pde ipv6-node 5000::11/128
             pde ipv6-node 5000::21/128
             pde ipv6-node 5000::22/128
             pde ipv6-node 5000::23/128
             pde ipv6-node 5000::14/128
            !
           !
           ppr group INTERFACE_PDES
            ppr ipv6 6000:1::2/128 prefix 5000::11/128
             pde ipv6-node 5000::14/128
             pde ipv6-node 5000::23/128
             pde ipv6-node 5000::33/128
             pde ipv6-interface 4000:121::41/64
             pde ipv6-node 5000::32/128
             pde ipv6-interface 4000:113::21/64
             pde ipv6-node 5000::11/128
            !
            ppr ipv6 6000:2::2/128 prefix 5000::14/128
             pde ipv6-node 5000::11/128
             pde ipv6-node 5000::21/128
             pde ipv6-node 5000::32/128
             pde ipv6-interface 4000:121::41/64
             pde ipv6-node 5000::33/128
             pde ipv6-interface 4000:116::23/64
             pde ipv6-node 5000::14/128
            !
           !
           ppr group BROKEN
            ppr ipv6 6000:1::3/128 prefix 5000::11/128 metric 1500
             pde ipv6-node 5000::14/128
             pde ipv6-node 5000::23/128
             ! non-existing node!!!
             pde ipv6-node 5000::99/128
             pde ipv6-node 5000::21/128
             pde ipv6-node 5000::11/128
            !
            ppr ipv6 6000:2::3/128 prefix 5000::14/128 metric 1500
             pde ipv6-node 5000::11/128
             pde ipv6-node 5000::21/128
             ! non-existing node!!!
             pde ipv6-node 5000::99/128
             pde ipv6-node 5000::23/128
             pde ipv6-node 5000::14/128
            !
           !
           router isis 1
            net 49.0000.0000.0000.0011.00
            is-type level-1
            topology ipv6-unicast
            ppr on
            ppr advertise VOIP
            ppr advertise INTERFACE_PDES
            ppr advertise BROKEN
           !

     rt12:
       links:
         eth-rt11:
           peer: [rt11, eth-rt12]
         eth-rt13:
           peer: [rt13, eth-rt12]
         eth-rt21:
           peer: [rt21, eth-rt12]
         eth-rt22:
           peer: [rt22, eth-rt12]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::12/128
            ipv6 router isis 1
           !
           interface eth-rt11
            ipv6 address 4000:101::12/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt13
            ipv6 address 4000:102::12/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt21
            ipv6 address 4000:105::12/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt22
            ipv6 address 4000:106::12/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0012.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt13:
       links:
         eth-rt12:
           peer: [rt12, eth-rt13]
         eth-rt14:
           peer: [rt14, eth-rt13]
         eth-rt22:
           peer: [rt22, eth-rt13]
         eth-rt23:
           peer: [rt23, eth-rt13]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::13/128
            ipv6 router isis 1
           !
           interface eth-rt12
            ipv6 address 4000:102::13/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt14
            ipv6 address 4000:103::13/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt22
            ipv6 address 4000:107::13/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt23
            ipv6 address 4000:108::13/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0013.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt14:
       links:
         lo-ppr:
         eth-ce2:
           peer: [ce2, eth-rt14]
         eth-rt13:
           peer: [rt13, eth-rt14]
         eth-rt23:
           peer: [rt23, eth-rt14]
       shell: |
         # GRE tunnel for preferred packets (PPR)
         ip -6 tunnel add tun-ppr mode ip6gre remote 6000:1::1 local 6000:2::1 ttl 64
         ip link set dev tun-ppr up
         # PBR rules
         ip -6 rule add from fd00:20:1::/64 to fd00:10:1::/64 iif eth-ce2 lookup 10000
         ip -6 route add default dev tun-ppr table 10000
       frr:
         zebra:
         staticd:
         isisd:
         config: |
           interface lo-ppr
            ipv6 address 6000:2::1/128
            ipv6 address 6000:2::2/128
            ipv6 address 6000:2::3/128
           !
           interface lo
            ipv6 address 5000::14/128
            ipv6 router isis 1
           !
           interface eth-ce2
            ipv6 address fd00:20:0::14/64
           !
           interface eth-rt13
            ipv6 address 4000:103::14/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt23
            ipv6 address 4000:109::14/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           ipv6 route fd00:20::/32 fd00:20:0::100
           !
           router isis 1
            net 49.0000.0000.0000.0014.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt21:
       links:
         eth-rt11:
           peer: [rt11, eth-rt21]
         eth-rt12:
           peer: [rt12, eth-rt21]
         eth-rt22:
           peer: [rt22, eth-rt21]
         eth-rt31:
           peer: [rt31, eth-rt21]
         eth-rt32:
           peer: [rt32, eth-rt21]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::21/128
            ipv6 router isis 1
           !
           interface eth-rt11
            ipv6 address 4000:104::21/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt12
            ipv6 address 4000:105::21/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt22
            ipv6 address 4000:110::21/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt31
            ipv6 address 4000:112::21/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt32
            ipv6 address 4000:113::21/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0021.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt22:
       links:
         eth-rt12:
           peer: [rt12, eth-rt22]
         eth-rt13:
           peer: [rt13, eth-rt22]
         eth-rt21:
           peer: [rt21, eth-rt22]
         eth-rt23:
           peer: [rt23, eth-rt22]
         eth-rt32:
           peer: [rt32, eth-rt22]
         eth-rt33:
           peer: [rt33, eth-rt22]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::22/128
            ipv6 router isis 1
           !
           interface eth-rt12
            ipv6 address 4000:106::22/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt13
            ipv6 address 4000:107::22/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt21
            ipv6 address 4000:110::22/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt23
            ipv6 address 4000:111::22/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt32
            ipv6 address 4000:114::22/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt33
            ipv6 address 4000:115::22/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0022.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt23:
       links:
         eth-rt13:
           peer: [rt13, eth-rt23]
         eth-rt14:
           peer: [rt14, eth-rt23]
         eth-rt22:
           peer: [rt22, eth-rt23]
         eth-rt33:
           peer: [rt33, eth-rt23]
         eth-rt34:
           peer: [rt34, eth-rt23]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::23/128
            ipv6 router isis 1
           !
           interface eth-rt13
            ipv6 address 4000:108::23/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt14
            ipv6 address 4000:109::23/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt22
            ipv6 address 4000:111::23/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt33
            ipv6 address 4000:116::23/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt34
            ipv6 address 4000:117::23/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0023.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt31:
       links:
         eth-rt21:
           peer: [rt21, eth-rt31]
         eth-rt32:
           peer: [rt32, eth-rt31]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::31/128
            ipv6 router isis 1
           !
           interface eth-rt21
            ipv6 address 4000:112::31/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt32
            ipv6 address 4000:118::31/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0031.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt32:
       links:
         eth-rt21:
           peer: [rt21, eth-rt32]
         eth-rt22:
           peer: [rt22, eth-rt32]
         eth-rt31:
           peer: [rt31, eth-rt32]
         eth-rt33:
           peer: [rt33, eth-rt32]
         eth-sw1:
           peer: [sw1, eth-rt32]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::32/128
            ipv6 router isis 1
           !
           interface eth-rt21
            ipv6 address 4000:113::32/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt22
            ipv6 address 4000:114::32/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt31
            ipv6 address 4000:118::32/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt33
            ipv6 address 4000:119::32/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-sw1
            ipv6 address 4000:121::32/64
            ipv6 router isis 1
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0032.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt33:
       links:
         eth-rt22:
           peer: [rt22, eth-rt33]
         eth-rt23:
           peer: [rt23, eth-rt33]
         eth-rt32:
           peer: [rt32, eth-rt33]
         eth-rt34:
           peer: [rt34, eth-rt33]
         eth-sw1:
           peer: [sw1, eth-rt33]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::33/128
            ipv6 router isis 1
           !
           interface eth-rt22
            ipv6 address 4000:115::33/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt23
            ipv6 address 4000:116::33/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt32
            ipv6 address 4000:119::33/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt34
            ipv6 address 4000:120::33/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-sw1
            ipv6 address 4000:121::33/64
            ipv6 router isis 1
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0033.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt34:
       links:
         eth-rt23:
           peer: [rt23, eth-rt34]
         eth-rt33:
           peer: [rt33, eth-rt34]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::34/128
            ipv6 router isis 1
           !
           interface eth-rt23
            ipv6 address 4000:117::34/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           interface eth-rt33
            ipv6 address 4000:120::34/64
            ipv6 router isis 1
            isis network point-to-point
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0034.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

     rt41:
       links:
         eth-sw1:
           peer: [sw1, eth-rt41]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ipv6 address 5000::41/128
            ipv6 router isis 1
           !
           interface eth-sw1
            ipv6 address 4000:121::41/64
            ipv6 router isis 1
            isis hello-multiplier 3
           !
           router isis 1
            net 49.0000.0000.0000.0041.00
            is-type level-1
            topology ipv6-unicast
            ppr on
           !

   switches:
     sw1:
       links:
         eth-rt32:
           peer: [rt32, eth-sw1]
         eth-rt33:
           peer: [rt33, eth-sw1]
         eth-rt41:
           peer: [rt41, eth-sw1]

   frr:
     base-config: |
       hostname %(node)
       password 1
       log file %(logdir)/%(node).log
       log commands
       !
       debug zebra rib
       debug isis ppr
       debug isis events
       debug isis route-events
       debug isis spf-events
       debug isis lsp-gen
       !

YANG
^^^^

PPR can also be configured using NETCONF, RESTCONF and gRPC based on the
following YANG models: \*
`frr-ppr.yang <https://github.com/opensourcerouting/frr/blob/isisd-ppr/yang/frr-ppr.yang>`__
\*
`frr-isisd.yang <https://github.com/opensourcerouting/frr/blob/isisd-ppr/yang/frr-isisd.yang>`__

As an example, here’s R11 configuration in the XML format:

.. code:: xml

   <lib xmlns="http://frrouting.org/yang/interface">
     <interface>
       <name>lo-ppr</name>
       <vrf>default</vrf>
     </interface>
     <interface>
       <name>lo</name>
       <vrf>default</vrf>
       <isis xmlns="http://frrouting.org/yang/isisd">
         <area-tag>1</area-tag>
         <ipv6-routing>true</ipv6-routing>
       </isis>
     </interface>
     <interface>
       <name>eth-ce1</name>
       <vrf>default</vrf>
     </interface>
     <interface>
       <name>eth-rt12</name>
       <vrf>default</vrf>
       <isis xmlns="http://frrouting.org/yang/isisd">
         <area-tag>1</area-tag>
         <ipv6-routing>true</ipv6-routing>
         <hello>
           <multiplier>
             <level-1>3</level-1>
             <level-2>3</level-2>
           </multiplier>
         </hello>
         <network-type>point-to-point</network-type>
       </isis>
     </interface>
     <interface>
       <name>eth-rt21</name>
       <vrf>default</vrf>
       <isis xmlns="http://frrouting.org/yang/isisd">
         <area-tag>1</area-tag>
         <ipv6-routing>true</ipv6-routing>
         <hello>
           <multiplier>
             <level-1>3</level-1>
             <level-2>3</level-2>
           </multiplier>
         </hello>
         <network-type>point-to-point</network-type>
       </isis>
     </interface>
   </lib>
   <ppr xmlns="http://frrouting.org/yang/ppr">
     <group>
       <name>VOIP</name>
       <ipv6>
         <ppr-id>6000:1::1/128</ppr-id>
         <ppr-prefix>5000::11/128</ppr-prefix>
         <ppr-pde>
           <pde-id>5000::14/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>    
         </ppr-pde>                        
         <ppr-pde>                      
           <pde-id>5000::23/128</pde-id>       
           <pde-id-type>ipv6-node</pde-id-type>  
           <pde-type>topological</pde-type>
         </ppr-pde>          
         <ppr-pde>                                           
           <pde-id>5000::22/128</pde-id>       
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>                    
         <ppr-pde>                            
           <pde-id>5000::21/128</pde-id>       
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>    
         </ppr-pde>                        
         <ppr-pde>                         
           <pde-id>5000::11/128</pde-id>            
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>    
         </ppr-pde>                        
         <attributes>                   
           <ppr-metric>50</ppr-metric>         
         </attributes>                     
       </ipv6>
       <ipv6>                                  
         <ppr-id>6000:2::1/128</ppr-id>
         <ppr-prefix>5000::14/128</ppr-prefix>
         <ppr-pde>
           <pde-id>5000::11/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::21/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::22/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::23/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::14/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <attributes>
           <ppr-metric>50</ppr-metric>
         </attributes>
       </ipv6>
     </group>
     <group>
       <name>INTERFACE_PDES</name>
       <ipv6>
         <ppr-id>6000:1::2/128</ppr-id>
         <ppr-prefix>5000::11/128</ppr-prefix>
         <ppr-pde>
           <pde-id>5000::14/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::23/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::33/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>4000:121::41/64</pde-id>
           <pde-id-type>ipv6-interface</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::32/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>4000:113::21/64</pde-id>
           <pde-id-type>ipv6-interface</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::11/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
       </ipv6>
       <ipv6>
         <ppr-id>6000:2::2/128</ppr-id>
         <ppr-prefix>5000::14/128</ppr-prefix>
         <ppr-pde>
           <pde-id>5000::11/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::21/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::32/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>4000:121::41/64</pde-id>
           <pde-id-type>ipv6-interface</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::33/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>4000:116::23/64</pde-id>
           <pde-id-type>ipv6-interface</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::14/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
       </ipv6>
     </group>
     <group>
       <name>BROKEN</name>
       <ipv6>
         <ppr-id>6000:1::3/128</ppr-id>
         <ppr-prefix>5000::11/128</ppr-prefix>
         <ppr-pde>
           <pde-id>5000::14/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::23/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::99/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::21/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::11/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <attributes>
           <ppr-metric>1500</ppr-metric>
         </attributes>
       </ipv6>
       <ipv6>
         <ppr-id>6000:2::3/128</ppr-id>
         <ppr-prefix>5000::14/128</ppr-prefix>
         <ppr-pde>
           <pde-id>5000::11/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::21/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::99/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::23/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>5000::14/128</pde-id>
           <pde-id-type>ipv6-node</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <attributes>
           <ppr-metric>1500</ppr-metric>
         </attributes>
       </ipv6>
     </group>
   </ppr>
   <isis xmlns="http://frrouting.org/yang/isisd">
     <instance>
       <area-tag>1</area-tag>
       <area-address>49.0000.0000.0000.0011.00</area-address>
       <multi-topology>
         <ipv6-unicast>
         </ipv6-unicast>
       </multi-topology>
       <ppr>
         <enable>true</enable>
         <ppr-advertise>
           <name>VOIP</name>
         </ppr-advertise>
         <ppr-advertise>
           <name>INTERFACE_PDES</name>
         </ppr-advertise>
         <ppr-advertise>
           <name>BROKEN</name>
         </ppr-advertise>
       </ppr>
     </instance>
   </isis>

Verification - Control Plane
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Verify that R11 has flooded the PPR TLVs correctly to all IS-IS routers:

::

   # show isis database detail 0000.0000.0011
   Area 1:
   IS-IS Level-1 link-state database:
   LSP ID                  PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL
   debian.00-00             1233   0x00000009  0x7bd4     683    0/0/0
     Protocols Supported: IPv4, IPv6
     Area Address: 49.0000
     MT Router Info: ipv4-unicast
     MT Router Info: ipv6-unicast
     Hostname: debian
     MT Reachability: 0000.0000.0012.00 (Metric: 10) ipv6-unicast
     MT Reachability: 0000.0000.0021.00 (Metric: 10) ipv6-unicast
     MT IPv6 Reachability: 5000::11/128 (Metric: 10) ipv6-unicast
     MT IPv6 Reachability: 4000:101::/64 (Metric: 10) ipv6-unicast
     MT IPv6 Reachability: 4000:104::/64 (Metric: 10) ipv6-unicast
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::11/128
       ID: 6000:1::3/128 (Native IPv6)
       PDE: 5000::14/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::23/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::99/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::21/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::11/128 (IPv6 Node Address), L:0 N:1 E:0
       Metric: 1500
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::14/128
       ID: 6000:2::3/128 (Native IPv6)
       PDE: 5000::11/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::21/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::99/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::23/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::14/128 (IPv6 Node Address), L:0 N:1 E:0
       Metric: 1500
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::11/128
       ID: 6000:1::2/128 (Native IPv6)
       PDE: 5000::14/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::23/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::33/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 4000:121::41 (IPv6 Interface Address), L:0 N:0 E:0
       PDE: 5000::32/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 4000:113::21 (IPv6 Interface Address), L:0 N:0 E:0
       PDE: 5000::11/128 (IPv6 Node Address), L:0 N:1 E:0
       Metric: 0
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::14/128
       ID: 6000:2::2/128 (Native IPv6)
       PDE: 5000::11/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::21/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::32/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 4000:121::41 (IPv6 Interface Address), L:0 N:0 E:0
       PDE: 5000::33/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 4000:116::23 (IPv6 Interface Address), L:0 N:0 E:0
       PDE: 5000::14/128 (IPv6 Node Address), L:0 N:1 E:0
       Metric: 0
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::11/128
       ID: 6000:1::1/128 (Native IPv6)
       PDE: 5000::14/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::23/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::22/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::21/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::11/128 (IPv6 Node Address), L:0 N:1 E:0
       Metric: 50
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::14/128
       ID: 6000:2::1/128 (Native IPv6)
       PDE: 5000::11/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::21/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::22/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::23/128 (IPv6 Node Address), L:0 N:0 E:0
       PDE: 5000::14/128 (IPv6 Node Address), L:0 N:1 E:0
       Metric: 50

The PPR TLVs can also be seen using a modified version of Wireshark as
seen below:

.. figure:: https://user-images.githubusercontent.com/931662/61582441-9551e500-ab01-11e9-8f6f-400ee3fba927.png
   :alt: s2

   s2

Using the ``show isis ppr`` command, verify that all routers installed
the PPR-IDs for the paths they are part of. Example:

Router RT11
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime    
    --------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Tail-End  -       -         
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Tail-End  -       -         
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Tail-End  -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Head-End  Up      00:45:41  
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Head-End  Up      00:45:41  
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Head-End  Up      00:45:41  

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:2::1/128 [115/50] via fe80::c2a:54ff:fe39:bff7, eth-rt21, 00:01:33
   I>* 6000:2::2/128 [115/0] via fe80::c2a:54ff:fe39:bff7, eth-rt21, 00:01:33
   I>* 6000:2::3/128 [115/1500] via fe80::c2a:54ff:fe39:bff7, eth-rt21, 00:01:33

Router RT12
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime  
    ------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path  -       -       
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Off-Path  -       -       
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path  -       -       
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path  -       -       
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Off-Path  -       -       
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path  -       -       

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT13
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime  
    ------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path  -       -       
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Off-Path  -       -       
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path  -       -       
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path  -       -       
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Off-Path  -       -       
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path  -       -       

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT14
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime    
    --------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Head-End  Up      00:45:45  
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Head-End  Up      00:45:45  
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Head-End  Up      00:45:45  
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Tail-End  -       -         
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Tail-End  -       -         
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Tail-End  -       -         

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::58ea:78ff:fe00:92c1, eth-rt23, 00:01:36
   I>* 6000:1::2/128 [115/0] via fe80::58ea:78ff:fe00:92c1, eth-rt23, 00:01:36
   I>* 6000:1::3/128 [115/1500] via fe80::58ea:78ff:fe00:92c1, eth-rt23, 00:01:36

Router RT21
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Mid-Point  Up      00:45:46  
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Mid-Point  Up      00:45:46  
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Mid-Point  Up      00:45:46  
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Mid-Point  Up      00:45:46  
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Mid-Point  Up      00:45:46  
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Mid-Point  Down    -         

   # show isis ppr id ipv6 6000:2::3/128 detail
   Area 1:
     PPR-ID: 6000:2::3/128 (Native IPv6)
       PPR-Prefix: 5000::14/128
       PDEs:
         5000::11/128 (IPv6 Node Address)
         5000::21/128 (IPv6 Node Address) [LOCAL]
         5000::99/128 (IPv6 Node Address) [NEXT]
         5000::23/128 (IPv6 Node Address)
         5000::14/128 (IPv6 Node Address)
       Attributes:
         Metric: 1500
       Position: Mid-Point
       Originator: 0000.0000.0011
       Level: L1
       Algorithm: 1
       MT-ID: ipv4-unicast
       Status: Down: PDE is unreachable
       Last change: 00:00:37

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::142e:79ff:feeb:cffc, eth-rt11, 00:01:38
   I>* 6000:1::2/128 [115/0] via fe80::142e:79ff:feeb:cffc, eth-rt11, 00:01:38
   I>* 6000:1::3/128 [115/1500] via fe80::142e:79ff:feeb:cffc, eth-rt11, 00:01:38
   I>* 6000:2::1/128 [115/50] via fe80::c88e:7fff:fe5f:a08d, eth-rt22, 00:01:38
   I>* 6000:2::2/128 [115/0] via fe80::8b2:9eff:fe98:f66a, eth-rt32, 00:01:38

Router RT22
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Mid-Point  Up      00:45:47  
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Off-Path   -       -         
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Mid-Point  Up      00:45:47  
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Off-Path   -       -         
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path   -       -         

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::2cb5:edff:fe60:29b1, eth-rt21, 00:01:38
   I>* 6000:2::1/128 [115/50] via fe80::e8d9:63ff:fea3:177b, eth-rt23, 00:01:38

Router RT23
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Mid-Point  Up      00:45:49  
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Mid-Point  Up      00:45:49  
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Mid-Point  Down    -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Mid-Point  Up      00:45:49  
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Mid-Point  Up      00:45:49  
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Mid-Point  Up      00:45:49  

   # show isis ppr id ipv6 6000:1::3/128 detail
   Area 1:
     PPR-ID: 6000:1::3/128 (Native IPv6)
       PPR-Prefix: 5000::11/128
       PDEs:
         5000::14/128 (IPv6 Node Address)
         5000::23/128 (IPv6 Node Address) [LOCAL]
         5000::99/128 (IPv6 Node Address) [NEXT]
         5000::21/128 (IPv6 Node Address)
         5000::11/128 (IPv6 Node Address)
       Attributes:
         Metric: 1500
       Position: Mid-Point
       Originator: 0000.0000.0011
       Level: L1
       Algorithm: 1
       MT-ID: ipv4-unicast
       Status: Down: PDE is unreachable
       Last change: 00:02:50

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::d09f:1bff:fe31:e9c9, eth-rt22, 00:01:40
   I>* 6000:1::2/128 [115/0] via fe80::c0c3:b3ff:fe9f:b5d3, eth-rt33, 00:01:40
   I>* 6000:2::1/128 [115/50] via fe80::f40a:66ff:fefc:5c32, eth-rt14, 00:01:40
   I>* 6000:2::2/128 [115/0] via fe80::f40a:66ff:fefc:5c32, eth-rt14, 00:01:40
   I>* 6000:2::3/128 [115/1500] via fe80::f40a:66ff:fefc:5c32, eth-rt14, 00:01:40

Router RT31
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime  
    ------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path  -       -       
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Off-Path  -       -       
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path  -       -       
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path  -       -       
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Off-Path  -       -       
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path  -       -       

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT32
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Mid-Point  Up      00:45:51  
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Mid-Point  Up      00:45:51  
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path   -       -         

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::2/128 [115/0] via 4000:113::21, eth-rt21, 00:01:42
   I>* 6000:2::2/128 [115/0] via 4000:121::41, eth-sw1, 00:01:42

Router RT33
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Mid-Point  Up      00:45:52  
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Mid-Point  Up      00:45:52  
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path   -       -         

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::2/128 [115/0] via 4000:121::41, eth-sw1, 00:01:43
   I>* 6000:2::2/128 [115/0] via 4000:116::23, eth-rt23, 00:01:43

Router RT34
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime  
    ------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path  -       -       
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Off-Path  -       -       
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path  -       -       
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path  -       -       
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Off-Path  -       -       
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path  -       -       

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT41
'''''''''''

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:1::2/128 (Native IPv6)  5000::11/128  0       Mid-Point  Up      00:45:55  
    1     L1     6000:1::3/128 (Native IPv6)  5000::11/128  1500    Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         
    1     L1     6000:2::2/128 (Native IPv6)  5000::14/128  0       Mid-Point  Up      00:45:55  
    1     L1     6000:2::3/128 (Native IPv6)  5000::14/128  1500    Off-Path   -       -         

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::2/128 [115/0] via fe80::b4b9:60ff:feee:3c73, eth-sw1, 00:01:46
   I>* 6000:2::2/128 [115/0] via fe80::bc2a:d9ff:fe65:97f2, eth-sw1, 00:01:46

As it can be seen by the output of ``show isis ppr id ipv6 ... detail``,
routers R21 and R23 couldn’t install the third PPR path because of an
unreachable PDE (configuration error).

Verification - Forwarding Plane
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On Router R11, use the ``traceroute`` tool to ensure that the PPR paths
were installed correctly in the network:

::

   root@rt11:~# traceroute 6000:2::1
   traceroute to 6000:2::1 (6000:2::1), 30 hops max, 80 byte packets
    1  4000:104::21 (4000:104::21)  0.612 ms  0.221 ms  0.241 ms
    2  4000:110::22 (4000:110::22)  0.257 ms  0.113 ms  0.105 ms
    3  4000:111::23 (4000:111::23)  0.257 ms  0.151 ms  0.098 ms
    4  6000:2::1 (6000:2::1)  0.346 ms  0.139 ms  0.100 ms
   root@rt11:~#
   root@rt11:~# traceroute 6000:2::2
   traceroute to 6000:2::2 (6000:2::2), 30 hops max, 80 byte packets
    1  4000:104::21 (4000:104::21)  4.383 ms  4.148 ms  0.044 ms
    2  4000:113::32 (4000:113::32)  0.272 ms  0.065 ms  0.064 ms
    3  4000:121::41 (4000:121::41)  0.263 ms  0.101 ms  0.086 ms
    4  4000:115::33 (4000:115::33)  0.351 ms 4000:119::33 (4000:119::33)  0.249 ms 4000:115::33 (4000:115::33)  0.153 ms
    5  4000:111::23 (4000:111::23)  0.232 ms  0.293 ms  0.131 ms
    6  6000:2::2 (6000:2::2)  0.184 ms  0.212 ms  0.140 ms
   root@rt11:~#
   root@rt11:~# traceroute 6000:2::3
   traceroute to 6000:2::3 (6000:2::3), 30 hops max, 80 byte packets
    1  4000:104::21 (4000:104::21)  1.537 ms !N  1.347 ms !N  1.075 ms !N

The failure on the third traceroute is expected since the 6000:2::3
PPR-ID is misconfigured.

Now ping Host 3 from Host 1 and use tcpdump or wireshark to verify that
the ICMP packets are being tunneled using GRE and following the {R11 -
R21 - R22 - R23 - R14} path. Here’s a wireshark capture between R11 and
R21:

.. figure:: https://user-images.githubusercontent.com/931662/61582398-d4cc0180-ab00-11e9-83a8-d219f98010b9.png
   :alt: s1

   s1

Using ``traceroute`` it’s also possible to see that the ICMP packets are
being tunneled through the IS-IS network:

::

   root@host1:~# traceroute fd00:20:1::1 -s fd00:10:1::1                                                                                                                                                                                        
   traceroute to fd00:20:1::1 (fd00:20:1::1), 30 hops max, 80 byte packets
    1  fd00:10:1::100 (fd00:10:1::100)  0.354 ms  0.092 ms  0.031 ms
    2  fd00:10::11 (fd00:10::11)  0.125 ms  0.022 ms  0.026 ms
    3  * * *
    4  * * *
    5  fd00:20:1::1 (fd00:20:1::1)  0.235 ms  0.106 ms  0.091 ms
