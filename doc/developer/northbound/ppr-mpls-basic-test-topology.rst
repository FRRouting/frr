IS-IS PPR Basic MPLS
====================

.. contents:: Table of contents
    :local:
    :backlinks: entry
    :depth: 2

Software
~~~~~~~~

The FRR PPR implementation for IS-IS is available here:
https://github.com/opensourcerouting/frr/tree/isisd-ppr-sr

Topology
~~~~~~~~

In this topology we have an IS-IS network consisting of 12 routers. CE1
and CE2 are the consumer edges, connected to R11 and R14, respectively.
Three hosts are connected to the CEs using only static routes.

Router R11 advertises 6 PPR TLVs: \* **IPv6 prefixes 6000:1::1/128 and
6000:2::1/128:** {R11 - R21 - R22 - R23 - R14} (IPv6 Node Addresses). \*
**MPLS SR Prefix-SIDs 500 and 501:** {R11 - R21 - R22 - R23 - R14} (SR
Prefix-SIDs). \* **MPLS SR Prefix-SIDs 502 and 503:** {R11 - R21 - R31 -
R32 - R41 - R33 - R34 - R23 - R14} (SR Prefix-SIDs)

PBR rules are configured on R11 and R14 to route the traffic between
Host 1 and Host 3 using the first PPR tunnel, whereas all other traffic
between CE1 and CE2 uses the second PPR tunnel.

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
           ipv6 route ::/0 fd00:10:0::11 label 16501

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
           ipv6 route ::/0 fd00:20:0::14 label 16500

     rt11:
       links:
         lo:
           mpls: yes
         lo-ppr:
         eth-ce1:
           peer: [ce1, eth-rt11]
           mpls: yes
         eth-rt12:
           peer: [rt12, eth-rt11]
           mpls: yes
         eth-rt21:
           peer: [rt21, eth-rt11]
           mpls: yes
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
           !
           interface lo
            ip address 10.0.0.11/32
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
           ppr group PPR_IPV6
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
           ppr group PPR_MPLS_1
            ppr mpls 500 prefix 5000::11/128
             pde prefix-sid 14
             pde prefix-sid 23
             pde prefix-sid 22
             pde prefix-sid 21
             pde prefix-sid 11
            !
            ppr mpls 501 prefix 5000::14/128
             pde prefix-sid 11
             pde prefix-sid 21
             pde prefix-sid 22
             pde prefix-sid 23
             pde prefix-sid 14
            !
           !
           ppr group PPR_MPLS_2
            ppr mpls 502 prefix 5000::11/128
             pde prefix-sid 14
             pde prefix-sid 23
             pde prefix-sid 34
             pde prefix-sid 33
             pde prefix-sid 41
             pde prefix-sid 32
             pde prefix-sid 31
             pde prefix-sid 21
             pde prefix-sid 11
            !
            ppr mpls 503 prefix 5000::14/128
             pde prefix-sid 11
             pde prefix-sid 21
             pde prefix-sid 31
             pde prefix-sid 32
             pde prefix-sid 41
             pde prefix-sid 33
             pde prefix-sid 34
             pde prefix-sid 23
             pde prefix-sid 14
            !
           !
           router isis 1
            net 49.0000.0000.0000.0011.00
            is-type level-1
            topology ipv6-unicast
            segment-routing on
            segment-routing prefix 5000::11/128 index 11 no-php-flag
            ppr on
            ppr advertise PPR_IPV6
            ppr advertise PPR_MPLS_1
            ppr advertise PPR_MPLS_2
           !

     rt12:
       links:
         lo:
           mpls: yes
         eth-rt11:
           peer: [rt11, eth-rt12]
           mpls: yes
         eth-rt13:
           peer: [rt13, eth-rt12]
           mpls: yes
         eth-rt21:
           peer: [rt21, eth-rt12]
           mpls: yes
         eth-rt22:
           peer: [rt22, eth-rt12]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.12/32
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
            segment-routing on
            segment-routing prefix 5000::12/128 index 12 no-php-flag
            ppr on
           !

     rt13:
       links:
         lo:
           mpls: yes
         eth-rt12:
           peer: [rt12, eth-rt13]
           mpls: yes
         eth-rt14:
           peer: [rt14, eth-rt13]
           mpls: yes
         eth-rt22:
           peer: [rt22, eth-rt13]
           mpls: yes
         eth-rt23:
           peer: [rt23, eth-rt13]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.13/32
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
            segment-routing on
            segment-routing prefix 5000::13/128 index 13 no-php-flag
            ppr on
           !

     rt14:
       links:
         lo:
           mpls: yes
         lo-ppr:
         eth-ce2:
           peer: [ce2, eth-rt14]
           mpls: yes
         eth-rt13:
           peer: [rt13, eth-rt14]
           mpls: yes
         eth-rt23:
           peer: [rt23, eth-rt14]
           mpls: yes
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
           !
           interface lo
            ip address 10.0.0.14/32
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
            segment-routing on
            segment-routing prefix 5000::14/128 index 14 no-php-flag
            ppr on
           !

     rt21:
       links:
         lo:
           mpls: yes
         eth-rt11:
           peer: [rt11, eth-rt21]
           mpls: yes
         eth-rt12:
           peer: [rt12, eth-rt21]
           mpls: yes
         eth-rt22:
           peer: [rt22, eth-rt21]
           mpls: yes
         eth-rt31:
           peer: [rt31, eth-rt21]
           mpls: yes
         eth-rt32:
           peer: [rt32, eth-rt21]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.21/32
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
            segment-routing on
            segment-routing prefix 5000::21/128 index 21 no-php-flag
            ppr on
           !

     rt22:
       links:
         lo:
           mpls: yes
         eth-rt12:
           peer: [rt12, eth-rt22]
           mpls: yes
         eth-rt13:
           peer: [rt13, eth-rt22]
           mpls: yes
         eth-rt21:
           peer: [rt21, eth-rt22]
           mpls: yes
         eth-rt23:
           peer: [rt23, eth-rt22]
           mpls: yes
         eth-rt32:
           peer: [rt32, eth-rt22]
           mpls: yes
         eth-rt33:
           mpls: yes
           peer: [rt33, eth-rt22]
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.22/32
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
            segment-routing on
            segment-routing prefix 5000::22/128 index 22 no-php-flag
            ppr on
           !

     rt23:
       links:
         lo:
           mpls: yes
         eth-rt13:
           peer: [rt13, eth-rt23]
           mpls: yes
         eth-rt14:
           peer: [rt14, eth-rt23]
           mpls: yes
         eth-rt22:
           peer: [rt22, eth-rt23]
           mpls: yes
         eth-rt33:
           peer: [rt33, eth-rt23]
           mpls: yes
         eth-rt34:
           peer: [rt34, eth-rt23]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.23/32
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
            segment-routing on
            segment-routing global-block 20000 27999
            segment-routing prefix 5000::23/128 index 23 no-php-flag
            ppr on
           !

     rt31:
       links:
         lo:
           mpls: yes
         eth-rt21:
           peer: [rt21, eth-rt31]
           mpls: yes
         eth-rt32:
           peer: [rt32, eth-rt31]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.31/32
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
            segment-routing on
            segment-routing prefix 5000::31/128 index 31 no-php-flag
            ppr on
           !

     rt32:
       links:
         lo:
           mpls: yes
         eth-rt21:
           peer: [rt21, eth-rt32]
           mpls: yes
         eth-rt22:
           peer: [rt22, eth-rt32]
           mpls: yes
         eth-rt31:
           peer: [rt31, eth-rt32]
           mpls: yes
         eth-rt33:
           peer: [rt33, eth-rt32]
           mpls: yes
         eth-sw1:
           peer: [sw1, eth-rt32]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.32/32
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
            segment-routing on
            segment-routing prefix 5000::32/128 index 32 no-php-flag
            ppr on
           !

     rt33:
       links:
         lo:
           mpls: yes
         eth-rt22:
           peer: [rt22, eth-rt33]
           mpls: yes
         eth-rt23:
           peer: [rt23, eth-rt33]
           mpls: yes
         eth-rt32:
           peer: [rt32, eth-rt33]
           mpls: yes
         eth-rt34:
           peer: [rt34, eth-rt33]
           mpls: yes
         eth-sw1:
           peer: [sw1, eth-rt33]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.33/32
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
            segment-routing on
            segment-routing prefix 5000::33/128 index 33 no-php-flag
            ppr on
           !

     rt34:
       links:
         lo:
           mpls: yes
         eth-rt23:
           peer: [rt23, eth-rt34]
           mpls: yes
         eth-rt33:
           peer: [rt33, eth-rt34]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.34/32
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
            segment-routing on
            segment-routing prefix 5000::34/128 index 34 no-php-flag
            ppr on
           !

     rt41:
       links:
         lo:
           mpls: yes
         eth-sw1:
           peer: [sw1, eth-rt41]
           mpls: yes
       frr:
         zebra:
         isisd:
         config: |
           interface lo
            ip address 10.0.0.41/32
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
            segment-routing on
            segment-routing prefix 5000::41/128 index 41 no-php-flag
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
     #valgrind: yes
     base-config: |
       hostname %(node)
       password 1
       log file %(logdir)/%(node).log
       log commands
       !
       debug zebra rib
       debug isis sr-events
       debug isis ppr
       debug isis events
       debug isis route-events
       debug isis spf-events
       debug isis lsp-gen
       !

..

   NOTE: it’s of fundamental importance to enable MPLS processing on the
   loopback interfaces, otherwise the tail-end routers of the PPR-MPLS
   tunnels will drop the labeled packets they receive.

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
       <name>PPR_IPV6</name>                    
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
       <name>PPR_MPLS_1</name>
       <mpls>
         <ppr-id>500</ppr-id>
         <ppr-prefix>5000::11/128</ppr-prefix>
         <ppr-pde>
           <pde-id>14</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>23</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>22</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>21</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>11</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
       </mpls>
       <mpls>
         <ppr-id>501</ppr-id>
         <ppr-prefix>5000::14/128</ppr-prefix>
         <ppr-pde>
           <pde-id>11</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>21</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>22</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>23</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>14</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
       </mpls>
     </group>
     <group>
       <name>PPR_MPLS_2</name>
       <mpls>
         <ppr-id>502</ppr-id>
         <ppr-prefix>5000::11/128</ppr-prefix>
         <ppr-pde>
           <pde-id>14</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>23</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>34</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>33</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>41</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>32</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>31</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>21</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>11</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
       </mpls>
       <mpls>
         <ppr-id>503</ppr-id>
         <ppr-prefix>5000::14/128</ppr-prefix>
         <ppr-pde>
           <pde-id>11</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>21</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>31</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>32</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>41</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>33</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>34</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>23</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
         <ppr-pde>
           <pde-id>14</pde-id>
           <pde-id-type>prefix-sid</pde-id-type>
           <pde-type>topological</pde-type>
         </ppr-pde>
       </mpls>
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
       <segment-routing>
         <enabled>true</enabled>
         <prefix-sid-map>
           <prefix-sid>
             <prefix>5000::11/128</prefix>
             <sid-value>11</sid-value>
             <last-hop-behavior>no-php</last-hop-behavior>
           </prefix-sid>
         </prefix-sid-map>
       </segment-routing>
       <ppr>
         <enable>true</enable>
         <ppr-advertise>
           <name>PPR_IPV6</name>
         </ppr-advertise>
         <ppr-advertise>
           <name>PPR_MPLS_1</name>
         </ppr-advertise>
         <ppr-advertise>
           <name>PPR_MPLS_2</name>
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
   debian.00-00         *    980   0x00000003  0x3b69     894    0/0/0
     Protocols Supported: IPv4, IPv6
     Area Address: 49.0000
     MT Router Info: ipv4-unicast
     MT Router Info: ipv6-unicast
     Hostname: debian
     TE Router ID: 10.0.0.11
     Router Capability: 10.0.0.11 , D:0, S:0
       Segment Routing: I:1 V:1, SRGB Base: 16000 Range: 8000
         Algorithm: 0: SPF 0: Strict SPF
     MT Reachability: 0000.0000.0012.00 (Metric: 10) ipv6-unicast
       Adjacency-SID: 16, Weight: 0, Flags: F:1 B:0, V:1, L:1, S:0, P:0
     MT Reachability: 0000.0000.0021.00 (Metric: 10) ipv6-unicast
       Adjacency-SID: 17, Weight: 0, Flags: F:1 B:0, V:1, L:1, S:0, P:0
     IPv4 Interface Address: 10.0.0.11
     Extended IP Reachability: 10.0.0.11/32 (Metric: 10)
     MT IPv6 Reachability: 5000::11/128 (Metric: 10) ipv6-unicast
       Subtlvs:
         SR Prefix-SID Index: 11, Algorithm: 0, Flags: NO-PHP
     MT IPv6 Reachability: 4000:101::/64 (Metric: 10) ipv6-unicast
     MT IPv6 Reachability: 4000:104::/64 (Metric: 10) ipv6-unicast
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
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::11/128
       ID: 500 (MPLS)
       PDE: 14 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 23 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 22 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 21 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 11 (SR-MPLS Prefix SID), L:0 N:1 E:0
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::14/128
       ID: 501 (MPLS)
       PDE: 11 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 21 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 22 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 23 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 14 (SR-MPLS Prefix SID), L:0 N:1 E:0
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::11/128
       ID: 502 (MPLS)
       PDE: 14 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 23 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 34 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 33 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 41 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 32 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 31 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 21 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 11 (SR-MPLS Prefix SID), L:0 N:1 E:0
     PPR: Fragment ID: 0, MT-ID: ipv4-unicast, Algorithm: SPF, F:0 D:0 A:0 U:1
       PPR Prefix: 5000::14/128
       ID: 503 (MPLS)
       PDE: 11 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 21 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 31 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 32 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 41 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 33 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 34 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 23 (SR-MPLS Prefix SID), L:0 N:0 E:0
       PDE: 14 (SR-MPLS Prefix SID), L:0 N:1 E:0

Using the ``show isis ppr`` command, verify that all routers installed
the PPR-IDs for the paths they are part of. Example:

Router RT11
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime    
    --------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Tail-End  Up      00:00:42  
    1     L1     501 (MPLS)                   5000::14/128  0       Head-End  Up      00:00:41  
    1     L1     502 (MPLS)                   5000::11/128  0       Tail-End  Up      00:00:42  
    1     L1     503 (MPLS)                   5000::14/128  0       Head-End  Up      00:00:41  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Tail-End  -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Head-End  Up      00:00:41  

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   implicit-null   
    17             SR (IS-IS)   fe80::345f:dfff:fea4:913d  implicit-null   
    16011          SR (IS-IS)   lo                         -               
    16012          SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   16012           
    16013          SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   16013           
    16014          SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   16014           
    16021          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16021           
    16022          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16022           
    16022          SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   16022           
    16023          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16023           
    16023          SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   16023           
    16031          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16031           
    16032          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16032           
    16033          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16033           
    16033          SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   16033           
    16034          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16034           
    16034          SR (IS-IS)   fe80::2065:5ff:fe72:d6c5   16034           
    16041          SR (IS-IS)   fe80::345f:dfff:fea4:913d  16041           
    16500          PPR (IS-IS)  lo                         -               
    16501          PPR (IS-IS)  fe80::345f:dfff:fea4:913d  16501           
    16502          PPR (IS-IS)  lo                         -               
    16503          PPR (IS-IS)  fe80::345f:dfff:fea4:913d  16503           

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:2::1/128 [115/50] via fe80::345f:dfff:fea4:913d, eth-rt21, 00:00:41

Router RT12
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime  
    ------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Off-Path  -       -       
    1     L1     501 (MPLS)                   5000::14/128  0       Off-Path  -       -       
    1     L1     502 (MPLS)                   5000::11/128  0       Off-Path  -       -       
    1     L1     503 (MPLS)                   5000::14/128  0       Off-Path  -       -       
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path  -       -       
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path  -       -       

   # show mpls table
    Inbound Label  Type        Nexthop                    Outbound Label  
    ----------------------------------------------------------------------
    16             SR (IS-IS)  fe80::60ad:96ff:fe3f:9989  implicit-null   
    17             SR (IS-IS)  fe80::9cd2:25ff:febc:84c4  implicit-null   
    18             SR (IS-IS)  fe80::941c:12ff:fe55:8a12  implicit-null   
    19             SR (IS-IS)  fe80::78a7:59ff:fedc:48b8  implicit-null   
    16011          SR (IS-IS)  fe80::60ad:96ff:fe3f:9989  16011           
    16012          SR (IS-IS)  lo                         -               
    16013          SR (IS-IS)  fe80::9cd2:25ff:febc:84c4  16013           
    16014          SR (IS-IS)  fe80::9cd2:25ff:febc:84c4  16014           
    16021          SR (IS-IS)  fe80::941c:12ff:fe55:8a12  16021           
    16022          SR (IS-IS)  fe80::78a7:59ff:fedc:48b8  16022           
    16023          SR (IS-IS)  fe80::78a7:59ff:fedc:48b8  16023           
    16023          SR (IS-IS)  fe80::9cd2:25ff:febc:84c4  16023           
    16031          SR (IS-IS)  fe80::941c:12ff:fe55:8a12  16031           
    16032          SR (IS-IS)  fe80::78a7:59ff:fedc:48b8  16032           
    16032          SR (IS-IS)  fe80::941c:12ff:fe55:8a12  16032           
    16033          SR (IS-IS)  fe80::78a7:59ff:fedc:48b8  16033           
    16034          SR (IS-IS)  fe80::78a7:59ff:fedc:48b8  16034           
    16034          SR (IS-IS)  fe80::9cd2:25ff:febc:84c4  16034           
    16041          SR (IS-IS)  fe80::78a7:59ff:fedc:48b8  16041           
    16041          SR (IS-IS)  fe80::941c:12ff:fe55:8a12  16041           

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT13
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime  
    ------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Off-Path  -       -       
    1     L1     501 (MPLS)                   5000::14/128  0       Off-Path  -       -       
    1     L1     502 (MPLS)                   5000::11/128  0       Off-Path  -       -       
    1     L1     503 (MPLS)                   5000::14/128  0       Off-Path  -       -       
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path  -       -       
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path  -       -       

   # show mpls table
    Inbound Label  Type        Nexthop                    Outbound Label  
    ----------------------------------------------------------------------
    16             SR (IS-IS)  fe80::1c70:63ff:fe40:3a35  implicit-null   
    17             SR (IS-IS)  fe80::20:56ff:feff:b218    implicit-null   
    18             SR (IS-IS)  fe80::44c5:3fff:fe1e:f34a  implicit-null   
    19             SR (IS-IS)  fe80::387d:34ff:fe02:87c3  implicit-null   
    16011          SR (IS-IS)  fe80::20:56ff:feff:b218    16011           
    16012          SR (IS-IS)  fe80::20:56ff:feff:b218    16012           
    16013          SR (IS-IS)  lo                         -               
    16014          SR (IS-IS)  fe80::1c70:63ff:fe40:3a35  16014           
    16021          SR (IS-IS)  fe80::387d:34ff:fe02:87c3  16021           
    16021          SR (IS-IS)  fe80::20:56ff:feff:b218    16021           
    16022          SR (IS-IS)  fe80::387d:34ff:fe02:87c3  16022           
    16023          SR (IS-IS)  fe80::44c5:3fff:fe1e:f34a  20023           
    16031          SR (IS-IS)  fe80::387d:34ff:fe02:87c3  16031           
    16031          SR (IS-IS)  fe80::20:56ff:feff:b218    16031           
    16032          SR (IS-IS)  fe80::387d:34ff:fe02:87c3  16032           
    16033          SR (IS-IS)  fe80::44c5:3fff:fe1e:f34a  20033           
    16033          SR (IS-IS)  fe80::387d:34ff:fe02:87c3  16033           
    16034          SR (IS-IS)  fe80::44c5:3fff:fe1e:f34a  20034           
    16041          SR (IS-IS)  fe80::44c5:3fff:fe1e:f34a  20041           
    16041          SR (IS-IS)  fe80::387d:34ff:fe02:87c3  16041           

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT14
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position  Status  Uptime    
    --------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Head-End  Up      00:00:46  
    1     L1     501 (MPLS)                   5000::14/128  0       Tail-End  Up      00:00:47  
    1     L1     502 (MPLS)                   5000::11/128  0       Head-End  Up      00:00:46  
    1     L1     503 (MPLS)                   5000::14/128  0       Tail-End  Up      00:00:47  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Head-End  Up      00:00:46  
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Tail-End  -       -         

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  implicit-null   
    17             SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  implicit-null   
    16011          SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  16011           
    16012          SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  16012           
    16013          SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  16013           
    16014          SR (IS-IS)   lo                         -               
    16021          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20021           
    16021          SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  16021           
    16022          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20022           
    16022          SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  16022           
    16023          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20023           
    16031          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20031           
    16031          SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  16031           
    16032          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20032           
    16032          SR (IS-IS)   fe80::bcb5:99ff:fed7:22ad  16032           
    16033          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20033           
    16034          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20034           
    16041          SR (IS-IS)   fe80::4c7b:a1ff:fe66:6ca7  20041           
    16500          PPR (IS-IS)  fe80::4c7b:a1ff:fe66:6ca7  20500           
    16501          PPR (IS-IS)  lo                         -               
    16502          PPR (IS-IS)  fe80::4c7b:a1ff:fe66:6ca7  20502           
    16503          PPR (IS-IS)  lo                         -               

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::4c7b:a1ff:fe66:6ca7, eth-rt23, 00:00:02

Router RT21
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:49  
    1     L1     501 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:48  
    1     L1     502 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:49  
    1     L1     503 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:48  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Mid-Point  Up      00:00:49  
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Mid-Point  Up      00:00:48  

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::b886:2cff:fe84:a76f  implicit-null   
    17             SR (IS-IS)   fe80::bc7e:bbff:fe7f:ecb0  implicit-null   
    18             SR (IS-IS)   fe80::e877:a2ff:feb7:4438  implicit-null   
    19             SR (IS-IS)   fe80::a0c2:82ff:fe39:204c  implicit-null   
    20             SR (IS-IS)   fe80::ac6a:8aff:fe14:4f36  implicit-null   
    16011          SR (IS-IS)   fe80::e877:a2ff:feb7:4438  16011           
    16012          SR (IS-IS)   fe80::a0c2:82ff:fe39:204c  16012           
    16013          SR (IS-IS)   fe80::ac6a:8aff:fe14:4f36  16013           
    16013          SR (IS-IS)   fe80::a0c2:82ff:fe39:204c  16013           
    16014          SR (IS-IS)   fe80::ac6a:8aff:fe14:4f36  16014           
    16014          SR (IS-IS)   fe80::a0c2:82ff:fe39:204c  16014           
    16021          SR (IS-IS)   lo                         -               
    16022          SR (IS-IS)   fe80::ac6a:8aff:fe14:4f36  16022           
    16023          SR (IS-IS)   fe80::ac6a:8aff:fe14:4f36  16023           
    16031          SR (IS-IS)   fe80::bc7e:bbff:fe7f:ecb0  16031           
    16032          SR (IS-IS)   fe80::b886:2cff:fe84:a76f  16032           
    16033          SR (IS-IS)   fe80::b886:2cff:fe84:a76f  16033           
    16033          SR (IS-IS)   fe80::ac6a:8aff:fe14:4f36  16033           
    16034          SR (IS-IS)   fe80::b886:2cff:fe84:a76f  16034           
    16034          SR (IS-IS)   fe80::ac6a:8aff:fe14:4f36  16034           
    16041          SR (IS-IS)   fe80::b886:2cff:fe84:a76f  16041           
    16500          PPR (IS-IS)  fe80::e877:a2ff:feb7:4438  16500           
    16501          PPR (IS-IS)  fe80::ac6a:8aff:fe14:4f36  16501           
    16502          PPR (IS-IS)  fe80::e877:a2ff:feb7:4438  16502           
    16503          PPR (IS-IS)  fe80::bc7e:bbff:fe7f:ecb0  16503           

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::e877:a2ff:feb7:4438, eth-rt11, 00:00:04
   I>* 6000:2::1/128 [115/50] via fe80::ac6a:8aff:fe14:4f36, eth-rt22, 00:00:04

Router RT22
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:50  
    1     L1     501 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:50  
    1     L1     502 (MPLS)                   5000::11/128  0       Off-Path   -       -         
    1     L1     503 (MPLS)                   5000::14/128  0       Off-Path   -       -         
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Mid-Point  Up      00:00:50  
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Mid-Point  Up      00:00:50  

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::3432:84ff:fe9d:2e41  implicit-null   
    17             SR (IS-IS)   fe80::c436:63ff:feb3:4f5d  implicit-null   
    18             SR (IS-IS)   fe80::56:41ff:fe53:a6b2    implicit-null   
    19             SR (IS-IS)   fe80::b423:eaff:fea1:8247  implicit-null   
    20             SR (IS-IS)   fe80::9c2f:11ff:fe0a:ab34  implicit-null   
    21             SR (IS-IS)   fe80::7402:b8ff:fee9:682e  implicit-null   
    16011          SR (IS-IS)   fe80::b423:eaff:fea1:8247  16011           
    16011          SR (IS-IS)   fe80::3432:84ff:fe9d:2e41  16011           
    16012          SR (IS-IS)   fe80::3432:84ff:fe9d:2e41  16012           
    16013          SR (IS-IS)   fe80::c436:63ff:feb3:4f5d  16013           
    16014          SR (IS-IS)   fe80::56:41ff:fe53:a6b2    20014           
    16014          SR (IS-IS)   fe80::c436:63ff:feb3:4f5d  16014           
    16021          SR (IS-IS)   fe80::b423:eaff:fea1:8247  16021           
    16022          SR (IS-IS)   lo                         -               
    16023          SR (IS-IS)   fe80::56:41ff:fe53:a6b2    20023           
    16031          SR (IS-IS)   fe80::9c2f:11ff:fe0a:ab34  16031           
    16031          SR (IS-IS)   fe80::b423:eaff:fea1:8247  16031           
    16032          SR (IS-IS)   fe80::9c2f:11ff:fe0a:ab34  16032           
    16033          SR (IS-IS)   fe80::7402:b8ff:fee9:682e  16033           
    16034          SR (IS-IS)   fe80::7402:b8ff:fee9:682e  16034           
    16034          SR (IS-IS)   fe80::56:41ff:fe53:a6b2    20034           
    16041          SR (IS-IS)   fe80::7402:b8ff:fee9:682e  16041           
    16041          SR (IS-IS)   fe80::9c2f:11ff:fe0a:ab34  16041           
    16500          PPR (IS-IS)  fe80::b423:eaff:fea1:8247  16500           
    16501          PPR (IS-IS)  fe80::56:41ff:fe53:a6b2    20501           

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::b423:eaff:fea1:8247, eth-rt21, 00:00:06
   I>* 6000:2::1/128 [115/50] via fe80::56:41ff:fe53:a6b2, eth-rt23, 00:00:06

Router RT23
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:52  
    1     L1     501 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:52  
    1     L1     502 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:52  
    1     L1     503 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:52  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Mid-Point  Up      00:00:52  
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Mid-Point  Up      00:00:52  

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::c4ca:41ff:fe2d:de8c  implicit-null   
    17             SR (IS-IS)   fe80::a02b:1eff:fed6:97e4  implicit-null   
    18             SR (IS-IS)   fe80::5c15:8aff:feea:1d07  implicit-null   
    19             SR (IS-IS)   fe80::a42f:50ff:fe9c:af9f  implicit-null   
    20             SR (IS-IS)   fe80::d0dc:6eff:fe71:9f19  implicit-null   
    20011          SR (IS-IS)   fe80::5c15:8aff:feea:1d07  16011           
    20011          SR (IS-IS)   fe80::a02b:1eff:fed6:97e4  16011           
    20012          SR (IS-IS)   fe80::5c15:8aff:feea:1d07  16012           
    20012          SR (IS-IS)   fe80::a02b:1eff:fed6:97e4  16012           
    20013          SR (IS-IS)   fe80::a02b:1eff:fed6:97e4  16013           
    20014          SR (IS-IS)   fe80::c4ca:41ff:fe2d:de8c  16014           
    20021          SR (IS-IS)   fe80::5c15:8aff:feea:1d07  16021           
    20022          SR (IS-IS)   fe80::5c15:8aff:feea:1d07  16022           
    20023          SR (IS-IS)   lo                         -               
    20031          SR (IS-IS)   fe80::a42f:50ff:fe9c:af9f  16031           
    20031          SR (IS-IS)   fe80::5c15:8aff:feea:1d07  16031           
    20032          SR (IS-IS)   fe80::a42f:50ff:fe9c:af9f  16032           
    20032          SR (IS-IS)   fe80::5c15:8aff:feea:1d07  16032           
    20033          SR (IS-IS)   fe80::a42f:50ff:fe9c:af9f  16033           
    20034          SR (IS-IS)   fe80::d0dc:6eff:fe71:9f19  16034           
    20041          SR (IS-IS)   fe80::a42f:50ff:fe9c:af9f  16041           
    20500          PPR (IS-IS)  fe80::5c15:8aff:feea:1d07  16500           
    20501          PPR (IS-IS)  fe80::c4ca:41ff:fe2d:de8c  16501           
    20502          PPR (IS-IS)  fe80::d0dc:6eff:fe71:9f19  16502           
    20503          PPR (IS-IS)  fe80::c4ca:41ff:fe2d:de8c  16503           

   # show ipv6 route 6000::/16 longer-prefixes isis
   Codes: K - kernel route, C - connected, S - static, R - RIPng,
          O - OSPFv3, I - IS-IS, B - BGP, N - NHRP, T - Table,
          v - VNC, V - VNC-Direct, A - Babel, D - SHARP, F - PBR,
          f - OpenFabric,
          > - selected route, * - FIB route, q - queued route, r - rejected route

   I>* 6000:1::1/128 [115/50] via fe80::5c15:8aff:feea:1d07, eth-rt22, 00:00:07
   I>* 6000:2::1/128 [115/50] via fe80::c4ca:41ff:fe2d:de8c, eth-rt14, 00:00:07

Router RT31
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Off-Path   -       -         
    1     L1     501 (MPLS)                   5000::14/128  0       Off-Path   -       -         
    1     L1     502 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:54  
    1     L1     503 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:54  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  implicit-null   
    17             SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  implicit-null   
    16011          SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  16011           
    16012          SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  16012           
    16013          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16013           
    16013          SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  16013           
    16014          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16014           
    16014          SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  16014           
    16021          SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  16021           
    16022          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16022           
    16022          SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  16022           
    16023          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16023           
    16023          SR (IS-IS)   fe80::a067:c6ff:fe2c:3385  16023           
    16031          SR (IS-IS)   lo                         -               
    16032          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16032           
    16033          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16033           
    16034          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16034           
    16041          SR (IS-IS)   fe80::f46d:c8ff:fe8a:a341  16041           
    16502          PPR (IS-IS)  fe80::a067:c6ff:fe2c:3385  16502           
    16503          PPR (IS-IS)  fe80::f46d:c8ff:fe8a:a341  16503           

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT32
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Off-Path   -       -         
    1     L1     501 (MPLS)                   5000::14/128  0       Off-Path   -       -         
    1     L1     502 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:55  
    1     L1     503 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:55  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::881f:d3ff:febd:9e8c  implicit-null   
    17             SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  implicit-null   
    18             SR (IS-IS)   fe80::9863:abff:fed0:d7e   implicit-null   
    19             SR (IS-IS)   fe80::ec65:d1ff:fe32:b508  implicit-null   
    20             SR (IS-IS)   fe80::a4e9:77ff:feaa:f690  implicit-null   
    21             SR (IS-IS)   fe80::40c4:e6ff:fe26:767f  implicit-null   
    16011          SR (IS-IS)   fe80::881f:d3ff:febd:9e8c  16011           
    16012          SR (IS-IS)   fe80::40c4:e6ff:fe26:767f  16012           
    16012          SR (IS-IS)   fe80::881f:d3ff:febd:9e8c  16012           
    16013          SR (IS-IS)   fe80::40c4:e6ff:fe26:767f  16013           
    16014          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16014           
    16014          SR (IS-IS)   fe80::ec65:d1ff:fe32:b508  16014           
    16014          SR (IS-IS)   fe80::40c4:e6ff:fe26:767f  16014           
    16021          SR (IS-IS)   fe80::881f:d3ff:febd:9e8c  16021           
    16022          SR (IS-IS)   fe80::40c4:e6ff:fe26:767f  16022           
    16023          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16023           
    16023          SR (IS-IS)   fe80::ec65:d1ff:fe32:b508  16023           
    16023          SR (IS-IS)   fe80::40c4:e6ff:fe26:767f  16023           
    16031          SR (IS-IS)   fe80::9863:abff:fed0:d7e   16031           
    16032          SR (IS-IS)   lo                         -               
    16033          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16033           
    16033          SR (IS-IS)   fe80::ec65:d1ff:fe32:b508  16033           
    16034          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16034           
    16034          SR (IS-IS)   fe80::ec65:d1ff:fe32:b508  16034           
    16041          SR (IS-IS)   fe80::a4e9:77ff:feaa:f690  16041           
    16502          PPR (IS-IS)  fe80::9863:abff:fed0:d7e   16502           
    16503          PPR (IS-IS)  fe80::a4e9:77ff:feaa:f690  16503           

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT33
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Off-Path   -       -         
    1     L1     501 (MPLS)                   5000::14/128  0       Off-Path   -       -         
    1     L1     502 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:57  
    1     L1     503 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:57  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::2832:a9ff:fec3:7078  implicit-null   
    17             SR (IS-IS)   fe80::7806:e1ff:fe72:9b1f  implicit-null   
    18             SR (IS-IS)   fe80::5476:31ff:fe94:c39   implicit-null   
    19             SR (IS-IS)   fe80::a4e9:77ff:feaa:f690  implicit-null   
    20             SR (IS-IS)   fe80::68c9:2ff:fe04:5eba   implicit-null   
    21             SR (IS-IS)   fe80::d053:97ff:fee2:1711  implicit-null   
    16011          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16011           
    16011          SR (IS-IS)   fe80::5476:31ff:fe94:c39   16011           
    16011          SR (IS-IS)   fe80::d053:97ff:fee2:1711  16011           
    16012          SR (IS-IS)   fe80::d053:97ff:fee2:1711  16012           
    16013          SR (IS-IS)   fe80::68c9:2ff:fe04:5eba   20013           
    16013          SR (IS-IS)   fe80::d053:97ff:fee2:1711  16013           
    16014          SR (IS-IS)   fe80::68c9:2ff:fe04:5eba   20014           
    16021          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16021           
    16021          SR (IS-IS)   fe80::5476:31ff:fe94:c39   16021           
    16021          SR (IS-IS)   fe80::d053:97ff:fee2:1711  16021           
    16022          SR (IS-IS)   fe80::d053:97ff:fee2:1711  16022           
    16023          SR (IS-IS)   fe80::68c9:2ff:fe04:5eba   20023           
    16031          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16031           
    16031          SR (IS-IS)   fe80::5476:31ff:fe94:c39   16031           
    16032          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16032           
    16032          SR (IS-IS)   fe80::5476:31ff:fe94:c39   16032           
    16033          SR (IS-IS)   lo                         -               
    16034          SR (IS-IS)   fe80::7806:e1ff:fe72:9b1f  16034           
    16041          SR (IS-IS)   fe80::a4e9:77ff:feaa:f690  16041           
    16502          PPR (IS-IS)  fe80::a4e9:77ff:feaa:f690  16502           
    16503          PPR (IS-IS)  fe80::7806:e1ff:fe72:9b1f  16503           

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT34
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Off-Path   -       -         
    1     L1     501 (MPLS)                   5000::14/128  0       Off-Path   -       -         
    1     L1     502 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:00:59  
    1     L1     503 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:00:59  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  implicit-null   
    17             SR (IS-IS)   fe80::f009:b9ff:fe05:e540  implicit-null   
    16011          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16011           
    16011          SR (IS-IS)   fe80::f009:b9ff:fe05:e540  20011           
    16012          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16012           
    16012          SR (IS-IS)   fe80::f009:b9ff:fe05:e540  20012           
    16013          SR (IS-IS)   fe80::f009:b9ff:fe05:e540  20013           
    16014          SR (IS-IS)   fe80::f009:b9ff:fe05:e540  20014           
    16021          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16021           
    16021          SR (IS-IS)   fe80::f009:b9ff:fe05:e540  20021           
    16022          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16022           
    16022          SR (IS-IS)   fe80::f009:b9ff:fe05:e540  20022           
    16023          SR (IS-IS)   fe80::f009:b9ff:fe05:e540  20023           
    16031          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16031           
    16032          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16032           
    16033          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16033           
    16034          SR (IS-IS)   lo                         -               
    16041          SR (IS-IS)   fe80::ac33:5dff:fe99:81ec  16041           
    16502          PPR (IS-IS)  fe80::ac33:5dff:fe99:81ec  16502           
    16503          PPR (IS-IS)  fe80::f009:b9ff:fe05:e540  20503           

   # show ipv6 route 6000::/16 longer-prefixes isis

Router RT41
^^^^^^^^^^^

::

   # show isis ppr
    Area  Level  ID                           Prefix        Metric  Position   Status  Uptime    
    ---------------------------------------------------------------------------------------------
    1     L1     500 (MPLS)                   5000::11/128  0       Off-Path   -       -         
    1     L1     501 (MPLS)                   5000::14/128  0       Off-Path   -       -         
    1     L1     502 (MPLS)                   5000::11/128  0       Mid-Point  Up      00:01:01  
    1     L1     503 (MPLS)                   5000::14/128  0       Mid-Point  Up      00:01:01  
    1     L1     6000:1::1/128 (Native IPv6)  5000::11/128  50      Off-Path   -       -         
    1     L1     6000:2::1/128 (Native IPv6)  5000::14/128  50      Off-Path   -       -         

   # show mpls table
    Inbound Label  Type         Nexthop                    Outbound Label  
    -----------------------------------------------------------------------
    16             SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  implicit-null   
    17             SR (IS-IS)   fe80::2832:a9ff:fec3:7078  implicit-null   
    16011          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16011           
    16012          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16012           
    16012          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16012           
    16013          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16013           
    16013          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16013           
    16014          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16014           
    16021          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16021           
    16022          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16022           
    16022          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16022           
    16023          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16023           
    16031          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16031           
    16032          SR (IS-IS)   fe80::2832:a9ff:fec3:7078  16032           
    16033          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16033           
    16034          SR (IS-IS)   fe80::1c7e:c3ff:fe5e:7a54  16034           
    16041          SR (IS-IS)   lo                         -               
    16502          PPR (IS-IS)  fe80::2832:a9ff:fec3:7078  16502           
    16503          PPR (IS-IS)  fe80::1c7e:c3ff:fe5e:7a54  16503           

   # show ipv6 route 6000::/16 longer-prefixes isis

Notice how R23 uses a different SRGB compared to the other routers in
the network. As such, this router install different labels for PPR-IDs
500 and 501 (e.g. 20500 instead of 16500 using the default SRGB).

Verification - Forwarding Plane
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ping Host 3 from Host2 and use tcpdump or wireshark to verify that the
ICMP packets are being tunneled using MPLS LSPs and following the {R11 -
R21 - R22 - R23 - R14} path. Here’s a wireshark capture between R11 and
R21:

.. figure:: https://user-images.githubusercontent.com/931662/64057179-2e980080-cb70-11e9-89c3-ff43e6d66cae.png
   :alt: wireshark

   wireshark

Using ``traceroute`` it’s also possible to see that the ICMP packets are
being tunneled through the IS-IS network:

::

   root@host2:~# traceroute -n fd00:20:1::1 -s fd00:10:2::1
   traceroute to fd00:20:1::1 (fd00:20:1::1), 30 hops max, 80 byte packets
    1  fd00:10:2::100  1.996 ms  1.832 ms  1.725 ms
    2  * * *
    3  * * *
    4  * * *
    5  * * *
    6  * * *
    7  * * *
    8  fd00:20::100  0.154 ms  0.191 ms  0.116 ms
    9  fd00:20:1::1  0.125 ms  0.105 ms  0.104 ms
