.. _bgp-link-state:

BGP Link-State
==============

BGP Link-State (BGP-LS) is a mechanism to distribute network topology information
via BGP. It enables BGP to carry link-state information learned from IGP protocols
(IS-IS, OSPF) to other BGP speakers. This is useful for applications such as
Software-Defined Networking (SDN) controllers, Traffic Engineering, and network
visualization tools that need a complete view of the network topology.

BGP-LS is defined in :rfc:`9552`.

Overview
--------

BGP-LS introduces a new BGP AFI/SAFI combination (AFI 16388, SAFI 71) to carry
link-state Network Layer Reachability Information (NLRI). The link-state NLRI
describes nodes, links, and prefixes in the network topology.

Three types of BGP-LS NLRI are defined:

- **Node NLRI** - Describes routers/nodes in the network
- **Link NLRI** - Describes links between nodes
- **Prefix NLRI** - Describes IPv4/IPv6 prefixes advertised by nodes

BGP-LS carries topology information in a new BGP path attribute called the
BGP-LS Attribute (type 29), which contains various TLVs describing node
properties, link metrics, bandwidth, prefix attributes, and other topology
characteristics.

Configuration
-------------

BGP-LS Producer Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enable BGP-LS and originate topology information from the local IGP, configure
the link-state address family:

.. code-block:: frr

   router bgp 65001
    neighbor 192.0.2.1 remote-as 65002
    !
    address-family link-state
     neighbor 192.0.2.1 activate
    exit-address-family

When the link-state address family is activated on a neighbor, BGP will:

1. Negotiate BGP-LS capability during session establishment
2. Receive IGP topology updates from Zebra (IS-IS and OSPF)
3. Convert IGP topology to BGP-LS NLRI (Node, Link, Prefix)
4. Advertise BGP-LS routes to the activated neighbor

BGP-LS Consumer Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To receive and process BGP-LS information from peers without originating routes:

.. code-block:: frr

   router bgp 65002
    neighbor 192.0.2.2 remote-as 65001
    !
    address-family link-state
     neighbor 192.0.2.2 activate
    exit-address-family

Displaying BGP-LS Information
------------------------------

Show All BGP-LS NLRIs
^^^^^^^^^^^^^^^^^^^^^^^

.. clicmd:: show bgp link-state link-state [json]

   Display all BGP-LS routes in the link-state RIB. Shows Node, Link, and Prefix
   NLRI with their associated attributes.

   Example output:

   .. code-block:: frr

      router# show bgp link-state link-state
      BGP table version is 15, local router ID is 192.0.2.1
      Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
                    i internal, r RIB-failure, S Stale, R Removed
      Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
      Origin codes: i - IGP, e - EGP, ? - incomplete
      RPKI validation codes: V valid, I invalid, N Not found

         Network          Next Hop            Metric LocPrf Weight Path
      *> [1][0.0.0.0][6][0][0][0300.0000.0001]
                          0.0.0.0(vrf1)            0         32768 ?
      *> [2][0.0.0.0][6][0][0][0300.0000.0001][0300.0000.0002][192.0.2.1][192.0.2.2]
                          0.0.0.0(vrf1)            0         32768 ?

   With the ``json`` option, output is displayed in JSON format suitable for
   programmatic processing.

Show Specific BGP-LS NLRI
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. clicmd:: show bgp link-state link-state NLRI [json]

   Display detailed information about a specific BGP-LS NLRI identified by its
   NLRI string. The NLRI string format is:

   - Node NLRI: ``[1][IGP-ID][Protocol][Instance][AS][Area/Domain][IGP-Router-ID]``
   - Link NLRI: ``[2][IGP-ID][Protocol][Instance][AS][Area][Local-Router-ID][Remote-Router-ID][Local-IP][Remote-IP]``
   - Prefix NLRI: ``[3|4][IGP-ID][Protocol][Instance][AS][Area][Router-ID][Prefix]``

   Example:

   .. code-block:: frr

      router# show bgp link-state link-state [1][0.0.0.0][6][0][0][0300.0000.0001]
      BGP routing table entry for [1][0.0.0.0][6][0][0][0300.0000.0001]
      Paths: (1 available, best #1, table link-state)
        Not advertised to any peer
        Local from 0.0.0.0 (192.0.2.1)
          Origin incomplete, metric 0, localpref 100, valid, sourced, local, best (First path received)
          Last update: Thu Jan 23 10:15:42 2026

          Node Descriptors:
            Protocol-ID: IS-IS Level 2
            AS Number: 0
            IGP Router-ID: 0300.0000.0001

          Node Attributes:
            Router-ID: 192.0.2.1
            ISIS Area-ID: 49.0001
            Node Flags: 0x00

Use ``show bgp [afi] [safi] summary`` to display BGP session summary including
link-state address family statistics.

Debugging
---------

.. clicmd:: debug bgp linkstate

   Enable debugging for BGP-LS operations including:

   - NLRI encoding/decoding
   - Attribute processing
   - IGP topology updates
   - Route origination and withdrawal
   - TED updates

Configuration Example
---------------------

Complete example with IS-IS IGP and BGP-LS:

.. code-block:: frr

   ! IS-IS configuration
   router isis 1
    net 49.0001.0300.0000.0001.00
    is-type level-2-only
    topology ipv6-unicast
   !
   interface eth0
    ip router isis 1
    isis network point-to-point
   !
   ! BGP configuration with Link-State
   router bgp 65001
    bgp router-id 192.0.2.1
    neighbor 192.0.2.100 remote-as 65002
    neighbor 192.0.2.100 description SDN-Controller
    !
    address-family link-state
     neighbor 192.0.2.100 activate
    exit-address-family

In this example:

- IS-IS is configured to run on the local router
- BGP session is established with an SDN controller (192.0.2.100)
- Link-state address family is activated for the controller neighbor
- BGP-LS will automatically convert IS-IS topology to BGP-LS NLRI and
  advertise it to the controller

Use Cases
---------

BGP-LS is typically used in the following scenarios:

**SDN Controllers**
   SDN controllers use BGP-LS to obtain a complete view of the network topology
   for path computation, traffic engineering, and network optimization.

**PCE (Path Computation Element)**
   PCE servers use BGP-LS to maintain an up-to-date TED for computing MPLS-TE
   and SR-TE paths.

**Network Monitoring and Visualization**
   Network management systems use BGP-LS to visualize network topology and
   monitor link utilization, metrics, and failures.

**Multi-Domain TE**
   BGP-LS enables traffic engineering across multiple IGP domains by sharing
   topology information between domains via BGP.