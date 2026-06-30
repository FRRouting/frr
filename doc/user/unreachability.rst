Unreachability Information SAFI
================================

Overview
--------

BGP Unreachability Information SAFI provides a mechanism to propagate prefix
unreachability information through BGP without affecting the installation or
removal of routes in the Routing Information Base (RIB) or Forwarding Information
Base (FIB). This creates a parallel information plane for sharing unreachability
data for monitoring, debugging, and coordination purposes.

The implementation is based on the IETF draft:
`draft-tantsura-idr-unreachability-safi <https://datatracker.ietf.org/doc/draft-tantsura-idr-unreachability-safi/>`_

Key characteristics:

- Maintains a separate Unreachability Information RIB (UI-RIB)
- Does NOT install routes in Loc-RIB or affect forwarding
- Uses standard BGP path selection for UI-RIB entries
- Supports IPv4 (AFI=1) and IPv6 (AFI=2) address families
- Uses SAFI=81 (IANA-assigned)


Design Principles
-----------------

FRR implements the core Unreachability Information SAFI functionality:

**NLRI Structure**

The NLRI is uniquely identified by the combination of Prefix Length and Prefix.
Reporter TLVs are NOT part of the NLRI key but provide information about each
reporting speaker.

Each Unreachability NLRI is carried in a length-prefixed envelope
(``draft-tantsura-idr-unreachability-safi-06``)::

    +-----------------------------------+
    | NLRI Length (2 octets)            |
    +-----------------------------------+
    | Prefix Length (1 octet)           |
    +-----------------------------------+
    | Prefix (variable)                 |
    +-----------------------------------+
    | Reporter TLV(s) (variable)        |  (MP_REACH only)
    +-----------------------------------+

The 2-octet NLRI Length counts every octet that follows it (Prefix Length,
Prefix, and any Reporter TLVs) but does NOT include the AddPath Path
Identifier, when present, which precedes the NLRI Length. This explicit
length removes the parsing ambiguity of earlier draft revisions, where the
octet following a Reporter TLV was indistinguishable from the next NLRI's
Prefix Length, and makes the NLRI boundary unambiguous regardless of how
many Reporter TLVs an aggregating peer packs into a single NLRI. Withdrawals
(MP_UNREACH_NLRI) use the same envelope but carry only the Prefix
(no Reporter TLV).

Each Unreachability NLRI contains:

- Prefix (IPv4 or IPv6)
- Reporter TLV containing:

  - Reporter Identifier (BGP Router-ID of the reporting speaker)
  - Reporter AS Number (4-octet AS number of the reporting speaker)
  - Sub-TLVs (one or more):

    - **Sub-TLV Type 1: Reason Code** (2 octets) - Indicates why the prefix
      is unreachable

      - 0: Unspecified
      - 1: Policy Blocked
      - 2: Security Filtered
      - 3: RPKI Invalid
      - 4: No Export Policy
      - 5: Martian Address
      - 6: Bogon Prefix
      - 7: Maintenance
      - 8: Local Administrative Action
      - 9: Local Link Down
      - 10-64535: Reserved
      - 64536-65535: Reserved for Private Use

    - **Sub-TLV Type 2: Timestamp** (8 octets) - Unix timestamp (seconds since
      epoch) in network byte order, indicates when the unreachability event
      occurred or was detected by this reporter

**Next Hop Handling**

For Unreachability SAFI, the Next Hop Length in MP_REACH_NLRI is set to 0, as
this information is purely for monitoring and does not affect forwarding decisions.

**Implementation Scope**

The current implementation includes:

- Length-prefixed NLRI envelope (2-octet NLRI Length)
- Single Reporter TLV per originated NLRI (no aggregation). A received NLRI
  that carries multiple Reporter TLVs is tolerated: the first Reporter TLV is
  retained and any additional ones are ignored without resetting the session.
- Capability negotiation via AFI/SAFI
- Standard BGP path attributes (AS_PATH, ORIGIN, etc.)
- Graceful Restart support
- Show commands with detailed reporting information

**Not Implemented:**

- Origination of multiple Reporter TLVs (aggregation)
- Individual reporter withdrawal
- Enhanced capability with aggregation (A) bit


Configuration Guide
-------------------

Basic Address Family Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enable Unreachability Information SAFI with a neighbor:

.. code-block:: frr

   router bgp 65001
     neighbor 192.0.2.1 remote-as 65002
     !
     address-family ipv4 unreachability
      neighbor 192.0.2.1 activate
     exit-address-family
     !
     address-family ipv6 unreachability
      neighbor 2001:db8::1 activate
     exit-address-family
   exit


Show Commands
-------------

.. clicmd:: show bgp [ipv4|ipv6] unreachability [PREFIX] [detail] [json]

   Display unreachability information from the UI-RIB.

   **Basic output** shows a table with Network, Metric, Local Preference, Weight,
   Reason Code, Reporter (ID/AS), and AS Path.

   **Detail output** includes additional information:

   - Reporter details (Router-ID and AS number)
   - Reason code with descriptive name
   - Timestamp of unreachability event
   - Full BGP path attributes

   **Example - Basic output:**

   .. code-block:: frr

      router# show bgp ipv6 unreachability

      BGP table version is 1, local router ID is 6.1.1.1, vrf id 0
      Default local pref 100, local AS 65011
      Status codes:  s suppressed, d damped, h history, u unsorted, * valid, > best,
                     i internal, S Stale, R Removed
      Origin codes:  i - IGP, e - EGP, ? - incomplete
      RPKI validation codes: V valid, I invalid, N Not found

      Note: Unreachability routes are informational only and not installed in RIB/FIB
      Reason: Unreachability reason code
      Reporter: BGP router ID of the original reporter

          Network                                           Metric  LocPrf  Weight Reason                Reporter          Path
       *>  2001:1:2:3::/127                                       0              0 Security-Filtered     6.1.2.3/65021     65200 65100 65200 65021 i
       *                                                          0              0 Security-Filtered     6.1.2.3/65021     65200 65100 65200 65021 i
      Total: 2 unreachability entries

   **Example - Detail output:**

   .. code-block:: frr

      router# show bgp ipv6 unreachability detail

      BGP routing table entry for 2001:1:2:3::/127, version 1
      Paths: (2 available, best #1)
        Advertised to peers:
        peer1(2001:db8:12::) peer2(2001:db8:16::)
        65200 65100 65200 65021
          from peer1(2001:db8:12::) (7.1.1.1)
            Origin IGP, valid, external, bestpath-from-AS 65200, best (Router ID)
            Reporter: 6.1.2.3 AS 65021
              Reason Code: 2 (Security-Filtered)
              Timestamp: Wed Dec 24 08:23:15 2025
            Last update: Wed Dec 24 08:23:15 2025
      BGP routing table entry for 2001:1:2:3::/127, version 1
      Paths: (2 available, best #1)
        Advertised to peers:
        peer1(2001:db8:12::) peer2(2001:db8:16::)
        65200 65100 65200 65021
          from peer2(2001:db8:16::) (7.1.2.1)
            Origin IGP, valid, external
            Reporter: 6.1.2.3 AS 65021
              Reason Code: 2 (Security-Filtered)
              Timestamp: Wed Dec 24 08:23:15 2025
            Last update: Wed Dec 24 08:23:15 2025
      Total: 2 unreachability entries

.. clicmd:: show bgp [ipv4|ipv6] unreachability summary [json]

   Display BGP neighbor summary for unreachability address family.

   **Example output:**

   .. code-block:: frr

      router# show bgp ipv6 unreachability summary

      BGP router identifier 6.1.1.1, local AS number 65011 VRF default vrf-id 0
      BGP table version 1
      RIB entries 1, using 128 bytes of memory
      Peers 2, using 44 KiB of memory
      Peer groups 1, using 64 bytes of memory

      Neighbor                     V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
      peer1(2001:db8:12::) 4      65200       339       339        1    0    0 00:16:21            1        1 FRRouting/10.0.3
      peer2(2001:db8:16::) 4      65200       339       339        1    0    0 00:16:21            1        1 FRRouting/10.0.3

      Total number of neighbors 2

.. clicmd:: show bgp [ipv4|ipv6] unreachability statistics

   Display statistical information about the Unreachability RIB.

   **Example output:**

   .. code-block:: frr

      router# show bgp ipv6 unreachability statistics

      BGP IPv6 Unreachability RIB statistics (VRF default)
      Total Advertisements          :            2
      Total Prefixes                :            1
      Average prefix length         :       127.00
      Unaggregateable prefixes      :            1
      Maximum aggregateable prefixes:            0
      BGP Aggregate advertisements  :            0
      Address space advertised      :            2
                  /32 equivalent %s :  2.52435e-29
                  /48 equivalent %s :  1.65436e-24

      Advertisements with paths     :            2
      Longest AS-Path (hops)        :            4
      Average AS-Path length (hops) :         4.00
      Largest AS-Path (bytes)       :           18
      Average AS-Path size (bytes)  :        18.00
      Highest public ASN            :            0

``show bgp interface [IFNAME] [detail] [json]``

   Display interface information from BGP's perspective, including cached addresses
   for unreachability tracking when interfaces are down.

``show bgp neighbors [NEIGHBOR] [established]``

   Display BGP neighbor information including capability negotiation for
   unreachability SAFI. When viewing established neighbors, shows active
   AFI/SAFI combinations.

   **Example output showing capability negotiation:**

   .. code-block:: frr

      leaf1# show bgp neighbors 2001:db8:12::

      BGP neighbor is 2001:db8:12::, remote AS 65200, local AS 65011, external link
        Hostname: peer1
        Member of peer-group PEER-GROUP for session parameters
        BGP version 4, remote router ID 7.1.1.1, local router ID 6.1.1.1
        BGP state = Established, up for 00:24:52
        Neighbor capabilities:
          4 Byte AS: advertised and received
          AddPath:
            IPv6 Unicast: RX advertised and received
            IPv6 Unreachability: RX advertised and received
          Address Family IPv6 Unicast: advertised and received
          Address Family IPv6 Unreachability: advertised and received
          Graceful Restart Capability: advertised and received
            Remote Restart timer is 120 seconds
        Graceful restart information:
          End-of-RIB send: IPv6 Unicast, IPv6 Unreachability
          End-of-RIB received: IPv6 Unicast, IPv6 Unreachability
          IPv6 Unreachability:
            F bit: False
            End-of-RIB sent: Yes
            End-of-RIB received: Yes
            Configured Stale Path Time(sec): 360

       For address family: IPv6 Unreachability
        PEER-GROUP peer-group member
        Update group 2, subgroup 2
        Packet Queue length 0
        1 accepted prefixes

   **Example - Established neighbors with AFI/SAFI:**

   .. code-block:: frr

      leaf1# show bgp neighbors established

      Neighbor                            AS   MsgRcvd   MsgSent  ResetTime        State         Afi/Safi    PfxRcd    PfxSnt

      peer1(2001:db8:12::)     65200       429       429   00:20:57  Established     IPv6 Unicast         7         7
                                                                                        IPv6 Unreachability         1         1
      peer2(2001:db8:16::)     65200       429       429   00:20:57  Established     IPv6 Unicast         7         7
                                                                                        IPv6 Unreachability         1         1


Operational Aspects
-------------------

Capability Negotiation
^^^^^^^^^^^^^^^^^^^^^^

Unreachability Information SAFI is negotiated like any other AFI/SAFI using
the Multiprotocol Extensions capability (RFC 5492). The capability exchange
includes:

- AFI: 1 (IPv4) or 2 (IPv6)
- SAFI: 81 (Unreachability Information SAFI)

Both peers must negotiate the capability before exchanging unreachability NLRIs.

Graceful Restart
^^^^^^^^^^^^^^^^

Graceful Restart (RFC 4724) is supported for Unreachability SAFI:

- Forwarding State (F) bit is set to 0 (no forwarding state to preserve)
- Stale marking applies during peer restart
- End-of-RIB marker signals completion of re-advertisement
- Stale entries are removed after End-of-RIB or timeout

Path Selection
^^^^^^^^^^^^^^

Standard BGP path selection applies to UI-RIB entries:

- Considers Weight, Local Preference, AS_PATH length, ORIGIN, MED, etc.
- Reporter TLV content does NOT influence path selection
- Maximum paths is hardcoded to 1 (single best path)

Route Filtering
^^^^^^^^^^^^^^^

Standard BGP filtering mechanisms apply:

- Route-maps for import/export policies
- Prefix-lists for prefix filtering
- Community matching for policy control
- AS-path filtering

**Example with route-map:**

.. code-block:: frr

   router bgp 65001
     neighbor 198.51.100.1 remote-as 65002
     !
     address-family ipv4 unreachability
      neighbor 198.51.100.1 activate
      neighbor 198.51.100.1 route-map UNREACH-IN in
      neighbor 198.51.100.1 route-map UNREACH-OUT out
     exit-address-family
   !
   route-map UNREACH-IN permit 10
     set local-preference 50
   !
   route-map UNREACH-OUT permit 10
     match community NO-EXPORT-UNREACH
   !


Limitations / Known Issues
--------------------------

**Not Implemented:**

- **Multiple Reporter TLV Aggregation**: The current implementation supports
  only a single Reporter TLV per NLRI. The draft's aggregation mechanism for
  combining multiple reporters into one NLRI is not implemented.

- **Individual Reporter Withdrawal**: Cannot selectively withdraw individual
  reporters from an aggregated NLRI (since aggregation is not implemented).

- **Enhanced Capability**: The aggregation (A) bit in the enhanced capability
  is not implemented.

- **ADD-PATH**: ADD-PATH extension for unreachability SAFI is not supported.

**Operational Limits:**

- Maximum paths is hardcoded to 1 (no multipath for unreachability)
- UI-RIB size should be monitored to prevent memory exhaustion
- Rate limiting on unreachability updates is recommended


Debugging & Troubleshooting
----------------------------

``debug bgp updates``

   Enable debugging of BGP update messages, including unreachability NLRIs.

``debug bgp zebra``

   Enable debugging of Zebra integration for unreachability SAFI, including
   interface state changes.

**Monitoring UI-RIB:**

You can verify unreachability information is being processed correctly:

.. code-block:: frr

   router# show bgp ipv4 unreachability
   router# show bgp ipv6 unreachability detail
   router# show bgp interface detail

**Logs:**

Unreachability events are logged via syslog when:

- Interface state changes occur
- Test commands are executed
- Unreachability NLRIs are received from peers


Security Considerations
-----------------------

**Deployment Recommendations:**

- Enable unreachability SAFI only with trusted peers
- Use BGP TCP-AO (RFC 5925) or MD5 authentication for session protection
- Implement prefix filtering using route-maps
- Monitor UI-RIB size and growth patterns
- Configure maximum-prefix limits for unreachability address-family
- Consider information leakage implications (reveals network topology)

**Potential Risks:**

- **State Exhaustion**: Malicious peers could advertise excessive unreachable
  prefixes. Use maximum-prefix limits.

- **False Information**: Peers could advertise incorrect unreachability data.
  This does not affect routing but may impact monitoring systems.

- **Information Disclosure**: Unreachability reports reveal internal network
  state. Use careful peering policies.


Use Cases
---------

**Inter-AS Debugging**

Share unreachability information between cooperating ASes for troubleshooting
without affecting production traffic:

.. code-block:: frr

   router bgp 65001
     neighbor 198.51.100.1 remote-as 65002
     neighbor 198.51.100.1 description "Peer for debugging"
     !
     address-family ipv4 unreachability
      neighbor 198.51.100.1 activate
      neighbor 198.51.100.1 maximum-prefix 10000
     exit-address-family

**Route Collector Integration**

Deploy on route collector sessions for enhanced telemetry:

.. code-block:: frr

   router bgp 65001
     neighbor 203.0.113.1 remote-as 65001
     neighbor 203.0.113.1 description "Route Collector"
     !
     address-family ipv4 unreachability
      neighbor 203.0.113.1 activate
     exit-address-family
     !
     address-family ipv6 unreachability
      neighbor 203.0.113.1 activate
     exit-address-family

**DDoS Target Coordination**

Share attack target information across network boundaries without null-routing:

.. code-block:: frr

   router bgp 65001
     neighbor 198.51.100.1 remote-as 65002
     !
     address-family ipv4 unreachability
      neighbor 198.51.100.1 activate
      neighbor 198.51.100.1 route-map DDOS-TARGETS-OUT out
     exit-address-family
   !
   route-map DDOS-TARGETS-OUT permit 10
     match community DDOS-TARGET
   !


References
----------

- IETF Draft: `draft-tantsura-idr-unreachability-safi <https://datatracker.ietf.org/doc/draft-tantsura-idr-unreachability-safi/>`_
- RFC 4271: Border Gateway Protocol 4 (BGP-4)
- RFC 4760: Multiprotocol Extensions for BGP-4
- RFC 5492: Capabilities Advertisement with BGP-4
- RFC 4724: Graceful Restart Mechanism for BGP
