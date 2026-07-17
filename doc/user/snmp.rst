.. _snmp-support:

************
SNMP Support
************

:abbr:`SNMP (Simple Network Managing Protocol)` is a widely implemented feature
for collecting network information from router and/or host. FRR itself does
not support SNMP agent (server daemon) functionality but is able to connect to
a SNMP agent using the the AgentX protocol (:rfc:`2741`) and make the
routing protocol MIBs available through it.

Note that SNMP Support needs to be enabled at compile-time and loaded as module
on daemon startup. Refer to :ref:`loadable-module-support` on the latter.  If
you do not start the daemons with snmp module support snmp will not work
properly.

BGP SNMP Support
================

In addition to the standard BGP4-MIB (:rfc:`4273`) and BGP4V2-MIB, FRR also
supports the CISCO-BGP4-MIB (OID 1.3.6.1.4.1.9.9.187). This MIB provides
extended information about BGP peers, capabilities, routes, and prefix
statistics organized by address family, along with SNMP trap notifications
for peer state changes and prefix threshold events.

**Global Scalars** (cbgpGlobal, .1.3):

- cbgpLocalAs: the local BGP AS number
- cbgpNotifsEnable: bitmask of enabled notification types

**Peer Tables** (cbgpPeerTable, cbgpPeer2Table, cbgpPeer3Table):

- Peer state, timers, connection details, and FSM transition counters
- Accepted, denied, filtered, withdrawn, and suppressed prefix counts per AFI/SAFI
- Advertised prefix counts per address family
- Prefix limits, thresholds, and clear thresholds per address family
- MinASOriginationInterval and MinRouteAdvertisementInterval
- Previous state and last error text for diagnostics
- cbgpPeer3Table adds VRF-aware indexing

**Capability Tables** (cbgpPeerCapsTable, cbgpPeer2CapsTable):

- Received BGP capabilities reconstructed from parsed peer state
- Zero per-peer memory overhead (capabilities built on demand)
- Supported capability codes: MP (1), Route Refresh (2), Extended Nexthop (5),
  Extended Message (6), Role (9), Graceful Restart (64), 4-byte AS (65),
  Dynamic (67), Addpath (69), Enhanced Route Refresh (70), LLGR (71),
  FQDN (73), Route Refresh Old/Cisco (128)

**Address Family Prefix Tables** (cbgpPeerAddrFamilyPrefixTable, cbgpPeer2AddrFamilyPrefixTable):

- Accepted, denied, advertised, withdrawn, and suppressed prefix counters
- Prefix admin limit and threshold/clear-threshold configuration
- Per-AFI/SAFI granularity (IPv4/IPv6 unicast, L2VPN EVPN, etc.)

**Route Table** (cbgpRouteTable):

- Loc-RIB entries for IPv4 unicast, IPv6 unicast, and L2VPN EVPN
- Per-route attributes: origin, AS-path, next-hop, MED, local-pref
- Aggregator information, best-path indication, and unknown attributes (transit data)
- EVPN route type encoding (Type-1 through Type-5)

**Trap Notifications** (cbgpNotifications, .0):

Ten notification types are supported:

- cbgpFsmStateChange (1): legacy IPv4 peer FSM state change
- cbgpBackwardTransition (2): legacy IPv4 backward transition (Established to lower)
- cbgpPrefixThresholdExceeded (3): legacy IPv4 prefix threshold exceeded
- cbgpPrefixThresholdClear (4): legacy IPv4 prefix threshold cleared
- cbgpPeer2EstablishedNotification (5): IPv4/IPv6 peer established
- cbgpPeer2BackwardTransNotification (6): IPv4/IPv6 backward transition
- cbgpPeer2FsmStateChange (7): IPv4/IPv6 FSM state change
- cbgpPeer2BackwardTransition (8): IPv4/IPv6 backward transition (extended)
- cbgpPeer2PrefixThresholdExceeded (9): IPv4/IPv6 prefix threshold exceeded
- cbgpPeer2PrefixThresholdClear (10): IPv4/IPv6 prefix threshold cleared

To receive traps, configure ``trap2sink`` in your ``snmpd.conf``::

   trap2sink localhost public

Then enable CISCO-BGP4-MIB traps in FRR (disabled by default)::

   bgp snmp traps cisco-bgp4

The CISCO-BGP4-MIB is particularly useful for monitoring BGP peers and
routes in multi-protocol environments and provides more detailed statistics
than the standard BGP4-MIB.

.. _getting-and-installing-an-snmp-agent:

Getting and installing an SNMP agent
====================================

The supported SNMP agent is AgentX. We recommend to use
the latest version of `net-snmp` which was formerly known as `ucd-snmp`. It is
free and open software and available at `http://www.net-snmp.org/ <http://www.net-snmp.org/>`_
and as binary package for most Linux distributions.

.. _net-smtp-configuration:

NET-SNMP configuration
======================

Routers with a heavy amount of routes (e.g. BGP full table) might experience
problems with a hanging vtysh from time to time, 100% CPU on the snmpd or
even crashes of the frr daemon(s) due to stalls within AgentX. Once snmp
agents connects they start receiving a heavy amount of SNMP data (all the
routes) which cannot be handled quick enough. It's recommended (by several
vendors as well) to exclude these OID's unless you really need them, which
can be achieved by amending the default view from SNMP

:file:`/etc/snmp/snmpd.conf`:

::

   # This is the default view
   view all    included  .1 80
   # Remove ipRouteTable from view
   view all    excluded  .1.3.6.1.2.1.4.21
   # Remove ipNetToMediaTable from view
   view all    excluded  .1.3.6.1.2.1.4.22
   # Remove ipNetToPhysicalPhysAddress from view
   view all    excluded  .1.3.6.1.2.1.4.35
   # Remove ipCidrRouteTable  from view
   view all    excluded  .1.3.6.1.2.1.4.24
   # Optionally protect SNMP private/secret values
   view all    excluded  .1.3.6.1.6.3.15
   view all    excluded  .1.3.6.1.6.3.16
   view all    excluded  .1.3.6.1.6.3.18
   # Optionally allow SNMP public info (sysName, location, etc)
   view system included  .iso.org.dod.internet.mgmt.mib-2.system


.. _agentx-configuration:

AgentX configuration
====================

.. program:: configure

To enable AgentX protocol support, FRR must have been build with the
:option:`--enable-snmp` option. Both the
master SNMP agent (snmpd) and each of the FRR daemons must be configured. In
:file:`/etc/snmp/snmpd.conf`, the ``master agentx`` directive should be added.
In each of the FRR daemons, ``agentx`` command will enable AgentX support.

:file:`/etc/snmp/zebra.conf`:

::

   #
   # example access restrictions setup
   #
   com2sec readonly default public
   group MyROGroup v1 readonly
   view all included .1 80
   access MyROGroup "" any noauth exact all none none
   #
   # enable master agent for AgentX subagents
   #
   master agentx

:file:`/etc/frr/ospfd.conf:`

   .. code-block:: frr

      ! ... the rest of ospfd.conf has been omitted for clarity ...
      !
      agentx
      !


Upon successful connection, you should get something like this in the log of
each FRR daemons:

::

   2012/05/25 11:39:08 ZEBRA: snmp[info]: NET-SNMP version 5.4.3 AgentX subagent connected


Then, you can use the following command to check everything works as expected:

::

   # snmpwalk -c public -v1 localhost .1.3.6.1.2.1.14.1.1
   OSPF-MIB::ospfRouterId.0 = IpAddress: 192.168.42.109
   [...]

An example below is how to query SNMP for BGP:

   .. code-block:: shell

      $ # BGP4-MIB (https://www.circitor.fr/Mibs/Mib/B/BGP4-MIB.mib)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.2.1.15

      $ # CISCO-BGP4-MIB (https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/CISCO-BGP4-MIB.my)

      $ # cbgpRouteTable - BGP route entries (IPv4/IPv6 unicast, L2VPN EVPN)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.1.1

      $ # cbgpPeerTable - Basic peer information (legacy IPv4, deprecated)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.1

      $ # cbgpPeerCapsTable - Legacy peer capabilities (IPv4 only)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.2

      $ # cbgpPeerAddrFamilyTable - Address families supported by peer
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.3

      $ # cbgpPeerAddrFamilyPrefixTable - Prefix counts per address family
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.4

      $ # cbgpPeer2Table - Extended peer information (IPv4 and IPv6)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.5

      $ # cbgpPeer2CapsTable - Peer2 capabilities (IPv4 and IPv6)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.6

      $ # cbgpPeer2AddrFamilyTable - Address families for Peer2 entries
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.7

      $ # cbgpPeer2AddrFamilyPrefixTable - Prefix counts for Peer2 entries
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.8

      $ # cbgpPeer3Table - VRF-aware peer information
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.2.9

      $ # cbgpGlobal - Global scalars (local AS, notification enables)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.4.1.9.9.187.1.3

      $ # BGP4V2-MIB (http://www.circitor.fr/Mibs/Mib/B/BGP4V2-MIB.mib)
      $ # Information about the peers (bgp4V2PeerTable):
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.3.5.1.1.2
      ...
      .1.3.6.1.3.5.1.1.2.1.1.1.1.192.168.10.124 = Gauge32: 0
      .1.3.6.1.3.5.1.1.2.1.1.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 0
      .1.3.6.1.3.5.1.1.2.1.2.1.1.192.168.10.124 = INTEGER: 1
      .1.3.6.1.3.5.1.1.2.1.2.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.3.1.1.192.168.10.124 = Hex-STRING: C0 A8 0A 11
      .1.3.6.1.3.5.1.1.2.1.3.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: 2A 02 47 80 0A BC 00 00 00 00 00 00 00 00 00 01
      .1.3.6.1.3.5.1.1.2.1.4.1.1.192.168.10.124 = INTEGER: 1
      .1.3.6.1.3.5.1.1.2.1.4.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.5.1.1.192.168.10.124 = Hex-STRING: C0 A8 0A 7C
      .1.3.6.1.3.5.1.1.2.1.5.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: 2A 02 47 80 0A BC 00 00 00 00 00 00 00 00 00 02
      .1.3.6.1.3.5.1.1.2.1.6.1.1.192.168.10.124 = Gauge32: 179
      .1.3.6.1.3.5.1.1.2.1.6.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 179
      .1.3.6.1.3.5.1.1.2.1.7.1.1.192.168.10.124 = Gauge32: 65002
      .1.3.6.1.3.5.1.1.2.1.7.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 65002
      .1.3.6.1.3.5.1.1.2.1.8.1.1.192.168.10.124 = Hex-STRING: C0 A8 0A 11
      .1.3.6.1.3.5.1.1.2.1.8.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: C0 A8 0A 11
      .1.3.6.1.3.5.1.1.2.1.9.1.1.192.168.10.124 = Gauge32: 41894
      .1.3.6.1.3.5.1.1.2.1.9.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 39960
      .1.3.6.1.3.5.1.1.2.1.10.1.1.192.168.10.124 = Gauge32: 65001
      .1.3.6.1.3.5.1.1.2.1.10.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 65001
      .1.3.6.1.3.5.1.1.2.1.11.1.1.192.168.10.124 = Hex-STRING: C8 C8 C8 CA
      .1.3.6.1.3.5.1.1.2.1.11.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: C8 C8 C8 CA
      .1.3.6.1.3.5.1.1.2.1.12.1.1.192.168.10.124 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.12.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.13.1.1.192.168.10.124 = INTEGER: 6
      .1.3.6.1.3.5.1.1.2.1.13.1.2.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 6

      $ # Information about the BGP table (bgp4V2NlriTable):
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.3.5.1.1.9
      ...
        .1.3.6.1.3.5.1.1.9.1.1.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.1.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.1.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.1.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.2.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.2.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.2.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 2
        .1.3.6.1.3.5.1.1.9.1.2.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 2
        .1.3.6.1.3.5.1.1.9.1.3.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.3.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.3.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.3.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.4.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.4.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.4.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 2
        .1.3.6.1.3.5.1.1.9.1.4.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 2
        .1.3.6.1.3.5.1.1.9.1.5.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Hex-STRING: 0A 00 00 00 
        .1.3.6.1.3.5.1.1.9.1.5.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Hex-STRING: 0A 00 00 02 
        .1.3.6.1.3.5.1.1.9.1.5.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: 20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01 
        .1.3.6.1.3.5.1.1.9.1.5.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: 20 01 0D B8 00 01 00 00 00 00 00 00 00 00 00 00 
        .1.3.6.1.3.5.1.1.9.1.6.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Gauge32: 31
        .1.3.6.1.3.5.1.1.9.1.6.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Gauge32: 32
        .1.3.6.1.3.5.1.1.9.1.6.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 128
        .1.3.6.1.3.5.1.1.9.1.6.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 56
        .1.3.6.1.3.5.1.1.9.1.7.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.7.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.7.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.7.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.8.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.8.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.8.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.8.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.9.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.9.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 3
        .1.3.6.1.3.5.1.1.9.1.9.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.9.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 3
        .1.3.6.1.3.5.1.1.9.1.10.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.10.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.10.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 4
        .1.3.6.1.3.5.1.1.9.1.10.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 4
        .1.3.6.1.3.5.1.1.9.1.11.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Hex-STRING: C0 A8 0C 01 
        .1.3.6.1.3.5.1.1.9.1.11.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Hex-STRING: C0 A8 0C 01 
        .1.3.6.1.3.5.1.1.9.1.11.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: FE 80 00 00 00 00 00 00 30 39 84 FF FE 9A 24 2B 
        .1.3.6.1.3.5.1.1.9.1.11.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: FE 80 00 00 00 00 00 00 30 39 84 FF FE 9A 24 2B 
        .1.3.6.1.3.5.1.1.9.1.14.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 0
        .1.3.6.1.3.5.1.1.9.1.14.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 0
        .1.3.6.1.3.5.1.1.9.1.14.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 0
        .1.3.6.1.3.5.1.1.9.1.14.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 0
        .1.3.6.1.3.5.1.1.9.1.15.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.15.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.15.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.15.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        .1.3.6.1.3.5.1.1.9.1.16.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.16.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.16.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 1
        .1.3.6.1.3.5.1.1.9.1.16.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 1
        1.3.6.1.3.5.1.1.9.1.17.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Gauge32: 1
        1.3.6.1.3.5.1.1.9.1.17.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Gauge32: 2
        1.3.6.1.3.5.1.1.9.1.17.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 1
        1.3.6.1.3.5.1.1.9.1.17.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 2
        1.3.6.1.3.5.1.1.9.1.18.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.18.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.18.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.18.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.19.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.19.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.19.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.19.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = INTEGER: 0
        1.3.6.1.3.5.1.1.9.1.20.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Gauge32: 0
        1.3.6.1.3.5.1.1.9.1.20.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Gauge32: 0
        1.3.6.1.3.5.1.1.9.1.20.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        1.3.6.1.3.5.1.1.9.1.20.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 0
        1.3.6.1.3.5.1.1.9.1.21.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Hex-STRING: 00 00 00 00 
        1.3.6.1.3.5.1.1.9.1.21.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Hex-STRING: 00 00 00 00 
        1.3.6.1.3.5.1.1.9.1.21.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: 00 00 00 00 
        1.3.6.1.3.5.1.1.9.1.21.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: 00 00 00 00 
        1.3.6.1.3.5.1.1.9.1.22.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Gauge32: 1
        1.3.6.1.3.5.1.1.9.1.22.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Gauge32: 1
        .1.3.6.1.3.5.1.1.9.1.22.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 1
        .1.3.6.1.3.5.1.1.9.1.22.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Gauge32: 1
        .1.3.6.1.3.5.1.1.9.1.24.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1 = Hex-STRING: 02 01 FD E9 
        .1.3.6.1.3.5.1.1.9.1.24.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1 = Hex-STRING: 02 01 FD E9 
        .1.3.6.1.3.5.1.1.9.1.24.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: 02 01 FD E9 
        .1.3.6.1.3.5.1.1.9.1.24.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1 = Hex-STRING: 02 01 FD E9 


The AgentX protocol can be transported over a Unix socket or using TCP or UDP.
It usually defaults to a Unix socket and depends on how NetSNMP was built. If
need to configure FRR to use another transport, you can configure it through
:file:`/etc/snmp/frr.conf`:

::

   [snmpd]
   # Use a remote master agent
   agentXSocket tcp:192.168.15.12:705


Here is the syntax for using AgentX:

.. clicmd:: agentx

   Once enabled, it can't be unconfigured. Only removing from the daemons file
   the keyword ``agentx`` takes an effect.

.. include:: snmptrap.rst
