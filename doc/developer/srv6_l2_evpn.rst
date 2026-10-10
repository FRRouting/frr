.. SPDX-License-Identifier: GPL-2.0-or-later

.. _srv6-l2-evpn:

************
SRv6 L2 EVPN
************

This chapter describes the high-level design of SRv6 L2 EVPN in FRR: EVPN
ELAN (Type-2/Type-3) and EVPN-VPWS (Type-1) delivered over an SRv6 dataplane
instead of VXLAN, as specified by :rfc:`9252` using the endpoint behaviors of
:rfc:`8986`. For operator configuration see :ref:`evpn-srv6-l2`.

Summary
=======

.. list-table::
   :header-rows: 1
   :widths: 22 22 22 34

   * - Service
     - EVPN routes
     - SRv6 behavior
     - Dataplane use
   * - EVPN ELAN, per EVI
     - Type-2 (MAC/IP), Type-3 (IMET)
     - ``End.DT2U`` (unicast), ``End.DT2M`` (BUM)
     - bridge-domain lookup / flood
   * - EVPN-VPWS (E-Line)
     - Type-1 (EAD per-EVI)
     - ``End.DX2``
     - fixed cross-connect to an attachment circuit

An EVI is not anchored on a VXLAN netdev. It is anchored on a VLAN-aware Linux
bridge plus per-EVI SRv6 service SIDs. EVPN routes carry those SIDs in the BGP
Prefix-SID attribute (SRv6 L2 Service TLV, type 6) in place of a VNI. The VXLAN
EVPN path is unchanged; the two are selected per EVI and can coexist.

Goals and non-goals
-------------------

Goals:

* Per-EVI ``End.DT2U``/``End.DT2M`` and per-attachment-circuit ``End.DX2`` SIDs
  allocated from the existing SRv6 locators and SID manager (legacy and uSID).
* Originate and consume the SRv6 L2 Service TLV on EVPN Type-1/2/3.
* Reuse existing infrastructure: ZAPI SID manager, the RIB for ``seg6local``
  decap, and the zebra dataplane (dplane) for all netlink programming.
* No change to VXLAN EVPN behavior.
* The operator owns the kernel netdev topology; FRR does not create netdevs.

Non-goals:

* VXLAN to SRv6 EVPN gateway/interworking.
* EVPN multihoming (ESI) on SRv6 EVIs; VPWS is single-homed.
* L3 services (Type-5, symmetric IRB) over an SRv6 EVI.
* Non-Linux dataplanes. The netlink code is Linux-only.

Architecture
============

.. code-block:: none

                        +-------------------------------------------+
   operator ----------> | Linux: bridge brN (vlan_filtering),       |
   (pre-creates)        | sr6-N, bum-sr6-N, vpws bridge, vpws-sr6-X |
                        +-------------------^-----------------------+
                                            | netlink (via dplane)
   +----------------------+   ZAPI    +------+-----------------------+
   | bgpd                 |<--------->| zebra                        |
   |  EVPN T1/T2/T3       |           |  SRv6 SID manager/locators   |
   |  SRv6 L2 Service TLV |           |  zebra_srv6_l2evpn (EVI)     |
   |  vpws-instance       |           |  zebra_sr6 (sr6 netdev mgr)  |
   |  per-EVI SID request |           |  zebra_srv6_vpws (VPWS)      |
   +----------------------+           |  dplane: brport/vlan/sr6 ops |
                                      |  rt_netlink: seg6local enc.  |
                                      +------------------------------+

bgpd
   ``bgp_evpn.c``, ``bgp_attr.c``: encode/decode the SRv6 L2 Service TLV,
   attach the per-EVI SID to Type-2/Type-3 routes, import remote SIDs, install
   local decap once zebra reports the decap output interface.

   ``bgp_evpn_vpws.[ch]``, ``bgp_evpn_vpws_vty.c``: the ``vpws-instance`` model,
   Type-1 origination and import, per-instance ``End.DX2`` SID lifecycle.

   ``bgp_zebra.c``: ZAPI handling (VNI_ADD SRv6 block, SID request/notify, VPWS
   messages).

zebra
   ``zebra_srv6_l2evpn.[ch]``: per-EVI model (``struct zebra_srv6_evi``), the
   ``l2-evpn`` config node, SID allocation, locator-change handling, MAC/BUM
   backend.

   ``zebra_sr6.[ch]``: discovery and in-place programming of operator-owned
   ``sr6-<n>``/``bum-sr6-<n>`` interfaces, reference counting, MTU and encap
   mode propagation.

   ``zebra_srv6_vpws.[ch]``: VPWS dataplane driven by ZAPI VPWS messages.

   ``zebra_evpn*.c``, ``zebra_vxlan.c``, ``zebra_neigh.c``: per-EVI backend
   vtable and carriage of SRv6 SIDs on remote MAC/VTEP state.

   ``zebra_dplane.c``, ``if_netlink.c``, ``rt_netlink.c``: new dplane ops, the
   ``sr6`` netlink encoder and the ``seg6local`` End.DX2/DT2U/DT2M encoder.

lib, vtysh
   ``lib/srv6.h`` (behaviors, ``seg6local`` actions), ``lib/zclient.[ch]``
   (ZAPI), ``lib/command.h`` and ``vtysh`` (CLI nodes).

Per-EVI dataplane backend
-------------------------

zebra selects a backend vtable (``struct zevpn_dp_ops``) per EVI:

* ``zevpn_dp_ops_vxlan`` -- thin wrappers over the existing VXLAN path.
* ``zevpn_dp_ops_srv6`` -- VLAN-aware bridge, ``sr6`` ports and ``seg6local``
  decap; no VXLAN netdev.

Data model
==========

SRv6 EVI (zebra)
----------------

``struct zebra_srv6_evi`` is keyed by EVI id, which shares the BGP VNI value
space:

* ``svc_type``: ``vlan-based`` (one VLAN per EVI, Ethernet Tag 0),
  ``vlan-bundle`` (N VLANs in one bridge domain/FDB, Ethernet Tag 0),
  ``vlan-aware-bundle`` (per-VLAN bridge domain, Ethernet Tag = VLAN).
* ``locator``, ``bridge_if`` and the member-VLAN list.
* ``dt2u_sid``, ``dt2m_sid`` and their validity flags.
* ``sr6_ifindex``, ``bum_sr6_ifindex``: discovered operator-owned interfaces.
* ``local_decap_oif``/``local_decap_sid``: the l2dev used by local decap routes.
* ``l2_encap_mode`` (full or reduced).

Each member bridge domain is backed by an ordinary ``struct zebra_evpn``, so
the existing MAC and neighbor machinery (learning, mobility, aging) is reused.

sr6 interface descriptor (zebra)
--------------------------------

``struct zebra_sr6`` is keyed by remote SID and holds the ifindex, bridge,
``is_bum``, VLAN and a reference count of remote MACs using it. The
``local_decap`` flag marks the entry that only supplies the decap l2dev; it is
never programmed or reset as an encap SID, because in the operator-owned model
it resolves to the same netdev as the remote encap entry.

VPWS instance (bgpd)
--------------------

``struct bgp_evpn_vpws`` holds the name, EVI, source and target AC-ID, RD,
import/export RTs, AC interface and bridge, SID auto-allocation state, optional
per-instance locator, ``l2_encap_mode`` and the learned peer SID and behavior.

BGP attribute
-------------

``attr->extra->srv6_l2vpn`` carries the SRv6 L2 Service TLV: SID, endpoint
behavior and SID structure (block/node/function/argument lengths, transposition
offset and length). It takes part in attribute comparison and hashing so paths
that differ only in SID remain distinct.

Kernel dependency and dataplane model
=====================================

The dataplane uses:

* ``seg6local`` actions ``End.DX2`` (``SEG6_LOCAL_OIF``), ``End.DT2U`` and
  ``End.DT2M`` (``SEG6_LOCAL_L2DEV``, optional VRF table).
* A Linux virtual interface type ``sr6``, enslaved to the bridge, which performs
  ``H.Encaps.L2`` (full, SRH kept) or ``H.Encaps.L2.Red`` (reduced, SID in the
  outer IPv6 destination address, no SRH) on frames it egresses. The encap SID,
  MTU and mode are changed in place with ``RTM_NEWLINK`` changelink.

These are not all present in mainline Linux. Fallback constants are defined and
the topotests probe the running kernel and skip, rather than fail, when the
``sr6`` netdev or in-place changelink is missing.

ELAN packet flow, PE1 to PE2:

.. code-block:: none

   host A -> br10 (vlan 10) -> FDB hit: dst MAC via sr6-N port
   sr6-N encapsulates: outer IPv6 DA = PE2 End.DT2U SID (full mode: + SRH)
   ... SRv6 underlay: plain IPv6 routing toward PE2's locator ...
   PE2: DA matches local End.DT2U seg6local route (l2dev = sr6-N)
   decapsulate -> frame injected into br10 -> FDB lookup -> host B

BUM traffic is flooded to ``bum-sr6-<n>`` ports, one per remote PE, each
encapsulating to that PE's ``End.DT2M`` SID (ingress replication).

VPWS: frames from the attachment circuit (AC) are encapsulated by
``vpws-sr6-<name>`` to the peer ``End.DX2`` SID. A local ``End.DX2`` route with
the AC as output interface decapsulates with no MAC lookup.

Operator-owned netdev model
===========================

FRR does not create, enslave or delete the data-path netdevs. The operator
pre-creates:

* For an EVI: the VLAN-aware bridge, its VLAN membership, ``sr6-<n>`` (unicast)
  and ``bum-sr6-<n>`` (BUM), both enslaved to the bridge.
* For VPWS: a bridge, the attachment-circuit interface and
  ``vpws-sr6-<name>``, enslaved to the bridge.

zebra discovers them by name and bridge, reacts to interface-add events (so
ordering relative to provisioning does not matter), programs SID, MTU and encap
mode in place, applies bridge-port flags and VLAN membership through the dplane,
and on teardown resets the segment list to ``::`` and leaves the netdev in
place.

This keeps kernel topology policy out of the routing daemon and leaves nothing
to garbage-collect beyond resetting segments. Graceful-shutdown cleanup of
interfaces FRR tracked stays synchronous so it completes before the dplane
thread is joined.

Control plane
=============

SID allocation
--------------

SIDs come from the SRv6 SID manager through the asynchronous request/notify
model.

.. list-table::
   :header-rows: 1
   :widths: 15 50 35

   * - SID
     - Context key
     - Requested by
   * - End.DT2U
     - ``{behavior, vrf default, dt2_vni = EVI}``
     - zebra, per EVI
   * - End.DT2M
     - ``{behavior, vrf default, dt2_vni = EVI}``
     - zebra, per EVI
   * - End.DX2
     - ``{behavior, oif = AC ifindex, dt2_vni = EVI}``
     - bgpd via ZAPI, per VPWS instance

Behavior codepoints (IANA): End.DX2 0x15, End.DT2U 0x17, End.DT2M 0x18; the uSID
flavors uDX2 0x41, uDT2U 0x43, uDT2M 0x44 are used when the locator is uSID.

A legacy/uSID format change, or a change of the per-EVI or per-instance locator,
releases the old SID under the old locator name, clears its validity, requests a
new one, rebuilds local decap and re-advertises.

ZAPI
----

.. list-table::
   :header-rows: 1
   :widths: 38 14 48

   * - Message
     - Direction
     - Purpose
   * - ``ZEBRA_VNI_ADD`` plus ``struct zapi_srv6_l2_evi`` block
     - zebra to bgpd
     - Per-EVI DT2U/DT2M SIDs, decap oifs, service type, locator name and
       locator structure lengths. The block is always present and zeroed for
       VXLAN EVIs; zero SIDs mean "not an SRv6 EVI".
   * - ``ZEBRA_VPWS_LOCAL_ADD``/``DEL``
     - bgpd to zebra
     - AC name, bridge name, local End.DX2 SID, encap mode.
   * - ``ZEBRA_VPWS_REMOTE_ADD``/``DEL``
     - bgpd to zebra
     - Peer End.DX2 SID for the named instance.
   * - Existing SRv6 SID get/release/notify
     - both
     - SID allocation.
   * - Existing remote MAC/VTEP messages
     - bgpd to zebra
     - Extended to carry the remote End.DT2U/End.DT2M SID.

EVPN encapsulation is decided per EVI by whether zebra reports SRv6 SIDs for it;
there is no instance-wide encapsulation switch.

BGP routes
----------

.. list-table::
   :header-rows: 1
   :widths: 22 38 40

   * - Route
     - Key content
     - SRv6 content
   * - Type-3 IMET
     - EVI RD/RT, originator IP
     - L2 Service TLV: End.DT2M SID
   * - Type-2 MAC/IP
     - MAC (and IP), Ethernet Tag per service type
     - L2 Service TLV: End.DT2U SID
   * - Type-1 EAD per-EVI
     - Ethernet Tag = source AC-ID
     - L2 Service TLV: End.DX2 SID

SID transposition is not originated (length 0). On receive, a transposed SID is
reconstituted from the route label. Malformed TLVs are handled as specified in
:rfc:`9252`.

Import
------

Type-3
   The remote End.DT2M SID creates or refreshes a ``bum-sr6`` flood port for that
   peer.

Type-2
   The remote End.DT2U SID is attached to the remote MAC, which is installed in
   the bridge FDB pointing at the matching ``sr6-<n>`` with the SID programmed.
   Entries are reference counted per SID. MAC mobility and withdraw reuse the
   existing logic.

Type-1
   The Ethernet Tag is matched against ``target_ac_id`` (and EVI) and a
   ``VPWS_REMOTE_ADD`` is sent. A SID change arrives as an attribute change on
   the same NLRI and is handled as replace: the old peer state is removed first.

Reachability of the remote SID uses the normal IPv6 underlay (a route to the
remote locator, resolved through nexthop tracking). FRR does not synthesize a
per-SID /128; the operator-provided locator route makes the remote SID
reachable. If the next hop is unreachable the EVPN route stays invalid, as for
any other EVPN route.

Dataplane programming
=====================

All kernel writes go through the zebra dplane so the single FIFO preserves
ordering (enslave, bridge-port flags, VLAN, link up, SID):

* ``DPLANE_OP_BRPORT_FLAGS`` and ``DPLANE_OP_BRIDGE_VLAN_ADD``: learning, flood
  and isolation flags and VLAN membership for sr6 ports.
* ``DPLANE_OP_SR6_UPDATE_SID`` and ``DPLANE_OP_SR6_SET_MTU``: in-place changelink
  of SID, MTU and encap mode. These never use ``NLM_F_CREATE``.
* Remote MAC install/delete through an sr6 FDB encoder (no VXLAN attributes).
* Local decap is installed as an ordinary RIB route with a ``seg6local`` nexthop
  (``zclient_send_localsid``, as for other SRv6 decap behaviors). Verify at the
  kernel with ``ip -6 route``.

.. note::

   The kernel rejects ``LWTUNNEL_ENCAP_SEG6_LOCAL`` inside an ``RTM_NEWNEXTHOP``
   object. Nexthop entries carrying a ``seg6local`` action therefore skip the
   kernel nexthop-group install and the route encoder falls back to inline
   nexthop encoding. This only affects ``seg6local`` nexthops
   (``zebra_nhg.c``, ``rt_netlink.c``).

Encapsulation mode and MTU
--------------------------

``l2-encap-mode <full|reduced>`` is set per EVI and per VPWS instance. FRR owns
the value (it is not mirrored from the kernel) and sends it on every changelink,
so a change is applied live.

``l2-mtu`` (1280-9216) under ``l2-evpn`` sets the sr6 interface MTU and is
applied live. When unset the kernel default is kept (1422 on a 1500 byte
underlay). The underlay must carry the inner frame plus SRv6 overhead (about 78
bytes in full mode, 54 in reduced mode).

Configuration and observability
===============================

zebra:

.. code-block:: frr

   segment-routing
    srv6
     locators
      locator MAIN
       prefix fcbb:bbbb:1::/48
       format usid-f3216
      exit
     exit
     l2-evpn
      l2-mtu 9000
      evi 10 locator MAIN bridge br10
       service-type vlan-based
       l2-encap-mode reduced
       vlan 10
      exit
     exit
    exit

bgpd:

.. code-block:: frr

   router bgp 65001
    segment-routing srv6
     locator MAIN
    exit
    address-family l2vpn evpn
     advertise-srv6-evpn
     evi 10
      rd 65001:10
      route-target both 65000:10
     exit-evi
     vpws-instance V2
      vpws-id source 200 target 100
      vpws-evi 1000
      rd 65001:1000
      route-target both 65000:1000
      interface eth2 sid auto bridge br-vpws
      locator MAIN
      l2-encap-mode full
     exit-vpws-instance
    exit-address-family

The peer PE mirrors the VPWS configuration with ``source`` and ``target``
swapped, the same ``vpws-evi`` and the same route target.

Show commands:

* ``show evpn evi [detail] [json]``
* ``show bgp l2vpn evpn srv6``
* ``show bgp l2vpn evpn vpws [NAME]``
* ``show segment-routing srv6 sid`` -- per-EVI and per-VPWS SIDs, including the
  ``End.DT2U``/``End.DT2M``/``End.DX2`` seg6local rendering in JSON.

Lifecycle and failure handling
==============================

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Event
     - Behavior
   * - Configuration precedes netdev creation
     - State is recorded and realized from the interface-add hook.
   * - Operator removes a netdev
     - SID state is dropped and re-bound when the netdev returns.
   * - BGP session and AC come up in either order
     - The peer-established and interface-up hooks complete setup.
   * - Locator format or name change
     - Release the old SID, request a new one, rebuild decap, re-advertise.
   * - EVI removed
     - Withdraw routes, remove decap, reset sr6 segments to ``::``, release SIDs.
   * - Last remote reference to an sr6 SID dropped
     - Segments reset; the netdev is left in place.
   * - zebra shutdown
     - Tracked interfaces are cleaned up synchronously before the dplane joins.
   * - Peer SID changes on the same NLRI
     - Old peer state is removed, then the new state is installed.

Compatibility and review surface
================================

* VXLAN EVPN runs through the unchanged backend wrappers. ZAPI additions are
  appended blocks or new message ids.
* Shared files touched: ``zebra_evpn*.c``, ``zebra_vxlan.c``, ``zebra_neigh.c``,
  ``zebra_nhg.c``, ``rt_netlink.c``, ``bgp_evpn.c``, ``bgp_attr.c``.
* New netlink code is guarded for Linux; other platforms get stubs.
* Exhaustive ``seg6local`` switches in isisd and staticd are extended with no
  functional change.

Testing
=======

Topotests (two PEs, kernel with ``sr6``; skipped otherwise):

``bgp_srv6_l2_evpn``
   Two EVIs and one VPWS: BGP/EVPN peering, per-EVI SID allocation, underlay and
   DT2M routes, ``End.DX2`` decap in the kernel, sr6 interface programming,
   end-to-end ping per EVI, DT2U decap after traffic, SID release on EVI unbind.

``bgp_srv6_l2_evpn_vlan_bundle``
   Multiple VLANs bundled into one bridge domain with a single sr6: SID
   allocation, per-EVI locator SID advertised, transparent ping.

Assertions are prefix- and behavior-based because SID function values are
assigned by zebra.

Known limitations
=================

* Requires a kernel with the ``sr6`` netdev (including in-place changelink) and
  ``End.DT2U``/``End.DT2M``/``End.DX2``; these are not all in mainline Linux.
* VPWS is single-homed; no multihoming or FXC.
* ``vlan-aware-bundle`` realizes one ``zebra_evpn`` per VLAN; ``vlan-bundle``
  shares one.
* No VXLAN to SRv6 gateway and no Type-5/IRB over SRv6 EVIs.
* BUM uses ingress replication, one ``bum-sr6`` per remote PE.

References
==========

* :rfc:`9252` -- BGP Overlay Services Based on SRv6
* :rfc:`8986` -- SRv6 Network Programming
* :rfc:`7432` -- BGP MPLS-Based Ethernet VPN
* :rfc:`8214` -- Virtual Private Wire Service Support in Ethernet VPN
