.. SPDX-License-Identifier: GPL-2.0-or-later

.. _srv6-l2-evpn-irb:

**************************
SRv6 L2 EVPN symmetric IRB
**************************

This chapter describes the design of symmetric integrated routing and
bridging (IRB) for SRv6 L2 EVPN in FRR, as specified by :rfc:`9252`
section 5.1. It builds on :ref:`srv6-l2-evpn`: an EVI bound to a tenant VRF
carries both its L2 service and the VRF's L3 service, so a PE routes between
bridge domains without a VXLAN tunnel and without a centralized gateway. For
operator configuration see :ref:`evpn-srv6-l2` and the *Symmetric IRB over
SRv6* section of the EVPN user documentation.

Summary
=======

.. list-table::
   :header-rows: 1
   :widths: 24 38 38

   * - Item
     - L2 service (bridged)
     - L3 service (routed)
   * - EVPN route
     - Type-2 (MAC), Type-3 (IMET)
     - Type-2 (MAC+IP) and Type-5 (IP prefix)
   * - SRv6 behavior
     - ``End.DT2U`` / ``End.DT2M`` per EVI
     - ``End.DT46`` (or per-AFI ``End.DT4`` / ``End.DT6``) per VRF
   * - SID TLV in the route
     - SRv6 L2 Service TLV
     - SRv6 L3 Service TLV
   * - Ingress behavior
     - FDB lookup in the EVI bridge
     - lookup in the tenant VRF, then SRv6 encapsulation

Goals and non-goals
===================

Goals:

* Symmetric IRB with an anycast gateway: the same SVI address and MAC on every
  PE of an EVI, hosts attached to different PEs, routing at the ingress and the
  egress PE.
* IPv4 and IPv6 hosts, and IPv4 and IPv6 prefixes as Type-5 routes.
* No change to the VXLAN code paths: everything new is gated on the EVI being
  an SRv6 EVI and the VRF having an SRv6 SID.

Non-goals:

* Asymmetric IRB and centralized gateways.
* Interworking with VXLAN EVIs in the same VRF.
* A route-target or RD scheme specific to SRv6.

Architecture
============

An *SRv6 EVI* (zebra) is bound to an operator-created VLAN-aware bridge, which
is also the SVI: there is no vxlan device and no VLAN sub-interface. The bridge
is enslaved to the tenant VRF. The EVI is linked to its VRF by ``vrf NAME``
under ``evi``. bgpd links the matching ``bgpevpn`` to the ``bgp_vrf`` instance
once the VRF has a SID.

.. code-block:: text

   zebra                                        bgpd
   -----                                        ----
   srv6 evi (bridge, vlan, vrf)  --VNI_ADD-->   bgpevpn (tenant_vrf_id)
   SVI neighbors / local MACs    --MACIP_ADD->  Type-2 (L2 SID + L3 SID)
   remote MAC/neigh install     <--MACIP_ADD--  received Type-2
   VRF SID (End.DT46)           <--SID notify-> bgp_vrf (is_srv6_vrf_live)
   seg6local route + seg6 nexthops <--route--  Type-5 / host route in VRF

Control plane
=============

SRv6 VRF liveness
-----------------

``is_srv6_vrf_live()`` is the SRv6 counterpart of ``is_l3vni_live()``. It is
true when the VRF has the shared per-VRF ``End.DT46`` SID, or a per-AFI
``End.DT4`` / ``End.DT6`` SID. It replaces the l3vni guard in
``bgpevpn_link_to_l3vni()``, Type-5 origination triggers, route-target change
handling and the (un)mapping of VRF route targets. It is false for every VXLAN
VRF, so the VXLAN behavior is unchanged.

Linking an EVI to its VRF
-------------------------

zebra sends the EVI's tenant VRF id in ``VNI_ADD`` (``tenant_vrf_id``). When
bgpd receives the VRF's SID from zebra, it links every L2 VNI whose tenant VRF
it is (``bgp_evpn_link_l2vnis_to_vrf()``), installs the ``End.DT46``
seg6local route and reinstalls the routes of the VRF. If the VNI was linked
only now, Type-2 routes already built without the L3 SID are re-advertised.

SID allocation
--------------

For a locator without a named SID format, VRF-level SIDs (bgpd, over zapi) and
per-EVI SIDs (zebra internal) share one function counter, so the VRF SID
depended on which request zebra handled first. Functions
``[SRV6_SID_NOFORMAT_EVI_FUNC_BASE, SRV6_SID_NOFORMAT_EVI_FUNC_END)`` are
reserved for the per-EVI ``End.DT2U/DT2M``; every other service, including
``End.DT4/DT6/DT46`` and IS-IS ``End.X``, keeps allocating from the general
pool, which starts at 1 and skips that window. The window needs
``SRV6_SID_NOFORMAT_EVI_FUNC_BITS`` (11) function bits; a locator with a
narrower function field cannot hold it (the function would wrap in the SID), so
its per-EVI SIDs come from the general pool as before. Locators with a named
format are unchanged.

Type-2 with two SIDs
--------------------

For a MAC+IP route of an EVI whose tenant VRF is SRv6-live
(``bgp_evpn_is_macip_with_l3vni()``), bgpd attaches the L3 SID next to the L2
SID. Both go in one Prefix-SID attribute with the L2 Service TLV appended to the
L3 Service TLV, because two Prefix-SID attributes in one UPDATE are rejected as
a duplicate (:rfc:`7606` section 3g). If the L3 SID uses transposition
(:rfc:`9252` section 4), the transposed function is carried in the second label
slot; the first slot is the mandatory EVI label.
``bgp_evpn_type2_srv6_transpose_label()`` derives it from the interned
attribute.

The RMAC extended community is not added for SRv6 EVIs. L3 resolution is done
by the SID.

Local routes and self-reflection
--------------------------------

A locally originated host route is reflected into the VRF only
(``in_vni_rt`` false), and a locally originated route is never imported into the
VRF as if it were remote. The RMAC based self-check cannot catch it, because the
RMAC is zero for SRv6.

Receive path
------------

A remote Type-2 route with an L2 SID and an L3 SID installs the host route in
the VRF with the L3 SID as nexthop, so the egress PE decapsulates into the VRF
(``install_evpn_route_entry_in_vrf()``). A received path with an SRv6 service
SID is validated by nexthop tracking on that SID, as for L3VPN, so it becomes
invalid when the originating PE's locator is no longer reachable, even while the
BGP session that carried it stays up. This needs an IPv6 BGP nexthop, which is
what an SRv6 EVI originates; a path with an IPv4 nexthop is tracked on that
address, as for VXLAN.

Type-5 over SRv6
----------------

The VRF's prefixes are originated as Type-5 routes with the L3 Service TLV.
When the locator's function fits in the label, only the locator is sent as the
SID, the function is carried in the NLRI label and the transposition length
and offset are set (:rfc:`9252` section 4). The received label is marked valid
so that transposition is applied when the SID is rebuilt. Origination is
suppressed while no valid originator exists, and re-triggered when one does.

A Type-5 route carrying an SRv6 L3 Service TLV is imported through the VPN RIB
(``bgp_evpn_type5_route_is_vpn()``), so the VRF needs ``import vpn`` and
``rt vpn import`` in each address-family. Without them only Type-2 host routes
are installed in the VRF.

Originator and startup ordering
-------------------------------

On an all-IPv6 SRv6 router, Type-2/3/5 origination may run before any underlay
session is Established. There is then no local IPv6 session address to use as
the originator (``bgp_evpn_srv6_local_originator()``). The ``peer_established``
hook (``bgp_evpn_handle_peer_established()``) re-derives the originator of VNIs
left on the IPv4 router-id fallback and re-triggers origination. While the
router-id is unset, the auto RD uses the AS number instead of ``0.0.0.0``.

zebra
=====

SVI and anycast gateway
-----------------------

``zebra_evpn_from_svi()`` resolves the SRv6 EVI that owns a bridge.
``zebra_srv6_evpn_gw_macip_add()`` registers the SVI MAC+IP pairs as the
anycast default gateway (:rfc:`9135` section 9), honouring
``advertise-default-gw`` and ``advertise-svi-ip``.

Local and remote hosts
----------------------

A local neighbor is advertised once its MAC is a known local MAC. While the MAC
is still an AUTO placeholder, zebra re-reads the bridge FDB. The kernel FDB and
neighbor table are re-scanned once per bridge on realize, so hosts that existed
before a restart are re-originated. A remote MAC+IP install adds the MAC
(with its SID), then the neighbor. A withdraw removes the neighbor first, since
it holds a reference on the MAC, then the MAC.

When a MAC moves to remote, the dynamic kernel FDB entry is flushed and a
neighbor left LOCAL+INACTIVE is reaped after a grace period if nothing reclaims
it.

Bridge and tunnel devices
-------------------------

The ``sr6-<n>`` and ``bum-sr6-<n>`` devices are created by the operator and
discovered by bridge membership and name (see :ref:`srv6-l2-evpn`). For IRB
zebra also programs the bridge device's own VLAN membership and PVID. A routed
packet delivered to the bridge device has no ingress port; without a matching
self-PVID the FDB lookup misses and the frame is flooded out the BUM tunnel.

An EVI whose bridge appears after the EVI was configured is bound and realized
from the interface-add hook.

Dependencies and review notes
=============================

* The bridge MAC must be pinned. An unpinned bridge adopts a port MAC, the
  VLAN-local FDB entry for the SVI disappears and frames to the gateway are
  flooded.
* ``net.vrf.strict_mode=1`` is required for ``End.DT4/DT6/DT46``.
* The VRF needs the VPN import knob for Type-5 routes, as described above.

Testing
=======

``tests/topotests/bgp_srv6_l2_evpn_irb`` covers IPv4 IRB between two PEs: dual
SIDs in Type-2, host and subnet routes in the VRF, neighbors, BUM leak check,
VRF SID delivery and zebra, bgpd and full restart recovery.
``bgp_srv6_l2_evpn_irb_v2`` covers IPv4 and IPv6 IRB with the VPN import knob.
Both need the complete series.

The two IRB suites need a kernel with the ``sr6`` netdev, which is not in
mainline Linux (see :ref:`srv6-l2-evpn`). They probe for it and are skipped
otherwise; ``SR6_SUPPORTED=0`` or ``1`` overrides the probe. Type-5
origination and the VPN import run without the ``sr6`` device in
``bgp_srv6_evpn_rt5``.

Known limitations
=================

* Gateway ARP/ND for the anycast gateway is flooded over the BUM tunnel; the
  ``sr6`` devices are not created with the proxy flag.
* Removing an EVI also removes the ``sr6`` devices on its bridge.
* Interworking with other vendors has not been tested.
* The IPv6 VPN import after a full restart has not been tested.

References
==========

* :rfc:`9252` SRv6 BGP based Overlay Services
* :rfc:`9135` Integrated Routing and Bridging in EVPN
* :rfc:`8986` SRv6 Network Programming
* :rfc:`7606` Revised Error Handling for BGP UPDATE Messages
