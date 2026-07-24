.. _srv6-l2-evpn:

************
SRv6 L2 EVPN
************

This chapter describes the design and implementation of SRv6 L2 EVPN support
in FRR: L2 EVPN (RFC 9252 Type-2/Type-3) and SRv6 VPWS (Type-1) delivered over
an SRv6 dataplane in a VXLAN-decoupled model, together with the zebra/bgpd
control interface (ZAPI), the SID lifecycle, and the CLI/observability surface.

Overview
========

An EVPN Instance (EVI) is decoupled from any VXLAN device. It is anchored on a
VLAN-aware Linux bridge plus a set of per-EVI SRv6 service SIDs, and EVPN routes
carry those SIDs in place of a VXLAN VNI (RFC 9252). The SRv6 endpoint
behaviors (RFC 8986) used are:

``End.DT2U``
   Bridge-domain unicast table lookup and decapsulation (EVPN Type-2, MAC/IP).

``End.DT2M``
   BUM (broadcast/unknown-unicast/multicast) flooding decapsulation
   (EVPN Type-3, IMET).

``End.DX2``
   L2 cross-connect to a fixed attachment circuit (EVPN Type-1, VPWS/E-Line).

The EVI id reuses the BGP VNI value space; for an SRv6 EVI there is no VXLAN
netdev. Per-EVI service SIDs are carved from the EVI's SRv6 locator (legacy or
uSID format) through the existing SRv6 SID manager, and zebra installs the
``seg6local`` decap bound to a dedicated bridge-slave (``srl2``) so that
decapsulated frames are delivered into the correct bridge-domain.

Design goals:

* Reuse the existing SRv6 SID manager and locator infrastructure rather than
  introducing a parallel one.
* Keep the base VXLAN EVPN path unchanged, behind a per-EVI dataplane-backend
  abstraction, to minimize regression risk.
* Signal per-EVI SRv6 state over ZAPI as an extension of the existing
  ``ZEBRA_VNI_ADD`` message.

Architecture
============

Component split
---------------

zebra
   Per-EVI. Owns the EVI data model, the dataplane-backend abstraction
   (``dp_ops``), per-EVI SID allocation from the locator, creation of the
   ``srl2`` decap interface, and ``seg6local`` programming. Signals per-EVI
   state to bgpd via ``ZEBRA_VNI_ADD``.

bgpd
   Originates EVPN Type-1/2/3 routes carrying SRv6 service SIDs and installs
   local decap. The encapsulation choice is currently instance-wide
   (``bgp->evpn_encap`` selected by ``encapsulation srv6``).

kernel
   Provides ``seg6local`` ``End.DT2U``/``End.DT2M``/``End.DX2`` and VLAN-aware
   bridging. The upstream ``End.DT2U`` fix is required.

Dataplane-backend abstraction
-----------------------------

zebra selects a per-EVI backend vtable at EVI realization:

* ``zevpn_dp_ops_vxlan`` -- verbatim wrappers over the existing VXLAN path.
* ``zevpn_dp_ops_srv6`` -- VLAN-aware bridge + ``srl2`` bridge-slave +
  ``seg6local`` decap; no VXLAN netdev.

Because the backend is per-EVI, the dataplane is already prepared for VXLAN and
SRv6 EVIs to coexist; only the bgpd encapsulation decision remains instance-wide
in this revision.

Data model
==========

Each SRv6 EVI carries:

* the EVI id (shared with the VNI value space);
* the SRv6 locator name it draws SIDs from;
* the allocated ``End.DT2U`` and ``End.DT2M`` SIDs and their validity flags;
* the decap output interface(s) (the ``srl2`` bridge-slave);
* the EVPN service-type (``vlan-based`` / ``vlan-bundle``);
* the bound VLAN(s) and VLAN-aware bridge.

SID lifecycle
=============

Allocation
----------

Per-EVI SIDs are requested from the zebra SID manager keyed by an
``srv6_sid_ctx`` of ``{behavior, vrf_id = VRF_DEFAULT, dt2_vni = evi->vni}``.

The ``get_srv6_sid()`` return contract is:

* ``0`` -- SID already exists / unchanged;
* ``1`` -- SID newly allocated or changed;
* ``< 0`` -- error.

The per-EVI allocation helper must treat both ``0`` and ``1`` as success and
only fail on ``< 0``. Rejecting the "newly allocated" (``1``) case was the
root cause of a defect where uSID per-EVI SIDs were allocated but the kernel
decap was never installed.

Realization
-----------

On EVI realize, zebra allocates ``End.DT2U``/``End.DT2M`` from the EVI's
locator, creates the flood-off ``srl2`` bridge-slave (used as the ``seg6local``
l2dev), programs the decap, and sends ``ZEBRA_VNI_ADD`` to bgpd.

Locator lifecycle
-----------------

Two locator events force SID reallocation:

Format change
   When a locator changes between legacy and uSID (uSID functions are drawn
   from the LIB range, ``format usid-f3216``), the format-change hook releases
   the old decap and rebuilds it against the new SID format.

Per-EVI locator reassignment
   When an EVI's ``locator`` is changed, zebra releases the old decap and old
   SIDs *using the old locator name*, clears the ``dt2u_sid_valid`` /
   ``dt2m_sid_valid`` flags, records the new locator name, and re-realizes the
   EVI so new SIDs are allocated from the new locator and the decap is
   reinstalled.

ZAPI extension
==============

Per-EVI SRv6 state is appended to ``ZEBRA_VNI_ADD`` as a length-guarded block so
that non-SRv6 (VXLAN) EVIs and older peers are unaffected:

.. code-block:: none

   dt2u_sid   (16 bytes)   End.DT2U service SID
   dt2m_sid   (16 bytes)   End.DT2M service SID
   dt2u_oif   (4 bytes)    End.DT2U decap output interface index
   dt2m_oif   (4 bytes)    End.DT2M decap output interface index
   svc_type   (1 byte)     EVPN service-type
   loc_len    (1 byte)     locator-name length
   loc_name   (loc_len)    locator name

zebra encodes the block (``zebra_evpn_send_add_to_client()``); bgpd decodes it
(``bgp_zebra`` VNI_ADD handler), storing the service-type and locator name on
``struct bgpevpn`` (``srv6_svc_type``, ``srv6_locator_name``).

.. note::

   The message also carries a per-EVI encapsulation indicator from the start, so
   the planned move to per-EVI encapsulation does not require another wire
   change.

Control-plane origination (bgpd)
================================

With ``encapsulation srv6`` selected for the EVPN address-family, bgpd:

* originates EVPN Type-2 (MAC/IP) and Type-3 (IMET) routes carrying the per-EVI
  ``End.DT2U``/``End.DT2M`` SIDs;
* originates EVPN Type-1 (EAD/EVI) routes carrying ``End.DX2`` for VPWS;
* installs the local ``seg6local`` decap (l2dev = ``srl2``) for received state.

The encapsulation gate sites (Type-2 attach, Type-3 attach, remote processing,
and the ``srl2`` install trigger) currently consult the instance-wide
``bgp->evpn_encap``. Moving these to a per-``bgpevpn`` decision is the contained
refactor required for VXLAN/SRv6 coexistence.

SRv6 VPWS (End.DX2)
===================

The VPWS (Virtual Private Wire Service, E-Line) service provides a
point-to-point Ethernet pseudowire between two attachment circuits (ACs) on
two PEs, signalled with EVPN Type-1 (EAD/EVI) routes per :rfc:`8214` and carried
over SRv6 with the ``End.DX2`` endpoint behavior (:rfc:`8986`). Frames received
on the local AC are encapsulated toward the peer's ``End.DX2`` SID; frames
arriving on the local ``End.DX2`` SID are decapsulated and cross-connected out
the local AC. Unlike the L2 EVPN (ELAN) service there is no bridge-domain MAC
learning -- the cross-connect is fixed.

Configuration lives under ``router bgp <asn>`` / ``address-family l2vpn evpn``
in a named ``vpws-instance``:

.. code-block:: frr

   router bgp 65002
    address-family l2vpn evpn
     vpws-instance V4
      vpws-id source 203 target 103
      vpws-evi 3000
      rd 65002:3000
      route-target both 65000:3000
      interface cust2-vpws sid auto
      locator LOC-N3
     exit-vpws-instance

The peer PE mirrors this with swapped AC-IDs (``vpws-id source 103 target
203``), the same ``vpws-evi`` and Route Target, and its own RD/locator.

Data model
----------

Each instance is a ``struct bgp_evpn_vpws`` (in ``bgpd/bgp_evpn_vpws.h``) on the
BGP instance's ``evpn_vpws_list``:

``name``
   Operator-facing instance name and list key (not signalled).

``evi``
   EVPN Instance id; also used as the MPLS/label scope (``vni2label(evi)``).

``source_ac_id`` / ``target_ac_id``
   Local AC-ID (advertised in the EAD Ethernet Tag) and remote AC-ID (matched
   against imported EAD routes' Ethernet Tag).

``prd`` / ``import_rtl`` / ``export_rtl``
   Route Distinguisher and import/export Route Targets.

``ac_ifname`` / ``ac_ifindex`` / ``ac_ifindex_valid``
   Bound attachment-circuit interface and its resolved ifindex.

``sid_auto`` / ``sid_requested`` / ``sid_allocated`` / ``local_sid`` / ``sid_locator``
   ``End.DX2`` SID auto-allocation state and the allocated SID/locator.

``locator_name``
   Optional per-instance SRv6 locator (mirrors ``evi N locator X``); empty means
   fall back to the BGP-instance-wide locator.

``peer_present`` / ``peer_sid`` / ``peer_behavior`` / ``peer_attr_snap`` / ``peer_peer_snap``
   Remote endpoint state learned from the imported EAD route; the interned attr
   snapshot is retained so the underlay ``/128`` can be withdrawn on teardown.

An instance is considered fully configured
(``vpws_required_config_present()``) once ``evi``, ``source_ac_id``,
``target_ac_id``, RD and both RTs are set. The cross-connect is dataplane-ready
(``vpws_xc_sid_ready()``) when the encap is SRv6, the AC ifindex is valid, and
the local SID has been allocated.

SID allocation
--------------

zebra is the authoritative SID allocator (asynchronous notify model). The SID
context (``vpws_build_sid_ctx()``) is keyed by
``{behavior = End.DX2, oif = ac_ifindex, dt2_vni = evi}`` so every VPWS instance
receives a distinct SID even though they all share the ``End.DX2`` behavior.

``vpws_request_sid()`` is invoked when ``sid auto`` is set and the AC ifindex is
resolved. It selects the per-instance locator if configured, otherwise the
BGP-instance-wide locator, and sends a dynamic ZAPI SID request (passing a
zeroed ``in6_addr`` rather than ``NULL`` -- a ``NULL`` pointer makes the zclient
flip the request from DYNAMIC to EXPLICIT and zebra then rejects it). The SID
arrives via ``bgp_evpn_vpws_handle_sid_notify()``, which matches on
``(oif, evi)``, stores ``local_sid`` and the locator (restoring the per-instance
locator name so ``show`` attributes it correctly), sets ``sid_allocated``, calls
``bgp_evpn_vpws_originate()``, and pushes the local dataplane
(``bgp_zebra_send_vpws_local()`` creates the ``srl2`` bound to the AC with the
local SID). ``vpws_release_sid()`` releases under the same locator the SID was
drawn from.

Origination (EAD/EVI Type-1)
----------------------------

``bgp_evpn_vpws_originate()`` builds and installs the EAD-EVI route:

* ``vpws_build_prefix()`` -- ``build_evpn_type1_prefix()`` with ``source_ac_id``
  as the Ethernet Tag, a zero ESI, and the router-id as originator.
* ``vpws_build_attr()`` -- IPv4 nexthop = router-id; MPLS label =
  ``vni2label(evi)``; a VXLAN encap ext-community (kept for compatibility with
  the existing EVPN path -- the SRv6 binding rides separately); the export RTs;
  and an SRv6 L2 Service TLV (``attr->srv6_l2vpn``) carrying the ``End.DX2`` SID.
  The endpoint-behavior codepoint is ``End.DX2`` or the uSID-flavored
  ``uDX2`` (``SRV6_ENDPOINT_BEHAVIOR_END_DX2_USID``) depending on whether the
  locator has the ``SRV6_LOCATOR_USID`` flag; block/node/function/argument
  lengths are taken from the locator.

Import and remote endpoint
--------------------------

``bgp_evpn_vpws_handle_remote_ead()`` processes a received EAD route carrying an
SRv6 L2 Service TLV. It matches the route's Ethernet Tag against an instance's
``target_ac_id`` (cross-checked on ``evi``), records ``peer_sid`` /
``peer_behavior``, pushes the peer dataplane
(``bgp_zebra_send_vpws_remote()`` creates the peer-side ``srl2`` and enslaves it
to the bridge), and installs an IPv6 underlay ``/128`` to the peer ``End.DX2``
SID so the encap has a route to the remote endpoint. If the peer SID changes
(e.g. a legacy/uSID locator flip on the remote PE, which arrives as an attribute
change on the same NLRI rather than a withdraw), the old ``/128`` is withdrawn
first using the interned attribute snapshot. ``handle_remote_ead_withdraw()``
tears the state down.

Locator lifecycle
-----------------

Changing an instance's ``locator`` releases the SID held under the old locator
and re-requests from the new one (``bgp_evpn_vpws_set_locator()``).
``bgp_evpn_vpws_on_locator_update()`` re-drives allocation on a locator format
change, and ``request_missing_sids()`` / ``on_interface_up()`` re-request SIDs
when the AC interface becomes operational.

Observability
-------------

``show bgp l2vpn evpn vpws [NAME]`` prints, per instance: EVI, AC interface and
ifindex (flagged ``[not operational]`` until resolved), local SID (with
``(alloc pending)`` while awaiting notify), the SRv6 locator (or
``(BGP instance-wide)``), source/target AC-IDs, RD, import/export RT, EAD-EVI
advertised status, and the learned peer SID.

Packet flow
===========

L2 EVPN (ELAN):

.. code-block:: none

   config: srv6 l2-evpn evi 50000 locator LOC-R bridge br10 / vlan 10
   zebra:  allocate End.DT2U/End.DT2M from LOC-R;
           create flood-off srl2 (decap l2dev)
   zebra:  ZEBRA_VNI_ADD { vni, dt2u_sid, dt2m_sid, oif, svc_type, locator, encap }
   bgpd:   install seg6local End.DT2U/DT2M (l2dev = srl2);
           advertise Type-2/3 with SRv6 SID
   peer:   encaps toward SID; kernel End.DT2U decap -> srl2 -> bridge (vlan 10)

VPWS (E-Line):

.. code-block:: none

   config: vpws-instance V4 / interface cust2-vpws sid auto / locator LOC-N3
   zebra:  allocate End.DX2 (key: End.DX2, oif=cust2-vpws, evi=3000) from LOC-N3
   bgpd:   advertise EAD-EVI (Type-1) with SRv6 L2 Service TLV (End.DX2 SID)
   import: match remote EAD (eth_tag == target 103); learn peer SID;
           install underlay /128 to peer SID; create peer srl2
   fwd:    frame on cust2-vpws -> srl2 encap toward peer End.DX2 SID;
           remote PE End.DX2 decap -> remote AC (and symmetric in reverse)

CLI / observability
===================

* ``show evpn evi [detail] [json]`` -- SRv6-backed EVIs (SRv6-only view;
  VxLAN-IF / #Remote-VTEP columns removed).
* ``show segment-routing srv6 sid`` -- per-EVI ``End.DT2U``/``End.DT2M`` SIDs
  labelled with "EVI <id>"; SIDs without an EVI binding are hidden.
* ``show bgp l2vpn evpn srv6`` -- per-EVI SID bindings with EVI, service-type,
  locator, ``End.DT2U`` and ``End.DT2M``.
* ``show bgp segment-routing srv6`` -- BGP SRv6 SID/locator state including
  SRv6 EVPN service-type and EVI.
* ``show bgp l2vpn evpn vpws [NAME]`` -- per-VPWS-instance state: EVI, AC
  interface, local/peer ``End.DX2`` SID, locator, AC-IDs, RD/RT, EAD status.

Kernel requirements
===================

The dataplane requires ``seg6local`` ``End.DT2U``/``End.DX2`` and
VLAN-aware bridging, and the upstream Linux ``End.DT2U`` fix. On mainline or$
other distributions the ``End.DT2U`` fix must be present or backported;$
without it, ``End.DT2U`` unicast decap does not deliver into the bridge.

Known limitations / follow-ups
==============================

* Encapsulation is instance-wide today; per-EVI encapsulation (VXLAN + SRv6
  coexistence in one instance) is planned.
* ``vlan-aware-bundle`` currently realizes one ``zebra_evpn`` per EVI (exact for
  ``vlan-based``); ``vlan-bundle`` ( n VLAN -> EVI) is planned for incremental
  commit.
* ``End.DT2M`` support is not yet implemented in upstream kernel(NETDEV).
* ``End.DT2M`` functionality is achieved using ``End.DT2U`` with Source end$
  replication + flooding to bridge member ports per PE.
* Encapsulation interworking/gateway (bridging a VXLAN EVI to an SRv6 EVI) is
  out of scope and tracked separately.

References
==========

* :rfc:`9252` -- BGP Overlay Services Based on SRv6
* :rfc:`8986` -- SRv6 Network Programming (End.DT2U/DT2M/DX2)
