.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright (C) 2026  Eric Parsonage

OSPF YANG Northbound Notes
==========================

OSPF northbound work should converge on the standard RFC 9129 ``ietf-ospf``
model for behavior covered by the RFC. FRR-native OSPF modules should be used
as augments for behavior outside the RFC model, not as parallel replacements
for standard OSPF state or configuration.

The tree contains ``yang/frr-ospfd.yang`` for future FRR-specific OSPFv2
work, but ``ospfd`` should not advertise that module until there are concrete
callbacks or augments behind it. The OSPFv3 daemon has route-map YANG support
but no native ``frr-ospf6d`` module. A native OSPFv3 module should be added
only when there is concrete FRR-specific state or configuration to expose.

IETF Module Sources
-------------------

The added IETF modules, ``ietf-ospf.yang``, ``ietf-routing.yang``,
``ietf-bfd-types.yang``, ``iana-routing-types.yang``, and
``iana-bfd-types.yang``, are imported from their respective RFCs and keep the
IETF Trust BSD license text unchanged. This follows the existing
``yang/ietf/`` treatment of ``ietf-interfaces.yang``,
``ietf-key-chain.yang``, and ``ietf-routing-types.yang``.

Related Work
------------

Earlier OSPF northbound work is useful context for future development:

* FRR PR #18401, ``pr-18401-ospf-yang``

  * Adds ``yang/frr-ospf-common-lite.yang`` and
    ``yang/frr-ospfd-lite.yang``.
  * Adds real operational callbacks in ``ospfd/ospf_nb_state.c``.
  * Good source material for instance, area, interface, and neighbor state.
  * Targets a lite model, so paths do not map directly to current
    ``frr-ospfd.yang``.

* FRR PR #19066, ``pr-19066-ospf-nb``

  * Adds a broad generated callback skeleton for current ``frr-ospfd.yang``.
  * Useful for path coverage and generated callback names.
  * Most callbacks are TODO/no-op stubs, so it should not be transplanted
    wholesale.

FRR also has an experimental YANG module translator for mapping non-native
models onto native FRR models with deviation modules and XPath translation
tables. This branch does not use that mechanism because OSPF does not yet have
a complete callback-backed native OSPF YANG model to serve as the source of
truth. Instead, RFC 9129 is implemented directly as the canonical northbound
surface for the OSPF behavior it covers.

Current Implementation
----------------------

This branch implements the RFC 9129 ``ietf-ospf`` tree directly for OSPFv2 and
OSPFv3 rather than adding an FRR-native OSPF model with parallel semantics.
``yang/frr-ospfd.yang`` remains on disk for future FRR-specific OSPFv2 work,
but ``ospfd`` does not link its generated schema into the daemon binary or
advertise it with no callbacks behind it.

Both daemons load ``ietf-ospf`` and map FRR behavior toward the RFC 9129
``/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf``
tree. OSPFv2 and OSPFv3 operational callbacks expose the RFC
``control-plane-protocol`` list, router-id, instance LSA counters, area
SPF/ABR/ASBR/LSA counters, interface list, and neighbor list with neighbor
address and state. The default instance name is ``default`` for normal
``ospfd`` and ``ospf6d`` instances. In ``ospfd --instance N`` daemon-instance
mode, the RFC 9129 ``control-plane-protocol`` name is the decimal instance ID
(``N``), matching the legacy ``router ospf N`` CLI. The OSPFv2 interface list
exposes one entry per interface key because RFC 9129 keys the list by interface
name while FRR can hold multiple OSPFv2 interface objects for different
addresses on the same interface.

``ospfd`` and ``ospf6d`` register as mgmtd backend clients for typed
``control-plane-protocol`` entries so OSPFv2 and OSPFv3 can share the standard
``ietf-routing`` list without one daemon claiming the other daemon's instance.
Instanced ``ospfd`` backends further constrain their registration with the
``name`` key so ``ospfd-1`` and ``ospfd-2`` receive only edits for their own
RFC 9129 protocol instance.
``mgmtd`` also loads the RFC OSPF modules so it can parse OSPF backend replies
in the merged operational datastore.

The mgmtd backend matcher treats predicates in backend registrations as
ownership constraints, not as a reason to hide unfiltered list data. A query
with ``type='ietf-ospf:ospfv2'`` must dispatch only to ``ospfd`` and a query
with ``type='ietf-ospf:ospfv3'`` must dispatch only to ``ospf6d``. A query that
omits the ``type`` predicate, such as a request for the whole
``control-plane-protocol`` list or one of its unkeyed descendants, still
dispatches to both daemons so mgmtd can merge the OSPFv2 and OSPFv3 entries.
Predicate values are compared through the key schema where possible, so
identityref values are matched by identity rather than by their rendered text.
This keeps shared IETF lists usable for current OSPF and future protocol
families without special-casing OSPF in mgmtd. The matcher is deliberately
tree-free: the same selection code is used for configuration, operational
state, notifications and RPC dispatch, and the latter three do not have a
candidate data tree at selection time. Config callbacks still validate against
the candidate tree once mgmtd has selected the owning backends.

Configuration write support is intentionally limited to CLI-equivalent RFC 9129
leaves. The converted leaves are router-id, preference, spf-control paths,
auto-cost, OSPFv2 mpls/ldp/igp-sync, OSPFv2 mpls/te-rid, OSPFv2 stub-router
unconditional, area lifecycle, area-type, area summary, OSPFv2 default-cost,
area ranges, per-interface area attachment, interface cost, hello-interval,
dead-interval, retransmit-interval, priority, mtu-ignore, transmit-delay,
interface-type, passive, and OSPFv2 prefix-suppression. Existing CLI commands
for those leaves set the same YANG nodes as mgmtd writes.

Configuration Mapping Model
---------------------------

The config-write implementation should be maintained as a mapping from RFC
9129 schema nodes to existing FRR daemon objects, not as a collection of
independent leaf fixes. Every supported config node should have an explicit
answer for these questions:

* Which FRR object owns the value?
* Which candidate-state constraints must be rejected during ``NB_EV_VALIDATE``?
* What daemon mutation and protocol side effects happen during ``NB_EV_APPLY``?
* What FRR default is restored when the YANG node is destroyed?
* Which legacy CLI commands enqueue the same YANG edit?
* Which topotest asserts mgmtd writes, CLI writes, deletion, and any negative
  validation path?

The common resolution chain is:

::

   control-plane-protocol[type,name]
     -> ospfd / ospf6d instance
     -> area
     -> interface, range, or per-instance attribute

Missing daemon objects should be rejected in ``NB_EV_VALIDATE`` when accepting
the commit would leave the intended daemon mutation as a silent no-op. The
``NB_EV_APPLY`` phase should still tolerate races, such as an instance, area, or
interface disappearing after validation, and return ``NB_OK`` where no useful
recovery exists.

The current config-write mapping is:

+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| RFC 9129 config node          | OSPFv2 owner / default      | OSPFv3 owner / default      | Notes                       |
+===============================+=============================+=============================+=============================+
| ``control-plane-protocol``    | ``struct ospf`` instance;   | ``struct ospf6`` instance;  | Parent list entry must stay |
|                               | destroy calls               | destroy calls               | in the candidate so child   |
|                               | ``ospf_finish()``           | ``ospf6_delete()``          | edits have a real parent.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/explicit-router-id``   | ``router_id_static``;       | ``router_id_static``;       | Apply updates the active    |
|                               | destroy clears to automatic | destroy clears to automatic | router ID and resets OSPFv3 |
|                               | selection                   | selection                   | when needed.                |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/preference/*``         | ``distance_*`` fields;      | ``distance_*`` fields;      | ``internal`` is a coarse    |
|                               | destroy restores OSPFv2     | destroy restores OSPFv3     | RFC leaf mapped onto intra  |
|                               | admin-distance defaults     | admin-distance defaults     | and inter area distances.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``areas/area``                | ``struct ospf_area``;       | ``struct ospf6_area``;      | Destroy must first restore  |
|                               | destroy resets area attrs   | destroy resets area attrs   | child defaults and remove   |
|                               | and ranges before free      | and ranges before free      | ranges so area-free checks  |
|                               | checks                      | checks                      | can pass.                   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``areas/area/area-type``      | ``external_routing`` via    | area stub/NSSA state via    | OSPFv2 validates virtual    |
|                               | stub/NSSA helpers; default  | ospf6 helpers; default is   | links before stub/NSSA      |
|                               | is normal area              | normal area                 | conversion.                 |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``areas/area/summary``        | ``no_summary`` inverted     | ``no_summary`` inverted     | RFC ``summary=true`` means  |
|                               | from the RFC leaf; destroy  | from the RFC leaf; destroy  | summary LSAs are allowed.   |
|                               | allows summaries            | allows summaries            |                             |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``areas/area/default-cost``   | ``area->default_cost``;     | Not implemented: ospf6d has | The RFC ``when`` constraint |
|                               | destroy restores ``1``      | no matching FRR CLI/daemon  | handles atomic area-type +  |
|                               |                             | knob                        | default-cost commits.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``areas/area/ranges/range``   | ``area->ranges`` route      | ``area->range_table`` route | Destroy removes the range   |
|                               | table; advertise defaults   | table; advertise defaults   | entry, including cost and   |
|                               | to true and cost unset      | to true and cost unset      | advertise state.            |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``range/advertise``           | range advertise flag;       | range flag; destroy         | ``false`` maps to           |
|                               | destroy restores advertise  | restores advertise          | ``not-advertise``.          |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``range/cost``                | range configured cost;      | ``cost_config``; destroy    | Destroy restores automatic  |
|                               | destroy unsets cost         | unsets configured cost      | range cost.                 |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interfaces/interface``      | ``ospf_if_params`` default  | ``struct ospf6_interface``  | The YANG shape is           |
|                               | params plus interface-area  | area attachment             | area-centric; validation    |
|                               | attachment                  |                             | enforces one area per       |
|                               |                             |                             | interface.                  |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/cost``            | ``params->output_cost_cmd`` | ``oi->cost`` plus           | Destroy returns to auto     |
|                               | and cost recalculation      | ``NOAUTOCOST`` flag         | cost.                       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/hello-interval``  | ``params->v_hello``;        | ``oi->hello_interval``      | OSPFv2 mirrors the legacy   |
|                               | destroy restores default    |                             | implicit dead-interval      |
|                               | hello behavior              |                             | behavior when dead is unset |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/dead-interval``   | ``params->v_wait`` plus     | ``oi->dead_interval``       | Destroy restores daemon     |
|                               | ``is_v_wait_set``           |                             | defaults.                   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/retransmit-``     | ``params->retransmit_``     | ``oi->rxmt_interval``       | Destroy restores daemon     |
| ``interval``                  | ``interval``                |                             | defaults.                   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/priority``        | ``params->priority`` and    | ``oi->priority``            | OSPFv2 schedules neighbor   |
|                               | neighbor-change side effect |                             | change when priority moves. |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/mtu-ignore``      | ``params->mtu_ignore``      | ``oi->mtu_ignore``          | Destroy restores false.     |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/transmit-delay``  | ``params->transmit_delay``; | ``oi->transdelay``; destroy | Passive flood-time scalar;  |
|                               | destroy restores ``1``      | restores ``1``              | no protocol side effects.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/interface-type``  | ``params->type`` / OSPF     | ``oi->type`` with           | Loopback and unsupported    |
|                               | interface type side effects | ``type_cfg`` marker         | enum values are rejected at |
|                               |                             |                             | validate.                   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/passive``         | ``params->passive_``        | ``OSPF6_INTERFACE_PASSIVE`` | Destroy restores active.    |
|                               | ``interface`` and passive   | flag                        |                             |
|                               | update helper               |                             |                             |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/prefix-``         | ``params->prefix_``         | Not implemented: ospf6d     | RFC 6860; toggling          |
| ``suppression``               | ``suppression``; destroy    | has no equivalent           | reoriginates Router-LSA on  |
|                               | restores                    | per-interface flag          | every adjacency and the     |
|                               | ``OSPF_PREFIX_SUPPRESSION_``|                             | Network-LSA on any iface    |
|                               | ``DEFAULT``                 |                             | where this router is DR.    |
|                               |                             |                             | Per-address overrides stay  |
|                               |                             |                             | on the legacy direct path.  |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/spf-control/paths``    | ``ospf->max_multipath``;    | ``ospf6->max_multipath``;   | RFC types ``paths`` as      |
|                               | destroy restores            | destroy restores            | uint16 (1..65535) and FRR's |
|                               | ``MULTIPATH_NUM``           | ``MULTIPATH_NUM``           | ``MULTIPATH_NUM`` cap stays |
|                               |                             |                             | enforced in the CLI body.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/auto-cost/enabled``    | no-op on modify=true;       | no-op on modify=true;       | FRR has no off-switch for   |
|                               | NB_EV_VALIDATE rejects      | NB_EV_VALIDATE rejects      | auto-cost.  Deviations file |
|                               | modify=false                | modify=false                | pins default to ``true`` so |
|                               |                             |                             | the ``when`` clause on      |
|                               |                             |                             | ``reference-bandwidth`` is  |
|                               |                             |                             | always satisfied.           |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/auto-cost/reference-`` | ``ospf->ref_bandwidth``;    | ``ospf6->ref_bandwidth``;   | RFC units are Mbits.        |
| ``bandwidth``                 | destroy restores            | destroy restores            | Modify walks every VRF      |
|                               | ``OSPF_DEFAULT_REF_``       | ``OSPF6_REFERENCE_``        | interface (v2) or area      |
|                               | ``BANDWIDTH``               | ``BANDWIDTH``               | interface (v3) to recompute |
|                               |                             |                             | output cost.                |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/mpls/ldp/igp-sync``    | ``ospf->ldp_sync_cmd``      | Not implemented: ospf6d     | Enable registers opaque     |
|                               | flags; modify=true enables  | has no LDP/IGP sync         | LDP zclient handlers and    |
|                               | and walks all PtoP ifaces,  | implementation              | walks all interfaces;       |
|                               | modify=false / destroy call |                             | ``ospf_ldp_sync_gbl_exit``  |
|                               | ``ospf_ldp_sync_gbl_exit``  |                             | tears the state back down.  |
|                               |                             |                             | Validate rejects non-       |
|                               |                             |                             | default VRF instances.      |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/mpls/te-rid/``         | ``OspfMplsTE.router_addr``  | Not implemented: ospf6d     | MPLS-TE state is per-       |
| ``ipv4-router-id``            | (process-wide global);      | has no MPLS-TE module       | process global; validate    |
|                               | destroy zeros the TLV       |                             | rejects non-default VRF.    |
|                               | header so the running       |                             | Modify refreshes the        |
|                               | config gates the line off   |                             | Opaque Router-Address LSAs  |
|                               |                             |                             | when MPLS-TE is enabled,    |
|                               |                             |                             | otherwise just stores the   |
|                               |                             |                             | value for later use.        |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/stub-router/always``   | ``OSPF_AREA_ADMIN_STUB_``   | Not implemented: ospf6d     | Presence container          |
|                               | ``ROUTED`` per area +       | has no stub-router          | (create / destroy           |
|                               | ``ospf->stub_router_admin`` | implementation              | callbacks).  RFC 6987       |
|                               | ``_set``; destroy preserves |                             | unconditional stub router;  |
|                               | in-flight startup-timer     |                             | per-area LSA reorigination  |
|                               | stub state                  |                             | triggered by the flag flip. |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+

When adding another RFC 9129 config node, add its row here before or alongside
the callback implementation. If the row cannot name a daemon owner, default
restore behavior, and CLI-equivalent command, the node is probably outside this
branch's current config-write scope.

Direct daemon config-file loads in ``ospfd`` and ``ospf6d`` opt in to batching
for the process lifetime, so cross-leaf validation can evaluate any direct
daemon config-file load as one northbound transaction. This is not a
startup-only temporary flag; a later ``config_from_file()`` call in these
daemons has the same cross-leaf validation requirements. Other daemons keep the
legacy per-line config-file behavior.

Remaining Scope
---------------

``ietf-ospf`` remains the canonical configuration tree for everything RFC 9129
models. ``frr-ospfd`` and future ``frr-ospf6d`` should augment only
FRR-specific behavior that the RFC model does not cover.

The current config-write scope deliberately does not include redistribution,
default-information-originate, virtual links, per-address OSPFv2 interface
overrides, OSPFv2 NSSA translator/suppress-fa knobs, or other FRR-specific
extensions outside RFC 9129. A native OSPFv3 module should be added only when
there is concrete FRR-specific state or configuration to expose.

Test Coverage
-------------

``tests/topotests/ospf_topo1/test_ospf_topo1.py`` includes an RFC 9129
operational-data check for OSPFv2 and OSPFv3 router-id, area, interface, and
neighbor state. It also checks that ``ospfd`` and ``ospf6d`` register with mgmtd
and that mgmtd's operational xpath registry includes the RFC 9129 control-plane
protocol subtree.

The operational tests also include a targeted mgmtd dispatch check. Predicate
queries for ``ietf-ospf:ospfv2`` and ``ietf-ospf:ospfv3`` must return exactly
one protocol entry from the correct backend, and the backend subscription check
must show that the other OSPF daemon was not selected. The same dispatch check
also covers a tree-free identityref predicate spelling, ``type='ospfv2'``,
which mgmtd must resolve to the same identity as ``ietf-ospf:ospfv2``.
Unfiltered parent/list queries must still select both OSPF daemons. A predicate
query against ``ietf-interfaces`` verifies that untyped backend registrations
still match.

The same test file includes config-write checks for the supported OSPFv2 and
OSPFv3 leaves. The tests exercise mgmtd writes, legacy CLI writes routed through
YANG, negative validation paths, and cleanup after deleting and recreating an
area.

``tests/topotests/ospf_yang_startup_config/test_ospf_yang_startup_config.py``
checks startup config-file batching in an isolated one-router topology. Its
``r1/ospfd.conf`` places an OSPFv2 ``default-cost`` line before the stub-area
line that makes it valid; startup succeeds only when the whole daemon config
file is committed as one northbound transaction. ``r1/ospf6d.conf`` keeps a
matching OSPFv3 stub area in the startup path.

The test queries the merged mgmtd operational datastore rather than daemon-local
``show yang operational-data`` output. Zebra supplies the narrow
``/ietf-interfaces:interfaces/interface`` operational state used by RFC 9129's
interface-name leafref. The OSPF deviation keeps the leafref type but sets
``require-instance false`` because the target is operational data, not config;
the daemon callback then validates the interface name against FRR's live
interface table. In netns-backed VRF mode, OSPF and zebra both emit
VRF-qualified interface names, matching FRR's existing
``frr-interface:lib/interface`` convention for netns interface keys.

The test should run without ``Invalid leafref``, ``Invalid identityref``, or
missing-module errors in the router daemon logs.
