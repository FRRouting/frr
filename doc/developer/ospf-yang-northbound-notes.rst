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

The instanced ``ospfd`` backend name is externally visible in mgmtd state:
an instanced process registers as ``ospfd-N`` rather than plain ``ospfd`` so
operators can distinguish backend ownership by OSPF instance.  This is an
intentional release-note item, along with the new RFC 9129 OSPF
configuration, RPC, operational state and notification surface.

Notifications emitted by this branch are available to mgmtd native frontend
subscribers today.  They are also the producer side expected by the companion
gRPC Subscribe work; the two branches remain independently useful.

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
auto-cost, OSPFv2 mpls/ldp/igp-sync, OSPFv2 mpls/te-rid, graceful-restart
enabled, restart-interval, helper-enabled and helper-strict-lsa-checking, OSPFv2 stub-router unconditional, area
lifecycle, area-type, area summary, OSPFv2 default-cost, area ranges,
per-interface area attachment, interface cost, hello-interval, dead-interval,
retransmit-interval, priority, mtu-ignore, transmit-delay, interface-type,
passive, OSPFv2 prefix-suppression, per-interface BFD
(enabled, local-multiplier, desired-min-tx-interval,
required-min-rx-interval), OSPFv2 per-interface static
neighbours (poll-interval, priority), and per-interface
authentication key-chain (OSPFv2 ospfv2-key-chain, OSPFv3
ospfv3-key-chain). Existing CLI commands for those leaves
set the same YANG nodes as mgmtd writes.

``ietf-ospf`` is a mixed-mode module in this branch.  Nodes listed in the
mapping table below have config callbacks and mutate daemon state.  Other RFC
9129 config nodes may still be parsed and schema-validated by libyang, but
they are intentionally outside the supported write surface unless they are
deviated as not-supported or listed below.  Future work should prefer adding a
real callback or a deviation over allowing a writable node to appear supported
without mutating daemon state.

The daemons advertise only the RFC 9129 features used by the converted
surface.  ``ospfd`` enables ``auto-cost``, ``bfd``, ``explicit-router-id``,
``graceful-restart``, ``key-chain``, ``ldp-igp-sync``, ``max-ecmp``,
``mtu-ignore``, ``prefix-suppression``, ``stub-router`` and ``te-rid``.
``ospf6d`` enables ``auto-cost``, ``bfd``, ``explicit-router-id``,
``graceful-restart``, ``key-chain``, ``max-ecmp``, ``mtu-ignore``,
and ``ospfv3-authentication-trailer``.  ``mgmtd`` loads the union so it can
validate writes for either backend, while deviations still remove unsupported
leaves from the advertised schema and reject OSPFv2-only writes on OSPFv3
instances.

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

Interface APPLY paths also need to materialise daemon-private interface state
when the RFC 9129 area/interface entry is valid but the daemon's native
``if_add`` hook has not populated ``ifp->info`` yet. This can happen during
batched startup loads. ``ospfd`` creates ``ospf_if_info`` before using
``IF_DEF_PARAMS(ifp)``; ``ospf6d`` creates ``struct ospf6_interface`` before
mutating per-interface state.

Aggregate subtrees use container or list-entry ``apply_finish`` callbacks when
the daemon-side mutation depends on more than one leaf, creates or refreshes a
daemon aggregate, or would otherwise depend on libyang callback ordering.  For
BFD, the per-leaf callbacks validate only; the ``/bfd`` container reads the
settled subtree once per transaction and materialises FRR's per-interface BFD
state.  For ``static-neighbors/neighbor``, the list-entry callback creates or
refreshes the FRR NBMA neighbour and then applies the settled
``poll-interval`` and ``priority`` values.

RIP-derived northbound conventions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This work deliberately follows the conventions used by the ``ripd``
northbound conversion and the developer notes that were written around it,
especially
``doc/developer/northbound/retrofitting-configuration-commands.rst`` and
``doc/developer/northbound/yang-module-translator.rst``.  The OSPF code
applies the same northbound rules directly to RFC 9129 ``ietf-ospf``.

The conventions carried over are:

* The loaded YANG schema describes the supported management surface.  RIP's
  translator notes use deviations to remove unsupported nodes and to expose
  FRR-specific defaults.  OSPF follows that model with
  ``frr-deviations-ietf-routing-ospf.yang``: unsupported RFC 9129 leaves are
  marked ``not-supported``, and fixed FRR defaults are advertised in the
  schema.
* Fixed defaults are read from the loaded model.  The RIP retrofitting notes
  show daemon state being initialised with ``yang_get_default_*()`` from the
  YANG model.  OSPF callbacks consume defaulted dnodes or read the same
  values with ``yang_get_default_*()`` when destroy/defaulted-modify paths
  restore FRR state.  Dynamic defaults, such as OSPF interface type, stay in
  daemon code because the value depends on the live interface.
* CLI commands are northbound clients.  RIP's converted commands enqueue
  candidate edits with ``nb_cli_enqueue_change()`` and commit them through
  the northbound layer.  Converted OSPF commands do the same so CLI, mgmtd
  and future northbound clients share one validation and apply path.
* Validation belongs in ``NB_EV_VALIDATE`` when accepting the candidate would
  leave daemon state inconsistent.  ``NB_EV_APPLY`` still tolerates daemon
  objects disappearing after validation, matching the normal FRR northbound
  phase split used by RIP callbacks.
* Aggregate daemon updates use ``apply_finish`` where leaf ordering would
  matter.  RIP uses this for list or container updates such as redistribute
  and timers.  OSPF uses the same technique for BFD and static neighbours so
  the callback reads the settled subtree once per transaction.

OSPF differs from RIP where the model shape requires it.  RIP's FRR-native
model can attach daemon objects to running dnodes with
``nb_running_set_entry()`` and fetch them later with ``nb_running_get_entry()``.
The RFC 9129 OSPF tree sits under ``ietf-routing`` and is implemented by two
daemons, so OSPF resolves from the ``control-plane-protocol`` keys to the
owning daemon instance instead of storing a single RIP-style running entry.

.. warning::

   Only the key-chain branch of the RFC authentication choice is implemented
   in this branch.  The explicit-key, IPsec SA and auth-trailer leaves are
   marked ``not-supported`` in ``frr-deviations-ietf-routing-ospf.yang`` so
   mgmtd rejects unsupported YANG writes at validation time.  Those deviation
   paths include the RFC ``choice`` / ``case`` schema nodes; direct data-leaf
   paths do not resolve through ``pyang`` or ``libyang`` for this part of the
   schema.

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
|                               | is normal area; destroy     | normal area; destroy        | conversion.                 |
|                               | restores normal area        | restores normal area        |                             |
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
|                               | delete consumes defaulted   | delete consumes defaulted   | implicit dead-interval      |
|                               | schema value                | schema value                | behavior when dead is unset |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/dead-interval``   | ``params->v_wait`` plus     | ``oi->dead_interval``       | Delete consumes schema      |
|                               | ``is_v_wait_set``; delete   | delete consumes defaulted   | default is advertised in    |
|                               | consumes defaulted value    | schema value                | the deviation module.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/retransmit-``     | ``params->retransmit_``     | ``oi->rxmt_interval``       | Delete consumes schema      |
| ``interval``                  | ``interval``; delete        | delete consumes defaulted   | default is advertised in    |
|                               | consumes defaulted value    | schema value                | the deviation module.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/priority``        | ``params->priority`` and    | ``oi->priority``            | OSPFv2 schedules neighbor   |
|                               | neighbor-change side effect |                             | change when priority moves; |
|                               | delete consumes defaulted   | delete consumes defaulted   | default is advertised in    |
|                               | schema value                | schema value                | the deviation module.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/mtu-ignore``      | ``params->mtu_ignore``      | ``oi->mtu_ignore``          | Delete consumes the         |
|                               |                             |                             | advertised false default.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/transmit-delay``  | ``params->transmit_delay``; | ``oi->transdelay``; delete  | Passive flood-time scalar;  |
|                               | delete consumes defaulted   | consumes defaulted schema   | no protocol side effects.   |
|                               | schema value                | value                       |                             |
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
| ``interface/bfd/enabled``     | ``params->bfd_config``      | ``oi->bfd_config.enabled``  | Presence-style toggle:      |
|                               | as active runtime mirror    | as active runtime mirror    | modify stores the requested |
|                               |                             |                             | state in YANG; parent       |
|                               |                             |                             | ``apply_finish``            |
|                               |                             |                             | materialises daemon BFD     |
|                               |                             |                             | state from stored parameter |
|                               |                             |                             | leaves; disable or destroy  |
|                               |                             |                             | tears down every session.   |
|                               |                             |                             | ``[quick]`` (v2) and        |
|                               |                             |                             | ``[profile X]`` (v3) have   |
|                               |                             |                             | no YANG counterpart and     |
|                               |                             |                             | stay on the legacy path.    |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/bfd/``            | ``bfd_config->``            | ``oi->bfd_config.``         | Type ``multiplier`` (uint8  |
| ``local-multiplier``          | ``detection_multiplier``;   | ``detection_multiplier``;   | 1..255).  Modify stores the |
|                               | delete restores the         | delete restores the         | parameter but does not      |
|                               | defaulted value through     | defaulted value through     | activate BFD; when enabled, |
|                               | parent ``apply_finish``     | parent ``apply_finish``     | the session is refreshed.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/bfd/``            | ``bfd_config->min_tx`` /    | ``oi->bfd_config.min_tx`` / | RFC unit is microseconds;   |
| ``desired-min-tx-interval``   | ``->min_rx``; delete        | ``.min_rx``; delete         | FRR stores milliseconds.    |
| ``interface/bfd/``            | restores defaults through   | restores defaults through   | NB_EV_VALIDATE rejects      |
| ``required-min-rx-interval``  | advertised schema defaults  | advertised schema defaults  | non-multiple-of-1000 or     |
|                               | read by the parent          | read by the parent          | out-of-range (50..60000 ms) |
|                               | ``apply_finish``            | ``apply_finish``            | values; the deviations file |
|                               |                             |                             | pins the RFC default to FRR |
|                               |                             |                             | 300000 us.  The single-     |
|                               |                             |                             | interval case is marked     |
|                               |                             |                             | not-supported.  Parameter   |
|                               |                             |                             | leaves follow the same      |
|                               |                             |                             | activation rule as          |
|                               |                             |                             | ``local-multiplier``.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/static-``         | ``struct ospf_nbr_nbma``    | Not implemented: ospf6d     | RFC keys the list per-      |
| ``neighbors/neighbor``        | via ``ospf_nbr_nbma_set`` / | has no NBMA neighbour       | (area, interface,           |
|                               | ``_unset``; list-entry      | surface                     | identifier); FRR's NBMA     |
|                               | ``apply_finish`` applies    |                             | table is per-(instance,     |
|                               | settled ``poll-interval``   |                             | addr).  Area/interface      |
|                               | and ``priority`` values     |                             | labels are stored in the    |
|                               | after create / modify       |                             | candidate but ignored on    |
|                               | callbacks validate          |                             | the FRR side: FRR auto-     |
|                               |                             |                             | binds the entry to the OI   |
|                               |                             |                             | whose subnet matches the    |
|                               |                             |                             | neighbour address.          |
|                               |                             |                             | Duplicate identifiers in    |
|                               |                             |                             | one OSPF instance are       |
|                               |                             |                             | rejected at validate.       |
|                               |                             |                             | ``poll-interval`` defaults  |
|                               |                             |                             | to 60 and ``priority`` to 0 |
|                               |                             |                             | to match FRR's NBMA         |
|                               |                             |                             | neighbour defaults.  The    |
|                               |                             |                             | RFC ``cost`` leaf is        |
|                               |                             |                             | marked not-supported in the |
|                               |                             |                             | deviations file (FRR has    |
|                               |                             |                             | no NBMA cost knob).  Legacy |
|                               |                             |                             | ``neighbor A.B.C.D`` CLI    |
|                               |                             |                             | stays on the direct path:   |
|                               |                             |                             | it is instance-level and    |
|                               |                             |                             | cannot synthesise a YANG    |
|                               |                             |                             | area/interface key.         |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``interface/``                | ``params->keychain_name``   | ``oi->at_data.keychain``    | Only the key-chain case of  |
| ``authentication/``           | + ``auth_type =             | + ``OSPF6_AUTH_TRAILER_``   | the RFC's authentication    |
| ``ospfv2-key-chain``          | OSPF_AUTH_CRYPTOGRAPHIC``;  | ``KEYCHAIN`` flag; destroy  | choice is implemented in    |
| (v2)                          | destroy restores            | clears flag + frees         | this branch.  v3 rejects    |
| ``interface/``                | NOTSET                      | keychain                    | the modify at               |
| ``authentication/``           |                             |                             | NB_EV_VALIDATE if a manual  |
| ``ospfv3-key-chain``          |                             |                             | key is already set (mirrors |
| (v3)                          |                             |                             | the legacy CLI's lock).     |
|                               |                             |                             | The RFC type is             |
|                               |                             |                             | ``key-chain:key-chain-ref`` |
|                               |                             |                             | (leafref), so the named     |
|                               |                             |                             | keychain must exist at      |
|                               |                             |                             | commit time; this diverges  |
|                               |                             |                             | from the legacy             |
|                               |                             |                             | CLI which accepts forward   |
|                               |                             |                             | references.  Other          |
|                               |                             |                             | authentication leaves       |
|                               |                             |                             | (explicit-key, IPsec SA,    |
|                               |                             |                             | auth-trailer-rfc) are       |
|                               |                             |                             | deferred and marked         |
|                               |                             |                             | ``not-supported`` via       |
|                               |                             |                             | deviations that include the |
|                               |                             |                             | RFC ``choice`` / ``case``   |
|                               |                             |                             | schema nodes.               |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/spf-control/paths``    | ``ospf->max_multipath``;    | ``ospf6->max_multipath``;   | RFC types ``paths`` as      |
|                               | destroy restores            | destroy restores            | uint16 (1..65535) and FRR's |
|                               | ``MULTIPATH_NUM``           | ``MULTIPATH_NUM``           | ``MULTIPATH_NUM`` cap stays |
|                               |                             |                             | enforced in the NB callback |
|                               |                             |                             | as well as the CLI body.    |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/auto-cost/enabled``    | no-op on modify=true;       | no-op on modify=true;       | FRR has no off-switch for   |
|                               | NB_EV_VALIDATE rejects      | NB_EV_VALIDATE rejects      | auto-cost.  Deviations file |
|                               | modify=false; destroy       | modify=false; destroy       | pins default to ``true`` so |
|                               | no-ops                      | no-ops                      |                             |
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
| ``ospf/graceful-restart/``    | ``ospf->gr_info.restart_``  | ``ospf6->gr_info.restart_`` | NB_EV_VALIDATE rejects      |
| ``enabled``                   | ``support`` plus zebra GR   | ``support`` plus zebra GR   | disable when a GR prepare   |
|                               | enable / NVM bookkeeping    | enable / NVM bookkeeping    | is in flight (mirrors the   |
|                               |                             |                             | legacy CLI rejection).      |
|                               |                             |                             | Sibling restart-interval is |
|                               |                             |                             | a separate northbound knob. |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/graceful-restart/``    | ``ospf->gr_info.grace_``    | ``ospf6->gr_info.grace_``   | RFC default is 120s, which  |
| ``restart-interval``          | ``period``; delete consumes | ``period``; delete consumes | matches FRR's compile-time  |
|                               | the defaulted schema value  | the defaulted schema value  | default; no deviation       |
|                               |                             |                             | needed.  Modify refreshes   |
|                               |                             |                             | the zebra stale-route timer |
|                               |                             |                             | when GR is enabled.         |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/graceful-restart/``    | ``ospf->is_helper_``        | ``ospf6->ospf6_helper_cfg`` | RFC has no enable-list; the |
| ``helper-enabled``            | ``supported`` via           | ``.is_helper_supported``    | legacy `graceful-restart    |
|                               | ``ospf_gr_helper_support_`` | via                         | helper enable A.B.C.D` per- |
|                               | ``set``                     | ``ospf6_gr_helper_support_``| router-id form stays on the |
|                               |                             | ``set``                     | legacy direct mutation path.|
|                               |                             |                             | Disable evicts every active |
|                               |                             |                             | helper not pinned by the    |
|                               |                             |                             | per-router-id list.         |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``ospf/graceful-restart/``    | ``ospf->strict_lsa_check``  | ``ospf6->ospf6_helper_cfg`` | FRR default is true on both |
| ``helper-strict-lsa-``        | via                         | ``.strict_lsa_check`` via   | daemons; destroy restores   |
| ``checking``                  | ``ospf_gr_helper_lsa_``     | ``ospf6_gr_helper_``        | true.  v3's legacy CLI uses |
|                               | ``check_set``               | ``lsacheck_set``            | the inverted form           |
|                               |                             |                             | ``lsa-check-disable``; the  |
|                               |                             |                             | DEFPY_YANG shim flips the   |
|                               |                             |                             | meaning before enqueueing.  |
|                               |                             |                             | The deviation module        |
|                               |                             |                             | advertises the true default.|
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

RPC Support
-----------

Both RFC 9129 RPCs are implemented on ospfd and ospf6d:

+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| RFC 9129 RPC                  | OSPFv2 mapping              | OSPFv3 mapping              | Notes                       |
+===============================+=============================+=============================+=============================+
| ``clear-neighbor``            | ``ospf_neighbor_reset`` for | ``ospf6_interface_clear``   | Both daemons register the   |
|                               | the instance, or            | iterated over every         | xpath; mgmtd fans the RPC   |
|                               | neighbour-on-OI loop for    | OSPFv3-bound interface, or  | out to every backend.       |
|                               | the per-interface case      | a single ``ifp`` for the    | Each handler looks up the   |
|                               |                             | per-interface case          | named instance and returns  |
|                               |                             |                             | ``NB_OK`` silently when     |
|                               |                             |                             | not local.  Unknown         |
|                               |                             |                             | interface returns           |
|                               |                             |                             | ``NB_ERR_NOT_FOUND`` with   |
|                               |                             |                             | ``ospf-interface-not-       |
|                               |                             |                             | found`` per the RFC.        |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``clear-database``            | ``ospf_process_reset``      | ``ospf6_process_reset``     | Flushes self-originated     |
|                               |                             |                             | LSAs and drops every        |
|                               |                             |                             | adjacency; the RFC          |
|                               |                             |                             | semantics line up exactly   |
|                               |                             |                             | with the existing process-  |
|                               |                             |                             | reset helpers the legacy    |
|                               |                             |                             | ``clear ip ospf process``   |
|                               |                             |                             | / ``clear ipv6 ospf6        |
|                               |                             |                             | process`` commands invoke.  |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+

The RPC xpaths are registered via the ``rpc_xpaths`` array on each daemon's
``mgmt_be_client_cbs`` (the per-frr-yang-module-info ``.cbs.rpc`` entry alone
is not enough -- mgmtd routes RPC dispatch through the BE-adapter subscription
map, not the schema callback registry).

The libyang RPC parser expects the input wrapped in the RPC name:

::

   mgmt rpc /ietf-ospf:clear-neighbor json
     {"ietf-ospf:clear-neighbor":{"routing-protocol-name":"default"}}

Two deviations from strict RFC 9129 wording are intentional:

* RFC 9129 says an RPC against an unknown ``routing-protocol-name`` SHALL
  fail with ``error-tag=data-missing`` and ``error-app-tag=routing-protocol-
  instance-not-found``.  Both daemons receive every dispatched RPC and look
  up the named instance locally; a non-owner can't distinguish "instance
  doesn't exist on me but might exist on the sibling" from "instance
  doesn't exist anywhere", so non-owners return ``NB_OK`` silently rather
  than racing each other to surface a misleading "not found" reply.  If no
  daemon owns the name, the client sees combined success.  Lifting this
  would require mgmtd-side coordination across backend replies (collect
  every backend's verdict before responding to the frontend), which is
  outside the scope of this slice.

  The same RFC input shape means an OSPFv2 instance and an OSPFv3 instance
  with the same ``routing-protocol-name`` both match the RPC.  In that case,
  ``clear-neighbor`` and ``clear-database`` intentionally act on both local
  instances.  The RFC RPC input has no protocol ``type`` key to disambiguate
  the two split FRR daemons, and treating both matching local instances as
  owners keeps the behaviour aligned with the model the client invoked.  A
  client that needs protocol-specific clearing should use distinct instance
  names until mgmtd grows a coordinated multi-backend RPC result model.

* RFC 9129 prescribes structured ``error-app-tag`` strings
  (``routing-protocol-instance-not-found``, ``ospf-interface-not-found``).
  FRR's ``nb_cb_rpc_args`` carries only an unstructured ``errmsg`` buffer,
  so the app-tag string is embedded in the message text rather than
  surfaced via a NETCONF / RESTCONF ``<error-app-tag>`` element.  The
  ``ospf-interface-not-found`` case returns ``NB_ERR_NOT_FOUND`` (mgmtd
  maps to ``MGMTD_INVALID_PARAM``) so the error code at least reflects
  "client supplied a bad reference" rather than a daemon-internal failure.

Frontend coverage
~~~~~~~~~~~~~~~~~

The vtysh frontend (``mgmt rpc XPATH json DATA``) is the supported
invocation path for these RPCs.  It exercises the full mgmtd commit and
backend-dispatch flow; the four topotests above cover it.

FRR's per-daemon gRPC frontend (``lib/northbound_grpc.cpp``, enabled with
``--enable-grpc`` and loaded per-daemon via ``-M grpc:<port>``) cannot
dispatch these RPCs in standalone mode.  ``HandleUnaryExecute`` calls
``lyd_validate_op(..., LYD_TYPE_RPC_YANG, ...)`` before invoking the
backend handler, and that validator strictly enforces the
``routing-protocol-name`` leafref against the daemon's local libyang
context.  ``ospfd`` and ``ospf6d`` have no ``/ietf-routing:routing/...``
state populated in their own contexts (that data lives in mgmtd's
candidate datastore), so every Execute call with a valid
``routing-protocol-name`` is rejected with ``grpc::StatusCode::INVALID_
ARGUMENT`` ``"Invalid input data"``.  This is a frontend-side limitation,
not specific to these RPCs; it affects every RFC 9129 RPC whose inputs
include a leafref into the routing tree.  Fixing it would require either
relaxing leafref validation for RPC inputs in
``lib/northbound_grpc.cpp``, or having backend daemons mirror the
routing-protocol list locally.  Use the mgmtd-fronted vtysh path until
either change lands upstream.

Notification Support
--------------------

RFC 9129 notifications are emitted by hooking the existing state-change
hooks each daemon already exposes:

+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| RFC 9129 notification         | OSPFv2 hook                 | OSPFv3 hook                 | Notes                       |
+===============================+=============================+=============================+=============================+
| ``nbr-state-change``          | ``ospf_nsm_change``         | ``ospf6_neighbor_change``   | OSPFv2 NSM state values     |
|                               |                             |                             | translate via a small table |
|                               |                             |                             | (FRR reserves 0/1 for       |
|                               |                             |                             | DependUpon/Deleted); OSPFv3 |
|                               |                             |                             | NSM values match RFC 1:1.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``if-state-change``           | ``ospf_ism_change``         | ``ospf6_interface_change``  | Both daemons need a state   |
|                               |                             |                             | translation table: numeric  |
|                               |                             |                             | values agree for the first  |
|                               |                             |                             | four states but FRR orders  |
|                               |                             |                             | the DR-election trio as     |
|                               |                             |                             | DROther/Backup/DR while RFC |
|                               |                             |                             | uses dr/bdr/dr-other.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``restart-status-change``     | ``ospf_gr_restart_enter`` / | ``ospf6_gr_restart_enter`` /| Direct emit calls from the  |
|                               | ``ospf_gr_restart_exit``    | ``ospf6_gr_restart_exit``   | GR enter/exit sites (no     |
|                               |                             |                             | dedicated hook).  All FRR-  |
|                               |                             |                             | known restart reasons are   |
|                               |                             |                             | software-initiated, so they |
|                               |                             |                             | map to RFC                  |
|                               |                             |                             | ``planned-restart`` (value  |
|                               |                             |                             | 2); ``unplanned-restart``   |
|                               |                             |                             | (3) would correspond to a   |
|                               |                             |                             | crash recovery FRR does     |
|                               |                             |                             | not currently signal.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``nbr-restart-helper-status-``| ``ospf_gr_helper`` enter +  | ``ospf6_gr_helper`` enter + | Direct emit calls, one when |
| ``change``                    | ``ospf_gr_helper_exit``     | ``ospf6_gr_helper_exit``    | the router accepts a grace- |
|                               |                             |                             | LSA and becomes helper, and |
|                               |                             |                             | one when helper status ends |
|                               |                             |                             | (completion, timeout, or    |
|                               |                             |                             | topology change).  FRR's    |
|                               |                             |                             | ``enum ospf_helper_exit_``  |
|                               |                             |                             | ``reason`` is reordered     |
|                               |                             |                             | through a lookup table into |
|                               |                             |                             | the RFC                     |
|                               |                             |                             | ``restart-exit-reason-type``|
|                               |                             |                             | values.                     |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``if-rx-bad-packet``          | ``ospf_read_helper`` post-  | ``ospf6_receive`` post-     | Emitted once per packet     |
|                               | ``ospf_verify_header``      | header-validation failure   | that fails the post-header  |
|                               | failure path                | path                        | sanity check.  ``packet-    |
|                               |                             |                             | type`` leaf is omitted when |
|                               |                             |                             | the header didn't parse far |
|                               |                             |                             | enough to extract it.       |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``if-config-error``           | hello-interval and dead-    | hello-interval and dead-    | Wired at the two most       |
|                               | interval mismatch checks    | interval mismatch checks    | commonly-hit per-packet     |
|                               | in ``ospf_hello``           | in ``ospf6_receive``        | mismatches; ``error`` leaf  |
|                               |                             |                             | passed as RFC enum name     |
|                               |                             |                             | string.  Other reject paths |
|                               |                             |                             | (auth-failure, mtu-         |
|                               |                             |                             | mismatch, area-mismatch,    |
|                               |                             |                             | option-mismatch, etc.) wire |
|                               |                             |                             | as future incremental work; |
|                               |                             |                             | the emit helper is generic  |
|                               |                             |                             | enough that additions are   |
|                               |                             |                             | one-line call insertions.   |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+
| ``nssa-translator-status-``   | ``ospf_abr_nssa_check_``    | n/a; ospf6d has no NSSA     | Wired at the                |
| ``change`` (v2 only)          | ``status`` transition site  | translator surface          | NSSATranslatorState         |
|                               |                             |                             | transition site.  FRR only  |
|                               |                             |                             | tracks DISABLED/ENABLED;    |
|                               |                             |                             | RFC defines three states    |
|                               |                             |                             | (enabled/elected/disabled). |
|                               |                             |                             | FRR ENABLED maps to RFC     |
|                               |                             |                             | `elected` because FRR only  |
|                               |                             |                             | enables translation on the  |
|                               |                             |                             | elected translator.         |
+-------------------------------+-----------------------------+-----------------------------+-----------------------------+

Each daemon registers its hook subscriber from
``ospf{,6}d_ietf_notif_init()``, called once from
``ospf{,6}_master_init()``.  The handlers build the YANG notification
data tree (instance header, interface identity, neighbour leaves, the
RFC ``nbr-state-type`` enum) and dispatch through
``nb_notification_send()``.  ``DEBUGD(&nb_dbg_notif, ...)`` logs every
emit so operators can verify wiring with
``debug northbound notifications``.

Out of scope for now: ``lsdb-approaching-overflow`` and
``lsdb-overflow`` (FRR has no max-LSA threshold, as documented under
Remaining Scope).  All other RFC 9129 notifications now have emit wiring on
at least one daemon.

Live tests cover ``nbr-state-change``, ``if-state-change`` and
``if-config-error`` by driving the protocol paths that emit them.  Live test
coverage for ``restart-status-change`` and
``nbr-restart-helper-status-change`` is deferred because triggering a
graceful-restart event in topotest requires a staged daemon kill and relaunch
with grace-LSA timing that the current topo1 setup does not have.  The
emit-side wiring compiles and links cleanly; ``debug northbound
notifications`` plus a ``clear ip ospf process`` from a neighbour during its
grace period is the manual reproduction path.  The companion gRPC Subscribe
work can close the observation side of this gap by letting a future combined
topotest assert the notifications as frontend subscriber data.  That test will
still need OSPF-specific choreography to create the graceful-restart lifecycle
reliably.

Live test coverage for ``if-rx-bad-packet`` and
``nssa-translator-status-change`` is also deferred.  The former needs a
topotest packet-injection helper that can send malformed OSPF packets safely
inside a router namespace.  The latter needs an NSSA topology that drives a
real translator state transition, rather than merely calling the notification
helper.  Both emit sites are documented in the table above and can be checked
manually with ``debug northbound notifications`` until those focused tests are
added.

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

The following RFC 9129 nodes are also out of scope because neither ``ospfd``
nor ``ospf6d`` has any matching FRR surface to map onto:

* ``ospf/nsr`` -- FRR has no OSPF Non-Stop Routing.
* ``ospf/database-control/max-lsa`` -- FRR's overload protection is
  ``max-metric router-lsa on-shutdown/on-startup``, structurally different
  from RFC 9129's max-LSA accept threshold.
* ``ospf/spf-control/ietf-spf-delay`` -- FRR's ``timers throttle spf``
  implements a different back-off algorithm.
* ``ospf/node-tag-config`` -- FRR has no node-tag CLI, struct field, or LSA
  encoding; ``router-info`` only enables the Opaque Router Information LSA
  without exposing administrative tags.
* ``ospf/enabled`` and per-interface ``interface/enabled`` -- FRR has no
  separate OSPF on/off toggle.  The protocol runs whenever an ``ospfd`` /
  ``ospf6d`` instance is configured (control-plane-protocol create) and on
  every interface that is bound into an area.  Writing ``enabled=false``
  has no corresponding FRR mutation.
* ``interface/multi-areas`` (``{multi-area-adj}`` feature) -- FRR has no
  multi-area-adjacency surface on either daemon.  Each interface belongs
  to exactly one area.
* ``interface/ttl-security`` (``{ttl-security}`` feature) -- neither
  ``ospfd`` nor ``ospf6d`` exposes a per-interface TTL-security check;
  GTSM is a generic socket option used elsewhere in FRR but not wired
  into the OSPF interface params.
* ``ospf/fast-reroute/lfa`` and ``interface/fast-reroute/lfa/*``
  (``{fast-reroute}`` / ``{lfa}`` / ``{remote-lfa}`` features) -- FRR's
  only OSPF fast-reroute surface is the instance-level
  ``fast-reroute ti-lfa [node-protection]`` command on ``ospfd`` (writes
  ``ospf->ti_lfa_enabled`` + ``ti_lfa_protection_type``).  RFC 9129 models
  LFA as a per-interface enable plus an empty instance-level container
  (``Container creation has no effect on LFA activation.``); the
  semantics don't line up.  ``ospf6d`` has no TI-LFA implementation at
  all.  The legacy ``fast-reroute ti-lfa`` CLI stays on the direct
  mutation path.
* ``ospf/address-family`` -- the RFC leaf is only present for OSPFv3
  and is retained there because notification headers leafref it. FRR
  constrains the leaf to ``ipv6`` in the deviation module; other values
  are rejected by schema validation because this branch has no separate
  address-family knob. OSPFv2 notifications omit the optional
  ``address-family`` header leaf because the base RFC module does not
  instantiate the referenced config leaf for OSPFv2 instances.
* ``ospf/mpls/te-rid/ipv6-router-id`` -- the converted OSPFv2 TE callback maps
  the IPv4 Router Address TLV.  The RFC 9129 IPv6 TE router-id leaf is not
  wired in this branch and is marked ``not-supported``.
* ``area/virtual-links`` -- FRR has OSPFv2 virtual-link CLI support, but the
  RFC 9129 virtual-link subtree is not wired through northbound callbacks in
  this branch.  It is marked ``not-supported`` until the timers and
  authentication leaves below it can be implemented as a coherent unit.
* ``interface/instance-id`` -- the OSPFv3 instance ID has legacy CLI support,
  but is not exposed through RFC 9129 callbacks in this branch.
* ``interface/authentication/(auth-key-explicit|ospfv2-auth-trailer-rfc)``
  and the OSPFv3 ``ospfv3-sa`` / ``ospfv3-key`` / ``ospfv3-sa-id``
  branches -- the legacy CLI supports them, but this branch implements
  only the key-chain case through YANG.  The unsupported leaves are
  marked ``not-supported`` by deviation so mgmtd rejects them at
  validation time.  The matching legacy CLI commands stay on the direct
  mutation path.

These should be revisited only if FRR grows the underlying surface; until
then, leaving the YANG nodes unimplemented is preferable to silent
no-op callbacks.

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

Deviation coverage follows the same mapping rule.  A deviation that supplies an
FRR default must have a positive test for the defaulted behaviour, such as bare
``auto-cost/reference-bandwidth``, bare BFD enable, or partial NBMA static
neighbour writes.  A deviation that marks an RFC leaf ``not-supported`` must
have a rejection test, such as ``ospf/enabled``, ``interface/enabled``, BFD
``min-interval``, or NBMA static-neighbour ``cost``.

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
