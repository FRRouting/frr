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

Implementation Plan
-------------------

1. Do not register inert FRR-native OSPF modules. ``yang/frr-ospfd.yang``
   remains on disk for future work, but ``ospfd`` no longer links its generated
   schema into the daemon binary or advertises it with no callbacks behind it.
   Add ``frr-ospfd`` or future ``frr-ospf6d`` module registrations only when
   there is a concrete FRR-specific augment or callback to expose.

2. Keep ``ietf-ospf`` loaded for both daemons and map FRR behavior toward the
   RFC 9129
   ``/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf``
   tree. The first OSPFv2 and OSPFv3 operational callbacks now expose the RFC
   ``control-plane-protocol`` list, router-id, instance LSA counters, area
   SPF/ABR/ASBR/LSA counters, interface list, and neighbor list with neighbor
   address and state. The default instance name is ``default`` for both daemons.
   The OSPFv2 interface list currently exposes the first ``ospf_interface`` per
   interface key because RFC 9129 keys the list by interface name while FRR can
   hold multiple OSPFv2 interface objects for different addresses on the same
   interface.

3. Add mgmtd backend registration after there is at least a narrow set of real
   callbacks or an explicitly operational-only xpath set. ``ospfd`` and
   ``ospf6d`` register as mgmtd backend clients for
   ``/ietf-routing:routing/control-plane-protocols/control-plane-protocol``.
   ``mgmtd`` also loads the RFC OSPF modules so it can parse OSPF backend
   replies in the merged operational datastore.

4. Port operational callbacks from PR #18401 into the current model, beginning
   with OSPF instance and area statistics.

5. Convert configuration in narrow CLI-equivalent slices. For each leaf or list,
   move existing CLI behavior into a northbound callback and make the CLI set
   the YANG node. ``ietf-ospf`` should be the canonical configuration tree for
   everything RFC 9129 models; ``frr-ospfd`` and future ``frr-ospf6d`` should
   augment only FRR-specific behavior that the RFC model does not cover.

6. Add FRR-native OSPFv3 YANG only when a concrete FRR-specific augment is
   needed.

Test Coverage
-------------

``tests/topotests/ospf_topo1/test_ospf_topo1.py`` includes an RFC 9129
operational-data check for OSPFv2 and OSPFv3 router-id, area, interface, and
neighbor state. It also checks that ``ospfd`` and ``ospf6d`` register with mgmtd
and that mgmtd's operational xpath registry includes the RFC 9129 control-plane
protocol subtree.

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
