# BGP EVPN Three-Tier CLOS Topology Test Analysis

This document explains how `tests/topotests/bgp_evpn_three_tier_clos_topo1/test_bgp_evpn_v4_v6_vtep.py` is structured, what it validates, and how to debug it in a systematic, reusable way. It is intended for agents working on EVPN topotests and for future maintenance of similar test modules.

## 1. Test intent

The test validates a realistic EVPN/VXLAN datacenter fabric with:

- 3-tier CLOS underlay topology
- IPv4 and IPv6 underlay variants
- L2VPN EVPN overlay over BGP
- single VXLAN device (SVD) behavior on each VTEP
- L2VNI and L3VNI handling
- Type-2, Type-3, and Type-5 EVPN route learning
- external route import/export via VRF peering
- dynamic BGP neighbor behavior
- kernel route and nexthop validation
- downstream VNI kept across `import vrf`, including a destination VRF with no L3VNI
- RMAC lifecycle and flush/reinstall behavior

The file is not only a pass/fail suite; it documents the design so failures can be localized quickly and future tests can follow the same patterns.

---

## 2. Topology overview

### 2.1 Layer model

The topology is split into several layers:

- Spine layer: `spine-1`, `spine-2`
- Leaf layer: `leaf-11`, `leaf-12`, `leaf-21`, `leaf-22`
- Border ToR / ToR layer: `bordertor-11`, `bordertor-12`, `tor-21`, `tor-22`
- External layer: `ext-1`, `ext-21`
- Host layer: `host-111`, `host-121`, `host-211`, `host-221`, `host-1`

This is a realistic CLOS-style EVPN fabric: underlay connectivity is established first, the EVPN overlay carries L2 and L3 reachability, and external peers advertise Type-5 routes for interconnection.

### 2.2 VTEP and SVD model

The test emphasizes a single-VXLAN-device setup on each VTEP:

- one bridge: `br_default`
- one VXLAN device: `vxlan48`
- multiple VLANs mapped to multiple VNIs on the same device

This is central to the design and should be the first thing to verify when debugging a failure.

### 2.3 VNI plan

The key VNI model used by the test is:

- `1000111` -> VLAN `111` -> VRF `vrf2` -> L2VNI
- `1000112` -> VLAN `112` -> VRF `vrf1` -> L2VNI
- `104001` -> VLAN `4001` -> VRF `vrf1` -> L3VNI
- `104002` -> VLAN `4002` -> VRF `vrf2` -> L3VNI

This pattern is repeated across VTEPs and is the semantic foundation for most assertions in the file.

---

## 3. Test execution flow

The test uses a standard topotest fixture lifecycle:

1. Build the topology
2. Start the topology
3. Configure Linux/VXLAN state on VTEPs
4. Configure external links and VRF-specific peers
5. Load FRR configs
6. Trigger ARP/NDP to populate MAC tables
7. Run EVPN verification functions
8. Cleanup and stop the topology

This lifecycle matters because EVPN state is asynchronous. A robust test must separate setup, waiting for convergence, validation, and cleanup.

---

## 4. Functional blocks in the test file

### 4.1 BGP convergence checks

Examples:

- `test_bgp_summary_neighbor_state()`
- `test_evpn_routes_advertised()`

These assert that the control plane is up before verifying kernel or overlay state. If they fail, all later EVPN assertions are not trustworthy.

### 4.2 EVPN route and VTEP state

Examples:

- `test_evpn_vni_remote_vtep_and_hrep()`
- `test_evpn_local_vtep_ip()`
- `test_vni_state()`

These checks validate:

- remote VTEP learning
- HREP and FDB state
- VNI state in FRR and Linux
- local VTEP source IP mapping

### 4.3 L3VNI and RMAC verification

Examples:

- `test_l3vni_rmacs()`
- `test_evpn_vtep_nexthops()`
- `test_l3vni_l2vni_transition_restore()`

These verify route MAC reachability and next-hop correctness and are the most relevant to bridge-FDB flush and RMAC reinstall bugs.

### 4.4 Type-5 overlay route validation

Examples:

- `test_static_route_advertisement()`
- `test_evpn_check_overlay_route()`
- `test_evpn_rd_prefix_route_lookup()`

These ensure EVPN Type-5 routes are:

- advertised from the correct VRF
- installed in zebra/FRR RIB
- present in the Linux kernel
- correctly nexthopped with ECMP or onlink semantics

### 4.5 VRF policy and route leak behavior

Examples:

- `test_for_leaked_route_as_path()`
- `test_as_path_strip_survives_config_change()`
- `test_import_vrf_preserves_dvni_label()`
- `test_import_vrf_leaked_dvni_without_dest_l3vni()`

These tests protect against policy regressions where routes are leaked or imported with wrong path attributes, label semantics, or VNI correctness.

The two downstream-VNI tests check that a Type-5 VNI other than the hub L3VNI stays on `vxlan48` after `import vrf`. `test_import_vrf_preserves_dvni_label()` leaks `203.0.120.0/24` (VNI 900000) into `vrf2`, which has its own L3VNI. `test_import_vrf_leaked_dvni_without_dest_l3vni()` leaks `203.0.130.0/24` and `2001:db8:130::/64` (VNI 900001) into `vrf_nol3`, which has no L3VNI, so zebra borrows `vrf1`'s SVD. A non-EVPN blackhole leaked on the same path stays unlabeled. Both run on the IPv4 underlay. The IPv6 underlay is skipped until Linux 7.0: `ip6_route_check_nh_onlink()` rejects `via <IPv6 VTEP> dev vxlan48 onlink` (`RTM_NEWNEXTHOP`, "Nexthop has invalid gateway or device mismatch"), so the nexthop group and route never install. Commit b853b94e8482 removes that check. The IPv6 overlay prefix in the second test still runs; its VTEP is IPv4.

### 4.6 Dynamic neighbor tests

Examples:

- `test_ext21_dynamic_neighbor()`
- `test_ext21_dynamic_neighbor_password()`

These validate VRF-local BGP listener behavior and stale peer state after password changes.

---

## 5. Reusable helpers and their purpose

The file is much easier to maintain when treated as reusable helpers plus scenario logic.

### 5.1 Setup helpers

Examples:

- `setup_vtep()`
- `setup_bordertor_ext_connectivity()`
- `setup_ext1()`
- `setup_ext21_connectivity()`
- `setup_ext21_post_start()`

These prepare the environment and should be treated as infrastructure setup rather than feature assertions.

### 5.2 Verification helpers

Examples:

- `evpn_verify_vni_remote_vteps()`
- `evpn_verify_vni_state()`
- `evpn_verify_l3vni_remote_rmacs()`
- `evpn_verify_vrf_rib_route()`
- `evpn_verify_overlay_route_in_kernel()`
- `evpn_verify_imported_route()`
- `evpn_verify_vrf_route_labels()`
- `evpn_verify_kernel_encap_vni()`

These are the reusable verification modules. They turn CLI and kernel output into structured checks and should be kept generic enough for multiple EVPN scenarios. `evpn_verify_imported_route()` walks BGP unicast, the zebra label and VTEP, then the kernel encap id. It logs a route that has not converged yet at debug, and a real label or encap mismatch once at info, with the zebra route, kernel nexthop, and nexthop-group rib. The same helpers describe a symmetric L3VNI route (`dev` is the SVI, no label, no kernel encap) and a downstream-VNI route (`dev` is `vxlan48`, label and encap id set).

### 5.3 Policy-change helpers

Examples:

- `configure_import_vrf_test()`
- `configure_export_vrf_test()`
- route-leak update helpers

These are scenario-specific modifications. They should remain small and isolated so failing tests can be linked to a single policy change.

### 5.4 Retry logic

The file uses `topotest.run_and_expect()` and `partial()` heavily. This is the correct design for control-plane validation in EVPN because the state is asynchronous and often converges after a few seconds.

A common pattern is:

```python
check = partial(my_check_fn, router, some_arg)
_, result = topotest.run_and_expect(check, None, count=30, wait=1)
assert result is None
