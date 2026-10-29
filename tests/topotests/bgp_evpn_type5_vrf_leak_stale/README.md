# EVPN Type-5 VRF Leak and Stale Route Tests

## Overview

This topotest reproduces stale EVPN Type-5 routes created by inter-VRF route
leaking and checks the behavior of `advertise ipv4 unicast skip-evpn-imported`.
It verifies that routes learned from EVPN can still be imported and used
locally, while preventing those EVPN-derived paths from being advertised back
into EVPN. It also checks that locally originated paths continue to be
exported, and that withdrawals and configuration changes remove stale paths.

The original regression scenario models a route chain in which an imported
route is leaked between VRFs and re-exported by two peer VTEPs. If the original
route is withdrawn, a leaked copy can otherwise keep circulating and remain
visible after its origin is gone.

## Topology

```text
                         EVPN Type-5
                    +-------------------+
                    |                   |
              +-----+-----+       +-----+-----+
              |    r1     |       |    r2     |
              | origin PE |       |  PE/VTEP  |
              +-----+-----+       +-----+-----+
                    |                   |
                    +---------+---------+
                              |
                         +----+----+
                         |   s1    |
                         +----+----+
                              |
                         +----+----+
                         |   r3    |
                         |  PE/VTEP|
                         +---------+
```

`r1`, `r2`, and `r3` share a single test switch and establish BGP EVPN
sessions. Each router has a `GREEN` VRF (VNI 101). `r2` and `r3` also have
`BLUE` (VNI 102) and `PURPLE` (VNI 103), which are used to exercise multi-step
and multi-source VRF imports. The test creates the VRFs, bridges, and VXLAN
interfaces during setup and loads each router's BGP configuration from its
`r1/`, `r2/`, or `r3/` directory.

## VTEP IP Mapping

| Router | EVPN/VTEP address | BGP AS | VRFs and VNIs |
| --- | --- | --- | --- |
| `r1` | `192.168.100.1` | `65000` | `GREEN` / `101` |
| `r2` | `192.168.100.2` | `65000` | `GREEN` / `101`, `BLUE` / `102`, `PURPLE` / `103` |
| `r3` | `192.168.100.3` | `65000` | `GREEN` / `101`, `BLUE` / `102`, `PURPLE` / `103` |

These addresses are configured on each router's `*-eth0` interface and are
used as the EVPN peer and VXLAN local VTEP addresses. Tenant BGP instances use
router IDs from the corresponding VNI subnet, such as `192.168.102.2` for
`r2`'s `BLUE` VRF.

## Configuration Highlights

- All three routers use AS `65000` and form EVPN iBGP sessions over the shared
  `192.168.100.0/24` segment.
- The base BGP instance activates the fabric peer group under `l2vpn evpn` and
  advertises all configured VNIs.
- `r1` originates Type-5 routes from static routes in `GREEN` and advertises
  IPv4 unicast into EVPN. It is the origin PE in the stale-route scenario.
- `r2` and `r3` import routes between `GREEN`, `BLUE`, and `PURPLE`. Their
  tenant BGP EVPN address families use
  `advertise ipv4 unicast skip-evpn-imported` to prevent re-export of
  EVPN-derived paths while preserving local route leaking.
- The tests add and remove routes and change VRF import or advertisement
  configuration at runtime to check withdrawal, re-advertisement, and cleanup.
- The topology creates one VRF bridge and VXLAN interface per VNI, with VXLAN
  learning disabled.

The core EVPN configuration on a tenant VRF is:

```text
address-family l2vpn evpn
 advertise ipv4 unicast skip-evpn-imported
exit-address-family
```

## Reload-based Configuration Tests

Four testcases exercise `frr-reload.py` on `r2` using its existing
`/etc/frr/frr.conf`; they do not edit that file dynamically:

- `test_skip_evpn_imported_survives_bgpd_restart` restarts `bgpd` on `r2`,
  then runs `frr-reload.py --reload /etc/frr/frr.conf` to restore the unified
  configuration. It verifies BGP reconvergence, VRF route recovery, and that
  `skip-evpn-imported` still suppresses Type-5 re-export.

- `test_skip_evpn_imported_survives_bgp_session_clear` clears BGP sessions on
  `r2`, reloads its existing config, then verifies BGP route recovery and no
  additional Type-5 re-export.

- `test_skip_evpn_imported_survives_route_refresh` reloads `r2`'s existing
  config before a soft inbound refresh, then verifies imported VRF routes and
  Type-5 suppression remain correct.

- `test_evpn_type5_vrf_leak_stale_after_origin_withdraw` reloads `r2`'s
  existing config during the first of three origin cycles, then verifies the
  origin withdrawal removes all leaked and advertised copies.

The prefix-move and route-map testcases change runtime configuration with
`vtysh`/the shared route API; they do not use `frr-reload.py`.

## Main Regression Flow

1. `r1` originates `192.168.50.1/32` as a static route in `GREEN` and exports
   it as an EVPN Type-5 route.
2. `r2` and `r3` import the route into `GREEN` and leak it between `GREEN`,
   `BLUE`, and `PURPLE`. The leaked paths are eligible for EVPN re-export.
3. The test withdraws the original route from `r1`.
4. It checks that the withdrawn route disappears from the affected VRFs and
   EVPN tables, and that `r1` does not learn the route back from a peer.

With `skip-evpn-imported` enabled, the peers must retain the imported route for
local VRF routing while suppressing its EVPN-derived path from re-export.
Locally originated Type-5 routes remain exportable.

## Test Cases

### Core functional checks and verification points

In this topology, `r2` is the primary DUT under test, `r1` is the route
origin/remote PE, and `r3` is the second PE. The tests verify control-plane
state on the DUT and, where applicable, confirm the resulting EVPN Type-5
advertisement or withdrawal on remote routers. “All routers” means `r1`,
`r2`, and `r3`.

- **`test_normal_vrf_leak_exports_with_suppress_imported_from_evpn`**
  - Local: Adds a normal static route in `r2` `BLUE`, verifies the leak into
    `r2` `GREEN`, and verifies withdrawal from both VRFs after cleanup.
  - Propagation: Verifies the leaked route reaches `r1` `GREEN` and is
    withdrawn there.

- **`test_direct_evpn_import_is_not_reexported_without_skip`**
  - Local: Disables `skip-evpn-imported` in `GREEN` on `r2` and `r3`, then
    verifies both import the route originated on `r1`.
  - Propagation: Verifies the Type-5 count stays exactly one on all routers,
    so direct imports do not create additional Type-5 advertisements.

- **`test_skip_evpn_imported_preserves_local_type5_export`**
  - Local: On `r2`, verifies the `BLUE` option, local BGP route, Zebra RIB
    entry, and kernel FIB entry.
  - Peer-side: Verifies EVPN peers on all routers and BLUE L3VNI state on
    `r2` and `r3`.
  - Propagation: Verifies the locally originated Type-5 remains present on
    all routers.

- **`test_no_skip_evpn_imported_reexports_and_reenabling_cleans_up`**
  - Local: Verifies option configuration in every tenant VRF on `r2` and
    `r3` as it is disabled and restored.
  - Propagation: Verifies the Type-5 count on all routers changes from one
    to at least two when disabled, then returns to one when re-enabled.

- **`test_skip_evpn_imported_ipv6_is_independent_from_ipv4`**
  - Local: On `r2` and `r3`, verifies disabling IPv6 suppression leaves
    IPv4 suppression enabled.
  - Propagation: No route propagation is asserted; this case verifies
    address-family configuration independence on both PEs.

- **`test_skip_evpn_imported_preserves_default_route_export`**
  - Local: Installs a default route in `r2` `BLUE` and verifies it in the
    local BGP table.
  - Propagation: Verifies the default Type-5 route is present on `r1`, `r2`,
    and `r3`.

- **`test_skip_evpn_imported_coexists_with_route_map`**
  - Local: On `r2`, verifies route-map and skip configuration independently
    across tenant VRFs; applies route-map changes through `vtysh`.
  - Propagation: On `r1`, verifies allowed/denied route filtering and Type-5
    counts as the route-map and skip option are independently removed.

The remaining testcases are described below with their route/configuration
changes and the resulting DUT or peer checks.

### Baseline route behavior

- `test_normal_vrf_leak_exports_with_suppress_imported_from_evpn` verifies
  that a locally originated static route in `r2` `BLUE` leaks into `r2`
  `GREEN` and is exported to `r1` `GREEN`; it then verifies withdrawal from
  both routers. This testcase does not independently assert suppression of an
  EVPN-imported route.

- `test_direct_evpn_import_is_not_reexported_without_skip` verifies the
  baseline behavior with `skip-evpn-imported` disabled in `GREEN` on `r2` and
  `r3`: both peers import the route from `r1`, while the Type-5 count remains
  exactly one on all routers, so neither peer adds a re-exported copy.

- `test_evpn_type5_vrf_leak_stale_after_origin_withdraw` runs the original
  stale-route regression flow for three origin/withdrawal cycles. It checks
  route presence across `GREEN`, `BLUE`, and `PURPLE` before withdrawal, then
  verifies the route and Type-5 copies disappear from all routers. During the
  first cycle it also reloads `r2`'s existing configuration.

### Configuration and reconvergence

- `test_skip_evpn_imported_survives_bgpd_restart` checks suppression after a
  `bgpd` restart.

- `test_skip_evpn_imported_survives_bgp_session_clear` checks route
  reconvergence after clearing BGP sessions.

- `test_skip_evpn_imported_survives_route_refresh` checks that a route refresh
  does not re-advertise suppressed paths.

- `test_skip_evpn_imported_scale_and_repeated_toggle` exercises a larger set
  of 1,000 Type-5 prefixes originated in `r1` `GREEN`. It verifies one copy
  per prefix on all routers, then disables and re-enables the option on `r2`
  and `r3` `BLUE` for two cycles, checking for additional copies and their
  cleanup after each toggle.

- `test_no_skip_evpn_imported_reexports_and_reenabling_cleans_up` checks that
  disabling suppression permits re-export and that enabling it again withdraws
  the EVPN-derived paths.

- `test_skip_evpn_imported_ipv6_is_independent_from_ipv4` verifies that the
  IPv6 option can be disabled on `r2` and `r3` `BLUE` while IPv4 suppression
  remains configured; it checks configuration independence rather than route
  propagation.

### Route selection and export

- `test_skip_evpn_imported_preserves_local_type5_export` checks that locally
  originated Type-5 routes remain exportable.

- `test_skip_evpn_imported_preserves_default_route_export` checks that default
  route origination remains unaffected.

- `test_skip_evpn_imported_coexists_with_route_map` checks the interaction
  between EVPN ancestry suppression and route-map filtering.

- `test_skip_evpn_imported_selectively_withdraws_evpn_derived_paths` checks
  that enabling suppression on the peer tenant VRFs reduces the Type-5 copies
  of an EVPN-derived prefix, while a separate locally originated prefix
  remains exported and installed in `r2` `BLUE`.

- `test_skip_evpn_imported_preserves_mixed_local_and_evpn_paths` checks that
  when the same prefix has an EVPN origin in `r1` `GREEN` and a local route in
  `r2` `BLUE`, enabling suppression reduces its Type-5 RD set while preserving
  the valid local BGP path in `r2` `BLUE`.

### VRF import and withdrawal cleanup

- `test_skip_evpn_imported_prefix_move_between_vrfs` checks stale Type-5
  cleanup when a prefix is withdrawn from its original `r1` `GREEN` origin
  and originated instead in `r2` `BLUE`. It verifies the old origin's RDs are
  gone and the new route propagates through the tenant VRFs and to `r1`.

- `test_skip_evpn_imported_withdrawal_is_vrf_scoped` checks that withdrawal
  after removing `GREEN` and `PURPLE` imports into `BLUE` on both peers removes
  the route from `BLUE` but retains it in `PURPLE`; it also checks that some,
  but not all, Type-5 RDs are withdrawn.

- `test_skip_evpn_imported_multiple_source_vrfs_to_purple` checks suppression
  for routes originated separately in `r1` `GREEN` and `r2` `BLUE` and imported
  into `PURPLE`. It verifies both routes arrive there and that the original
  and legitimate local-leak Type-5 paths remain on all routers.

- `test_skip_evpn_imported_suppresses_after_initial_vrf_import` checks
  suppression when the route first arrives while `PURPLE` cannot import from
  `GREEN`, then the `GREEN` import is added. It verifies the route appears in
  `PURPLE` on both peers while the Type-5 count stays at one.

- `test_skip_evpn_imported_cleans_up_after_vrf_import_removal` checks stale
  cleanup after removing the `GREEN` import into `BLUE` on both peers. It
  verifies the route disappears from `BLUE` and the Type-5 count returns to
  one.

`test_memory_leak` runs the memory-leak check for the module.

## Running the Test

Run the full module from the FRR source tree:

```bash
sudo pytest -s -v \
  tests/topotests/bgp_evpn_type5_vrf_leak_stale/test_bgp_evpn_type5_vrf_leak_stale.py
```

Run an individual testcase by adding `-k` with its name, for example:

```bash
sudo pytest -s -v \
  tests/topotests/bgp_evpn_type5_vrf_leak_stale/test_bgp_evpn_type5_vrf_leak_stale.py \
  -k test_skip_evpn_imported_survives_bgpd_restart
```

The module requires a Linux kernel version of 4.18 or newer. Pytest skips the
module during setup when the running kernel is older.
