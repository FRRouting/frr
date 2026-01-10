# BGP EVPN Multihoming with IPv4/IPv6 VTEPs and EBGP Numbered Peering

## Overview

This test validates BGP EVPN Multi-Homing functionality using:
- **IPv6 VTEP addresses** for VXLAN tunnel endpoints (IPv4 support planned)
- **EBGP numbered peering** with explicit IPv6 neighbor addresses
- **Unified FRR configuration** using `service integrated-vtysh-config`
- **PIM6** for IPv6 multicast BUM traffic handling

## Topology

```
                    +--------+  +--------+
                    | spine1 |  | spine2 |
                    | AS6500 |  | AS6500 |
                    +---+----+  +----+---+
                        |  \/        |
                        |  /\        |
                    +---+----+  +----+---+
                    | leaf1  |  | leaf2  |
                    | AS6510 |  | AS6510 |
                    +---+----+  +----+---+
                        |  \/        |
                        |  /\        |
         +--------------+--++--------+---+--------------+
         |              |              |                |
      +--+---+     +----+---+     +----+---+       +----+---+
      |torm11|     |torm12  |     |torm21  |       |torm22  |
      |AS6500|     |AS6500  |     |AS6500  |       |AS6500  |
      |  2   |     |    3   |     |    4   |       |    5   |
      +--+---+     +----+---+     +----+---+       +----+---+
         |  \          /  |           |  \            /  |
         |   \        /   |           |   \          /   |
         |    \      /    |           |    \        /    |
      +--+---+ +----+---+ |        +--+---+ +------+---+ |
      |hostd11 |hostd12  |         |hostd21| |hostd22   |
      +--------+----------+         +--------+-----------+
         (Rack 1)                       (Rack 2)
```

## Key Features

### 1. IPv6 VTEP Addressing

All VXLAN tunnel endpoints currently use IPv6 addresses:
- **torm11**: `2001:db8:100::15/128`
- **torm12**: `2001:db8:100::16/128`
- **torm21**: `2001:db8:100::17/128`
- **torm22**: `2001:db8:100::18/128`

### 2. IPv6 Point-to-Point Links (/127)

All inter-router links use `/127` addressing for efficient IPv6 P2P:
- **spine1 ↔ leaf1**: `2001:db8:50::0/127` and `::1/127`
- **spine1 ↔ leaf2**: `2001:db8:51::0/127` and `::1/127`
- **spine2 ↔ leaf1**: `2001:db8:60::0/127` and `::1/127`
- **spine2 ↔ leaf2**: `2001:db8:61::0/127` and `::1/127`
- **leaf1 ↔ torm11**: `2001:db8:1::0/127` and `::1/127`
- **leaf1 ↔ torm12**: `2001:db8:2::0/127` and `::1/127`
- And so on...

### 3. AS Number Scheme (EBGP Numbered)

- **Spine layer**: AS 65001
- **Leaf layer**: AS 65101
- **TOR Rack 1**: AS 65002 (torm11), AS 65003 (torm12)
- **TOR Rack 2**: AS 65004 (torm21), AS 65005 (torm22)

### 4. BGP Configuration

All BGP sessions use:
- IPv6 neighbor addresses (EBGP numbered)
- `capability extended-nexthop` for IPv4 over IPv6 BGP sessions
- `no bgp default ipv4-unicast` (IPv6-only underlay for now)
- L2VPN EVPN address family for EVPN routes

### 5. PIM6 for IPv6 Multicast

TOR routers use PIM6 for handling BUM (Broadcast, Unknown Unicast, Multicast) traffic:
- IPv6 multicast group: `ff0e::100`
- PIM6 enabled on uplink interfaces
- Multicast termination device: `ipmr-lo`

### 6. EVPN Multihoming

Each rack has:
- Two TORs acting as PEs (Provider Edge)
- Dual-attached hosts with LACP bonds
- ES-ID (Ethernet Segment Identifier) per host
- ES system MAC for MH coordination

**Rack 1 ES Configuration:**
- ES system MAC: `44:38:39:ff:ff:01`
- hostd11 ES-ID: 1
- hostd12 ES-ID: 2

**Rack 2 ES Configuration:**
- ES system MAC: `44:38:39:ff:ff:02`
- hostd21 ES-ID: 1
- hostd22 ES-ID: 2

## Configuration Structure

### Unified FRR Configuration

Each router uses a single `frr.conf` file with:
```
frr defaults datacenter
service integrated-vtysh-config
hostname <router-name>
!
# Interface configurations
# Routing protocol configurations
!
end
```

This approach:
- Simplifies configuration management
- Matches production deployments
- Uses modern FRR best practices

## IPv6 Addressing Plan

### Loopback Addresses (VTEP)
- `2001:db8:100::/64` - VTEP loopback addresses
  - ::13 - spine1
  - ::14 - spine2
  - ::15 - torm11 (VTEP)
  - ::16 - torm12 (VTEP)
  - ::17 - torm21 (VTEP)
  - ::18 - torm22 (VTEP)

### Spine Loopbacks
- `2001:db8:200::/64` - Leaf/spine additional loopbacks
  - ::13 - leaf1
  - ::14 - leaf2

### Point-to-Point Links
- `2001:db8:1::/127` through `2001:db8:8::/127` - TOR to Leaf links
- `2001:db8:50::/127`, `2001:db8:51::/127` - Spine1 to Leaf links
- `2001:db8:60::/127`, `2001:db8:61::/127` - Spine2 to Leaf links

### SVI (Switched Virtual Interface)
- `2001:db8:45::/64` - VLAN 1000 SVI subnet
  - ::1 - Anycast gateway
  - ::2-::5 - TOR SVI addresses
  - ::11, ::12, ::21, ::22 - Host addresses

## Test Coverage

The test suite validates:

1. **ES Peering** (`test_evpn_es`)
   - Local ES peer discovery via Type-1 EAD routes
   - Remote ES PE list correctness

2. **EAD Route Updates** (`test_evpn_ead_update`)
   - Link flap handling
   - EAD route withdrawal and re-advertisement

3. **MAC Learning** (`test_evpn_mac`)
   - Local MAC sync between PEs
   - Remote MAC installation

4. **DF Election** (`test_evpn_df`)
   - Designated Forwarder role assignment
   - DF preference changes

5. **Uplink Tracking** (`test_evpn_uplink_tracking`)
   - Access port protodown on uplink failure
   - Recovery on uplink restoration

## Running the Tests

```bash
cd /work/penta-01/chirag/docker-home/tree/up/fr/frr/tests/topotests/bgp_evpn_mh_v4_v6_num

# Run all tests (fixture will run IPv6; IPv4 is currently skipped)
pytest test_evpn_mh_v4_v6_numbered.py -v

# Run specific test
pytest test_evpn_mh_v4_v6_numbered.py::test_evpn_es -v

# Run with debug output
pytest test_evpn_mh_v4_v6_numbered.py -v -s
```

## Requirements

- **FRR**: 8.1 or later (with mgmtd support)
- **Kernel**: 4.19 or later (for MH support)
- **IPv6**: Fully enabled with forwarding
- **Modules**: VXLAN, bridge, bonding, PIM6

## Key Differences from Original test_evpn_mh

1. **IPv6 VTEP first**: Uses IPv6 for VXLAN tunnel endpoints (IPv4 VTEPs can be added later)
2. **EBGP Numbered**: Explicit IPv6 neighbor addresses instead of unnumbered
3. **Unified Config**: Single `frr.conf` per router instead of separate daemon configs
4. **PIM6**: Uses IPv6 PIM instead of IPv4 PIM
5. **IPv6 Multicast**: Uses `ff0e::100` instead of `239.1.1.100`
6. **Pytest Fixture**: `tgen_and_ip_version` parametrizes the test for `"ipv4"` / `"ipv6"` underlay (IPv4 currently skipped)
7. **Critical Fixes**: Includes IPv6 forwarding and DAD configuration before daemon startup

## Known Issues and Workarounds

### IPv6 DAD (Duplicate Address Detection)

DAD is disabled globally and per-interface to prevent address configuration delays:
```python
router.run("sysctl -w net.ipv6.conf.all.accept_dad=0")
router.run("sysctl -w net.ipv6.conf.all.dad_transmits=0")
```

### mgmtd Requirement

Modern FRR requires mgmtd to be loaded before other daemons:
```python
router.load_config(TopoRouter.RD_MGMTD, "")
```

### IPv6 Forwarding

Must be enabled BEFORE starting FRR daemons:
```python
router.run("sysctl -w net.ipv6.conf.all.forwarding=1")
```

## Debugging

### View BGP EVPN ES Information
```bash
vtysh -c "show bgp l2vpn evpn es"
vtysh -c "show bgp l2vpn evpn es detail"
```

### View MAC Addresses
```bash
vtysh -c "show evpn mac vni 1000"
```

### View BGP IPv6 Neighbors
```bash
vtysh -c "show bgp ipv6 unicast summary"
```

### View EVPN Routes
```bash
vtysh -c "show bgp l2vpn evpn route"
```

### View PIM6 Status
```bash
vtysh -c "show ipv6 pim interface"
vtysh -c "show ipv6 mroute"
```

## References

- Original test: `tests/topotests/bgp_evpn_mh/`
- IPv6 VTEP reference: `tests/topotests/bgp_evpn_three_tier_clos_topo1/`
- FRR EVPN MH documentation: https://docs.frrouting.org/en/latest/evpn.html

## Authors

- Original test: Anuradha Karuppiah (Cumulus Networks)
- IPv4/IPv6 VTEP and EBGP numbered adaptation: Chirag Shah (Nvidia), 2025

## License

SPDX-License-Identifier: ISC
