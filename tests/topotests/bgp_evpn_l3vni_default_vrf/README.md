# BGP EVPN L3VNI in Default VRF Test

## Overview

This test validates the BGP EVPN L3VNI feature when configured in the default (global) VRF
instead of a custom VRF. This is a critical use case for data center interconnect (DCI)
scenarios where the global routing table needs EVPN capabilities.

## Test Topology

```
    +-------+         +---------+         +-------+
    |  R1   |---------|  Spine  |---------|  R3   |
    | AS    |  eBGP   | AS 65000|  eBGP   | AS    |
    | 65001 |         |  Underlay|        | 65003 |
    | L3VNI |         |   +EVPN  |        | No VNI|
    | 5000  |         |         |         |       |
    +-------+         +---------+         +-------+
    |  |                  |                  |  |
    c1 c2                R2                c3 c4
                       AS 65002
                       L3VNI 5000
                       (VXLAN endpoint)
```

## Key Components

### Routers
- **R1**: BGP AS 65001, L3VNI 5000, VTEP 10.0.1.1, Client subnet 192.168.1.0/24
- **R2**: BGP AS 65002, L3VNI 5000, VTEP 10.0.2.2 (VXLAN endpoint)
- **R3**: BGP AS 65003, No EVPN, Client subnet 192.168.3.0/24
- **Spine**: BGP AS 65000, eBGP underlay + EVPN route reflector

### Clients
- **c1, c2**: Behind R1 (192.168.1.0/24)
- **c3, c4**: Behind R3 (192.168.3.0/24)

## What This Test Validates

### 1. Configuration (Phase 1)
- L3VNI CLI command: `vrf DEFAULT-VRF vni 5000`
- Configuration persistence across reloads
- JSON output correctness
- Route-target configuration in EVPN address-family

### 2. RFC Compliance
- **Critical**: RD format must be `router-id:vrf_id` (e.g., "10.0.1.1:1")
- **NOT** "0:0" which breaks multi-router deployments
- This was a critical bug fixed in commit a8a40b4752

### 3. EVPN Route Advertisement (Phase 2)
- RT-5 (IP Prefix) routes properly advertised
- Correct RD in advertised routes
- Route reception across EVPN fabric
- EVPN and traditional BGP route coexistence in default VRF

### 4. Data Plane (Phase 3)
- BGP route propagation (R1 → R2 via EVPN, R1 → R3 via traditional BGP)
- Zebra RIB installation
- Kernel routing table updates
- Correct nexthop handling (VXLAN tunnel for EVPN routes)
- Bidirectional route exchange

### 5. End-to-End Connectivity (Phase 4)
- ICMP ping between clients across EVPN fabric (c1 ↔ c3)
- Verifies complete data plane functionality
- Tests VXLAN encapsulation/decapsulation

### 6. Additional Verification (Phase 5)
- VXLAN interface configuration
- No accidental VRF creation
- No L2VNI/L3VNI conflicts
- L3VNI removal and re-addition
- L3VNI removal disables advertise-all-vni when no other VNIs remain
- Invalid VNI range validation (0 and >16777215)
- Duplicate L3VNI configuration detection

## Test Execution

```bash
# From FRR build tree
cd tests/topotests
sudo pytest bgp_evpn_l3vni_default_vrf/test_bgp_evpn_l3vni_default_vrf.py -v
```

## Expected Results

All 30 tests should pass:
- 9 configuration tests (Phase 1)
- 4 EVPN route advertisement tests (Phase 2)
- 7 data plane tests (Phase 3)
- 2 connectivity tests (Phase 4)
- 8 verification tests (Phase 5)

## Key Configuration Example (R1)

```
router bgp 65001
 bgp router-id 10.0.1.1
 address-family ipv4 unicast
  network 192.168.1.0/24
 exit-address-family
 address-family l2vpn evpn
  advertise-all-vni
  advertise ipv4 unicast
  route-target import 65001:5000
  route-target export 65001:5000
 exit-address-family
 vrf DEFAULT-VRF vni 5000  ← The feature being tested
```

## VXLAN Interface Setup

The test creates VXLAN interfaces before loading router configs:

```bash
# R1 VXLAN interface
ip link add vxlan5000 type vxlan id 5000 dstport 4789 local 10.0.1.1 nolearning
ip link set vxlan5000 up

# R2 VXLAN interface
ip link add vxlan5000 type vxlan id 5000 dstport 4789 local 10.0.2.2 nolearning
ip link set vxlan5000 up
```

## Common Issues and Solutions

### Issue: Tests fail with RD "0:0"
**Solution**: Ensure `bgp_evpn_derive_auto_rd_for_vrf(bgp)` is called in the
`vrf DEFAULT-VRF vni` command implementation (fixed in commit a8a40b4752).

### Issue: Connectivity tests fail
**Solution**: Ensure client interfaces are configured AFTER routers start, with
a brief delay to allow route propagation. The setup_module() function handles this.

### Issue: No RT-5 routes advertised
**Solution**: Verify `advertise ipv4 unicast` is enabled in l2vpn evpn address-family.

### Issue: VXLAN routes not in kernel
**Solution**: Check that VXLAN interface exists and is UP before BGP starts.

## References

- [EVPN RFC 7432](https://datatracker.ietf.org/doc/html/rfc7432)
- [EVPN IP Prefix Advertisement RFC 9136](https://datatracker.ietf.org/doc/html/rfc9136)
- [BGP MPLS-Based VPNs RFC 4364](https://datatracker.ietf.org/doc/html/rfc4364)
