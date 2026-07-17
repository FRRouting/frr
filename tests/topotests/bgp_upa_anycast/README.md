# BGP UPA Anycast/ECMP Test Suite

## Overview

This test suite validates BGP Unreachable Prefix Announcement (UPA) in real-world data center ECMP/anycast scenarios.

**Primary Goal**: Validate multi-originator Extended Community aggregation (addresses PR documentation gap).

## Topology

```
    R1 (AS 65001)                              R2 (AS 65002)
    Client                                     Client
         │                                          │
         │ eBGP                                eBGP │
    ┌────┴──────────────┐                     ┌────┴─────┐
    │                   │                     │          │
┌───▼───┐         ┌─────▼────┐         ┌─────▼────┐     │
│ Leaf1 │         │  Leaf2   │         │  Leaf3   │◄────┘
│AS 65010│        │ AS 65011 │         │ AS 65012 │
│RID:10.255.1.1│  │RID:10.255.2.1│     │RID:10.255.3.1│
└───┬───┘         └─────┬────┘         └─────┬────┘
    │                   │                     │
    │    ┌──────────────┴──────────────┐     │
    │    │        eBGP underlay         │     │
    └────►            Spine              ◄─────┘
                   AS 65100
                 RID: 10.255.100.1
```

**eBGP Underlay**:
- Each leaf in its own AS (65010, 65011, 65012)
- Spine in AS 65100
- All Leaf-Spine connections are eBGP
- Traditional data center BGP underlay design

## Aggregate UPA Configuration

**Aggregate**: `192.168.100.0/24`

**Constituent Prefixes** (advertised by R1 and R2):
- `192.168.100.0/25` (on lo:100)
- `192.168.100.128/25` (on lo:200)

**R1 Configuration**:
- Advertises both /25 constituents to Leaf1 and Leaf2 via eBGP
- Prefixes on loopback interfaces (lo:100, lo:200)

**R2 Configuration**:
- Advertises both /25 constituents to Leaf3 via eBGP
- Prefixes on loopback interfaces (lo:100, lo:200)

**Leaf Configuration** (Leaf1, Leaf2, Leaf3):
- Learns constituent /25 prefixes via BGP from R1/R2
- Aggregates to 192.168.100.0/24 with UPA enabled
- Config: `aggregate-address 192.168.100.0/24 upa drop max-routes 10`
- **UPA Trigger**: When BGP session to R1/R2 fails, constituents become unreachable
- **UPA Origination**: Creates UPA for each unreachable /25 constituent
- **Purpose**: Tests Tier 2 (Per-Aggregate) UPA feature

## Test Scenarios

### Test 1: BGP Convergence
Verifies all BGP sessions establish properly.

### Test 2: ECMP Baseline
Validates Spine sees 2 equal-cost paths to aggregate 192.168.100.0/24.

### Test 3: Link Failure → UPA Origination
- Shutdown R1-Leaf1 link (r1-eth0)
- Leaf1 loses BGP session to R1
- Constituents 192.168.100.0/25 and 192.168.100.128/25 become unreachable
- Leaf1 originates UPA for BOTH constituents (upa:10.255.1.1:drop)
- Validates aggregate UPA origination trigger

### Test 4: ECMP Exclusion
- Spine has two paths: Leaf2 (reachable) and Leaf1 (UPA constituents)
- Spine prefers Leaf2 (reachable aggregate) over Leaf1 (UPA)
- Validates best-path selection (reachable > UPA)
- Simulates traffic shifting away from failed leaf

### Test 5: Link Recovery → UPA Withdrawal
- Restore R1-Leaf1 link (no shutdown)
- Leaf1 re-learns constituents from R1
- Leaf1 withdraws UPA for both /25 prefixes
- Validates UPA cleanup on constituent recovery

### Test 6: ECMP Restoration
- Verifies ECMP restored after recovery
- Both Leaf1 and Leaf2 have reachable aggregates again

### Test 7: Multi-AS ExtCom Aggregation ⭐
**PRIMARY TEST - Addresses PR Gap**

- Shutdown BOTH R1-Leaf1 AND R1-Leaf2 links
- Both leaves lose their BGP sessions to R1
- Leaf1 (AS 65010) loses constituents → originates UPA: `upa:10.255.1.1:drop`
- Leaf2 (AS 65011) loses constituents → originates UPA: `upa:10.255.2.1:drop`
- Spine (AS 65100) receives BOTH UPA announcements via eBGP from different ASes
- **Validates**: Spine aggregates both ExtComs in propagated path
  ```
  Extended Community: upa:10.255.1.1:drop upa:10.255.2.1:drop
  ```
- **Multi-AS**: Proves ExtCom aggregation works across different autonomous systems
- **Constituent-based**: UPA triggered by loss of /25 constituents, not aggregate itself
- Proves **true multi-AS** multi-originator tracking works (draft requirement)

### Test 8: Partial Recovery ExtCom Cleanup
- Restore Leaf1 only
- Validates ExtCom aggregation cleanup
- Only Leaf2's ExtCom should remain

## Running Tests

```bash
cd tests/topotests/bgp_upa_anycast
sudo pytest test_bgp_upa_anycast.py -v
```

## Expected Results

**All 8 tests passing (100%)**

## Key Validations

✅ ECMP/anycast in data center topology
✅ UPA origination on link failure
✅ D-bit functionality (blackhole signaling)
✅ Best-path selection (reachable > UPA)
✅ UPA withdrawal on recovery
✅ **Multi-originator ExtCom aggregation** ⭐
✅ ExtCom cleanup on partial recovery

## Documentation Impact

After this test suite passes:
- ✅ Remove: "⚠️ Multi-AS ExtCom aggregation needs additional testing"
- ✅ Add: Multi-originator ExtCom aggregation validated
- ✅ Total test count: 53 → 61 tests

## Files

- `test_bgp_upa_anycast.py` - Main test file
- `r1/`, `r2/` - Client router configs
- `leaf1/`, `leaf2/`, `leaf3/` - Leaf switch configs (UPA enabled)
- `spine/` - Spine switch config (route reflector)
