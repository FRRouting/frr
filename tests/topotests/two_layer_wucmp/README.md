# Two-Layer WECMP Nexthop Group Test

## Overview

This test validates nexthop group behavior with WECMP (Weighted Equal Cost Multi-Path) in a high-density CLOS topology. The test specifically focuses on verifying the fix for weight mismatch issues in dependent nexthop groups when interfaces go down/up.

## Problem Statement

The test addresses a bug where singleton nexthops (weight=1) were not properly matched with nexthop group nexthops (weight=255), causing improper inactive/active marking of nexthops. This led to issues where:

- Nexthops were incorrectly marked as inactive when they should remain active
- New nexthop groups were unnecessarily created instead of reusing existing ones
- Weight mismatches caused routing inconsistencies

## Topology

High-density 2-layer CLOS topology with:

```
    spine1 (AS 65100)    spine2 (AS 65100)
      |  \                 /  |
      |   \               /   |
      |    \             /    |
      |     \           /     |
      |      \         /      |
      |       \       /       |
      |        \     /        |
      |         \   /         |
   leaf1 (AS 65001)        leaf2 (AS 65002)
```

### Link Details
- **Leaf1 ↔ Spine1**: 32 parallel links (leaf1-eth0 to leaf1-eth31)
- **Leaf1 ↔ Spine2**: 32 parallel links (leaf1-eth32 to leaf1-eth63)
- **Leaf2 ↔ Spine1**: 32 parallel links (leaf2-eth0 to leaf2-eth31)
- **Leaf2 ↔ Spine2**: 32 parallel links (leaf2-eth32 to leaf2-eth63)

Total: 64 links per leaf (32 to each spine)

### BGP Configuration
- **Leaf1**: AS 65001, BGP neighbors to both spines
- **Leaf2**: AS 65002, BGP neighbors to both spines, 1000 routes injected via sharpd
- **Spine1**: AS 65100, BGP neighbors to both leafs
- **Spine2**: AS 65100, BGP neighbors to both leafs

## Test Cases

### 1. Single Link Down
**Purpose**: Test behavior when a single interface goes down

**Actions**:
- Bring down `leaf1-eth0` interface
- Verify NHG behavior

**Expected Results**:
- Same NHG ID is retained (no new NHG created)
- Exactly 1 nexthop marked as inactive
- 63 nexthops remain active (64-1)
- All routes continue to use the same NHG ID
- NHG is not marked for deletion

### 2. Single Link Up
**Purpose**: Test behavior when the downed interface comes back up

**Actions**:
- Bring up `leaf1-eth0` interface
- Verify NHG behavior

**Expected Results**:
- Same NHG ID is retained
- All 64 nexthops are active again
- All routes continue to use the same NHG ID

### 3. Partial Links Down (16 out of 32 to Spine1)
**Purpose**: Test behavior when multiple interfaces to spine1 go down simultaneously

**Actions**:
- Bring down 16 interfaces (leaf1-eth0 to leaf1-eth15) using `ip -batch`
- Verify NHG behavior

**Expected Results**:
- Same NHG ID is retained
- Exactly 16 nexthops marked as inactive
- 48 nexthops remain active (64-16)
- All routes continue to use the same NHG ID

### 4. Partial Links Up (16 out of 32 to Spine1)
**Purpose**: Test behavior when the downed interfaces come back up

**Actions**:
- Bring up 16 interfaces (leaf1-eth0 to leaf1-eth15) using `ip -batch`
- Verify NHG behavior

**Expected Results**:
- Same NHG ID is retained
- All 64 nexthops are active again
- All routes continue to use the same NHG ID

## Verification Commands

The test uses JSON-based commands for robust verification:

### Linux Kernel Commands
```bash
# Get nexthop groups
ip -j nexthop show group

# Get routes with nexthop information
ip -j route show
```

### FRR Commands
```bash
# Get detailed nexthop group information
show nexthop-group rib <id> json

# Get BGP summary
show bgp ipv4 unicast summary json
```

## Key Validation Points

1. **NHG Persistence**: The same nexthop group ID must be maintained throughout all link state changes
2. **Route Consistency**: All BGP routes must continue pointing to the same NHG ID
3. **Nexthop State**: Nexthops must be correctly marked as active/inactive based on interface state
4. **No Unnecessary NHGs**: New nexthop groups should not be created when existing ones can be reused
5. **Weight Matching**: Singleton nexthops and NHG nexthops must have consistent weight handling

## Configuration Files

- **leaf1/frr.conf**: Basic BGP configuration with 64 neighbors (32 to each spine)
- **leaf2/frr.conf**: BGP configuration with redistribute sharp for route injection
- **spine1/frr.conf**: BGP configuration as route reflector
- **spine2/frr.conf**: BGP configuration as route reflector

## Dependencies

- FRR with nexthop group support
- Linux kernel with nexthop group support
- BGP WECMP functionality
- JSON output support for verification commands

## Test Execution

```bash
# Run the specific test
python3 test_two_layer_wuecmp.py

# Run with pytest
pytest test_two_layer_wuecmp.py -v
```

## Expected Outcomes

This test validates that NHG logic in W-ECMP scenarios.
- Proper matching of singleton and NHG nexthops regardless of weight differences
- Correct active/inactive marking of nexthops during link state changes
- Prevention of unnecessary nexthop group creation
- Maintenance of routing consistency during network events

The test ensures that there is no NHG churn upon local link failures when using WECMP in high-density topologies where many parallel links exist between routers.
