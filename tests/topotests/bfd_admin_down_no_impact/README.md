# BFD Admin Down No Impact Test

## Purpose

This test verifies that when BFD receives an Admin Down message from a peer,
it does NOT tear down protocol sessions (BGP, OSPF, PIM). This is the expected
behavior because Admin Down indicates an administrative action (e.g., manual
shutdown of BFD), not an actual connectivity failure.

## Test Scenario

1. Two routers (r1 and r2) are connected via a single link
2. BGP (eBGP), OSPF, and PIM are configured on both routers
3. BFD is enabled for BGP and OSPF neighbors
4. All protocols converge and BFD sessions come UP
5. r1 administratively shuts down its BFD peer (sending Admin Down to r2)
6. r2 receives the Admin Down notification
7. **Expected behavior**: r2's BFD state goes to DOWN, but BGP/OSPF/PIM sessions remain UP
8. r1 re-enables BFD and the session comes back up

## Topology

```
    r1 ----------- r2
      .1   s1    .2
   10.0.1.0/24

r1: AS 65001, Router-ID 1.1.1.1, Loopback 1.1.1.1/32
r2: AS 65002, Router-ID 2.2.2.2, Loopback 2.2.2.2/32
```

## Test Coverage

### Direct Peer Shutdown Test
- **BGP with BFD**: Verifies BGP session remains Established after BFD Admin Down
- **OSPF with BFD**: Verifies OSPF neighbor remains in Full state after BFD Admin Down
- **PIM with BFD**: Verifies PIM neighbor remains UP after BFD Admin Down
- **BFD state transition**: Verifies BFD correctly moves to DOWN state on Admin Down
- **BFD re-enable**: Verifies BFD can be re-enabled and session comes back UP

### Profile-Based Shutdown Test
- **BFD Profile Configuration**: Creates and applies BFD profiles to peers
- **Profile Shutdown**: Shuts down BFD profile (affects all peers using that profile)
- **Protocol Stability**: Verifies BGP/OSPF/PIM remain UP when profile is shut down
- **Profile Re-enable**: Verifies BFD recovers when profile is re-enabled

## Implementation Details

The test validates the changes made to handle BFD Admin Down:

1. **bfdd/bfd.c**: Added `notify_admin_down` parameter to `ptm_bfd_sess_dn()`
2. **bfdd/bfd.c**: When receiving Admin Down from peer, BFD notifies clients with `PTM_BFD_ADM_DOWN` status instead of `PTM_BFD_DOWN`
3. **bgpd/bgp_bfd.c**: BGP client checks for `BSS_ADMIN_DOWN` and doesn't tear down session
4. **ospfd/ospf_bfd.c**: OSPF client checks for `BSS_ADMIN_DOWN` and doesn't tear down adjacency
5. **ospf6d/ospf6_bfd.c**: OSPFv6 client checks for `BSS_ADMIN_DOWN` and doesn't tear down adjacency
6. **pimd/pim_bfd.c**: PIM client checks for `BSS_ADMIN_DOWN` and doesn't delete neighbor

## Running the Test

```bash
cd tests/topotests/bfd_admin_down_no_impact
sudo -E pytest test_bfd_admin_down_no_impact.py -s -vv
```

## Expected Output

All tests should pass:
- `test_wait_protocols_convergence`: Verifies initial convergence
- `test_bfd_peers_up`: Verifies BFD sessions come UP
- `test_bfd_admin_down_no_protocol_impact`: **Main test** - verifies protocols remain UP after direct peer shutdown
- `test_bfd_reenable`: Verifies BFD can be re-enabled after peer shutdown
- `test_bfd_profile_shutdown_no_protocol_impact`: **Profile test** - verifies protocols remain UP after profile shutdown
- `test_memory_leak`: Checks for memory leaks


