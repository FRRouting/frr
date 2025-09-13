# BGP Graceful Restart FIB Suppression Tests

## Overview

This test suite validates the BGP Graceful Restart FIB suppression functionality implemented in FRR. The FIB suppression feature allows BGP to defer FIB (Forwarding Information Base) updates during graceful restart scenarios, improving network stability and reducing convergence time.

## Features Tested

### 1. Route FIB Install Counter (`gr_route_fib_install_cnt`)
- Tracks the number of routes waiting for FIB installation
- Incremented when `BGP_NODE_FIB_INSTALL_PENDING` flag is set
- Decremented when `BGP_NODE_FIB_INSTALL_PENDING` flag is unset
- Used to determine when graceful restart completion can proceed

### 2. BGP_NODE_FIB_INSTALL_PENDING Flag Management
- Set when a route is pending FIB installation
- Unset when FIB installation completes (success or failure)
- Properly handled during various BGP route processing scenarios

### 3. Deferred Route Processing
- Routes marked with `BGP_NODE_SELECT_DEFER` during graceful restart
- Processing deferred until graceful restart completion conditions are met
- Integration with FIB suppression logic

### 4. Zebra FIB Notifications
- Proper handling of ZAPI route installation notifications
- Route state updates based on zebra feedback
- Integration with graceful restart completion logic

## Test Topology

```
    R1 ---- R2
     \     /
      \   /
       R3
```

- **R1**: Helper router (can also be configured as restarting router)
- **R2**: Restarting router with FIB suppression enabled
- **R3**: Helper router
- All routers in AS 100 (iBGP)

## Test Cases

### 1. `test_bgp_gr_fib_suppress_basic`
**Objective**: Validate basic FIB suppression during graceful restart

**Steps**:
1. Configure GR helper mode on R1 and R3, restarting mode with FIB suppression on R2
2. Verify initial BGP convergence
3. Kill BGP on R2 (restarting router with FIB suppression)
4. Verify helper routers (R1, R3) maintain routes while R2 preserves FIB state
5. Restart BGP on R2 and verify graceful restart completion

**Expected Results**:
- Helper routers maintain stale routes during restart
- Restarting router (R2) preserves FIB state with suppression
- Graceful restart completes successfully

### 2. `test_bgp_gr_fib_suppress_route_counters`
**Objective**: Validate route counter management during graceful restart

**Steps**:
1. Configure GR helper on R1, restarting with FIB suppression on R2
2. Enable detailed debug logging
3. Trigger graceful restart on R2 and monitor counters
4. Verify counter increments/decrements on restarting router

**Expected Results**:
- `gr_route_fib_install_cnt` properly maintained on restarting router
- Counters accurately reflect pending routes during restart
- Debug logs show counter changes

### 3. `test_bgp_gr_fib_suppress_mixed_scenario`
**Objective**: Test scenarios where only restarting router has FIB suppression

**Steps**:
1. Configure R2 as restarting with FIB suppression, R1 and R3 as helpers without
2. Trigger graceful restart on R2
3. Test alternate scenario with R1 as restarting router with FIB suppression
4. Verify proper behavior in both scenarios

**Expected Results**:
- Only restarting router uses FIB suppression
- Helper routers maintain routes normally without FIB suppression
- Graceful restart works correctly regardless of which router restarts

### 4. `test_bgp_gr_fib_suppress_eor_timing`
**Objective**: Verify EOR (End-of-RIB) timing with FIB suppression

**Steps**:
1. Configure R2 as restarting router with FIB suppression
2. Trigger graceful restart and monitor EOR timing
3. Verify EOR is sent only after BGP updates are sent to helpers
4. Verify EOR is sent only after FIB install count reaches zero

**Expected Results**:
- Correct sequence: BGP Updates → FIB install count = 0 → EOR sent
- EOR not sent prematurely before updates complete
- FIB install counter properly tracked and reaches zero before EOR

## Code Changes Tested

### Core Functions
- `bgp_dest_increment_gr_fib_install_count()`
- `bgp_dest_decrement_gr_fib_install_count()`
- `bgp_process_gr_deferral_complete()`
- `bgp_do_deferred_path_selection()`

### Key Files Modified
- `frr/bgpd/bgp_route.c`: Core route processing logic
- `frr/bgpd/bgp_route.h`: Function declarations
- `frr/bgpd/bgp_zebra.c`: Zebra integration and FIB notifications
- `frr/bgpd/bgpd.h`: Data structures (`graceful_restart_info`)

### Configuration Options
- `bgp suppress-fib`: Enable FIB suppression
- `graceful-restart`: Enable graceful restart capability
- `graceful-restart-helper`: Enable helper mode

## Running the Tests

### Prerequisites
- FRR compiled with the GR FIB suppression changes
- Linux kernel version >= 4.16
- Python pytest framework
- Mininet for topology simulation

### Execution
```bash
# Run all GR FIB suppression tests
cd frr/tests/topotests/bgp_gr_fib_suppress
python -m pytest test_bgp_gr_fib_suppress.py -v

# Run specific test
python -m pytest test_bgp_gr_fib_suppress.py::test_bgp_gr_fib_suppress_basic -v

# Run with debug output
python -m pytest test_bgp_gr_fib_suppress.py -v -s --tb=short
```

### Debug Options
To enable debug logging during tests:
```bash
# Enable BGP graceful restart debugging
vtysh -c "debug bgp graceful-restart"

# Enable BGP zebra debugging  
vtysh -c "debug bgp zebra"

# Enable all BGP debugging
vtysh -c "debug bgp all"
```

## Expected Debugging Output

### Route Counter Changes
```
2024-01-01 12:00:00 [BGP] r1: GR route FIB install count incremented to 5 for ipv4 unicast (prefix: 2.2.1.0/24)
2024-01-01 12:00:01 [BGP] r1: GR route FIB install count decremented to 4 for ipv4 unicast (prefix: 2.2.1.0/24)
```

### Graceful Restart Completion
```
2024-01-01 12:00:05 [BGP] r1: Triggering GR deferral completion from FIB notification for ipv4 unicast
2024-01-01 12:00:05 [BGP] r1: All deferred routes processed, sending EOR
```

### Route Deferral
```
2024-01-01 12:00:00 [BGP] r1: Defer route 2.2.1.0/24, dest 0x12345678
```

### EOR (End-of-RIB) Timing
```
2024-01-01 12:00:03 [BGP] r2: All BGP updates sent to helpers
2024-01-01 12:00:04 [BGP] r2: FIB install count reached zero for ipv4 unicast
2024-01-01 12:00:04 [BGP] r2: Sending EOR to neighbor 192.168.1.1 for ipv4 unicast
2024-01-01 12:00:04 [BGP] r2: EOR sent after FIB install count = 0, timing verified
```

## Integration with Existing Tests

This test suite complements existing BGP graceful restart tests:
- `bgp_gr_functionality_topo1/`: Basic GR functionality
- `bgp_gr_functionality_topo2/`: Advanced GR scenarios
- `bgp_gr_functionality_topo3/`: Multi-hop GR testing
- `bgp_gr_restart_retain_routes/`: Route retention during restart

## Troubleshooting

### Common Issues
1. **Test timeouts**: Increase `GR_RESTART_TIMER` if tests timeout
2. **Route verification failures**: Check BGP configuration and convergence
3. **Counter mismatches**: Verify debug logging is enabled for detailed output

### Debug Commands
```bash
# Check BGP summary
show bgp summary

# Check specific route
show bgp ipv4 unicast 2.2.1.0/24

# Check graceful restart status
show bgp graceful-restart

# Check zebra FIB
show zebra fib summary
```

## Future Enhancements

1. **Enhanced Show Commands**: Add commands to display internal counters
2. **Performance Tests**: Measure convergence time improvements
3. **Scale Testing**: Test with larger route tables
4. **IPv6 Testing**: Expand coverage to IPv6 scenarios
5. **EVPN Integration**: Test with EVPN route types
