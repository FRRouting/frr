# BGP VRF Import Route-Map Test

This topotest verifies the BGP VRF-to-VRF import functionality with route-map application.

## Test Objectives

1. **BGP_CONFIG_VRF_TO_VRF_IMPORT Flag Setting**: Verify that the `BGP_CONFIG_VRF_TO_VRF_IMPORT` flag is properly set when the `import vrf route-map <rmap-name>` command is configured.

2. **Route-Map Application**: Test that route-maps are correctly applied during VRF import operations, specifically setting metric values on imported routes.

3. **Metric Setting**: Verify that the route-map correctly sets metric `100` on routes imported from one VRF to another.

4. **Configuration Removal**: Test the `no import vrf route-map <rmap-name>` command and verify proper cleanup of configuration and flags.

## Topology

```
    r1 (AS 65001)          r2 (AS 65002)
    +---+                  +---+
    |   |                  |   |
    |vrf1|                 |vrf3|
    |vrf2|                 |vrf4|
    +---+------------------+---+
         192.168.1.0/24
```

- **r1**: Has VRF1 and VRF2 with networks 10.1.x.0/24 and 10.2.x.0/24
- **r2**: Has VRF3 and VRF4 with networks 10.3.x.0/24 and 10.4.x.0/24
- **Test Focus**: Import routes from VRF3 to VRF4 on r2 with route-map application

## Key Test Cases

### 1. test_bgp_vrf_import_route_map_basic
- Configure `import vrf route-map metric-map` in VRF4
- Configure `import vrf vrf3` in VRF4
- Verify BGP_CONFIG_VRF_TO_VRF_IMPORT flag is set
- Verify routes from VRF3 are imported to VRF4 with metric 100

### 2. test_bgp_vrf_import_route_map_removal
- Remove route-map configuration with `no import vrf route-map`
- Verify route-map is removed but VRF import remains
- Remove VRF import with `no import vrf vrf3`
- Verify BGP_CONFIG_VRF_TO_VRF_IMPORT flag is unset

### 3. test_bgp_vrf_import_route_map_specific_routes
- Test specific routes (10.3.1.0/24, 10.3.2.0/24) for metric values
- Verify JSON output parsing and metric validation

### 4. test_bgp_vrf_import_no_route_map
- Remove the route-map definition itself (no route-map metric-map)
- Verify routes are still imported from VRF3 to VRF4
- Verify imported routes DO NOT have metric 100 (route-map not applied)
- Tests that route-map definition removal only affects metric, not import

### 5. test_bgp_vrf_import_remove_vrf
- Remove `import vrf vrf3` command but keep `import vrf route-map metric-map`
- Verify all imported routes from VRF3 are deleted
- Verify BGP_CONFIG_VRF_TO_VRF_IMPORT flag is STILL SET (because route-map command remains)
- Tests that flag is set by route-map command, not by VRF list

### 6. test_bgp_vrf_import_remove_route_map_command
- Remove `import vrf route-map` command
- Verify BGP_CONFIG_VRF_TO_VRF_IMPORT flag is UNSET
- Tests that removing route-map command unsets the flag

## Route-Map Configuration

```
route-map metric-map permit 10
 set metric 100
```

This route-map sets metric `100` on all matching routes during the VRF import process.

## Running the Test

```bash
cd frr/tests/topotests/bgp_vrf_import_route_map
python test_bgp_vrf_import_route_map.py
```

## Expected Results

- BGP_CONFIG_VRF_TO_VRF_IMPORT flag should be set when `import vrf route-map` is configured
- Routes imported from VRF3 to VRF4 should have metric 100 when route-map is applied
- Route-map definition removal should only affect metric setting, not route import
- Removing `import vrf vrf3` should delete routes but keep flag set (if route-map command remains)
- Removing `import vrf route-map` command should unset the BGP_CONFIG_VRF_TO_VRF_IMPORT flag
- All JSON parsing and route verification should pass
