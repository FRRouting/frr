# BGP ECMP Backup Paths Test

## Overview

This test verifies the BGP ECMP (Equal-Cost Multi-Path) backup paths functionality in FRR. It is designed to test the enhanced `bgp_compute_backup_path()` function that supports multiple equal-cost backup paths instead of just a single backup path.

## Topology

```
                    R4 (AS 65004, MED 100) -------- 10.99.99.0/24
                   /
                  /
R1 ------------- R2 (AS 65002)
AS 65001         \
  |               \
  |                R5 (AS 65005, MED 100) -------- 10.99.99.0/24
  |
  |
  |-------------- R3 (AS 65003)
                  /\
                 /  \
                /    \
               /      \
              R6       R7
         (AS 65006)  (AS 65007)
         MED 200     MED 200
            |           |
      10.99.99.0/24  10.99.99.0/24
```

## Path Selection Logic

R1 receives the prefix `10.99.99.0/24` from four different sources:

### Best Paths (MED 100)
1. **R4 via R2** (AS path: 65002 65004, MED 100) - **Best path**
2. **R5 via R2** (AS path: 65002 65005, MED 100) - **Multipath with R4**

### Backup Paths (MED 200)
3. **R6 via R3** (AS path: 65003 65006, MED 200) - **Backup ECMP path 1**
4. **R7 via R3** (AS path: 65003 65007, MED 200) - **Backup ECMP path 2**

The paths via R4 and R5 have the same MED (100) and equal AS path length, making them equal-cost best paths (ECMP).

The paths via R6 and R7 have higher MED (200), making them less preferred. However, they are equal-cost to each other, forming **ECMP backup paths**.

## Test Cases

### 1. ✅ Verify Backup Paths Don't Appear When Feature is Unconfigured

**Critical Test**: Before enabling `install backup-path`, the test verifies:
- No paths are marked with `backup: true` in BGP table JSON output
- No `backupNexthops` field in routing table JSON output
- No 'backup' keyword in text output

This ensures the feature is truly opt-in and doesn't affect routing when disabled.

### 2. ✅ Verify ECMP Backup Paths are Installed

After enabling `install backup-path`:
- Verifies that **2 backup paths** are selected (R6 and R7 via R3)
- Confirms both are marked with `backup: true` in BGP table
- Validates equal-cost selection logic

### 3. ✅ Verify Backup Paths in Routing Table

Checks routing table integration:
- JSON output contains `backupNexthops` array with 2 entries
- Text output shows 'b' marker for backup nexthops

### 4. ✅ Verify Backup Paths in BGP Table

Checks BGP table output:
- JSON output shows `backup: true` for backup paths
- Text output contains 'backup' keyword

### 5. ✅ Test Maximum-Paths Limit

Tests that backup paths respect `maximum-paths` configuration:
- Reduces `maximum-paths` from 2 to 1
- Verifies only **1 backup path** is installed
- Confirms maxpaths enforcement works correctly

### 6. ✅ Verify Feature Disable

**Critical Test**: After running `no install backup-path`:
- All backup path markings are removed from BGP table
- `backupNexthops` field is empty in routing table
- No backup markers in text output

### 7. ✅ Verify Feature Re-enable

Tests that the feature can be toggled:
- Re-enables `install backup-path`
- Verifies backup paths reappear correctly

## Running the Test

### **IMPORTANT: Run from FRR source root directory!**

### Method 1: Using the helper script (Recommended)
```bash
cd /path/to/frr/tests/topotests/bgp_backup_ecmp
./run_test.sh
```

### Method 2: Using FRR topotest Docker framework
```bash
# Change to FRR source root first!
cd /path/to/frr

# Run the test (path is relative to tests/topotests/)
./tests/topotests/docker/frr-topotests.sh bgp_backup_ecmp/test_bgp_backup_ecmp.py -vv -s
```

### Method 3: Using pytest directly (if topotest framework is installed)
```bash
cd /path/to/frr/tests/topotests/bgp_backup_ecmp
sudo pytest test_bgp_backup_ecmp.py -s -v
```

**See RUNNING.md for detailed instructions and troubleshooting.**

## Expected Output

The test should produce output similar to:
```
test_bgp_backup_ecmp.py::test_bgp_ecmp_backup_paths
  Waiting for BGP convergence on R1
  Waiting for R1 to receive all paths for 10.99.99.0/24
  Verifying best path and multipath selection (R4 and R5 via R2)
  CRITICAL TEST: Verifying backup paths are NOT present before enabling feature
  SUCCESS: Confirmed backup paths do NOT appear when feature is unconfigured
  Enabling backup path feature on R1
  Verifying ECMP backup paths are installed (R6 and R7 via R3)
  Verifying backup paths in routing table JSON output
  Verifying backup path 'b' marker in routing table text output
  Verifying backup path 'B' marker in BGP table text output
  Testing maximum-paths limit - reducing to 1
  Verifying only 1 backup path is installed after maximum-paths change
  CRITICAL TEST: Disabling backup path feature with 'no install backup-path'
  Verifying backup paths are removed from BGP table after disabling feature
  Verifying backup paths are removed from routing table after disabling feature
  SUCCESS: All backup paths properly removed after disabling feature
  Re-enabling backup path feature to verify it works again
  SUCCESS: ECMP backup paths test completed successfully
PASSED
```

## Key Differences from Existing `bgp_backup` Test

| Feature | `bgp_backup` | `bgp_backup_ecmp` (this test) |
|---------|--------------|-------------------------------|
| Backup Paths | 1 single backup | **2 ECMP backups** |
| Topology | 4 routers | 7 routers |
| Feature Toggle Test | Partial | **Complete** (unconfigured → enabled → disabled → re-enabled) |
| Maxpaths Testing | No | **Yes** |
| Equal-Cost Backups | No | **Yes** |
| Critical "No Feature" Test | No | **Yes** (verifies no backup when unconfigured) |

## Files

- `test_bgp_backup_ecmp.py` - Main test file (517 lines)
- `r1/frr.conf` - R1 configuration (test router)
- `r2/frr.conf` - R2 configuration (transit for best paths)
- `r3/frr.conf` - R3 configuration (transit for backup paths)
- `r4/frr.conf` - R4 configuration (origin, MED 100)
- `r5/frr.conf` - R5 configuration (origin, MED 100)
- `r6/frr.conf` - R6 configuration (origin, MED 200)
- `r7/frr.conf` - R7 configuration (origin, MED 200)
