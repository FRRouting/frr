#!/bin/bash

# Simple test runner for BGP VRF Import Route-Map test
# Usage: ./run_test.sh

set -e

echo "Starting BGP VRF Import Route-Map topotest..."

# Check if we're in the right directory
if [ ! -f "test_bgp_vrf_import_route_map.py" ]; then
    echo "Error: test_bgp_vrf_import_route_map.py not found in current directory"
    echo "Please run this script from the bgp_vrf_import_route_map directory"
    exit 1
fi

# Run the test with verbose output
python3 test_bgp_vrf_import_route_map.py -v

echo "Test completed successfully!"
