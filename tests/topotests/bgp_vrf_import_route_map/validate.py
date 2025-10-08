#!/usr/bin/env python3

"""
Quick validation script for BGP VRF Import Route-Map functionality.
This script can be used to manually verify the key components.
"""

import json
import sys

def validate_bgp_config(router_output):
    """Validate BGP configuration contains expected VRF import settings."""
    required_configs = [
        "import vrf route-map community-map",
        "import vrf vrf3",
        "route-map community-map permit 10",
        "set community 65000:100"
    ]
    
    for config in required_configs:
        if config not in router_output:
            print(f"❌ Missing configuration: {config}")
            return False
        else:
            print(f"✅ Found configuration: {config}")
    
    return True

def validate_bgp_json_routes(bgp_json_output):
    """Validate BGP JSON output contains routes with expected community."""
    try:
        bgp_data = json.loads(bgp_json_output)
        
        if "routes" not in bgp_data:
            print("❌ No routes found in BGP output")
            return False
        
        routes_with_community = 0
        total_routes = len(bgp_data["routes"])
        
        for prefix, route_info in bgp_data["routes"].items():
            if "paths" in route_info:
                for path in route_info["paths"]:
                    if "community" in path:
                        communities = path["community"]["string"].split()
                        if "65000:100" in communities:
                            routes_with_community += 1
                            print(f"✅ Route {prefix} has community 65000:100")
        
        if routes_with_community > 0:
            print(f"✅ Found {routes_with_community}/{total_routes} routes with community 65000:100")
            return True
        else:
            print("❌ No routes found with community 65000:100")
            return False
            
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        return False

def main():
    print("BGP VRF Import Route-Map Validation Tool")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print("Usage:")
            print("  python3 validate.py config <config_output>")
            print("  python3 validate.py routes <json_output>")
            print("  python3 validate.py --help")
            return
        
        if sys.argv[1] == "config" and len(sys.argv) > 2:
            result = validate_bgp_config(sys.argv[2])
            sys.exit(0 if result else 1)
        
        if sys.argv[1] == "routes" and len(sys.argv) > 2:
            result = validate_bgp_json_routes(sys.argv[2])
            sys.exit(0 if result else 1)
    
    # Interactive mode
    print("Interactive validation mode")
    print("This tool helps validate BGP VRF import route-map functionality")
    print("\nTo use:")
    print("1. Run: vtysh -c 'show running-config' | python3 validate.py config")
    print("2. Run: vtysh -c 'show bgp vrf vrf4 ipv4 unicast json' | python3 validate.py routes")

if __name__ == "__main__":
    main()
