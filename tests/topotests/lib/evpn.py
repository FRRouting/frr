#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# evpn.py
# Library of helper functions for EVPN testing
#
# Copyright (c) 2025 by Cisco Systems Inc.
#

"""
evpn.py: Library of helper functions for EVPN testing
"""

import json
import sys
from lib.topolog import logger


def evpn_verify_vni_remote_vteps(router, vni_list, expected_vteps):
    """
    Helper function to verify remote VTEPs for given L2VNIs.

    This function performs comprehensive verification of remote VTEPs:
    1. Checks remote VTEPs are learned via EVPN control plane (IMET route info
       synced in zebra using "show evpn vni <vni> json")
    2. Verifies HREP entries exist in bridge FDB ("bridge -j fdb show") with:
       - MAC address is all zeros (00:00:00:00:00:00)
       - src_vni field matches one of the VNIs in vni_list
       - Destination IP matches expected VTEP

    Parameters
    ----------
    * `router`: router object to check
    * `vni_list`: list of VNI strings/integers to verify (e.g., ["1000111", "1000112"])
    * `expected_vteps`: list of expected remote VTEP IP addresses (IPv4 or IPv6)

    Returns
    -------
    None on success, error string on failure (for use with topotest.run_and_expect)

    Usage
    -----
    from functools import partial
    from lib import topotest
    from lib.evpn import evpn_verify_vni_remote_vteps

    expected_remote_vteps = ["2006:20:20::1", "2006:20:20::2", "2006:20:20::30"]
    vni_list = ["1000111", "1000112"]
    test_func = partial(evpn_verify_vni_remote_vteps, router, vni_list, expected_remote_vteps)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"Remote VTEP verification failed: {result}"
    """
    # Normalize VNI list to integers for consistent comparison
    vni_list = [int(vni) for vni in vni_list]

    for vni in vni_list:
        # Get VNI details in JSON format
        output = router.vtysh_cmd(f"show evpn vni {vni} json", isjson=True)

        if not output:
            return f"No output for VNI {vni}"

        # Check if VNI is L2
        vni_type = output.get("type")
        if vni_type != "L2":
            return f"VNI {vni} is not L2VNI"

        # Check if remoteVteps key exists
        if "remoteVteps" not in output:
            return f"VNI {vni}: 'remoteVteps' key not found in output"

        # Extract remote VTEP IPs
        remote_vteps = output.get("remoteVteps", [])
        remote_vtep_ips = [vtep["ip"] for vtep in remote_vteps if "ip" in vtep]

        logger.info(
            f"{router.name} VNI {vni}: Found {len(remote_vtep_ips)} remote VTEPs: {remote_vtep_ips}"
        )

        # Check if all expected VTEPs are present
        for expected_vtep in expected_vteps:
            if expected_vtep not in remote_vtep_ips:
                return (
                    f"VNI {vni}: Expected remote VTEP {expected_vtep} not found. "
                    f"Found: {remote_vtep_ips}"
                )

        # Check if there are any unexpected VTEPs
        for remote_vtep_ip in remote_vtep_ips:
            if remote_vtep_ip not in expected_vteps:
                return (
                    f"VNI {vni}: Unexpected remote VTEP {remote_vtep_ip} found. "
                    f"Expected: {expected_vteps}"
                )

        # Verify numRemoteVteps matches
        num_remote_vteps = output.get("numRemoteVteps", 0)
        if num_remote_vteps != len(expected_vteps):
            return (
                f"VNI {vni}: numRemoteVteps mismatch. "
                f"Expected: {len(expected_vteps)}, Found: {num_remote_vteps}"
            )

    # Verify HREP entries in bridge FDB for remote VTEPs
    logger.info(f"{router.name}: Checking bridge FDB for HREP entries")
    fdb_output = router.run("bridge -j fdb show")
    try:
        fdb_entries = json.loads(fdb_output)
    except json.JSONDecodeError:
        return f"Failed to parse bridge FDB output as JSON"

    # Build dictionary: src_vni -> [list of dst IPs] for MAC all zeros entries
    vni_to_dsts = {}
    for entry in fdb_entries:
        # HREP entries have MAC all zeros, dst, and src_vni fields
        if (
            entry.get("mac") == "00:00:00:00:00:00"
            and "dst" in entry
            and "src_vni" in entry
        ):
            src_vni = entry["src_vni"]  # Already an integer from JSON
            dst_ip = entry["dst"]

            if src_vni not in vni_to_dsts:
                vni_to_dsts[src_vni] = []
            vni_to_dsts[src_vni].append(dst_ip)

            logger.debug(
                f"{router.name}: Found HREP entry - VNI {src_vni} -> VTEP {dst_ip}"
            )

    logger.info(
        f"{router.name}: Bridge FDB HREP entries by VNI: {dict((k, len(v)) for k, v in vni_to_dsts.items())}"
    )

    # Verify each L2VNI has HREP entries for all expected VTEPs
    for vni in vni_list:
        if vni not in vni_to_dsts:
            return (
                f"Bridge FDB: No HREP entries found for VNI {vni}. "
                f"Available VNIs: {list(vni_to_dsts.keys())}"
            )

        fdb_vteps = vni_to_dsts[vni]

        # Check all expected VTEPs are present for this VNI
        for expected_vtep in expected_vteps:
            if expected_vtep not in fdb_vteps:
                return (
                    f"Bridge FDB: VNI {vni} missing HREP entry for VTEP {expected_vtep}. "
                    f"Found VTEPs: {fdb_vteps}"
                )

    return None


def evpn_verify_vni_vtep_src_ip(
    router, expected_vtep_ip, vni_list, vni_type="L2", vxlan_device=None
):
    """
    Helper function to verify VTEP source IP is correctly configured in kernel and FRR.

    This function verifies that the expected VTEP source IP is correctly configured in:
    1. Kernel VXLAN device (via "ip -d link show")
    2. FRR interface view (via "show interface <vxlan_device> json") - vtepIp field
    3. FRR Zebra (via "show evpn vni <vni> json")
    4. FRR BGP (via "show bgp l2vpn evpn vni <vni> json")

    Parameters
    ----------
    * `router`: router object to check
    * `expected_vtep_ip`: expected VTEP source IP address (IPv4 or IPv6 string)
    * `vni_list`: list of VNI strings/integers to verify (e.g., ["1000111", "1000112"])
    * `vni_type`: "L2" or "L3" to determine which JSON field to check (default: "L2")
    * `vxlan_device`: kernel VXLAN device name to check (e.g., "vxlan48", "vxlan99").
                      If None, kernel check is skipped.

    Returns
    -------
    None on success, error string on failure (for use with topotest.run_and_expect)

    Usage
    -----
    from functools import partial
    from lib import topotest
    from lib.evpn import evpn_verify_vni_vtep_src_ip

    # For L2 VNIs
    vni_list = ["1000111", "1000112"]
    test_func = partial(
        evpn_verify_vni_vtep_src_ip,
        router,
        "2006:20:20::1",
        vni_list,
        vni_type="L2",
        vxlan_device="vxlan48"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"VTEP source IP verification failed: {result}"

    # For L3 VNIs
    l3vni_list = ["104001", "104002"]
    test_func = partial(
        evpn_verify_vni_vtep_src_ip,
        router,
        "2006:20:20::1",
        l3vni_list,
        vni_type="L3",
        vxlan_device="vxlan99"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"VTEP source IP verification failed: {result}"
    """

    # Check kernel VXLAN device if provided
    if vxlan_device:
        kernel_output = router.run(f"ip -d link show {vxlan_device}")
        check_src_ip = f"local {expected_vtep_ip}"

        if check_src_ip not in kernel_output:
            return (
                f"Kernel VTEP src IP verification failed for {vxlan_device}. "
                f"Expected 'local {expected_vtep_ip}' not found in output"
            )

        logger.info(
            f"{router.name}: Kernel VTEP src IP correct for {vxlan_device}: {expected_vtep_ip}"
        )

        # Check FRR interface view matches kernel
        frr_intf_output = router.vtysh_cmd(
            f"show interface {vxlan_device} json", isjson=True
        )

        if not frr_intf_output:
            return f"No output from 'show interface {vxlan_device} json'"

        if not isinstance(frr_intf_output, dict):
            return (
                f"Invalid output format from 'show interface {vxlan_device} json', "
                f"expected dict, got {type(frr_intf_output)}"
            )

        # The output is a dict with interface name as key
        if vxlan_device not in frr_intf_output:
            return (
                f"Interface {vxlan_device} not found in FRR interface output. "
                f"Available interfaces: {list(frr_intf_output.keys())}"
            )

        intf_data = frr_intf_output[vxlan_device]
        frr_vtep_ip = intf_data.get("vtepIp")

        if not frr_vtep_ip:
            return (
                f"Field 'vtepIp' not found in FRR interface output for {vxlan_device}"
            )

        if frr_vtep_ip != expected_vtep_ip:
            return (
                f"FRR interface VTEP IP mismatch for {vxlan_device}. "
                f"Expected: {expected_vtep_ip}, Found: {frr_vtep_ip}"
            )

        logger.info(
            f"{router.name}: FRR interface VTEP IP correct for {vxlan_device}: {frr_vtep_ip}"
        )

    # Check FRR Zebra for each VNI
    for vni in vni_list:
        output = router.vtysh_cmd(f"show evpn vni {vni} json", isjson=True)

        if not output:
            return f"VNI {vni}: No output from 'show evpn vni {vni} json'"

        # Determine which JSON field to check based on VNI type
        if vni_type == "L2":
            vtep_ip_field = "vtepIp"
        elif vni_type == "L3":
            vtep_ip_field = "localVtepIp"
        else:
            return f"VNI {vni}: Invalid VNI type '{vni_type}'. Must be 'L2' or 'L3'"

        if vtep_ip_field not in output:
            return f"VNI {vni}: Field '{vtep_ip_field}' not found in Zebra output"

        vtep_ip = output[vtep_ip_field]
        if vtep_ip != expected_vtep_ip:
            return (
                f"VNI {vni}: Zebra VTEP src IP mismatch. "
                f"Expected: {expected_vtep_ip}, Found: {vtep_ip}"
            )

        logger.info(
            f"{router.name}: Zebra VTEP src IP correct for VNI {vni}: {vtep_ip}"
        )

    # Check FRR BGP for each VNI
    for vni in vni_list:
        bgp_output = router.vtysh_cmd(
            f"show bgp l2vpn evpn vni {vni} json", isjson=True
        )

        if not bgp_output:
            return f"VNI {vni}: No output from 'show bgp l2vpn evpn vni {vni} json'"

        if "originatorIp" not in bgp_output:
            return f"VNI {vni}: Field 'originatorIp' not found in BGP output"

        bgp_vtep_ip = bgp_output["originatorIp"]
        if bgp_vtep_ip != expected_vtep_ip:
            return (
                f"VNI {vni}: BGP VTEP src IP (originatorIp) mismatch. "
                f"Expected: {expected_vtep_ip}, Found: {bgp_vtep_ip}"
            )

        logger.info(
            f"{router.name}: BGP VTEP src IP correct for VNI {vni}: {bgp_vtep_ip}"
        )

    return None


def evpn_verify_vni_state(router, vni_list, vni_type="L2", expected_state="Up"):
    """
    Helper function to verify VNI state and configuration.

    This function checks that VNIs are properly configured and operational by
    querying "show evpn vni <vni> json". For L2 VNIs, it additionally verifies
    remoteVteps are present.

    Parameters
    ----------
    * `router`: router object to check
    * `vni_list`: list of VNI strings/integers to verify (e.g., ["1000111", "1000112"])
    * `vni_type`: "L2" or "L3" to determine which checks to perform (default: "L2")
    * `expected_state`: expected VNI state (default: "Up")

    Returns
    -------
    None on success, error string on failure (for use with topotest.run_and_expect)

    Usage
    -----
    from functools import partial
    from lib import topotest
    from lib.evpn import evpn_verify_vni_state

    # For L2 VNIs
    l2vni_list = ["1000111", "1000112"]
    test_func = partial(
        evpn_verify_vni_state,
        router,
        l2vni_list,
        vni_type="L2"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"VNI state verification failed: {result}"

    # For L3 VNIs
    l3vni_list = ["104001", "104002"]
    test_func = partial(
        evpn_verify_vni_state,
        router,
        l3vni_list,
        vni_type="L3"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"L3 VNI state verification failed: {result}"
    """

    for vni in vni_list:
        # Get VNI details in JSON format
        output = router.vtysh_cmd(f"show evpn vni {vni} json", isjson=True)

        if not output:
            return f"VNI {vni}: No output from 'show evpn vni {vni} json'"

        # Check if VNI exists
        if "vni" not in output:
            return (
                f"VNI {vni}: 'vni' field not found in output, VNI may not be configured"
            )

        # Verify VNI number matches
        if str(output["vni"]) != str(vni):
            return (
                f"VNI {vni}: VNI number mismatch. "
                f"Expected: {vni}, Found: {output['vni']}"
            )

        # Check VNI state if available
        if "state" in output:
            vni_state = output["state"]
            if vni_state != expected_state:
                return (
                    f"VNI {vni}: State mismatch. "
                    f"Expected: {expected_state}, Found: {vni_state}"
                )
            logger.info(f"{router.name}: VNI {vni} state is {vni_state}")

        # For L2 VNIs, perform additional checks
        if vni_type == "L2":
            # Check if this is indeed an L2 VNI
            if "type" in output:
                if output["type"] != "L2":
                    return (
                        f"VNI {vni}: Expected L2 VNI but found type: {output['type']}"
                    )

            # Check remoteVteps field exists
            if "remoteVteps" not in output:
                return f"VNI {vni}: 'remoteVteps' field not found in output"

            # Check numRemoteVteps field exists and is valid
            if "numRemoteVteps" not in output:
                return f"VNI {vni}: 'numRemoteVteps' field not found in output"

            num_remote_vteps = output.get("numRemoteVteps", 0)
            remote_vteps = output.get("remoteVteps", [])
            actual_remote_vtep_count = len(remote_vteps)

            # Verify numRemoteVteps matches actual count
            if num_remote_vteps != actual_remote_vtep_count:
                return (
                    f"VNI {vni}: numRemoteVteps mismatch. "
                    f"Field says {num_remote_vteps}, but found {actual_remote_vtep_count} entries"
                )

            logger.info(
                f"{router.name}: VNI {vni} (L2) has {num_remote_vteps} remote VTEPs"
            )

            # Log remote VTEP IPs if available
            if remote_vteps:
                remote_vtep_ips = [vtep.get("ip", "unknown") for vtep in remote_vteps]
                logger.info(f"{router.name}: VNI {vni} remote VTEPs: {remote_vtep_ips}")

        # For L3 VNIs, perform L3-specific checks
        elif vni_type == "L3":
            # Check if this is indeed an L3 VNI
            if "type" in output:
                if output["type"] != "L3":
                    return (
                        f"VNI {vni}: Expected L3 VNI but found type: {output['type']}"
                    )

            # Check for VRF association
            if "vrf" in output:
                vrf_name = output["vrf"]
                logger.info(
                    f"{router.name}: VNI {vni} (L3) associated with VRF {vrf_name}"
                )
            else:
                logger.warning(f"{router.name}: VNI {vni} (L3) has no VRF association")

            # Check for L3VNI-specific fields
            if "routerMac" in output:
                router_mac = output["routerMac"]
                logger.info(f"{router.name}: VNI {vni} (L3) router MAC: {router_mac}")

        else:
            return f"VNI {vni}: Invalid VNI type '{vni_type}'. Must be 'L2' or 'L3'"

    return None


def evpn_verify_bgp_vni_state(
    router, vni_list, expected_originator_ip=None, expected_fields=None
):
    """
    Helper function to verify BGP L2VNI state and configuration.

    This function checks the BGP EVPN control plane state for L2VNIs by querying
    'show bgp l2vpn evpn vni <vni> json'. It validates:
    - VNI is configured in BGP
    - Route Distinguisher (RD) is present
    - Originator IP (VTEP source IP) matches expected value if provided
    - VNI is installed in kernel (inKernel field, logs warning if False)
    - Additional fields if specified via expected_fields parameter

    Parameters
    ----------
    * `router`: router object to check
    * `vni_list`: list of VNI strings/integers to verify (e.g., ["1000111", "1000112"])
    * `expected_originator_ip`: expected VTEP originator IP address (optional, for backward compatibility)
    * `expected_fields`: dict of field names and expected values to validate (optional)
      Example: {"advertiseGatewayMacip": "Enabled", "inKernel": True}

    Returns
    -------
    None on success, error string on failure (for use with topotest.run_and_expect)

    Usage
    -----
    from functools import partial
    from lib import topotest
    from lib.evpn import evpn_verify_bgp_vni_state

    # Basic check - just verify VNIs exist in BGP
    vni_list = ["1000111", "1000112"]
    test_func = partial(
        evpn_verify_bgp_vni_state,
        router,
        vni_list
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"BGP VNI state verification failed: {result}"

    # With originator IP validation (backward compatible)
    test_func = partial(
        evpn_verify_bgp_vni_state,
        router,
        vni_list,
        expected_originator_ip="2006:20:20::1"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"BGP VNI state verification failed: {result}"

    # With flexible field validation (L2VNI)
    test_func = partial(
        evpn_verify_bgp_vni_state,
        router,
        vni_list,
        expected_fields={
            "originatorIp": "2006:20:20::1",
            "advertiseGatewayMacip": "Enabled",
            "inKernel": True
        }
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"BGP VNI state verification failed: {result}"

    # For L3VNI with system IP/MAC (if BGP VNI command supports L3VNI)
    test_func = partial(
        evpn_verify_bgp_vni_state,
        router,
        l3vni_list,
        expected_fields={
            "systemIp": "6.0.0.30",
            "systemMac": "00:00:10:00:1e:07"
        }
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"BGP L3VNI state verification failed: {result}"
    """

    # Normalize VNI list to integers for consistent comparison
    vni_list = [int(vni) for vni in vni_list]

    for vni in vni_list:
        # Get BGP L2VPN EVPN VNI state
        bgp_output = router.vtysh_cmd(
            f"show bgp l2vpn evpn vni {vni} json", isjson=True
        )

        if not bgp_output:
            return f"VNI {vni}: No output from 'show bgp l2vpn evpn vni {vni} json'"

        if not isinstance(bgp_output, dict):
            return (
                f"VNI {vni}: Invalid BGP VNI output format, "
                f"expected dict, got {type(bgp_output)}"
            )

        # Check basic VNI fields
        bgp_vni = bgp_output.get("vni")
        if bgp_vni is None:
            return f"VNI {vni}: Field 'vni' not found in BGP output"

        if int(bgp_vni) != vni:
            return (
                f"VNI {vni}: VNI number mismatch in BGP. "
                f"Expected: {vni}, Found: {bgp_vni}"
            )

        # Check if VNI is installed in kernel
        in_kernel = bgp_output.get("inKernel")
        if in_kernel is not None:
            if in_kernel is True:
                logger.info(f"{router.name}: VNI {vni} is installed in kernel")
            else:
                logger.warning(
                    f"{router.name}: VNI {vni} is NOT installed in kernel (inKernel: {in_kernel})"
                )

        # Check Route Distinguisher (RD)
        rd = bgp_output.get("rd")
        if not rd:
            return f"VNI {vni}: Route Distinguisher (RD) not found in BGP output"

        logger.info(f"{router.name}: VNI {vni} BGP RD: {rd}")

        # Check Originator IP (VTEP source IP)
        originator_ip = bgp_output.get("originatorIp")
        if not originator_ip:
            return f"VNI {vni}: Originator IP not found in BGP output"

        logger.info(f"{router.name}: VNI {vni} BGP Originator IP: {originator_ip}")

        # Validate originator IP if expected value provided (backward compatibility)
        if expected_originator_ip is not None:
            if originator_ip != expected_originator_ip:
                return (
                    f"VNI {vni}: Originator IP mismatch. "
                    f"Expected: {expected_originator_ip}, Found: {originator_ip}"
                )

        # Validate additional expected fields if provided
        if expected_fields is not None:
            for field_name, expected_value in expected_fields.items():
                actual_value = bgp_output.get(field_name)

                if actual_value is None:
                    return (
                        f"VNI {vni}: Field '{field_name}' not found in BGP output. "
                        f"Expected: {expected_value}"
                    )

                if actual_value != expected_value:
                    return (
                        f"VNI {vni}: Field '{field_name}' mismatch. "
                        f"Expected: {expected_value}, Found: {actual_value}"
                    )

                logger.info(
                    f"{router.name}: VNI {vni} {field_name}: {actual_value} (validated)"
                )

        # Log optional informative fields if present
        adv_gw_macip = bgp_output.get("advertiseGatewayMacip")
        if adv_gw_macip is not None:
            logger.info(
                f"{router.name}: VNI {vni} advertiseGatewayMacip: {adv_gw_macip}"
            )

        adv_svi_macip = bgp_output.get("advertiseSviMacIp")
        if adv_svi_macip is not None:
            logger.info(f"{router.name}: VNI {vni} advertiseSviMacIp: {adv_svi_macip}")

    return None


def evpn_verify_route_advertisement(
    router, min_type2=None, min_type3=None, min_type5=None
):
    """
    Helper function to verify EVPN routes are advertised.

    This function checks that EVPN routes (Type-2, Type-3, Type-5) are present
    in BGP by querying "show bgp l2vpn evpn route json".

    Parameters
    ----------
    * `router`: router object to check
    * `min_type2`: minimum number of Type-2 (MAC/IP) routes expected (default: None, no check)
    * `min_type3`: minimum number of Type-3 (IMET) routes expected (default: None, no check)
    * `min_type5`: minimum number of Type-5 (IP Prefix) routes expected (default: None, no check)

    Returns
    -------
    None on success, error string on failure (for use with topotest.run_and_expect)

    Usage
    -----
    from functools import partial
    from lib import topotest
    from lib.evpn import evpn_verify_route_advertisement

    # Check that at least some Type-3 routes exist (VTEPs typically advertise these)
    test_func = partial(
        evpn_verify_route_advertisement,
        router,
        min_type3=1
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"EVPN route advertisement check failed: {result}"

    # Check for specific minimum counts of multiple route types
    test_func = partial(
        evpn_verify_route_advertisement,
        router,
        min_type2=5,
        min_type3=2,
        min_type5=10
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"EVPN route advertisement check failed: {result}"
    """

    # Get EVPN routes
    output = router.vtysh_cmd("show bgp l2vpn evpn route json", isjson=True)

    if not output:
        return "No output from 'show bgp l2vpn evpn route json'"

    if not isinstance(output, dict):
        return f"Invalid EVPN route output format, expected dict, got {type(output)}"

    # Parse and count EVPN route types
    # Route keys format: [type]:[0]:[length]:[prefix/mac/ip]
    # The JSON structure is nested: RD keys contain route keys
    type2_routes = []  # MAC/IP Advertisement
    type3_routes = []  # Inclusive Multicast Ethernet Tag (IMET)
    type5_routes = []  # IP Prefix routes

    for rd_key, rd_data in output.items():
        # Skip non-dict entries (like "numPrefix")
        if not isinstance(rd_data, dict):
            continue

        # Parse route keys within each RD
        for route_key in rd_data.keys():
            if route_key.startswith("[2]:"):
                type2_routes.append(route_key)
            elif route_key.startswith("[3]:"):
                type3_routes.append(route_key)
            elif route_key.startswith("[5]:"):
                type5_routes.append(route_key)

    # Log current counts
    logger.info(
        f"{router.name}: EVPN routes - Type-2: {len(type2_routes)}, "
        f"Type-3: {len(type3_routes)}, Type-5: {len(type5_routes)}"
    )

    # Check Type-2 routes if minimum specified
    if min_type2 is not None:
        if len(type2_routes) < min_type2:
            return (
                f"Type-2 (MAC/IP) routes insufficient. "
                f"Expected at least {min_type2}, found {len(type2_routes)}"
            )

    # Check Type-3 routes if minimum specified
    if min_type3 is not None:
        if len(type3_routes) < min_type3:
            return (
                f"Type-3 (IMET) routes insufficient. "
                f"Expected at least {min_type3}, found {len(type3_routes)}"
            )

    # Check Type-5 routes if minimum specified
    if min_type5 is not None:
        if len(type5_routes) < min_type5:
            return (
                f"Type-5 (IP Prefix) routes insufficient. "
                f"Expected at least {min_type5}, found {len(type5_routes)}"
            )

    return None


def evpn_verify_l3vni_nexthops(router, l3vni_list, expected_remote_vteps):
    """
    Helper function to verify L3VNI EVPN next-hops from remote VTEPs.

    This function verifies that for each L3VNI, FRR has learned next-hops
    from the expected remote VTEPs via the EVPN control plane.

    The function parses the JSON output of 'show evpn next-hops vni <vni> json' which has
    the structure:
    {
      "<vtep_ip1>": {
        "ip": "<vtep_ip1>",
        "rmac": "<mac>",
        ...
      },
      ...
    }

    Parameters
    ----------
    * `router`: router object to check
    * `l3vni_list`: list of L3VNI strings to verify (e.g., ["104001", "104002"])
    * `expected_remote_vteps`: list of expected remote VTEP IPs (IPv4 or IPv6 strings)

    Returns
    -------
    None on success, error string on failure (for use with topotest.run_and_expect)

    Usage
    -----
    from functools import partial
    from lib import topotest
    from lib.evpn import evpn_verify_l3vni_nexthops

    l3vni_list = ["104001", "104002"]
    expected_remote_vteps = ["2006:20:20::1", "2006:20:20::2", "2006:20:20::31"]

    test_func = partial(
        evpn_verify_l3vni_nexthops,
        router,
        l3vni_list,
        expected_remote_vteps
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"L3VNI next-hop verification failed: {result}"
    """
    import json
    import ipaddress

    for vni in l3vni_list:
        # Get JSON output to parse next-hop list
        json_output = router.vtysh_cmd(
            f"show evpn next-hops vni {vni} json", isjson=True
        )

        if not json_output:
            return (
                f"VNI {vni}: No JSON output from 'show evpn next-hops vni {vni} json'"
            )

        if not isinstance(json_output, dict):
            return f"VNI {vni}: Invalid JSON output format, expected dict, got {type(json_output)}"

        # Extract VTEP IPs from next-hop entries (keys are IP addresses)
        # Skip metadata keys like "numNextHops" by validating IP addresses
        found_vtep_ips = set()
        for key in json_output.keys():
            try:
                # Validate if key is a valid IPv4 or IPv6 address
                ipaddress.ip_address(key)
                found_vtep_ips.add(key)
            except ValueError:
                # Skip non-IP keys (e.g., "numNextHops")
                continue

        if not found_vtep_ips:
            return f"VNI {vni}: No next-hops found in JSON output (expected {len(expected_remote_vteps)} remote VTEPs)"

        logger.info(f"{router.name}: VNI {vni} has {len(found_vtep_ips)} next-hops")

        # Verify each expected remote VTEP is present as a next-hop
        for expected_vtep in expected_remote_vteps:
            if expected_vtep not in found_vtep_ips:
                return (
                    f"VNI {vni}: Expected remote VTEP {expected_vtep} not found in next-hop table. "
                    f"Expected VTEPs: {expected_remote_vteps}, Found VTEPs: {sorted(found_vtep_ips)}"
                )

        logger.info(
            f"{router.name}: VNI {vni} has next-hops from all expected remote VTEPs"
        )

        # Log details for each next-hop
        for vtep_ip in sorted(found_vtep_ips):
            nexthop_data = json_output.get(vtep_ip, {})
            rmac = nexthop_data.get("routerMac", "N/A")
            logger.debug(f"{router.name}: VNI {vni} next-hop {vtep_ip} (RMAC: {rmac})")

    # All VNIs verified successfully
    return None


def evpn_verify_l3vni_remote_nexthops(
    tgen, vtep_routers, l3vni_list, vxlan_device="vxlan48"
):
    """
    Helper function to verify L3VNI EVPN next-hops across all VTEPs in a topology.

    This function:
    1. Discovers VTEP IP addresses from the specified VXLAN device (IPv4/IPv6 agnostic)
    2. Verifies that each VTEP has learned next-hops from all other (remote) VTEPs for the specified L3VNIs

    Parameters
    ----------
    * `tgen`: Topogen object
    * `vtep_routers`: list of router names that are VTEPs
                      e.g., ["bordertor-11", "bordertor-12", "tor-22"]
    * `l3vni_list`: list of L3VNI strings to verify (e.g., ["104001", "104002"])
    * `vxlan_device`: name of the VXLAN device to query for VTEP IPs (default: "vxlan48")

    Returns
    -------
    None on success, raises assertion error on failure

    Usage
    -----
    from lib.evpn import evpn_verify_l3vni_remote_nexthops

    vtep_routers = ["bordertor-11", "bordertor-12", "tor-22"]
    l3vni_list = ["104001", "104002"]

    evpn_verify_l3vni_remote_nexthops(tgen, vtep_routers, l3vni_list)
    """
    import json
    from functools import partial
    from lib import topotest

    logger.info(f"Discovering VTEP IPs from {vxlan_device} device (IPv4/IPv6 agnostic)")

    # Discover VTEP addresses from VXLAN device
    vtep_ips = {}
    detected_ip_versions = set()

    for rname in vtep_routers:
        router = tgen.gears[rname]
        # Get VXLAN device details in JSON format
        output = router.run(f"ip -j -d link show {vxlan_device}")

        try:
            link_info = json.loads(output)
            if not link_info or not isinstance(link_info, list) or len(link_info) == 0:
                raise AssertionError(
                    f"{rname}: Invalid JSON output from 'ip -j -d link show {vxlan_device}'"
                )

            # Extract local VTEP IP from linkinfo
            # Kernel uses "local" for IPv4 and "local6" for IPv6
            vxlan_info = link_info[0].get("linkinfo", {}).get("info_data", {})
            local_ip = vxlan_info.get("local6") or vxlan_info.get("local")

            if local_ip:
                vtep_ips[rname] = local_ip
                # Detect IP version
                ip_version = "IPv6" if ":" in local_ip else "IPv4"
                detected_ip_versions.add(ip_version)
                logger.info(
                    f"{rname}: Discovered VTEP IP {vtep_ips[rname]} ({ip_version})"
                )
            else:
                raise AssertionError(
                    f"{rname}: No 'local' or 'local6' field found in {vxlan_device} device info"
                )
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            raise AssertionError(
                f"{rname}: Failed to parse {vxlan_device} device info: {e}"
            )

    # Log the IP version(s) detected in this topology
    logger.info(
        f"VTEP IP version(s) detected: {', '.join(sorted(detected_ip_versions))}"
    )

    # Verify L3VNI next-hops for all VTEPs
    for rname in vtep_routers:
        router = tgen.gears[rname]

        # Build expected remote VTEPs list (all VTEPs except itself)
        local_vtep_ip = vtep_ips[rname]
        expected_remote_vteps = [ip for ip in vtep_ips.values() if ip != local_vtep_ip]

        logger.info(
            f"Verifying {rname} (local VTEP: {local_vtep_ip}) - "
            f"expects next-hops from {len(expected_remote_vteps)} remote VTEPs"
        )

        # Use library function to check L3VNI next-hops
        test_func = partial(
            evpn_verify_l3vni_nexthops, router, l3vni_list, expected_remote_vteps
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f"{rname} L3VNI next-hop verification failed: {result}"


def evpn_verify_l3vni_rmacs(router, l3vni_list, expected_remote_vteps):
    """
    Helper function to verify L3VNI Router MACs (RMACs) from remote VTEPs.

    This function verifies that for each L3VNI:
    1. FRR has learned RMACs from expected remote VTEPs
    2. Bridge FDB has entries for each RMAC associated with the L3VNI

    The function parses the JSON output of 'show evpn rmac vni <vni> json' which has
    the structure:
    {
      "numRmacs": <number>,
      "<rmac1>": {
        "routerMac": "<mac>",
        "vtepIp": "<ip>"
      },
      ...
    }

    Parameters
    ----------
    * `router`: router object to check
    * `l3vni_list`: list of L3VNI strings to verify (e.g., ["104001", "104002"])
    * `expected_remote_vteps`: list of expected remote VTEP IPs (IPv4 or IPv6 strings)

    Returns
    -------
    None on success, error string on failure (for use with topotest.run_and_expect)

    Usage
    -----
    from functools import partial
    from lib import topotest
    from lib.evpn import evpn_verify_l3vni_rmacs

    l3vni_list = ["104001", "104002"]
    expected_remote_vteps = ["2006:20:20::1", "2006:20:20::2", "2006:20:20::30"]

    test_func = partial(
        evpn_check_l3vni_rmacs,
        router,
        l3vni_list,
        expected_remote_vteps
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"L3VNI RMAC verification failed: {result}"
    """
    import json

    for vni in l3vni_list:
        # Get JSON output to parse RMAC list
        json_output = router.vtysh_cmd(f"show evpn rmac vni {vni} json", isjson=True)

        if not json_output:
            return f"VNI {vni}: No JSON output from 'show evpn rmac vni {vni} json'"

        if not isinstance(json_output, dict):
            return f"VNI {vni}: Invalid JSON output format, expected dict, got {type(json_output)}"

        # Extract number of RMACs if present
        num_rmacs = json_output.get("numRmacs", 0)

        # Extract RMAC entries (keys are MAC addresses, except for metadata keys like "numRmacs")
        rmac_entries = {}
        for key, value in json_output.items():
            # Skip non-RMAC keys (metadata keys)
            if key == "numRmacs" or not isinstance(value, dict):
                continue
            # MAC addresses contain colons
            if ":" in key:
                rmac_entries[key] = value

        if not rmac_entries:
            return f"VNI {vni}: No RMACs found in JSON output (expected {len(expected_remote_vteps)} remote VTEPs)"

        logger.info(
            f"{router.name}: VNI {vni} has {len(rmac_entries)} RMACs (numRmacs: {num_rmacs})"
        )

        # Collect VTEP IPs from RMAC entries
        found_vtep_ips = set()
        for rmac, rmac_data in rmac_entries.items():
            vtep_ip = rmac_data.get("vtepIp")
            if vtep_ip:
                found_vtep_ips.add(vtep_ip)

        # Verify each expected remote VTEP has at least one RMAC
        for expected_vtep in expected_remote_vteps:
            if expected_vtep not in found_vtep_ips:
                return (
                    f"VNI {vni}: Expected remote VTEP {expected_vtep} not found in RMAC table. "
                    f"Expected VTEPs: {expected_remote_vteps}, Found VTEPs: {sorted(found_vtep_ips)}"
                )

        logger.info(
            f"{router.name}: VNI {vni} has RMACs from all expected remote VTEPs"
        )

        # Verify each RMAC has a bridge FDB entry for this VNI
        for rmac, rmac_data in rmac_entries.items():
            vtep_ip = rmac_data.get("vtepIp", "unknown")
            # Query bridge FDB for this RMAC and VNI
            # Format: "<rmac> dev <vxlan_dev> dst <vtep_ip> src_vni <vni> self permanent"
            fdb_cmd = f"bridge fdb show | grep '{rmac}' | grep '{vni}'"
            fdb_output = router.run(fdb_cmd)

            if not fdb_output or fdb_output.strip() == "":
                return (
                    f"VNI {vni}: Bridge FDB entry not found for RMAC {rmac} (VTEP: {vtep_ip}). "
                    f"Expected format: '<rmac> dev <vxlan_dev> dst {vtep_ip} src_vni {vni} self permanent'"
                )

            logger.info(
                f"{router.name}: VNI {vni} RMAC {rmac} (VTEP: {vtep_ip}) found in bridge FDB"
            )

    return None


def evpn_verify_l3vni_remote_rmacs(
    tgen, vtep_routers, l3vni_list, vxlan_device="vxlan48"
):
    """
    Helper function to verify L3VNI remote RMACs across all VTEPs in a topology.

    This function:
    1. Discovers VTEP IP addresses from the specified VXLAN device (IPv4/IPv6 agnostic)
    2. Verifies that each VTEP has learned RMACs from all other (remote) VTEPs for the specified L3VNIs

    Parameters
    ----------
    * `tgen`: Topogen object
    * `vtep_routers`: list of router names that are VTEPs
                      e.g., ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]
    * `l3vni_list`: list of L3VNI strings to verify (e.g., ["104001", "104002"])
    * `vxlan_device`: name of the VXLAN device to query for VTEP IPs (default: "vxlan48")

    Returns
    -------
    None on success, raises assertion error on failure

    Usage
    -----
    from lib.evpn import evpn_verify_l3vni_remote_rmacs

    vtep_routers = ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]
    l3vni_list = ["104001", "104002"]

    evpn_verify_l3vni_remote_rmacs(tgen, vtep_routers, l3vni_list)
    """
    import json
    from functools import partial
    from lib import topotest

    logger.info(f"Discovering VTEP IPs from {vxlan_device} device (IPv4/IPv6 agnostic)")

    # Discover VTEP addresses from VXLAN device
    vtep_ips = {}
    detected_ip_versions = set()

    for rname in vtep_routers:
        router = tgen.gears[rname]
        # Get VXLAN device details in JSON format
        output = router.run(f"ip -j -d link show {vxlan_device}")

        try:
            link_info = json.loads(output)
            if not link_info or not isinstance(link_info, list) or len(link_info) == 0:
                raise AssertionError(
                    f"{rname}: Invalid JSON output from 'ip -j -d link show {vxlan_device}'"
                )

            # Extract local VTEP IP from linkinfo
            # Kernel uses "local" for IPv4 and "local6" for IPv6
            vxlan_info = link_info[0].get("linkinfo", {}).get("info_data", {})
            local_ip = vxlan_info.get("local6") or vxlan_info.get("local")

            if local_ip:
                vtep_ips[rname] = local_ip
                # Detect IP version
                ip_version = "IPv6" if ":" in local_ip else "IPv4"
                detected_ip_versions.add(ip_version)
                logger.info(
                    f"{rname}: Discovered VTEP IP {vtep_ips[rname]} ({ip_version})"
                )
            else:
                raise AssertionError(
                    f"{rname}: No 'local' or 'local6' field found in {vxlan_device} device info"
                )
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            raise AssertionError(
                f"{rname}: Failed to parse {vxlan_device} device info: {e}"
            )

    # Log the IP version(s) detected in this topology
    logger.info(
        f"VTEP IP version(s) detected: {', '.join(sorted(detected_ip_versions))}"
    )

    # Verify L3VNI RMACs for all VTEPs
    for rname in vtep_routers:
        router = tgen.gears[rname]

        # Build expected remote VTEPs list (all VTEPs except itself)
        local_vtep_ip = vtep_ips[rname]
        expected_remote_vteps = [ip for ip in vtep_ips.values() if ip != local_vtep_ip]

        logger.info(
            f"Verifying {rname} (local VTEP: {local_vtep_ip}) - "
            f"expects RMACs from {len(expected_remote_vteps)} remote VTEPs"
        )

        # Use library function to check L3VNI RMACs
        test_func = partial(
            evpn_verify_l3vni_rmacs, router, l3vni_list, expected_remote_vteps
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f"{rname} L3VNI RMAC verification failed: {result}"


def evpn_trigger_host_arp(tgen, host_gateways, interface="swp1", count=3, interval=1):
    """
    Trigger ARP/NDP from hosts to populate MAC address tables in the EVPN fabric.

    This sends gratuitous ARP requests from each host to their default gateway,
    ensuring MAC addresses are learned by the VTEPs. This is useful for triggering
    EVPN Type-2 (MAC/IP) route advertisement.

    Parameters
    ----------
    * `tgen`: Topogen object
    * `host_gateways`: dict mapping host router names to their gateway IP addresses
                       e.g., {"host-111": "60.1.1.11", "host-211": "60.1.1.21"}
    * `interface`: interface name to send ARP requests from (default: "swp1")
    * `count`: number of ARP requests to send per host (default: 3)
    * `interval`: interval in seconds between ARP requests (default: 1)

    Returns
    -------
    None

    Usage
    -----
    from lib.evpn import evpn_trigger_host_arp

    host_gateways = {
        "host-111": "60.1.1.11",
        "host-112": "60.1.1.11",
        "host-211": "60.1.1.21",
        "host-221": "60.1.1.22",
    }

    # Using default interface (swp1)
    evpn_trigger_host_arp(tgen, host_gateways)

    # Using custom interface
    evpn_trigger_host_arp(tgen, host_gateways, interface="eth0")

    # Custom count and interval
    evpn_trigger_host_arp(tgen, host_gateways, interface="swp1", count=5, interval=2)
    """
    from time import sleep

    for hostname, gateway_ip in host_gateways.items():
        if hostname not in tgen.gears:
            logger.info(f"{hostname}: Router not found, skipping ARP trigger")
            continue

        host = tgen.gears[hostname]
        logger.info(
            f"{hostname}: Sending {count} ARP requests to {gateway_ip} on {interface}"
        )

        # Send ARP requests with specified interval (similar to ssim3 post-up)
        # arping -q: quiet mode, -c 1: count 1 packet, -w 1: timeout 1 sec, -I: interface
        for i in range(1, count + 1):
            cmd = f"arping -q -c 1 -w 1 -I {interface} {gateway_ip}"
            host.run(cmd)
            if i < count:  # Don't sleep after the last iteration
                sleep(interval)


def evpn_trigger_arp_scapy(tgen, host_gateways, interface="swp1"):
    """
    Trigger ARP using Scapy to populate MAC address tables in the EVPN fabric.

    This function uses Scapy to craft and send ARP requests, providing more
    flexibility for complex scenarios like anycast gateway testing or custom
    packet crafting. This is particularly useful when testing scenarios that
    require specific MAC addresses or when arping utility is not available.

    Parameters
    ----------
    * `tgen`: Topogen object
    * `host_gateways`: dict mapping host router names to their gateway IP addresses
                       e.g., {"host-111": "60.1.1.11", "host-211": "60.1.1.21"}
    * `interface`: interface name to send ARP requests from (default: "swp1")

    Returns
    -------
    None

    Usage
    -----
    from lib.evpn import evpn_trigger_arp_scapy

    host_gateways = {
        "host-111": "60.1.1.11",
        "host-112": "60.1.1.11",
        "host-211": "60.1.1.21",
        "host-221": "60.1.1.22",
    }

    # Using default interface (swp1)
    evpn_trigger_arp_scapy(tgen, host_gateways)

    # Using custom interface
    evpn_trigger_arp_scapy(tgen, host_gateways, interface="eth0")

    Notes
    -----
    - Requires Scapy to be installed on the system
    - Uses the scapy_sendpkt.py helper script from lib/
    - More powerful than arping for custom packet crafting
    - Better for anycast gateway testing where specific MAC addresses are needed
    """
    import os
    import subprocess

    # Get path to scapy_sendpkt.py script
    lib_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(lib_dir, "scapy_sendpkt.py")

    if not os.path.exists(script_path):
        logger.error(f"scapy_sendpkt.py not found at {script_path}")
        return

    # Get python3 executable path
    python3_path = tgen.net.get_exec_path(["python3", "python"])

    for hostname, gateway_ip in host_gateways.items():
        if hostname not in tgen.gears:
            logger.info(f"{hostname}: Router not found, skipping ARP trigger")
            continue

        host = tgen.net.hosts[hostname]
        logger.info(
            f"{hostname}: Sending ARP request to {gateway_ip} on {interface} using Scapy"
        )

        # Craft ARP packet using Scapy
        # Ether(dst="ff:ff:ff:ff:ff:ff") = broadcast Ethernet frame
        # ARP(pdst="<gateway_ip>") = ARP request for gateway IP
        ping_cmd = [
            python3_path,
            script_path,
            "--imports=Ether,ARP",
            "--interface=" + interface,
            f'Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="{gateway_ip}")',
        ]

        try:
            _, stdout, _ = host.cmd_status(
                ping_cmd, warn=False, stderr=subprocess.STDOUT
            )
            stdout = stdout.strip()
            if stdout:
                logger.debug(
                    f"{hostname}: Scapy ARP on {interface} for {gateway_ip} returned: {stdout}"
                )
        except Exception as e:
            logger.warning(
                f"{hostname}: Failed to send ARP via Scapy to {gateway_ip}: {e}"
            )
