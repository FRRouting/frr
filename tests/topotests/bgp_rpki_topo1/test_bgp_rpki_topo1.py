#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            " -M bgpd_rpki" if rname == "r2" else "",
        )

    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")

    tgen.gears["r2"].run("ip link set r2-eth1 master vrf10")

    tgen.start_router()

    global rtrd_process
    rtrd_process = {}

    for rname in ["r1", "r3"]:
        rtr_path = os.path.join(CWD, rname)
        log_dir = os.path.join(tgen.logdir, rname)
        log_file = os.path.join(log_dir, "rtrd.log")

        tgen.gears[rname].cmd("chmod u+x {}/rtrd.py".format(rtr_path))
        rtrd_process[rname] = tgen.gears[rname].popen(
            "{}/rtrd.py {}".format(rtr_path, log_file)
        )


def teardown_module(mod):
    tgen = get_topogen()

    for rname in ["r1", "r3"]:
        logger.info("{}: sending SIGTERM to rtrd RPKI server".format(rname))
        rtrd_process[rname].kill()

    tgen.stop_topology()


def show_rpki_prefixes(rname, expected, vrf=None):
    tgen = get_topogen()

    if vrf:
        cmd = "show rpki prefix-table vrf {} json".format(vrf)
    else:
        cmd = "show rpki prefix-table json"

    output = json.loads(tgen.gears[rname].vtysh_cmd(cmd))

    return topotest.json_cmp(output, expected)


def show_rpki_valid(rname, expected, vrf=None):
    tgen = get_topogen()

    cmd = "show bgp ipv4 detail json"

    output = json.loads(tgen.gears[rname].vtysh_cmd(cmd))

    return topotest.json_cmp(output, expected)


def show_bgp_ipv4_table_rpki(rname, rpki_state, expected, vrf=None):
    tgen = get_topogen()

    cmd = "show bgp"
    if vrf:
        cmd += " vrf {}".format(vrf)
    cmd += " ipv4 unicast"
    if rpki_state:
        cmd += " rpki {}".format(rpki_state)
    cmd += " json"

    output = json.loads(tgen.gears[rname].vtysh_cmd(cmd))

    expected_nb = len(expected.get("routes"))
    output_nb = len(output.get("routes", {}))

    if expected_nb != output_nb:
        return {"error": "expected {} prefixes. Got {}".format(expected_nb, output_nb)}

    return topotest.json_cmp(output, expected)


def test_show_bgp_rpki_prefixes_valid():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    rname = "r2"
    expected = open(os.path.join(CWD, "{}/bgp_rpki_valid.json".format(rname))).read()
    expected_json = json.loads(expected)
    test_func = functools.partial(show_rpki_valid, rname, expected_json)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see RPKI on {}".format(rname)


def test_show_bgp_rpki_prefixes():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    rname = "r2"

    step("Check RPKI prefix table")

    expected = open(os.path.join(CWD, "{}/rpki_prefix_table.json".format(rname))).read()
    expected_json = json.loads(expected)
    test_func = functools.partial(show_rpki_prefixes, rname, expected_json)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see RPKI prefixes on {}".format(rname)

    for rpki_state in ["valid", "invalid", "notfound", None]:
        if rpki_state:
            step("Check RPKI state of prefixes in BGP table: {}".format(rpki_state))
        else:
            step("Check prefixes in BGP table")
        expected = open(
            os.path.join(
                CWD,
                "{}/bgp_table_rpki_{}.json".format(
                    rname, rpki_state if rpki_state else "any"
                ),
            )
        ).read()
        expected_json = json.loads(expected)
        test_func = functools.partial(
            show_bgp_ipv4_table_rpki, rname, rpki_state, expected_json
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Unexpected prefixes RPKI state on {}".format(rname)


def test_show_bgp_rpki_prefixes_no_rpki_cache():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    def _show_rpki_no_connection(rname):
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show rpki cache-connection json")
        )

        return output == {"error": "No connection to RPKI cache server."}

    step("Remove RPKI server from configuration")
    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
rpki
 no rpki cache tcp 192.0.2.1 15432 preference 1
exit
"""
    )

    step("Check RPKI connection state")

    test_func = functools.partial(_show_rpki_no_connection, rname)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "RPKI is still connected on {}".format(rname)


def test_show_bgp_rpki_prefixes_reconnect():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Restore RPKI server configuration")

    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
rpki
 rpki cache tcp 192.0.2.1 15432 preference 1
exit
"""
    )

    step("Check RPKI prefix table")

    expected = open(os.path.join(CWD, "{}/rpki_prefix_table.json".format(rname))).read()
    expected_json = json.loads(expected)
    test_func = functools.partial(show_rpki_prefixes, rname, expected_json)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see RPKI prefixes on {}".format(rname)

    for rpki_state in ["valid", "invalid", "notfound", None]:
        if rpki_state:
            step("Check RPKI state of prefixes in BGP table: {}".format(rpki_state))
        else:
            step("Check prefixes in BGP table")
        expected = open(
            os.path.join(
                CWD,
                "{}/bgp_table_rpki_{}.json".format(
                    rname, rpki_state if rpki_state else "any"
                ),
            )
        ).read()
        expected_json = json.loads(expected)
        test_func = functools.partial(
            show_bgp_ipv4_table_rpki, rname, rpki_state, expected_json
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Unexpected prefixes RPKI state on {}".format(rname)


def test_show_bgp_rpki_route_map():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Apply RPKI valid route-map on neighbor")

    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
route-map RPKI permit 10
 match rpki valid
!
router bgp 65002
 address-family ipv4 unicast
  neighbor 192.0.2.1 route-map RPKI in
"""
    )

    for rpki_state in ["valid", "invalid", "notfound", None]:
        if rpki_state:
            step("Check RPKI state of prefixes in BGP table: {}".format(rpki_state))
        else:
            step("Check prefixes in BGP table")
        expected = open(
            os.path.join(
                CWD,
                "{}/bgp_table_rmap_rpki_{}.json".format(
                    rname, rpki_state if rpki_state else "any"
                ),
            )
        ).read()
        expected_json = json.loads(expected)
        test_func = functools.partial(
            show_bgp_ipv4_table_rpki,
            rname,
            rpki_state,
            expected_json,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Unexpected prefixes RPKI state on {}".format(rname)


def test_show_bgp_rpki_prefixes_vrf():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Configure RPKI cache server on vrf10")

    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
vrf vrf10
 rpki
  rpki cache tcp 192.0.2.3 15432 preference 1
 exit
exit
"""
    )

    step("Check vrf10 RPKI prefix table")

    expected = open(os.path.join(CWD, "{}/rpki_prefix_table.json".format(rname))).read()
    expected_json = json.loads(expected)
    test_func = functools.partial(show_rpki_prefixes, rname, expected_json, vrf="vrf10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see RPKI prefixes on {}".format(rname)

    for rpki_state in ["valid", "invalid", "notfound", None]:
        if rpki_state:
            step(
                "Check RPKI state of prefixes in vrf10 BGP table: {}".format(rpki_state)
            )
        else:
            step("Check prefixes in vrf10 BGP table")
        expected = open(
            os.path.join(
                CWD,
                "{}/bgp_table_rpki_{}.json".format(
                    rname, rpki_state if rpki_state else "any"
                ),
            )
        ).read()
        expected_json = json.loads(expected)
        test_func = functools.partial(
            show_bgp_ipv4_table_rpki, rname, rpki_state, expected_json, vrf="vrf10"
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Unexpected prefixes RPKI state on {}".format(rname)


def test_show_bgp_rpki_route_map_vrf():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Apply RPKI valid route-map on vrf10 neighbor")

    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
router bgp 65002 vrf vrf10
 address-family ipv4 unicast
  neighbor 192.0.2.3 route-map RPKI in
"""
    )

    for rpki_state in ["valid", "invalid", "notfound", None]:
        if rpki_state:
            step(
                "Check RPKI state of prefixes in vrf10 BGP table: {}".format(rpki_state)
            )
        else:
            step("Check prefixes in vrf10 BGP table")
        expected = open(
            os.path.join(
                CWD,
                "{}/bgp_table_rmap_rpki_{}.json".format(
                    rname, rpki_state if rpki_state else "any"
                ),
            )
        ).read()
        expected_json = json.loads(expected)
        test_func = functools.partial(
            show_bgp_ipv4_table_rpki,
            rname,
            rpki_state,
            expected_json,
            vrf="vrf10",
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Unexpected prefixes RPKI state on {}".format(rname)


def test_bgp_ecommunity_rpki():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    # Flush all the states what was before and try sending out the prefixes
    # with RPKI extended community.
    r2.vtysh_cmd("clear ip bgp 192.168.4.4 soft out")

    def _bgp_check_ecommunity_rpki(community=None):
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 unicast 198.51.100.0/24 json"))
        expected = {
            "paths": [
                {
                    "extendedCommunity": community,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_ecommunity_rpki, {"string": "OVS:valid"})
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Didn't receive RPKI extended community"

    r2.vtysh_cmd(
        """
    configure terminal
     router bgp 65002
      address-family ipv4 unicast
       no neighbor 192.168.4.4 send-community extended rpki
    """
    )

    test_func = functools.partial(_bgp_check_ecommunity_rpki)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Received RPKI extended community"


def test_show_bgp_rpki_as_number():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Check RPKI prefixes for ASN 65531")

    rname = "r2"
    output = json.loads(tgen.gears[rname].vtysh_cmd("show rpki as-number 65531 json"))

    # Expected output should show no prefixes for this ASN
    expected = {"ipv4PrefixCount": 0, "ipv6PrefixCount": 0, "prefixes": []}

    assert output == expected, "Found unexpected RPKI prefixes for ASN 65531"


def test_show_bgp_rpki_as_number_65530():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Check RPKI prefixes for ASN 65530")

    rname = "r2"
    output = json.loads(tgen.gears[rname].vtysh_cmd("show rpki as-number 65530 json"))

    expected = {
        "prefixes": [
            {
                "prefix": "198.51.100.0",
                "prefixLenMin": 24,
                "prefixLenMax": 24,
                "asn": 65530,
            },
            {
                "prefix": "203.0.113.0",
                "prefixLenMin": 24,
                "prefixLenMax": 24,
                "asn": 65530,
            },
            {
                "prefix": "2001:db8:1::",
                "prefixLenMin": 48,
                "prefixLenMax": 48,
                "asn": 65530,
            },
        ],
        "ipv4PrefixCount": 2,
        "ipv6PrefixCount": 1,
    }

    result = topotest.json_cmp(output, expected)
    assert result is None, "RPKI prefixes for ASN 65530 do not match expected output"


def test_rpki_stop_and_check_connection():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Stop RPKI on r2")
    rname = "r2"
    tgen.gears[rname].vtysh_cmd("rpki stop")

    step("Check RPKI cache connection status")
    output = json.loads(tgen.gears[rname].vtysh_cmd("show rpki cache-connection json"))

    expected = {"error": "No connection to RPKI cache server."}
    assert (
        output == expected
    ), "RPKI cache connection status does not show as disconnected"


def test_rpki_start_and_check_connection():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Start RPKI on r2")
    rname = "r2"
    tgen.gears[rname].vtysh_cmd("rpki start")

    def _check_rpki_connection():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show rpki cache-connection json")
        )
        # We expect to see a connected group and at least one connection
        return "connectedGroup" in output and "connections" in output

    step("Check RPKI cache connection status")
    _, result = topotest.run_and_expect(
        _check_rpki_connection, True, count=60, wait=0.5
    )
    assert result, "RPKI cache connection did not establish after start"


def test_rpki_invalid_state():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Remove any existing route-map from r1 neighbor to see all routes")
    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
router bgp 65002
 address-family ipv4 unicast
  no neighbor 192.0.2.1 route-map RPKI in
"""
    )

    step("Verify RPKI invalid route is present")

    def _check_invalid_routes():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp ipv4 unicast rpki invalid json")
        )
        routes = output.get("routes", {})
        if "10.0.0.0/24" not in routes:
            return {"error": "10.0.0.0/24 not found in invalid routes"}
        return None

    _, result = topotest.run_and_expect(_check_invalid_routes, None, count=60, wait=0.5)
    assert result is None, "Failed to see RPKI invalid route on {}".format(rname)

    step("Verify valid routes are still present")

    def _check_valid_routes():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp ipv4 unicast rpki valid json")
        )
        routes = output.get("routes", {})
        if len(routes) != 2:
            return {"error": "expected 2 valid routes, got {}".format(len(routes))}
        return None

    _, result = topotest.run_and_expect(_check_valid_routes, None, count=60, wait=0.5)
    assert result is None, "Unexpected valid route count on {}".format(rname)

    step("Verify no notfound routes remain")

    def _check_no_notfound():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp ipv4 unicast rpki notfound json")
        )
        routes = output.get("routes", {})
        if len(routes) != 0:
            return {"error": "expected 0 notfound routes, got {}".format(len(routes))}
        return None

    _, result = topotest.run_and_expect(_check_no_notfound, None, count=60, wait=0.5)
    assert result is None, "Unexpected notfound routes on {}".format(rname)


def test_rpki_route_map_deny_invalid():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    step("Apply route-map denying RPKI invalid routes on neighbor")
    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
route-map DENY-INVALID deny 10
 match rpki invalid
!
route-map DENY-INVALID permit 20
!
router bgp 65002
 address-family ipv4 unicast
  neighbor 192.0.2.1 route-map DENY-INVALID in
"""
    )

    step("Verify invalid route 10.0.0.0/24 is rejected")

    def _check_no_invalid():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp ipv4 unicast rpki invalid json")
        )
        routes = output.get("routes", {})
        return len(routes) == 0

    _, result = topotest.run_and_expect(_check_no_invalid, True, count=60, wait=0.5)
    assert result, "Invalid routes still present after deny route-map on {}".format(
        rname
    )

    step("Verify valid routes are still accepted")

    def _check_valid_present():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp ipv4 unicast rpki valid json")
        )
        routes = output.get("routes", {})
        return len(routes) == 2

    _, result = topotest.run_and_expect(_check_valid_present, True, count=60, wait=0.5)
    assert result, "Valid routes missing after deny-invalid route-map on {}".format(
        rname
    )

    step("Remove deny-invalid route-map from neighbor")
    tgen.gears[rname].vtysh_cmd(
        """
configure
router bgp 65002
 address-family ipv4 unicast
  no neighbor 192.0.2.1 route-map DENY-INVALID in
"""
    )


def test_rpki_strict_mode():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    rname = "r2"

    step("Verify r4 peer is Established")

    def _check_r4_established():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp neighbor 192.168.4.4 json")
        )
        peer = output.get("192.168.4.4", {})
        return peer.get("bgpState") == "Established"

    _, result = topotest.run_and_expect(_check_r4_established, True, count=60, wait=0.5)
    assert result, "r4 peer not Established before strict test"

    step("Configure rpki strict on r4 neighbor and stop RPKI")
    tgen.gears[rname].vtysh_cmd(
        """
configure
router bgp 65002
 neighbor 192.168.4.4 rpki strict
"""
    )
    tgen.gears[rname].vtysh_cmd("rpki stop")

    step("Clear r4 peer to trigger FSM re-evaluation")
    tgen.gears[rname].vtysh_cmd("clear ip bgp 192.168.4.4")

    step("Verify r4 peer cannot reach Established (RPKI not connected)")
    established_seen = False
    for _ in range(15):
        time.sleep(1)
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp neighbor 192.168.4.4 json")
        )
        peer = output.get("192.168.4.4", {})
        if peer.get("bgpState") == "Established":
            established_seen = True
            break

    assert (
        not established_seen
    ), "r4 reached Established despite rpki strict and no RPKI connection"

    step("Start RPKI and wait for cache connection")
    tgen.gears[rname].vtysh_cmd("rpki start")

    step("Verify r4 peer reaches Established after RPKI connects")
    _, result = topotest.run_and_expect(_check_r4_established, True, count=60, wait=0.5)
    assert (
        result
    ), "r4 peer did not reach Established after RPKI started with strict mode"

    step("Remove rpki strict from r4 neighbor")
    tgen.gears[rname].vtysh_cmd(
        """
configure
router bgp 65002
 no neighbor 192.168.4.4 rpki strict
"""
    )


def test_rpki_extcommunity_match():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    step("Re-enable send-community extended rpki on r2 toward r4")
    r2.vtysh_cmd(
        """
configure
router bgp 65002
 address-family ipv4 unicast
  neighbor 192.168.4.4 send-community extended rpki
"""
    )
    r2.vtysh_cmd("clear ip bgp 192.168.4.4 soft out")

    step("Verify r4 receives OVS:valid extended community")

    def _check_ovs_valid():
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 unicast 198.51.100.0/24 json"))
        expected = {"paths": [{"extendedCommunity": {"string": "OVS:valid"}}]}
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_check_ovs_valid, None, count=30, wait=1)
    assert result is None, "r4 did not receive OVS:valid extended community"

    step("Verify r4 receives OVS:invalid for 10.0.0.0/24")

    def _check_ovs_invalid():
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/24 json"))
        expected = {"paths": [{"extendedCommunity": {"string": "OVS:invalid"}}]}
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_check_ovs_invalid, None, count=30, wait=1)
    assert result is None, "r4 did not receive OVS:invalid extended community"

    step("Apply route-map on r4 matching rpki-extcommunity valid")
    r4.vtysh_cmd(
        """
configure
route-map MATCH-OVS permit 10
 match rpki-extcommunity valid
!
router bgp 65002
 address-family ipv4 unicast
  neighbor 192.168.4.2 route-map MATCH-OVS in
"""
    )

    step("Verify r4 only accepts routes with OVS:valid")

    def _check_r4_filtered():
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 unicast json"))
        routes = output.get("routes", {})
        if "198.51.100.0/24" not in routes:
            return {"error": "198.51.100.0/24 missing (should have OVS:valid)"}
        if "203.0.113.0/24" not in routes:
            return {"error": "203.0.113.0/24 missing (should have OVS:valid)"}
        if "10.0.0.0/24" in routes:
            return {"error": "10.0.0.0/24 should be filtered (OVS:invalid)"}
        return None

    _, result = topotest.run_and_expect(_check_r4_filtered, None, count=60, wait=0.5)
    assert result is None, "rpki-extcommunity route-map filtering failed on r4"

    step("Clean up route-map on r4")
    r4.vtysh_cmd(
        """
configure
router bgp 65002
 address-family ipv4 unicast
  no neighbor 192.168.4.2 route-map MATCH-OVS in
"""
    )


def test_rpki_ipv6_validation():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r3"]:
        logger.info("{}: checking if rtrd is running".format(rname))
        if rtrd_process[rname].poll() is not None:
            pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Add IPv6 addresses and BGP peering between r1 and r2")
    r1.vtysh_cmd(
        """
configure
interface r1-eth0
 ipv6 address 2001:db8:100::1/64
!
router bgp 65530
 neighbor 2001:db8:100::2 remote-as 65002
 neighbor 2001:db8:100::2 timers 1 3
 neighbor 2001:db8:100::2 timers connect 1
 address-family ipv6 unicast
  network 2001:db8:1::/48
  network 2001:db8:2::/48
  neighbor 2001:db8:100::2 activate
 exit-address-family
"""
    )

    r2.vtysh_cmd(
        """
configure
interface r2-eth0
 ipv6 address 2001:db8:100::2/64
!
router bgp 65002
 neighbor 2001:db8:100::1 remote-as 65530
 neighbor 2001:db8:100::1 timers 1 3
 neighbor 2001:db8:100::1 timers connect 1
 address-family ipv6 unicast
  neighbor 2001:db8:100::1 activate
 exit-address-family
"""
    )

    rname = "r2"

    step("Verify IPv6 RPKI valid route (2001:db8:1::/48)")

    def _check_ipv6_valid():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp ipv6 unicast 2001:db8:1::/48 json")
        )
        paths = output.get("paths", [])
        if not paths:
            return {"error": "no paths for 2001:db8:1::/48"}
        state = paths[0].get("rpkiValidationState")
        if state != "valid":
            return {"error": "expected valid, got {}".format(state)}
        return None

    _, result = topotest.run_and_expect(_check_ipv6_valid, None, count=60, wait=0.5)
    assert result is None, "IPv6 prefix 2001:db8:1::/48 not RPKI valid on {}".format(
        rname
    )

    step("Verify IPv6 RPKI notfound route (2001:db8:2::/48)")

    def _check_ipv6_notfound():
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp ipv6 unicast 2001:db8:2::/48 json")
        )
        paths = output.get("paths", [])
        if not paths:
            return {"error": "no paths for 2001:db8:2::/48"}
        state = paths[0].get("rpkiValidationState")
        if state != "not found":
            return {"error": "expected not found, got {}".format(state)}
        return None

    _, result = topotest.run_and_expect(_check_ipv6_notfound, None, count=60, wait=0.5)
    assert result is None, "IPv6 prefix 2001:db8:2::/48 not RPKI notfound on {}".format(
        rname
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
