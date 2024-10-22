#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_isis_topo1.py: Test ISIS topology.
"""
import datetime
import functools
import json
import os
import re
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import (
    retry,
    stop_router,
    start_router,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.isisd]

VERTEX_TYPE_LIST = [
    "pseudo_IS",
    "pseudo_TE-IS",
    "IS",
    "TE-IS",
    "ES",
    "IP internal",
    "IP external",
    "IP TE",
    "IP6 internal",
    "IP6 external",
    "UNKNOWN",
]


def build_topo(tgen):
    "Build function"

    # Add ISIS routers:
    # r1      r2
    #  | sw1  | sw2
    # r3     r4
    #  |      |
    # sw3    sw4
    #   \    /
    #     r5
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    # r1 <- sw1 -> r3
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r3"])

    # r2 <- sw2 -> r4
    sw = tgen.add_switch("sw2")
    sw.add_link(tgen.gears["r2"])
    sw.add_link(tgen.gears["r4"])

    # r3 <- sw3 -> r5
    sw = tgen.add_switch("sw3")
    sw.add_link(tgen.gears["r3"])
    sw.add_link(tgen.gears["r5"])

    # r4 <- sw4 -> r5
    sw = tgen.add_switch("sw4")
    sw.add_link(tgen.gears["r4"])
    sw.add_link(tgen.gears["r5"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_isis_convergence():
    "Wait for the protocol to converge before starting to test"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for ISIS protocol to converge")
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_topology.json".format(CWD, rname)
        expected = json.loads(open(filename).read())

        def compare_isis_topology(router, expected):
            "Helper function to test ISIS topology convergence."
            actual = json.loads(router.vtysh_cmd("show isis topology json"))
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(compare_isis_topology, router, expected)
        (result, diff) = topotest.run_and_expect(test_func, None, wait=0.5, count=120)
        assert result, "ISIS did not converge on {}:\n{}".format(rname, diff)


def test_isis_route_installation():
    "Check whether all expected routes are present"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS routes")

    # Check for routes in 'show ip route json'
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())

        def compare_isis_installed_routes(router, expected):
            "Helper function to test ISIS routes installed in rib."
            actual = router.vtysh_cmd("show ip route json", isjson=True)
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(compare_isis_installed_routes, router, expected)
        (result, _) = topotest.run_and_expect(test_func, None, wait=1, count=10)
        assertmsg = "Router '{}' routes mismatch".format(rname)
        assert result, assertmsg


def test_isis_linux_route_installation():
    "Check whether all expected routes are present and installed in the OS"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS routes in OS")

    # Check for routes in `ip route`
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route_linux.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = topotest.ip4_route(router)
        assertmsg = "Router '{}' OS routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_isis_route6_installation():
    "Check whether all expected routes are present"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS IPv6 routes")

    # Check for routes in 'show ip route json'
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route6.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())

        def compare_isis_v6_installed_routes(router, expected):
            "Helper function to test ISIS v6 routes installed in rib."
            actual = router.vtysh_cmd("show ipv6 route json", isjson=True)
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(
            compare_isis_v6_installed_routes, router, expected
        )
        (result, _) = topotest.run_and_expect(test_func, None, wait=1, count=10)
        assertmsg = "Router '{}' routes mismatch".format(rname)
        assert result, assertmsg


def test_isis_linux_route6_installation():
    "Check whether all expected routes are present and installed in the OS"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS IPv6 routes in OS")

    # Check for routes in `ip route`
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route6_linux.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = topotest.ip6_route(router)
        assertmsg = "Router '{}' OS routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_isis_summary_json():
    "Check json struct in show isis summary json"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking 'show isis summary json'")
    for rname, _ in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd("show isis summary json", isjson=True)
        assertmsg = "Test isis summary json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert json_output["vrfs"][0]["vrf"] == "default", assertmsg
        assert json_output["vrfs"][0]["areas"][0]["area"] == "1", assertmsg
        assert json_output["vrfs"][0]["areas"][0]["levels"][0]["id"] != "3", assertmsg


def test_isis_interface_json():
    "Check json struct in show isis interface json"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking 'show isis interface json'")
    for rname, _ in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis interface json", isjson=True
        )
        assertmsg = "Test isis interface json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][0]["interface"]["name"]
            == rname + "-eth0"
        ), assertmsg

    for rname, router in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis interface detail json", isjson=True
        )
        assertmsg = "Test isis interface json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][0]["interface"]["name"]
            == rname + "-eth0"
        ), assertmsg


def test_isis_neighbor_json():
    "Check json struct in show isis neighbor json"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli()
    logger.info("Checking 'show isis neighbor json'")
    for rname, _ in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis neighbor json", isjson=True
        )
        assertmsg = "Test isis neighbor json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][0]["interface"] == rname + "-eth0"
        ), assertmsg

    for rname, router in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis neighbor detail json", isjson=True
        )
        assertmsg = "Test isis neighbor json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][0]["interface"]["name"]
            == rname + "-eth0"
        ), assertmsg


def test_isis_database_json():
    "Check json struct in show isis database json"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli()
    logger.info("Checking 'show isis database json'")
    for rname, _ in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis database json", isjson=True
        )
        assertmsg = "Test isis database json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert json_output["areas"][0]["area"]["name"] == "1", assertmsg
        assert json_output["areas"][0]["levels"][0]["id"] != "3", assertmsg

    for rname, router in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis database detail json", isjson=True
        )
        assertmsg = "Test isis database json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert json_output["areas"][0]["area"]["name"] == "1", assertmsg
        assert json_output["areas"][0]["levels"][0]["id"] != "3", assertmsg


def test_isis_overload_on_startup():
    "Check that overload on startup behaves as expected"

    tgen = get_topogen()
    net = get_topogen().net
    overload_time = 120

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing overload on startup behavior")

    # Configure set-overload-bit on-startup on r3
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        f"""
          configure
            router isis 1
              set-overload-bit on-startup {overload_time}
        """
    )
    # Restart r3
    logger.info("Stop router")
    stop_router(tgen, "r3")
    logger.info("Start router")

    tstamp_before_start_router = datetime.datetime.now()
    start_router(tgen, "r3")
    tstamp_after_start_router = datetime.datetime.now()
    startup_router_time = (
        tstamp_after_start_router - tstamp_before_start_router
    ).total_seconds()

    # Check that the overload bit is set in r3's LSP
    check_lsp_overload_bit("r3", "r3.00-00", "0/0/1")
    check_lsp_overload_bit("r1", "r3.00-00", "0/0/1")

    # Attempt to unset overload bit while timer is still running
    r3.vtysh_cmd(
        """
          configure
            router isis 1
              no set-overload-bit on-startup
              no set-overload-bit
        """
    )

    # Check overload bit is still set
    check_lsp_overload_bit("r1", "r3.00-00", "0/0/1")

    # Check that overload bit is unset after timer completes
    check_lsp_overload_bit("r3", "r3.00-00", "0/0/0")
    tstamp_after_bit_unset = datetime.datetime.now()
    check_lsp_overload_bit("r1", "r3.00-00", "0/0/0")

    # Collect time overloaded
    time_overloaded = (
        tstamp_after_bit_unset - tstamp_after_start_router
    ).total_seconds()
    logger.info(f"Time Overloaded: {time_overloaded}")

    # Use time it took to startup router as lower bound
    logger.info(
        f"Assert that overload time falls in range: {overload_time - startup_router_time} < {time_overloaded} <= {overload_time}"
    )
    result = overload_time - startup_router_time < time_overloaded <= overload_time
    assert result


def test_isis_overload_on_startup_cancel_timer():
    "Check that overload on startup timer is cancelled when overload bit is set/unset"

    tgen = get_topogen()
    net = get_topogen().net
    overload_time = 90

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Testing overload on startup behavior with set overload bit: cancel timer"
    )

    # Configure set-overload-bit on-startup on r3
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        f"""
          configure
            router isis 1
              set-overload-bit on-startup {overload_time}
              set-overload-bit
        """
    )
    # Restart r3
    logger.info("Stop router")
    stop_router(tgen, "r3")
    logger.info("Start router")
    start_router(tgen, "r3")

    # Check that the overload bit is set in r3's LSP
    check_lsp_overload_bit("r3", "r3.00-00", "0/0/1")

    # Check that overload timer is running
    check_overload_timer("r3", True)

    # Unset overload bit while timer is running
    r3.vtysh_cmd(
        """
          configure
            router isis 1
              no set-overload-bit
        """
    )

    # Check that overload timer is cancelled
    check_overload_timer("r3", False)

    # Check overload bit is unset
    check_lsp_overload_bit("r3", "r3.00-00", "0/0/0")


def test_isis_overload_on_startup_override_timer():
    "Check that overload bit remains set after overload timer expires if overload bit is configured"

    tgen = get_topogen()
    net = get_topogen().net
    overload_time = 60

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Testing overload on startup behavior with set overload bit: override timer"
    )

    # Configure set-overload-bit on-startup on r3
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        f"""
          configure
            router isis 1
              set-overload-bit on-startup {overload_time}
              set-overload-bit
        """
    )
    # Restart r3
    logger.info("Stop router")
    stop_router(tgen, "r3")
    logger.info("Start router")
    start_router(tgen, "r3")

    # Check that the overload bit is set in r3's LSP
    check_lsp_overload_bit("r3", "r3.00-00", "0/0/1")

    # Check that overload timer is running
    check_overload_timer("r3", True)

    # Check that overload timer expired
    check_overload_timer("r3", False)

    # Check overload bit is still set
    check_lsp_overload_bit("r3", "r3.00-00", "0/0/1")


def test_isis_advertise_passive_only():
    """Check that we only advertise prefixes of passive interfaces when advertise-passive-only is enabled."""
    tgen = get_topogen()
    net = get_topogen().net
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing isis advertise-passive-only behavior")
    expected_prefixes_no_advertise_passive_only = set(
        ["10.0.20.0/24", "10.254.0.1/32", "2001:db8:f::1/128", "2001:db8:1:1::/64"]
    )
    expected_prefixes_advertise_passive_only = set(
        ["10.254.0.1/32", "2001:db8:f::1/128"]
    )
    lsp_id = "r1.00-00"

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        configure
        router isis 1
         no redistribute ipv4 connected level-2
         no redistribute ipv6 connected level-2
        interface lo
         ip router isis 1
         ipv6 router isis 1
         isis passive
        end
        """
    )

    result = check_advertised_prefixes(
        r1, lsp_id, expected_prefixes_no_advertise_passive_only
    )
    assert result is True, result

    r1.vtysh_cmd(
        """
        configure
        router isis 1
         advertise-passive-only
        end
        """
    )

    result = check_advertised_prefixes(
        r1, lsp_id, expected_prefixes_advertise_passive_only
    )
    assert result is True, result


def test_isis_hello_padding_during_adjacency_formation():
    """Check that IIH packets is only padded when adjacency is still being formed
    when isis hello padding during-adjacency-formation is configured
    """
    tgen = get_topogen()
    net = get_topogen().net
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing isis hello padding during-adjacency-formation behavior")
    r3 = tgen.gears["r3"]

    # Reduce hello-multiplier to make the adjacency go down faster.
    r3.vtysh_cmd(
        """
        configure
        interface r3-eth0
            isis hello-multiplier 2
        """
    )

    r1 = tgen.gears["r1"]
    cmd_output = r1.vtysh_cmd(
        """
        configure
        interface r1-eth0
            isis hello padding during-adjacency-formation
        end
        debug isis adj-packets
        """
    )
    result = check_last_iih_packet_for_padding(r1, expect_padding=False)
    assert result is True, result

    r3.vtysh_cmd(
        """
        configure
        interface r3-eth0
            shutdown
        """
    )
    result = check_last_iih_packet_for_padding(r1, expect_padding=True)
    assert result is True, result

    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        """
        configure
        interface r3-eth0
            no shutdown
        """
    )
    result = check_last_iih_packet_for_padding(r1, expect_padding=False)
    assert result is True, result


@retry(retry_timeout=10)
def check_last_iih_packet_for_padding(router, expect_padding):
    logfilename = "{}/{}".format(router.gearlogdir, "isisd.log")
    last_hello_packet_line = None
    with open(logfilename, "r") as f:
        lines = f.readlines()
        for line in lines:
            if re.search("Sending .+? IIH", line):
                last_hello_packet_line = line

    if last_hello_packet_line is None:
        return "Expected IIH packet in {}, but no packet found".format(logfilename)

    interface_name, packet_length = re.search(
        r"Sending .+ IIH on (.+), length (\d+)", last_hello_packet_line
    ).group(1, 2)
    packet_length = int(packet_length)
    interface_output = router.vtysh_cmd("show interface {} json".format(interface_name))
    interface_json = json.loads(interface_output)
    padded_packet_length = interface_json[interface_name]["mtu"] - 3
    if expect_padding:
        if packet_length == padded_packet_length:
            return True
        return (
            "Expected padded packet with length {}, got packet with length {}".format(
                padded_packet_length, packet_length
            )
        )
    if packet_length < padded_packet_length:
        return True
    return "Expected unpadded packet with length less than {}, got packet with length {}".format(
        padded_packet_length, packet_length
    )


@retry(retry_timeout=5)
def check_advertised_prefixes(router, lsp_id, expected_prefixes):
    output = router.vtysh_cmd("show isis database detail {}".format(lsp_id))
    prefixes = set(re.findall(r"IP(?:v6)? Reachability: (.*) \(Metric: 10\)", output))
    if prefixes == expected_prefixes:
        return True
    return str({"expected_prefixes:": expected_prefixes, "prefixes": prefixes})


@retry(retry_timeout=200)
def _check_lsp_overload_bit(router, overloaded_router_lsp, att_p_ol_expected):
    "Verfiy overload bit in router's LSP"

    tgen = get_topogen()
    router = tgen.gears[router]
    logger.info(f"check_overload_bit {router}")
    isis_database_output = router.vtysh_cmd(
        "show isis database {} json".format(overloaded_router_lsp)
    )

    database_json = json.loads(isis_database_output)
    if "lsps" not in database_json["areas"][0]["levels"][1]:
        return "The LSP of {} has not been synchronized yet ".format(router.name)

    att_p_ol = database_json["areas"][0]["levels"][1]["lsps"][0]["attPOl"]
    if att_p_ol == att_p_ol_expected:
        return True
    return "{} peer with expected att_p_ol {} got {} ".format(
        router.name, att_p_ol_expected, att_p_ol
    )


def check_lsp_overload_bit(router, overloaded_router_lsp, att_p_ol_expected):
    "Verfiy overload bit in router's LSP"

    assertmsg = _check_lsp_overload_bit(
        router, overloaded_router_lsp, att_p_ol_expected
    )
    assert assertmsg is True, assertmsg


@retry(retry_timeout=200)
def _check_overload_timer(router, timer_expected):
    "Verfiy overload bit in router's LSP"

    tgen = get_topogen()
    router = tgen.gears[router]
    output = router.vtysh_cmd("show event timers")

    timer_running = "set_overload_on_start_timer" in output
    if timer_running == timer_expected:
        return True
    return "Expected timer running status: {}".format(timer_expected)


def check_overload_timer(router, timer_expected):
    "Verfiy overload bit in router's LSP"

    assertmsg = _check_overload_timer(router, timer_expected)
    assert assertmsg is True, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


#
# Auxiliary functions
#


def dict_merge(dct, merge_dct):
    """
    Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.
    :param dct: dict onto which the merge is executed
    :param merge_dct: dct merged into dct
    :return: None

    Source:
    https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
    """
    for k, _ in merge_dct.items():
        if k in dct and isinstance(dct[k], dict) and topotest.is_mapping(merge_dct[k]):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


def parse_topology(lines, level):
    """
    Parse the output of 'show isis topology level-X' into a Python dict.
    """
    areas = {}
    area = None
    ipv = None
    vertex_type_regex = "|".join(VERTEX_TYPE_LIST)

    for line in lines:
        area_match = re.match(r"Area (.+):", line)
        if area_match:
            area = area_match.group(1)
            if area not in areas:
                areas[area] = {level: {"ipv4": [], "ipv6": []}}
            ipv = None
            continue
        elif area is None:
            continue

        if re.match(r"IS\-IS paths to level-. routers that speak IPv6", line):
            ipv = "ipv6"
            continue
        if re.match(r"IS\-IS paths to level-. routers that speak IP", line):
            ipv = "ipv4"
            continue

        item_match = re.match(
            r"([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)", line
        )
        if (
            item_match is not None
            and item_match.group(1) == "Vertex"
            and item_match.group(2) == "Type"
            and item_match.group(3) == "Metric"
            and item_match.group(4) == "Next-Hop"
            and item_match.group(5) == "Interface"
            and item_match.group(6) == "Parent"
        ):
            # Skip header
            continue

        item_match = re.match(
            r"([^\s]+) ({}) ([0]|([1-9][0-9]*)) ([^\s]+) ([^\s]+) ([^\s]+)".format(
                vertex_type_regex
            ),
            line,
        )
        if item_match is not None:
            areas[area][level][ipv].append(
                {
                    "vertex": item_match.group(1),
                    "type": item_match.group(2),
                    "metric": item_match.group(3),
                    "next-hop": item_match.group(5),
                    "interface": item_match.group(6),
                    "parent": item_match.group(7),
                }
            )
            continue

        item_match = re.match(
            r"([^\s]+) ({}) ([0]|([1-9][0-9]*)) ([^\s]+)".format(vertex_type_regex),
            line,
        )

        if item_match is not None:
            areas[area][level][ipv].append(
                {
                    "vertex": item_match.group(1),
                    "type": item_match.group(2),
                    "metric": item_match.group(3),
                    "parent": item_match.group(5),
                }
            )
            continue

        item_match = re.match(r"([^\s]+)", line)
        if item_match is not None:
            areas[area][level][ipv].append({"vertex": item_match.group(1)})
            continue

    return areas
