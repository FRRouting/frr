#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2022 6WIND S.A.
#

"""
Test the BGP route-map conditional advertisement from file tracker
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
# *.dmp is ignored from git by .gitignore
TRACKER_PATH = os.path.join(CWD, "{}/tracker.dmp".format("r1"))


# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    tgen = get_topogen()

    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.net["r1"].cmd("[ -f {} ] && rm {}".format(TRACKER_PATH, TRACKER_PATH))
    tgen.stop_topology()


def bgp_check_accept_prefixes_on_r2(nb):
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]

    output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
    expected = {
        "192.168.255.1": {
            "bgpState": "Established",
            "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": nb}},
        }
    }
    return topotest.json_cmp(output, expected)

def router_compare_json_output(rname, command, reference, wait=0.5, count=120):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    ref_str = json.dumps(reference)
    expected = json.loads(ref_str)

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = functools.partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def test1_initial_state():
    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 1)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test2_tracker_down_add_tracker_path_and_route_map_match_tracker():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    # remove previous tracker file
    tgen.net[rname].cmd("[ -f {} ] && rm {}".format(TRACKER_PATH, TRACKER_PATH))
    # configure tracker
    r1.vtysh_cmd("conf\ntracker TRACKER file\n path {}\n".format(TRACKER_PATH))

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": False},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"exist"}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    # apply the route-map to the BGP neighbor
    r1.vtysh_cmd("conf\nrouter bgp 65000\n address-family ipv4 unicast\n  network 192.168.13.0/24 route-map RM-TRACKER\n")

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 0)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test3_tracker_up_add_file():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    # remove previous tracker file
    tgen.net[rname].cmd("touch {}".format(TRACKER_PATH))

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": True},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"exist"}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 1)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test4_tracker_down_add_pattern_master():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd("conf\ntracker TRACKER file\n condition pattern master\n")

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": False},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"pattern", "pattern": "master", "exact": False}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 0)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test5_tracker_down_add_backup_value_to_file():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    tgen.net[rname].cmd("echo backup >{}".format(TRACKER_PATH))

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": False},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"pattern", "pattern": "master", "exact": False}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 0)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test6_tracker_up_set_master_value_in_file():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    tgen.net[rname].cmd("echo master >{}".format(TRACKER_PATH))

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": True},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"pattern", "pattern": "master", "exact": False}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 1)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test7_tracker_up_set_routemap_match_tracker_down():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd("conf\nroute-map RM-TRACKER permit 10\n match tracker TRACKER down\n")

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": True},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"pattern", "pattern": "master", "exact": False}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 0)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test8_tracker_down_set_backup_value_in_file():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    tgen.net[rname].cmd("echo backup >{}".format(TRACKER_PATH))

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": False},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"pattern", "pattern": "master", "exact": False}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 1)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test9_tracker_init_remove_pattern():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd("conf\ntracker TRACKER file\n no condition pattern")

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"description": "init"},
                "path":"{}".format(TRACKER_PATH),
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 0)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test10_tracker_removed():
    def _tracker_removed(router):
        output = json.loads(router.vtysh_cmd("show tracker file json"))
        expect = {
            "file":[]
        }
        return topotest.json_cmp(output, expect, exact=True)

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd("conf\nno tracker TRACKER")

    router = tgen.gears[rname]
    test_func = functools.partial(_tracker_removed, router)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, "Tracker TRACKER still running on {}.".format(rname)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 0)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test11_tracker_down_add_unexisting_path():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd("conf\ntracker TRACKER file\n path /tmp/dontexist\n condition exist")

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": False},
                "path":"/tmp/dontexist",
                "condition":{"type":"exist"}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 1)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test12_tracker_up_set_existing_path():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd("conf\ntracker TRACKER file\n path {}\n".format(TRACKER_PATH))

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": True},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"exist"}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 0)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


def test13_tracker_down_remove_file():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    rname = "r1"
    r1 = tgen.gears[rname]

    tgen.net["r1"].cmd("rm {}".format(TRACKER_PATH, TRACKER_PATH))

    expect = {
        "file":[
            {
                "name":"TRACKER",
                "status":{"value": False},
                "path":"{}".format(TRACKER_PATH),
                "condition":{"type":"exist"}
            }
        ]
    }
    router_compare_json_output(rname, "show tracker file json", expect, 0.5, 10)

    test_func = functools.partial(bgp_check_accept_prefixes_on_r2, 1)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Invalid number of prefixes received on r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
