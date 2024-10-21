#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_sharp_recursive_nexthop.py
#
# Copyright (c) 2020 by 6WIND
#

"""
test_sharp_recursive_nexthop.py
"""

import os
import sys
import pytest
import json
from functools import partial

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step
from lib.nexthopgroup import route_get_nhg_id, verify_nexthop_group_has_nexthop

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def setup_module(mod):
    tgen = Topogen({None: "r1"}, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        router.run(
            "/bin/bash {}".format(os.path.join(CWD, "{}/setup.sh".format(rname)))
        )
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check(router, dest, expected):
    output = json.loads(router.vtysh_cmd("show ip route {0} json".format(dest)))
    output = output.get(f"{dest}")
    if output is None:
        return False
    if "nexthops" not in output[0].keys():
        return False
    if len(expected[0]["nexthops"]) != len(output[0]["nexthops"]):
        return False
    return topotest.json_cmp(output, expected)


def nocheck(router, dest):
    output = json.loads(router.vtysh_cmd("show ip route {0} json".format(dest)))
    return output.get(f"{dest}")


def test_sharp_create_nexthop_and_route():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Check that static route is installed.")
    expected = open_json_file(os.path.join(CWD, "r1/route_static.json"))
    test_func = partial(check, r1, "172.31.0.0/24", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Failed"

    step("From sharpd, creation of a recursive nexthop with route. Check install is ok")
    r1.vtysh_cmd(
        """
        configure terminal\n
        nexthop-group A\n
        allow-recursion\n
        nexthop 172.31.0.55\n
        exit\n
        exit\n
        """
    )

    test_func = partial(verify_nexthop_group_has_nexthop, r1, "172.31.0.55")
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)

    step(
        "From sharpd, install route to 192.168.0.1 using nexthop-group A. Check install is ok"
    )
    r1.vtysh_cmd(
        """
        sharp install routes 192.168.0.1 nexthop-group A 1\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_recursive.json"))
    test_func = partial(check, r1, "192.168.0.1/32", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)


def test_sharp_change_static_route_to_ecmp():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Change static route to ECMP. Check route is ECMP")
    r1.vtysh_cmd(
        """
        configure terminal\n
        ip route 172.31.0.0/24 192.0.2.102\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_static_2.json"))
    test_func = partial(check, r1, "172.31.0.0/24", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)

    step("Update nexthop-group. Check recursive route is refreshed.")
    r1.vtysh_cmd(
        """
        sharp reinstall nexthop-group A\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_recursive_2.json"))
    test_func = partial(check, r1, "192.168.0.1/32", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)


def test_sharp_change_static_route_to_single_nh():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Change static route to a single nexthop. Check route is installed.")
    r1.vtysh_cmd(
        """
        configure terminal\n
        no ip route 172.31.0.0/24 192.0.2.100\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_static_3.json"))
    test_func = partial(check, r1, "172.31.0.0/24", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)

    step("Update nexthop-group. Check recursive route is refreshed.")
    r1.vtysh_cmd(
        """
        sharp reinstall nexthop-group A\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_recursive_3.json"))
    test_func = partial(check, r1, "192.168.0.1/32", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)

def test_sharp_remove_static_route():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Remove static route. Check route is removed.")
    r1.vtysh_cmd(
        """
        configure terminal\n
        no ip route 172.31.0.0/24 192.0.2.102\n
        """
    )
    test_func = partial(nocheck, r1, "172.31.0.0/24")
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)

    step("Update nexthop-group. Check recursive route is inactive.")
    r1.vtysh_cmd(
        """
        sharp reinstall nexthop-group A\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_recursive_4.json"))
    test_func = partial(check, r1, "192.168.0.1/32", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    r1.vtysh_cmd(
        """
        show nexthop-group rib sharp detail\n
        """
    )
    r1.vtysh_cmd(
        """
        show nexthop-group rib sharp detail json\n
        """
    )


def test_sharp_readded_static_route():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Readd static route, but undefined. Check route is still inactive.")
    r1.vtysh_cmd(
        """
        configure terminal\n
        ip route 172.31.0.0/24 192.0.2.202\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_static_4.json"))
    test_func = partial(check, r1, "172.31.0.0/24", expected)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=1)

    step("Update nexthop-group. Check recursive route is active.")
    r1.vtysh_cmd(
        """
        sharp reinstall nexthop-group A\n
        """
    )
    expected = open_json_file(os.path.join(CWD, "r1/route_recursive_5.json"))
    test_func = partial(check, r1, "192.168.0.1/32", expected)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
