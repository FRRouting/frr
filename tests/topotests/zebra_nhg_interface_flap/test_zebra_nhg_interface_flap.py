#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_nhg_interface_flap.py
#
# Copyright (c) 2026 Nvidia Inc.
#                    Rajasekar Raja
#

"""
test_zebra_nhg_interface_flap.py: re-send a route after an interface flap.

A route whose kernel nexthop group sits entirely on one interface is removed
by the kernel, together with the group, when that interface goes down. Zebra
re-creates the group when the interface comes back. A client that then sends
the same route again must get it back into the kernel.
"""

import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd]

PREFIX = "10.100.0.1/32"
SHARP_INSTALL = "sharp install routes 10.100.0.1 nexthop 192.168.1.10 1"


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(extra_daemons=["sharpd"])

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _kernel_route(router):
    output = router.run("ip -j route show {}".format(PREFIX))
    try:
        routes = json.loads(output)
    except json.JSONDecodeError:
        return None
    return routes[0] if routes else None


def _kernel_nhg_present(router, nhid):
    output = router.run("ip -j nexthop show id {} 2>/dev/null".format(nhid))
    try:
        return bool(json.loads(output))
    except json.JSONDecodeError:
        return False


def _zebra_interface_up(router, ifname, up):
    output = router.vtysh_cmd("show interface {} json".format(ifname), isjson=True)
    status = output.get(ifname, {}).get("administrativeStatus")
    return status == ("up" if up else "down")


def _skipped_updates(router):
    output = router.vtysh_cmd("show zebra dplane")
    match = re.search(r"Route updates skipped:\s+(\d+)", output)
    return int(match.group(1)) if match else None


def test_route_resend_after_interface_flap():
    "A route re-sent after its whole nexthop group was flushed must be reinstalled"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Install {} through sharpd".format(PREFIX))
    r1.vtysh_cmd(SHARP_INSTALL)

    def _route_in_kernel():
        return _kernel_route(r1) is not None

    _, result = topotest.run_and_expect(_route_in_kernel, True)
    assert result, "{} was never installed in the kernel".format(PREFIX)

    route = _kernel_route(r1)
    if "nhid" not in route:
        pytest.skip("kernel nexthop groups are not in use: {}".format(route))
    nhid = route["nhid"]
    logger.info("%s is in the kernel on nexthop group %s", PREFIX, nhid)

    step("Flap r1-eth0")
    r1.run("ip link set r1-eth0 down")
    _, result = topotest.run_and_expect(
        lambda: _zebra_interface_up(r1, "r1-eth0", False), True
    )
    assert result, "zebra never saw r1-eth0 go down"

    r1.run("ip link set r1-eth0 up")
    _, result = topotest.run_and_expect(
        lambda: _zebra_interface_up(r1, "r1-eth0", True), True
    )
    assert result, "zebra never saw r1-eth0 come back up"

    step("Wait for zebra to put nexthop group {} back".format(nhid))
    _, result = topotest.run_and_expect(lambda: _kernel_nhg_present(r1, nhid), True)
    assert result, "nexthop group {} never came back in the kernel".format(nhid)

    logger.info(
        "Before the re-send: kernel route %s, zebra route %s",
        _kernel_route(r1),
        r1.vtysh_cmd("show ip route {} json".format(PREFIX)),
    )

    skipped_before = _skipped_updates(r1)

    step("Re-send {} unchanged".format(PREFIX))
    r1.vtysh_cmd(SHARP_INSTALL)

    _, result = topotest.run_and_expect(_route_in_kernel, True)
    logger.info(
        "Kernel route updates skipped: before the re-send %s, after %s",
        skipped_before,
        _skipped_updates(r1),
    )
    assert result, "{} is missing from the kernel after the re-send".format(PREFIX)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
