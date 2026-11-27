#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""Global RIP/RIPng filters must use the same internal key on add and delete."""

import functools
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ripd, pytest.mark.ripngd]


def setup_module(mod):
    tgen = Topogen({"s1": ("r1", "r2")}, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config(daemons=["zebra", "ripd", "ripngd"])
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def route_state(router, family, protocol, denied, control, filtered):
    routes = router.vtysh_cmd(
        "show {} route {} json".format(family, protocol), isjson=True
    )
    expected = {control: [{"protocol": protocol}]}
    expected[denied] = None if filtered else [{"protocol": protocol}]
    return topotest.json_cmp(routes, expected)


def check_routes(router, family, protocol, denied, control, filtered):
    check = functools.partial(
        route_state, router, family, protocol, denied, control, filtered
    )
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, result
    # Require several periodic updates while the control route remains learned.
    # An empty table immediately after a restart must never count as success.
    if filtered:
        for _ in range(5):
            time.sleep(1)
            assert check() is None, "filter/control route state did not remain stable"


@pytest.mark.parametrize(
    "protocol,family,denied,control",
    [
        ("rip", "ip", "198.51.100.0/24", "203.0.113.0/24"),
        ("ripng", "ipv6", "2001:db8:5::/64", "2001:db8:6::/64"),
    ],
)
@pytest.mark.parametrize("direction", ["in", "out"])
@pytest.mark.parametrize("kind", ["prefix", "access"])
def test_global_distribute_list(protocol, family, denied, control, direction, kind):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    receiver = tgen.gears["r1"]
    target = receiver if direction == "in" else tgen.gears["r2"]
    name = "FILTER4" if family == "ip" else "FILTER6"
    if kind == "access":
        name += "ACL"
    command = "{}distribute-list {}{} {}".format(
        "ipv6 " if family == "ipv6" else "",
        "prefix " if kind == "prefix" else "",
        name,
        direction,
    )

    def configure(line):
        output = target.vtysh_cmd(
            "configure terminal\nrouter {}\n{}".format(protocol, line)
        )
        output = output.replace("% Configuration applied with notes:", "")
        assert "%" not in output, output

    check_routes(receiver, family, protocol, denied, control, False)
    active = None
    try:
        configure(command)
        active = command
        check_routes(receiver, family, protocol, denied, control, True)
        configure("no " + command)
        active = None
        check_routes(receiver, family, protocol, denied, control, False)
        # A nonempty interface key must retain its existing behavior.
        interface_command = command + " " + target.name + "-eth0"
        configure(interface_command)
        active = interface_command
        check_routes(receiver, family, protocol, denied, control, True)
        configure("no " + interface_command)
        active = None
        check_routes(receiver, family, protocol, denied, control, False)
        # Recreate the global entry after the old one was destroyed.
        configure(command)
        active = command
        check_routes(receiver, family, protocol, denied, control, True)
    finally:
        if active:
            configure("no " + active)
    check_routes(receiver, family, protocol, denied, control, False)
