#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test IS-IS leaking of level-1 prefixes into the level-2 LSP of a level-1-2
router (RFC 1195).

    r1 (L1) ---- r2 (L1/L2) ---- r3 (L2)

Without leaking, r3 has no route to the loopback of r1, and r1 can only
reach r3 through the default route announced with the attached bit.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.checkping import check_ping
from lib.common_config import step
from lib.kernel_routes import kernel_routes
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    """Build the r1 (L1) - r2 (L1/L2) - r3 (L2) topology."""
    for router in ("r1", "r2", "r3"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _expect(router, cmd, expected, count=60, wait=0.5):
    test_func = functools.partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    return result


def _route_absent(router, cmd, prefix):
    routes = json.loads(router.vtysh_cmd(cmd))
    if prefix in routes:
        return "{} is present in {}".format(prefix, routes)
    return None


def _route_diagnostics(router, prefix):
    ipv6 = ":" in prefix
    if prefix == "default":
        prefix = "0.0.0.0/0"
    elif "/" not in prefix:
        prefix += "/128" if ipv6 else "/32"

    kernel_prefix = prefix.split("/")[0] if prefix.endswith(("/32", "/128")) else prefix
    if kernel_prefix == "0.0.0.0/0":
        kernel_prefix = "default"
    kernel = [
        route
        for route in kernel_routes(router, family="ipv6" if ipv6 else "ipv4")
        if route.get("dst") == kernel_prefix
    ]
    zebra_cmd = "show {} route {} json".format("ipv6" if ipv6 else "ip", prefix)
    zebra = router.vtysh_cmd(zebra_cmd, isjson=True)
    diagnostics = "{}: kernel route {}\n{}\n{}: {}\n{}".format(
        router.name,
        prefix,
        json.dumps(kernel, indent=2),
        router.name,
        zebra_cmd,
        json.dumps(zebra, indent=2),
    )
    if not zebra.get(prefix):
        diagnostics += "\n{}: show isis route\n{}".format(
            router.name, router.vtysh_cmd("show isis route")
        )
    return diagnostics


def test_l1_prefixes_are_leaked_into_l2():
    """r3 must learn the loopbacks of r1 with the cost of the path to r1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    step("Check the IPv4 loopback of r1 on r3")
    expected = {"1.1.1.1/32": [{"protocol": "isis", "selected": True, "metric": 30}]}
    result = _expect(r3, "show ip route 1.1.1.1/32 json", expected)
    assert result is None, "{}\n{}".format(result, _route_diagnostics(r3, "1.1.1.1/32"))

    step("Check the IPv6 loopback of r1 on r3")
    expected = {
        "2001:db8:1::1/128": [{"protocol": "isis", "selected": True, "metric": 30}]
    }
    result = _expect(r3, "show ipv6 route 2001:db8:1::1/128 json", expected)
    assert result is None, "{}\n{}".format(
        result, _route_diagnostics(r3, "2001:db8:1::1/128")
    )

    step("Wait for the kernel routes for the ping and its reply")

    def kernel_route_cmp(router, expected):
        return topotest.json_cmp(kernel_routes(router), expected)

    ping_routes = (
        ("r3", "1.1.1.1", "10.0.23.2", "r3-eth0"),
        ("r2", "1.1.1.1", "10.0.12.1", "r2-eth0"),
        ("r1", "default", "10.0.12.2", "r1-eth0"),
        ("r2", "2.2.2.2", "10.0.23.3", "r2-eth1"),
    )
    for name, prefix, nexthop, interface in ping_routes:
        expected = [{"dst": prefix, "gateway": nexthop, "dev": interface}]
        test_func = functools.partial(kernel_route_cmp, tgen.gears[name], expected)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "{}: kernel route {} not ready: {}\n{}".format(
            name, prefix, result, _route_diagnostics(tgen.gears[name], prefix)
        )

    step("Check that r3 can reach r1")
    try:
        check_ping("r3", "1.1.1.1", True, count=60, wait=0.5, source_addr="2.2.2.2")
    except AssertionError as error:
        pytest.fail(
            "r3: ping from 2.2.2.2 to 1.1.1.1 failed: {}\n{}".format(
                error,
                "\n".join(
                    _route_diagnostics(tgen.gears[name], prefix)
                    for name, prefix, _, _ in ping_routes
                ),
            )
        )


def test_leaked_prefixes_in_l2_lsp():
    """The leaked prefixes must be in the L2 LSP of r2 with the right metric."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    step("Check the leaked IPv4 prefix in the L2 LSP of r2")
    expected = {
        "areas": [
            {
                "levels": [
                    {
                        "id": 2,
                        "lsps": [
                            {
                                "lsp": {"id": "r2.00-00"},
                                "extIpReach": [
                                    {
                                        "ipReach": "1.1.1.1/32",
                                        "ipReachMetric": 20,
                                        "down": False,
                                    }
                                ],
                                "ipv6Reach": [
                                    {
                                        "prefix": "2001:db8:1::1/128",
                                        "metric": 20,
                                        "down": False,
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    result = _expect(r3, "show isis database detail r2.00-00 json", expected)
    assert result is None, result

    step("A prefix r2 advertises itself must not be duplicated")
    lsp = json.loads(r3.vtysh_cmd("show isis database detail r2.00-00 json"))
    entries = lsp["areas"][0]["levels"][0]["lsps"][0]["extIpReach"]
    prefixes = [e["ipReach"] for e in entries]
    assert len(prefixes) == len(set(prefixes)), prefixes


def test_l1_keeps_default_route_and_gets_no_l2_prefixes():
    """Nothing is leaked from L2 into L1: r1 still uses the attached-bit default."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("r1 has the default route from the attached bit")
    expected = {"0.0.0.0/0": [{"protocol": "isis", "selected": True}]}
    result = _expect(r1, "show ip route 0.0.0.0/0 json", expected)
    assert result is None, result

    step("r1 has no specific route to the loopback of r3")
    result = _route_absent(r1, "show ip route 2.2.2.2/32 json", "2.2.2.2/32")
    assert result is None, result


def test_leaking_follows_changes():
    """Added and removed level-1 prefixes must follow into level-2."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    step("Add loopback addresses on r1")
    r1.run("ip addr add 1.1.1.99/32 dev lo")
    r1.run("ip -6 addr add 2001:db8:1::99/128 dev lo")

    expected = {"1.1.1.99/32": [{"protocol": "isis", "selected": True}]}
    result = _expect(r3, "show ip route 1.1.1.99/32 json", expected)
    assert result is None, result

    expected = {"2001:db8:1::99/128": [{"protocol": "isis", "selected": True}]}
    result = _expect(r3, "show ipv6 route 2001:db8:1::99/128 json", expected)
    assert result is None, result

    step("Remove the loopback addresses again")
    r1.run("ip addr del 1.1.1.99/32 dev lo")
    r1.run("ip -6 addr del 2001:db8:1::99/128 dev lo")

    test_func = functools.partial(
        _route_absent, r3, "show ip route 1.1.1.99/32 json", "1.1.1.99/32"
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    test_func = functools.partial(
        _route_absent,
        r3,
        "show ipv6 route 2001:db8:1::99/128 json",
        "2001:db8:1::99/128",
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def _count_prefix_in_l2_lsp(router, prefix):
    """Count how many times prefix is advertised in the L2 LSP of r2."""
    lsp = json.loads(router.vtysh_cmd("show isis database detail r2.00-00 json"))
    for level in lsp["areas"][0]["levels"]:
        if level["id"] != 2:
            continue
        for entry in level["lsps"]:
            if entry["lsp"]["id"] == "r2.00-00":
                return len(
                    [e for e in entry.get("extIpReach", []) if e["ipReach"] == prefix]
                )
    return 0


def test_leaked_and_redistributed_prefix_is_advertised_once():
    """A prefix that is both leaked from L1 and redistributed on r2 appears once."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Add a prefix on r1 and the same prefix as a kernel route on r2")
    r1.run("ip addr add 9.9.9.9/32 dev lo")
    r2.run("ip route add 9.9.9.9/32 dev lo proto boot")
    r2.vtysh_multicmd(
        "configure terminal\nrouter isis TEST\nredistribute ipv4 kernel level-2"
    )

    step("The prefix reaches level 2")
    expected = {"9.9.9.9/32": [{"protocol": "isis", "selected": True}]}
    result = _expect(r3, "show ip route 9.9.9.9/32 json", expected)
    assert result is None, result

    step("It is advertised once in the L2 LSP of r2")
    test_func = functools.partial(_count_prefix_in_l2_lsp, r3, "9.9.9.9/32")
    _, result = topotest.run_and_expect(test_func, 1, count=60, wait=0.5)
    assert result == 1, "9.9.9.9/32 is advertised {} times".format(result)

    step("Clean up")
    r2.vtysh_multicmd(
        "configure terminal\nrouter isis TEST\nno redistribute ipv4 kernel level-2"
    )
    r2.run("ip route del 9.9.9.9/32 dev lo proto boot")
    r1.run("ip addr del 9.9.9.9/32 dev lo")


def test_leaking_can_be_switched_off_and_on():
    """The leaking is disabled by default; 'no leak level-1 into level-2' disables it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("The leaking is enabled in the configuration of r2")
    assert " leak level-1 into level-2" in r2.vtysh_cmd("show running-config")

    step("Disable the leaking on r2")
    r2.vtysh_multicmd(
        "configure terminal\nrouter isis TEST\nno leak level-1 into level-2"
    )

    step("The loopbacks of r1 disappear from r3")
    for cmd, prefix in (
        ("show ip route json", "1.1.1.1/32"),
        ("show ipv6 route json", "2001:db8:1::1/128"),
    ):
        test_func = functools.partial(_route_absent, r3, cmd, prefix)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, result

    step("The default, disabled, is not shown in the running configuration")
    assert "leak level-1 into level-2" not in r2.vtysh_cmd("show running-config")

    step("Enable the leaking again")
    r2.vtysh_multicmd("configure terminal\nrouter isis TEST\nleak level-1 into level-2")

    step("The loopbacks of r1 are back on r3")
    expected = {"1.1.1.1/32": [{"protocol": "isis", "selected": True, "metric": 30}]}
    result = _expect(r3, "show ip route 1.1.1.1/32 json", expected)
    assert result is None, result
    expected = {
        "2001:db8:1::1/128": [{"protocol": "isis", "selected": True, "metric": 30}]
    }
    result = _expect(r3, "show ipv6 route 2001:db8:1::1/128 json", expected)
    assert result is None, result

    step("The setting is part of the running configuration again")
    assert " leak level-1 into level-2" in r2.vtysh_cmd("show running-config")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
