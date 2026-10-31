#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 NVIDIA Corporation
#               Rajasekar Raja
#

"""
Check the hidden "bgp test" commands.

    r3 (192.168.23.3) --+
                        +-- r2 --- r4 (2001:db8:24::4)
    r5 (192.168.23.5) --+

r3 and r5 are IPv4 iBGP peers of r2 with the same outbound policy, so they
share one update subgroup. r4 is an IPv6 iBGP peer. r2 originates
10.0.1.0/24 towards r3 and r5, and 2001:db8:1::/64 towards r4.

- "bgp test metaq disable": r2 keeps the route queued for best path, so it
  is neither selected nor sent until the meta queue is unplugged.
- "bgp test updates disable": r2 selects the routes but sends no UPDATE
  until UPDATEs are unplugged.
- "bgp test updates disable neighbor X": only X gets no UPDATE.
  - IPv4: r3 is held while r5, in the same subgroup, still gets the route.
    r3 gets it once released.
  - IPv6: r4 is held while r3 still gets its route.

"bgp test updates disable" is only built with --enable-dev-build, so its
tests are skipped otherwise.
"""

import functools
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

R3 = "192.168.23.3"
R4 = "2001:db8:24::4"
R5 = "192.168.23.5"
PFX4 = "10.0.1.0/24"
PFX6 = "2001:db8:1::/64"


def build_topo(tgen):
    for rname in ["r2", "r3", "r4", "r5"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _afi(prefix):
    return "ipv6" if ":" in prefix else "ipv4"


def _paths(router, prefix):
    output = router.vtysh_cmd(
        "show bgp {} unicast {} json".format(_afi(prefix), prefix), isjson=True
    )
    return output.get("paths", [])


def _check_route(router, prefix, best=None, pending=None):
    """None if router has a path for prefix in the given state."""
    for path in _paths(router, prefix):
        if best is not None and path.get("bestpath", {}).get("overall", False) != best:
            continue
        if pending is not None and path.get("processScheduled", False) != pending:
            continue
        return None
    return "{} has no path for {} with best={} pending={}".format(
        router.name, prefix, best, pending
    )


def _check_no_route(router, prefix):
    return (
        "{} has a path for {}".format(router.name, prefix)
        if _paths(router, prefix)
        else None
    )


def _subgroup(router, nbr):
    output = router.vtysh_cmd("show bgp neighbor {} json".format(nbr), isjson=True)
    return output[nbr]["addressFamilyInfo"]["ipv4Unicast"].get("subGroupId")


def _check_same_subgroup(router, nbr1, nbr2):
    sub1, sub2 = _subgroup(router, nbr1), _subgroup(router, nbr2)
    if sub1 is None or sub1 != sub2:
        return "{} is in subgroup {}, {} in {}, want them together".format(
            nbr1, sub1, nbr2, sub2
        )
    return None


def _wait(func, *args, **kwargs):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args, **kwargs), None, count=30, wait=1
    )
    assert result is None, result


def _stays_absent(router, prefix, seconds=3):
    for _ in range(seconds):
        time.sleep(1)
        result = _check_no_route(router, prefix)
        assert result is None, result


def _network(prefix, enable):
    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 65000
          address-family {} unicast
           {}network {}
        """.format(
            _afi(prefix), "" if enable else "no ", prefix
        )
    )


def _updates_hold_built(router):
    """Release the UPDATE hold for every peer. False if bgpd was built
    without the command."""
    return "Unknown command" not in router.vtysh_cmd("no bgp test updates disable")


def _reset():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("no bgp test metaq disable")
    if _updates_hold_built(r2):
        r2.vtysh_cmd("no bgp test updates disable neighbor {}".format(R3))
        r2.vtysh_cmd("no bgp test updates disable neighbor {}".format(R4))
    _network(PFX4, False)
    _network(PFX6, False)
    for rname in ["r3", "r5"]:
        _wait(_check_no_route, tgen.gears[rname], PFX4)
    _wait(_check_no_route, tgen.gears["r4"], PFX6)


def test_bgp_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    for peer in [R3, R4, R5]:
        expected = {peer: {"bgpState": "Established"}}
        test_func = functools.partial(
            topotest.router_json_cmp,
            r2,
            "show bgp neighbor {} json".format(peer),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "r2 to {} not established".format(peer)


def test_metaq_disable():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2, r3 = tgen.gears["r2"], tgen.gears["r3"]
    _reset()

    step("Plug the meta queue on r2, then originate {}".format(PFX4))
    r2.vtysh_cmd("bgp test metaq disable")
    _network(PFX4, True)
    _wait(_check_route, r2, PFX4, best=False, pending=True)
    _stays_absent(r3, PFX4)

    step("Unplug the meta queue: r2 selects the route and r3 gets it")
    r2.vtysh_cmd("no bgp test metaq disable")
    _wait(_check_route, r2, PFX4, best=True, pending=False)
    _wait(_check_route, r3, PFX4)


def test_updates_disable():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2, r3, r4, r5 = (tgen.gears[r] for r in ["r2", "r3", "r4", "r5"])
    if not _updates_hold_built(r2):
        pytest.skip("bgp test updates disable needs --enable-dev-build")
    _reset()

    step("Plug UPDATEs on r2, then originate both prefixes")
    r2.vtysh_cmd("bgp test updates disable")
    _network(PFX4, True)
    _network(PFX6, True)
    _wait(_check_route, r2, PFX4, best=True, pending=False)
    _wait(_check_route, r2, PFX6, best=True, pending=False)
    _stays_absent(r3, PFX4)
    _stays_absent(r5, PFX4)
    _stays_absent(r4, PFX6)

    step("Unplug UPDATEs: r3, r4 and r5 get their prefixes")
    r2.vtysh_cmd("no bgp test updates disable")
    _wait(_check_route, r3, PFX4)
    _wait(_check_route, r5, PFX4)
    _wait(_check_route, r4, PFX6)


@pytest.mark.parametrize(
    "held, held_pfx, other, other_pfx",
    [("r3", PFX4, "r5", PFX4), ("r4", PFX6, "r3", PFX4)],
    ids=["ipv4_neighbor", "ipv6_neighbor"],
)
def test_updates_disable_neighbor(held, held_pfx, other, other_pfx):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    nbr = R3 if held == "r3" else R4
    if not _updates_hold_built(r2):
        pytest.skip("bgp test updates disable needs --enable-dev-build")
    _reset()

    if held == "r3":
        step("r3 and r5 share a subgroup on r2")
        _wait(_check_same_subgroup, r2, R3, R5)

    step("Plug UPDATEs on r2 for {} only, then originate both prefixes".format(nbr))
    r2.vtysh_cmd("bgp test updates disable neighbor {}".format(nbr))
    _network(PFX4, True)
    _network(PFX6, True)
    _wait(_check_route, tgen.gears[other], other_pfx)
    _wait(_check_route, r2, held_pfx, best=True, pending=False)
    _stays_absent(tgen.gears[held], held_pfx)

    step("Unplug UPDATEs for {}: {} gets {}".format(nbr, held, held_pfx))
    r2.vtysh_cmd("no bgp test updates disable neighbor {}".format(nbr))
    _wait(_check_route, tgen.gears[held], held_pfx)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
