#!/usr/bin/env python
# SPDX-License-Identifier: ISC

r"""
test_bgp_import_check_zebra_connect.py: a `network` that bgpd applies while
it has no zebra connection must still be checked against the RIB
(`bgp network import-check`, the default) once zebra connects.

    +----+ r1-eth0      10.0.1.0/24      r2-eth0 +----+
    | r1 |---------------------------------------| r2 |
    +----+                                       +----+
     r1-eth1 10.0.2.1/24, r1-eth2 10.0.3.1/24 (stub links)

r1 (AS 65001) has `network 10.0.2.0/24`, a connected route, and
`network 192.0.2.0/24`, for which there is no route at all. r2 (AS 65002)
must learn the first and never the second.

bgpd registers the import-check entry of a `network` with zebra when the
network is applied. Without a zebra connection the registration cannot be
sent, so it has to be sent when zebra connects:

- test_network_applied_before_zebra_connects: bgpd reads its config before
  it has ever connected to zebra, as on a boot where bgpd starts before
  zebra listens. Until zebra connects, every network counts as valid and
  r2 learns 192.0.2.0/24, so it must be withdrawn once zebra connects.
- test_network_added_while_zebra_is_down: a network is added while zebra is
  restarting. It counts as invalid until zebra says otherwise, so
  10.0.3.0/24 must be advertised once zebra is back.

The routers use per-daemon config files, not frr.conf, on purpose: a daemon
that the test restarts reads its own config file at startup, as on a boot.
With frr.conf the harness re-applies the whole config through vtysh after
zebra starts, and re-applying a `network` registers it again, which would
hide the problem.
"""

import os
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step, kill_router_daemons, start_router_daemons

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "r2"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-eth1 and r1-eth2: stub links for the connected routes
    for i in [2, 3]:
        switch = tgen.add_switch("s{}".format(i))
        switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()


def check_r2_routes(present, absent):
    "Return None when r2 has a BGP route for every prefix in present and none in absent"

    r2 = get_topogen().gears["r2"]
    output = r2.vtysh_cmd("show bgp ipv4 unicast json", isjson=True)
    routes = output.get("routes", {})
    for prefix in present:
        if prefix not in routes:
            return "r2 has no route for {}".format(prefix)
    for prefix in absent:
        if prefix in routes:
            return "r2 has a route for {}".format(prefix)
    return None


def check_r1_import_check(expected):
    """
    Return None when r1 has an import-check entry for every address in
    expected that is registered with zebra and whose validity is
    expected[address].
    """

    r1 = get_topogen().gears["r1"]
    output = r1.vtysh_cmd(
        "show bgp import-check-table json", isjson=True, daemon="bgpd"
    )
    entries = output.get("ipv4", {})
    for address, valid in expected.items():
        entry = entries.get(address)
        if entry is None:
            return "r1 has no import-check entry for {}".format(address)
        if entry.get("isRegistered", True) is False:
            return "r1 import-check entry for {} is not registered".format(address)
        if entry.get("valid") != valid:
            return "r1 import-check entry for {} has valid {}, expected {}".format(
                address, entry.get("valid"), valid
            )
    return None


def check_r1_unregistered(addresses):
    "Return None when r1 has an import-check entry for every address and none of them is registered"

    r1 = get_topogen().gears["r1"]
    output = r1.vtysh_cmd(
        "show bgp import-check-table json", isjson=True, daemon="bgpd"
    )
    entries = output.get("ipv4", {})
    for address in addresses:
        entry = entries.get(address)
        if entry is None:
            return "r1 has no import-check entry for {}".format(address)
        if entry.get("isRegistered", True) is not False:
            return "r1 import-check entry for {} is registered".format(address)
    return None


def test_bgp_converge():
    "r2 must learn 10.0.2.0/24 from r1, and not 192.0.2.0/24"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check that r2 has 10.0.2.0/24 and not 192.0.2.0/24")
    test_func = functools.partial(check_r2_routes, ["10.0.2.0/24"], ["192.0.2.0/24"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step("Check r1's import-check entries")
    test_func = functools.partial(
        check_r1_import_check, {"10.0.2.0": True, "192.0.2.0": False}
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_network_applied_before_zebra_connects():
    "Networks that bgpd applies before it ever connects to zebra must be checked once it does"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Stop bgpd and zebra on r1, then start bgpd alone")
    kill_router_daemons(tgen, "r1", ["bgpd", "zebra"], save_config=False)
    start_router_daemons(tgen, "r1", ["bgpd"])

    step("Check that bgpd applied its networks without registering them")
    test_func = functools.partial(check_r1_unregistered, ["10.0.2.0", "192.0.2.0"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    step("Check that r2 has both networks while r1 has not connected to zebra")
    test_func = functools.partial(check_r2_routes, ["10.0.2.0/24", "192.0.2.0/24"], [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step("Start zebra on r1")
    start_router_daemons(tgen, "r1", ["zebra"])

    step("Check that r2 has 10.0.2.0/24 and not 192.0.2.0/24")
    test_func = functools.partial(check_r2_routes, ["10.0.2.0/24"], ["192.0.2.0/24"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step("Check that r1 registered both import-check entries")
    test_func = functools.partial(
        check_r1_import_check, {"10.0.2.0": True, "192.0.2.0": False}
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_network_added_while_zebra_is_down():
    "A network added while zebra is down must be checked once zebra is back"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Stop zebra on r1")
    kill_router_daemons(tgen, "r1", ["zebra"], save_config=False)

    step("Add network 10.0.3.0/24 on r1 while zebra is down")
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          address-family ipv4 unicast
           network 10.0.3.0/24
        """,
        daemon="bgpd",
    )
    test_func = functools.partial(check_r1_unregistered, ["10.0.3.0"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    step("Start zebra on r1")
    start_router_daemons(tgen, "r1", ["zebra"])

    step("Check that r2 has 10.0.2.0/24 and 10.0.3.0/24, and not 192.0.2.0/24")
    test_func = functools.partial(
        check_r2_routes, ["10.0.2.0/24", "10.0.3.0/24"], ["192.0.2.0/24"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step("Check that r1 registered the import-check entry for 10.0.3.0/24")
    test_func = functools.partial(check_r1_import_check, {"10.0.3.0": True})
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
