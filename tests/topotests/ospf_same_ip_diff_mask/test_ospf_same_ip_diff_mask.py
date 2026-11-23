#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
One local IPv4 address with two prefix lengths on an OSPF interface.

ospfd keys its interfaces by host address. When the same address is
present with two prefix lengths (for example during a renumbering from
/28 to /27), deleting one of them must leave OSPF running on the
remaining one, and the remaining prefix must be advertised.

Addresses are changed in the kernel, the interfaces are
enabled with "ip ospf area A.B.C.D <address>".

r1-eth1: 192.0.2.1/28 -> add /27, delete /28; plus an unrelated
         192.0.2.129/28 that must not be affected (neighbor r4).
r1-eth2: 198.51.100.1/28 -> add /27, delete /27 (reverse order),
         OSPF on the /28 must not restart (neighbor r3).
r1-eth3: 198.51.100.129/28 single address (control).
"""

import os
import re
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    create_address_on_interface,
    delete_address_on_interface,
    step,
)

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r4"),
        "s3": ("r1", "r3"),
        "s4": ("r1",),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()

    # The LAN addresses are owned by the kernel, not by zebra
    create_address_on_interface(tgen, "r1", "r1-eth1", "192.0.2.1/28")
    create_address_on_interface(tgen, "r1", "r1-eth1", "192.0.2.129/28")
    create_address_on_interface(tgen, "r1", "r1-eth2", "198.51.100.1/28")
    create_address_on_interface(tgen, "r1", "r1-eth3", "198.51.100.129/28")


def teardown_module(mod):
    get_topogen().stop_topology()


def _r2_ospf_routes():
    r2 = get_topogen().gears["r2"]
    output = json.loads(r2.vtysh_cmd("show ip route ospf json"))
    return sorted(output.keys())


def _r1_ospf_addresses(ifname):
    r1 = get_topogen().gears["r1"]
    output = r1.vtysh_cmd("show ip ospf interface {}".format(ifname))
    if "OSPF not enabled on this interface" in output:
        return []
    return sorted(re.findall(r"Internet Address (\S+),", output))


def _r1_nbr_uptime(router_id):
    """Uptime in msec of the Full adjacency with router_id, else None."""
    r1 = get_topogen().gears["r1"]
    output = json.loads(r1.vtysh_cmd("show ip ospf neighbor json"))
    for nbr in output.get("neighbors", {}).get(router_id, []):
        if nbr.get("converged") == "Full":
            return nbr.get("upTimeInMsec")
    return None


def _expect_nbr_full(router_id):
    def _check():
        if _r1_nbr_uptime(router_id) is None:
            return "{} not Full".format(router_id)
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    return result


def _check_nbr_not_restarted(router_id, before):
    after = _r1_nbr_uptime(router_id)
    if after is None or after < before:
        return "adjacency with {} restarted: up {} ms before, {} ms after".format(
            router_id, before, after
        )
    return None


def _expect(present, absent, interfaces):
    def _check():
        routes = _r2_ospf_routes()
        addrs = {i: _r1_ospf_addresses(i) for i in interfaces}
        if (
            all(p in routes for p in present)
            and not any(p in routes for p in absent)
            and addrs == interfaces
        ):
            return None
        return "r2 routes {}, r1 OSPF addresses {}; want routes {} not {}, {}".format(
            routes, addrs, present, absent, interfaces
        )

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    return result


def test_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = _expect(
        ["192.0.2.0/28", "192.0.2.128/28", "198.51.100.0/28", "198.51.100.128/28"],
        [],
        {
            "r1-eth1": ["192.0.2.1/28", "192.0.2.129/28"],
            "r1-eth2": ["198.51.100.1/28"],
            "r1-eth3": ["198.51.100.129/28"],
        },
    )
    assert result is None, result

    for router_id in ["203.0.113.3", "203.0.113.4"]:
        result = _expect_nbr_full(router_id)
        assert result is None, result


def test_delete_bound_prefix():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    uptime = _r1_nbr_uptime("203.0.113.4")
    assert uptime is not None, "203.0.113.4 not Full"

    step("Add 192.0.2.1/27 next to 192.0.2.1/28, then delete the /28")
    create_address_on_interface(tgen, "r1", "r1-eth1", "192.0.2.1/27")
    delete_address_on_interface(tgen, "r1", "r1-eth1", "192.0.2.1/28")

    step("OSPF must run on 192.0.2.1/27, 192.0.2.129/28 must be unaffected")
    result = _expect(
        ["192.0.2.0/27", "192.0.2.128/28"],
        ["192.0.2.0/28"],
        {"r1-eth1": ["192.0.2.1/27", "192.0.2.129/28"]},
    )
    assert result is None, result
    result = _check_nbr_not_restarted("203.0.113.4", uptime)
    assert result is None, result


def test_delete_unbound_prefix():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    uptime = _r1_nbr_uptime("203.0.113.3")
    assert uptime is not None, "203.0.113.3 not Full"

    step("Add 198.51.100.1/27 next to 198.51.100.1/28, then delete the /27")
    create_address_on_interface(tgen, "r1", "r1-eth2", "198.51.100.1/27")
    delete_address_on_interface(tgen, "r1", "r1-eth2", "198.51.100.1/27")

    step("OSPF must keep running on 198.51.100.1/28")
    result = _expect(
        ["198.51.100.0/28"],
        ["198.51.100.0/27"],
        {"r1-eth2": ["198.51.100.1/28"]},
    )
    assert result is None, result
    result = _check_nbr_not_restarted("203.0.113.3", uptime)
    assert result is None, result


def test_single_address():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Delete the only address 198.51.100.129/28, OSPF must stop on it")
    delete_address_on_interface(tgen, "r1", "r1-eth3", "198.51.100.129/28")
    result = _expect([], ["198.51.100.128/28"], {"r1-eth3": []})
    assert result is None, result

    step("Add 198.51.100.129/28 back, OSPF must run on it again")
    create_address_on_interface(tgen, "r1", "r1-eth3", "198.51.100.129/28")
    result = _expect(["198.51.100.128/28"], [], {"r1-eth3": ["198.51.100.129/28"]})
    assert result is None, result


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
