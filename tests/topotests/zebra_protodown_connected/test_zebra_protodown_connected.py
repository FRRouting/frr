#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test for duplicate connected routes during interface state transitions.
"""

import os
import sys
import pytest
import json
from time import sleep

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.vrrpd]


def build_topo(tgen):
    tgen.add_router("vrrp1")
    tgen.add_router("vrrp2")
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["vrrp1"])
    switch.add_link(tgen.gears["vrrp2"])
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def has_duplicate_routes(router, prefix):
    """Return True if any interface appears more than once for prefix."""
    output = router.vtysh_cmd("show ip route {} json".format(prefix))
    try:
        routes = json.loads(output)
        if prefix not in routes:
            return False

        iface_counts = {}
        for route in routes[prefix]:
            if route.get("protocol") != "connected":
                continue
            for nh in route.get("nexthops", []):
                ifname = nh.get("interfaceName", "")
                iface_counts[ifname] = iface_counts.get(ifname, 0) + 1

        return any(count > 1 for count in iface_counts.values())
    except Exception:
        return False


def test_physical_updown():
    """Test physical interface up/down toggle."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vrrp2 = tgen.gears["vrrp2"]
    prefix = "192.168.100.0/24"

    sleep(5)  # Wait for initial convergence

    # Toggle up/down
    for _ in range(20):
        vrrp2.run("ip link set vrrp2-eth0 down")
        vrrp2.run("ip link set vrrp2-eth0 up")

    sleep(2)

    routes = vrrp2.vtysh_cmd("show ip route {}".format(prefix))
    logger.info("Physical interface routes:\n{}".format(routes))

    assert not has_duplicate_routes(
        vrrp2, prefix
    ), "DUPLICATE ROUTES on physical!\nRoutes:\n{}".format(routes)


def test_vlan_updown():
    """Test VLAN interface up/down toggle."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vrrp2 = tgen.gears["vrrp2"]
    vlan_if = "vrrp2-eth0.101"
    prefix = "50.0.0.0/24"

    # Create VLAN
    vrrp2.run("ip link del {} 2>/dev/null || true".format(vlan_if))
    cmd = "ip link add link vrrp2-eth0 name {} type vlan id 101"
    vrrp2.run(cmd.format(vlan_if))
    vrrp2.run("ip addr add 50.0.0.1/24 dev {}".format(vlan_if))
    vrrp2.run("ip link set {} up".format(vlan_if))
    sleep(2)

    # Toggle up/down
    for _ in range(20):
        vrrp2.run("ip link set {} down".format(vlan_if))
        vrrp2.run("ip link set {} up".format(vlan_if))

    sleep(2)

    routes = vrrp2.vtysh_cmd("show ip route {}".format(prefix))
    logger.info("VLAN routes:\n{}".format(routes))

    vrrp2.run("ip link del {} 2>/dev/null || true".format(vlan_if))

    assert not has_duplicate_routes(
        vrrp2, prefix
    ), "DUPLICATE ROUTES on VLAN!\nRoutes:\n{}".format(routes)


def test_macvlan_updown():
    """Test macvlan up/down toggle (like VRRP)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vrrp2 = tgen.gears["vrrp2"]
    macvlan = "test-mv"
    prefix = "10.99.0.0/24"

    # Create macvlan
    vrrp2.run("ip link del {} 2>/dev/null || true".format(macvlan))
    cmd = "ip link add {} link vrrp2-eth0 type macvlan mode bridge"
    vrrp2.run(cmd.format(macvlan))
    vrrp2.run("ip addr add 10.99.0.1/24 dev {}".format(macvlan))
    vrrp2.run("ip link set {} up".format(macvlan))
    sleep(2)

    # Toggle up/down
    for _ in range(20):
        vrrp2.run("ip link set {} down".format(macvlan))
        vrrp2.run("ip link set {} up".format(macvlan))

    sleep(2)

    routes = vrrp2.vtysh_cmd("show ip route {}".format(prefix))
    logger.info("Macvlan routes:\n{}".format(routes))

    vrrp2.run("ip link del {} 2>/dev/null || true".format(macvlan))

    assert not has_duplicate_routes(
        vrrp2, prefix
    ), "DUPLICATE ROUTES on macvlan!\nRoutes:\n{}".format(routes)


def test_rapid_updown():
    """Test rapid interface up/down."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vrrp2 = tgen.gears["vrrp2"]
    vlan_if = "vrrp2-eth0.102"
    prefix = "60.0.0.0/24"

    # Create VLAN
    vrrp2.run("ip link del {} 2>/dev/null || true".format(vlan_if))
    cmd = "ip link add link vrrp2-eth0 name {} type vlan id 102"
    vrrp2.run(cmd.format(vlan_if))
    vrrp2.run("ip addr add 60.0.0.1/24 dev {}".format(vlan_if))
    vrrp2.run("ip link set {} up".format(vlan_if))
    sleep(2)

    # Rapid up/down
    for _ in range(30):
        vrrp2.run("ip link set {} down".format(vlan_if))
        vrrp2.run("ip link set {} up".format(vlan_if))

    sleep(2)

    routes = vrrp2.vtysh_cmd("show ip route {}".format(prefix))
    logger.info("Routes after up/down:\n{}".format(routes))

    vrrp2.run("ip link del {} 2>/dev/null || true".format(vlan_if))

    assert not has_duplicate_routes(
        vrrp2, prefix
    ), "DUPLICATE ROUTES after up/down!\nRoutes:\n{}".format(routes)


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
