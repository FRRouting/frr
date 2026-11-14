#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Verify that zebra resends a nexthop group that was installed without one
of its depends once that depend is installed.

r1 has an ECMP static route with interface nexthops on two links. The
second link is down when the route is added, so its nexthop is left out
of the group sent to the kernel. The link is then brought up at two
points relative to the group's install:

- while the group's install is still in flight, held with
  "zebra test dplane disable install";
- after the group's install result has been processed.

In both cases the kernel group must end up with both nexthops.

The "zebra test dplane" commands are only built with --enable-dev-build,
so the in-flight case is skipped otherwise.
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
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


def build_topo(tgen):
    tgen.add_router("r1")
    for i in range(1, 5):
        tgen.add_switch("s{}".format(i)).add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for _, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _dplane_test_commands_built(router):
    return "Unknown command" not in router.vtysh_cmd(
        "no zebra test dplane disable install"
    )


def _link(router, ifname, up):
    router.run("ip link set {} {}".format(ifname, "up" if up else "down"))

    def _check():
        out = json.loads(router.vtysh_cmd("show interface {} json".format(ifname)))
        state = out.get(ifname, {}).get("operationalStatus")
        return None if state == ("up" if up else "down") else state

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "{} did not go {}".format(ifname, "up" if up else "down")


def _route_nhg(router, prefix):
    out = json.loads(router.vtysh_cmd("show ip route {}/32 json".format(prefix)))
    for route in out.get("{}/32".format(prefix), []):
        if route.get("protocol") == "static":
            return route.get("nexthopGroupId")
    return None


def _nhg(router, nhg_id):
    out = json.loads(router.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id)))
    return out.get(str(nhg_id), {})


def _check_nhg(router, prefix, flags):
    nhg_id = _route_nhg(router, prefix)
    if nhg_id is None:
        return "no static route for {}".format(prefix)
    nhe = _nhg(router, nhg_id)
    for flag, want in flags.items():
        if bool(nhe.get(flag)) != want:
            return "nhg {} {}={}, want {}: {}".format(
                nhg_id, flag, nhe.get(flag), want, nhe
            )
    return None


def _check_depend(router, prefix, ifname, flags):
    nhg_id = _route_nhg(router, prefix)
    if nhg_id is None:
        return "no static route for {}".format(prefix)
    for dep_id in _nhg(router, nhg_id).get("depends", []):
        dep = _nhg(router, dep_id)
        if dep.get("nexthops", [{}])[0].get("interfaceName") != ifname:
            continue
        for flag, want in flags.items():
            if bool(dep.get(flag)) != want:
                return "depend {} {}={}, want {}: {}".format(
                    dep_id, flag, dep.get(flag), want, dep
                )
        return None
    return "nhg {} has no depend on {}".format(nhg_id, ifname)


def _check_kernel(router, prefix, devs, absent=()):
    out = router.run("ip -4 route show {}".format(prefix))
    for dev in devs:
        if "dev {} ".format(dev) not in out:
            return "{} missing dev {}: {!r}".format(prefix, dev, out)
    for dev in absent:
        if "dev {} ".format(dev) in out:
            return "{} has dev {}: {!r}".format(prefix, dev, out)
    return None


def _wait(func, *args):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args), None, count=30, wait=1
    )
    assert result is None, result


def test_member_ready_while_group_in_flight():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    if not _dplane_test_commands_built(r1):
        pytest.skip("the zebra test dplane commands need --enable-dev-build")

    prefix = "198.51.100.1"
    _link(r1, "r1-eth1", False)

    logger.info("Hold dplane sends, then add the route with r1-eth1 down")
    r1.vtysh_cmd("zebra test dplane disable install")
    r1.vtysh_cmd(
        """
        configure terminal
         ip route {0}/32 r1-eth0
         ip route {0}/32 r1-eth1
        """.format(
            prefix
        )
    )
    try:
        _wait(_check_nhg, r1, prefix, {"queued": True, "installed": False})
        _wait(_check_depend, r1, prefix, "r1-eth1", {"valid": False})

        logger.info("Bring r1-eth1 up while the group install is held")
        _link(r1, "r1-eth1", True)
        _wait(_check_nhg, r1, prefix, {"queued": True, "installed": False})
        _wait(_check_depend, r1, prefix, "r1-eth1", {"valid": True, "queued": True})
    finally:
        logger.info("Release dplane sends")
        r1.vtysh_cmd("no zebra test dplane disable install")

    _wait(_check_kernel, r1, prefix, ["r1-eth0", "r1-eth1"])
    _wait(_check_nhg, r1, prefix, {"installed": True, "partial": False})


def test_member_ready_after_group_installed():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    prefix = "198.51.100.2"
    _link(r1, "r1-eth3", False)

    logger.info("Add the route with r1-eth3 down")
    r1.vtysh_cmd(
        """
        configure terminal
         ip route {0}/32 r1-eth2
         ip route {0}/32 r1-eth3
        """.format(
            prefix
        )
    )
    _wait(_check_nhg, r1, prefix, {"installed": True, "partial": True})
    _wait(_check_kernel, r1, prefix, ["r1-eth2"], ["r1-eth3"])

    logger.info("Bring r1-eth3 up after the group is installed")
    _link(r1, "r1-eth3", True)

    _wait(_check_kernel, r1, prefix, ["r1-eth2", "r1-eth3"])
    _wait(_check_nhg, r1, prefix, {"installed": True, "partial": False})


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
