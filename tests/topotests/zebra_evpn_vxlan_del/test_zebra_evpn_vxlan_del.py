#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_evpn_vxlan_del.py
#
# Copyright 2026 6WIND S.A.
#

"""
test_zebra_evpn_vxlan_del.py: check that zebra frees the L2-VNI entry bound
to a VxLAN interface deleted while EVPN is disabled.

The L2-VNI entry is created by removing the vrf-vni mapping of an L3-VNI
after bgpd has stopped (EVPN disabled). If the entry survives the deletion
of its VxLAN interface, it keeps a reference to the freed interface, which
is dereferenced when EVPN is enabled again.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.common_config import retry, kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.cmd_raises("ip link add l3vrf1 type vrf table 101")
    r1.cmd_raises("ip link set l3vrf1 up")
    r1.cmd_raises("ip link add br101 type bridge")
    r1.cmd_raises("ip link set br101 master l3vrf1 addrgenmode none")
    r1.cmd_raises(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.0.0.1 nolearning"
    )
    r1.cmd_raises("ip link set vxlan101 master br101 addrgenmode none")
    r1.cmd_raises("ip link set br101 up")
    r1.cmd_raises("ip link set vxlan101 up")

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_vni_hash_count(router):
    output = router.vtysh_cmd("show memory", daemon="zebra")
    for line in output.splitlines():
        if line.startswith("VNI hash"):
            return int(line.split(":")[1].split()[0])
    # The memory type is not displayed until it is allocated once
    return 0


@retry(retry_timeout=30)
def check_vni_hash_count(router, expected):
    count = get_vni_hash_count(router)
    if count != expected:
        return "{} L2-VNI entries in zebra, expected {}".format(count, expected)
    return True


@retry(retry_timeout=30)
def check_evpn(router, expected):
    output = json.loads(router.vtysh_cmd("show evpn json"))
    if expected is None:
        if output:
            return "EVPN still enabled: {}".format(output)
        return True

    for key, value in expected.items():
        if output.get(key) != value:
            return "{} is {}, expected {}: {}".format(
                key, output.get(key), value, output
            )
    return True


def test_evpn_enabled():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    result = check_evpn(r1, {"numL2Vnis": 0, "numL3Vnis": 1})
    assert result is True, result


def test_evpn_disabled_vxlan_del():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # EVPN is disabled when bgpd disconnects from zebra. bgpd is not
    # running until the end of the test, so routers_have_failure()
    # must not be called before.
    kill_router_daemons(tgen, "r1", ["bgpd"], save_config=False)
    result = check_evpn(r1, None)
    assert result is True, result

    # Removing the vrf-vni mapping turns VNI 101 into an L2-VNI
    r1.vtysh_cmd(
        """
        configure terminal
         vrf l3vrf1
          no vni 101
         exit-vrf
        """
    )
    result = check_vni_hash_count(r1, 1)
    assert result is True, result

    # The L2-VNI entry must be freed with its VxLAN interface
    r1.cmd_raises("ip link del vxlan101")
    result = check_vni_hash_count(r1, 0)
    assert result is True, result

    # Enabling EVPN again walks the L2-VNI entries and their VxLAN interface.
    # Do not re-apply frr.conf when bgpd restarts, it would restore the
    # vrf-vni mapping removed above. Only the bgp configuration is applied.
    r1.net.skip_unified_vtysh = True
    start_router_daemons(tgen, "r1", ["bgpd"])
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          bgp router-id 10.0.0.1
          no bgp default ipv4-unicast
          address-family l2vpn evpn
           advertise-all-vni
        """
    )
    result = check_evpn(r1, {"numL2Vnis": 0, "numL3Vnis": 0})
    assert result is True, result

    assert not tgen.routers_have_failure(), tgen.errors


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
