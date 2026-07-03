#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Verify that an L2VNI with no VXLAN local address reaches bgpd and uses the
router-id as its originator IP.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

VNI = 101
ROUTER_ID = "10.0.0.1"


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.cmd_raises(f"ip link add name br{VNI} type bridge")
    router.cmd_raises("ip link set dev r1-eth0 up")
    router.cmd_raises(
        f"ip link add vxlan{VNI} type vxlan id {VNI} dstport 4789 "
        "group 239.1.1.1 dev r1-eth0 nolearning"
    )
    router.cmd_raises(f"ip link set dev vxlan{VNI} master br{VNI}")
    router.cmd_raises(f"ip link set dev br{VNI} up")
    router.cmd_raises(f"ip link set dev vxlan{VNI} up")

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_vni_without_local_vtep_uses_router_id():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _check_bgp_vni():
        output = router.vtysh_cmd(
            f"show bgp l2vpn evpn vni {VNI} json", isjson=True
        )
        expected = {"originatorIp": ROUTER_ID}
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_check_bgp_vni, None, count=30, wait=1)
    assert result is None, (
        f"VNI {VNI} originator IP did not fall back to router-id {ROUTER_ID}"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
