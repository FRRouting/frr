#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Import an L2-only VNI's Type-2 route into a VRF without creating a BUM entry.

r1 and r2 peer over s1 and have L3VNI 101. r1 also has L2VNI 100 outside
the VRF, so its SVI MAC/IP advertisement has no Router MAC extended
community. r2 imports that route into vrf-101 using its L2 route target.
"""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import configure_interface_mac, create_static_routes
from lib.evpn import (
    evpn_kernel_vxlan_fdb_entry,
    evpn_plumb_l2vni,
    evpn_plumb_l3vni,
    get_remote_macs,
)
from lib.kernel_routes import kernel_routes
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

ZERO_MAC = "00:00:00:00:00:00"
REMOTE_RMAC = "52:54:00:00:01:65"


def build_topo(tgen):
    for name in ("r1", "r2"):
        tgen.add_router(name)
    switch = tgen.add_switch("s1")
    for router in tgen.routers().values():
        switch.add_link(router)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for index, router in enumerate(tgen.routers().values(), start=1):
        evpn_plumb_l3vni(router, "vrf-101", 101, 101, "192.0.2.{}".format(index))
        result = configure_interface_mac(
            tgen, {router.name: {"br101": "52:54:00:00:0{}:65".format(index)}}
        )
        assert result is True, result
    evpn_plumb_l2vni(tgen.gears["r1"], 100, "192.0.2.1")
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _wait_json(router, command, expected):
    def check():
        output = json.loads(router.vtysh_cmd(command, raises=True))
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, "{}\n{}\n{}".format(
        command, result, router.vtysh_cmd(command)
    )


def test_zero_rmac_is_not_a_flood_destination():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    # Wait for the imported host in zebra's nexthop table, rather than
    # allowing an empty RMAC table before BGP convergence to pass.
    _wait_json(
        r2,
        "show bgp vrf vrf-101 ipv4 unicast json",
        {"routes": {"10.0.100.1/32": [{"valid": True}]}},
    )
    _wait_json(
        r2,
        "show evpn next-hops vni 101 ip 192.0.2.1 json",
        {
            "ip": "192.0.2.1",
            "routerMac": ZERO_MAC,
            "refCount": 1,
            "prefixList": [{"prefix": "10.0.100.1/32", "pathCount": 1}],
        },
    )

    # The imported route is not installed in the kernel. Queue a static
    # route after its nexthop update and wait for it in the kernel, so earlier
    # RMAC installs have completed before checking for the zero-MAC entry.
    result = create_static_routes(
        tgen,
        {
            "r2": {
                "static_routes": [
                    {
                        "network": "203.0.113.254/32",
                        "next_hop": "Null0",
                        "vrf": "vrf-101",
                    }
                ]
            }
        },
    )
    assert result is True, result

    def check_kernel_route():
        return topotest.json_cmp(
            kernel_routes(r2, vrf="vrf-101"),
            [{"dst": "203.0.113.254", "type": "blackhole"}],
        )

    _, result = topotest.run_and_expect(check_kernel_route, None, count=30, wait=1)
    assert result is None, "Static route is missing from the kernel: {}".format(result)

    check_rmacs = partial(get_remote_macs, r2, 101)
    _, result = topotest.run_and_expect(check_rmacs, [], count=30, wait=1)
    assert result == [], "Unexpected remote RMACs: {}".format(result)
    result = evpn_kernel_vxlan_fdb_entry(r2, ZERO_MAC, None, "vxlan101")
    assert result is None, "Zero RMAC created a BUM flood destination: {}".format(
        result
    )

    # Withdrawal must also work when there was no RMAC entry to delete.
    tgen.gears["r1"].vtysh_cmd(
        """configure terminal
router bgp 65000
 address-family l2vpn evpn
  no advertise-svi-ip
"""
    )
    _wait_json(r2, "show evpn next-hops vni 101 json", {"192.0.2.1": None})

    # The guard must still permit a real RMAC from the same VTEP.
    tgen.gears["r1"].vtysh_cmd(
        """configure terminal
router bgp 65000 vrf vrf-101
 address-family ipv4 unicast
  network 198.51.100.1/32
"""
    )
    _, result = topotest.run_and_expect(check_rmacs, [REMOTE_RMAC], count=30, wait=1)
    assert result == [REMOTE_RMAC], "Unexpected remote RMACs: {}".format(result)

    def real_rmac_installed():
        fdb = evpn_kernel_vxlan_fdb_entry(r2, REMOTE_RMAC, None, "vxlan101")
        return fdb is not None and fdb["dst"] == "192.0.2.1"

    _, result = topotest.run_and_expect(real_rmac_installed, True, count=30, wait=1)
    assert result, "Nonzero RMAC was not installed in the kernel FDB"


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak testing is disabled")
    tgen.report_memory_leaks()
