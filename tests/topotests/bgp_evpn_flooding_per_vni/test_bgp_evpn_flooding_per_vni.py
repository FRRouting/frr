#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def setup_module(mod):
    if not topotest.platform_has_evpn():
        pytest.skip("platform does not support EVPN")

    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_evpn_flooding_per_vni():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.run(f"/bin/bash {CWD}/r1/setup.sh")
    r2.run(f"/bin/bash {CWD}/r2/setup.sh")

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp l2vpn evpn json"))
        expected = {
            "192.168.1.1:3": {
                "rd": "192.168.1.1:3",
                "[3]:[0]:[32]:[192.168.1.1]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "ET:8 RT:65001:20"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.1",
                                    "hostname": "r1",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "192.168.1.2:2": {
                "rd": "192.168.1.2:2",
                "[3]:[0]:[32]:[192.168.1.2]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "RT:65002:10 ET:8"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.2",
                                    "hostname": "r2",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "192.168.1.2:3": {
                "rd": "192.168.1.2:3",
                "[3]:[0]:[32]:[192.168.1.2]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "RT:65002:20 ET:8"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.2",
                                    "hostname": "r2",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "192.168.1.2:4": {
                "rd": "192.168.1.2:4",
                "[3]:[0]:[32]:[192.168.1.2]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "RT:65002:30 ET:8"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.2",
                                    "hostname": "r2",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "numPrefix": 4,
            "totalPrefix": 4,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assert result is None, "Can't see expected EVPN prefix"

    def check_flood_entry():
        if not topotest.iproute2_is_fdb_get_capable():
            return None

        output = int(r2.run("bridge fdb show | grep dst -c"))

        if output == 1:
            return None

        return f"Found more than one FDB entry: {output}"

    test_func = functools.partial(check_flood_entry)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assert result is None, result


def test_bgp_evpn_flooding_per_vni_local():
    """
    r1 floods toward r2 only on the VNIs where its own flooding mode is
    head-end replication, whatever the mode of the other VNIs and the order
    in which they change.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _expect_flooded_vnis(expected, step):
        def _check():
            flooded = [
                vni
                for vni in (10, 20, 30)
                if "00:00:00:00:00:00 dst 192.168.1.2"
                in r1.run("bridge fdb show dev vxlan%d" % vni)
            ]
            if flooded == expected:
                return None
            return "r1 floods toward r2 on VNIs %s, expected %s" % (flooded, expected)

        _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
        assert result is None, "%s: %s" % (step, result)

    def _configure(lines):
        r1.vtysh_cmd(
            "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n" + lines
        )

    def _expect_json(command, expected, step):
        test_func = functools.partial(topotest.router_json_cmp, r1, command, expected)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "%s: unexpected %s" % (step, command)

    def _relearn_remote_vteps(step):
        # zebra installs the flood entries of the remote VTEPs as they come,
        # with the mode it has for their VNI at that time.
        _configure("exit-address-family\nneighbor 192.168.1.2 shutdown\n")
        _expect_json(
            "show evpn vni json",
            {str(vni): {"numRemoteVteps": 0} for vni in (10, 20, 30)},
            step + ", remote VTEPs withdrawn",
        )
        _configure("exit-address-family\nno neighbor 192.168.1.2 shutdown\n")
        _expect_json(
            "show evpn vni json",
            {str(vni): {"numRemoteVteps": 1} for vni in (10, 20, 30)},
            step + ", remote VTEPs learnt again",
        )

    def _expect_vni_config(vni, line, step):
        def _check():
            output = r1.vtysh_cmd("show running-config bgpd")
            match = re.search(r"\n  vni %d\n(.*?)\n  exit-vni" % vni, output, re.DOTALL)
            if match and line in match.group(1).splitlines():
                return None
            return "no '%s' under vni %d" % (line.strip(), vni)

        _, result = topotest.run_and_expect(_check, None, count=5, wait=1)
        assert result is None, "%s: %s" % (step, result)

    # The mode of VNI 20 must reach zebra although it was configured before
    # the VNIs came up.
    _expect_flooded_vnis([20], "startup")

    # A mode of its own for VNI 10 must not change the other VNIs.
    _configure("vni 10\nflooding head-end-replication\n")
    _expect_flooded_vnis([10, 20], "head-end replication on VNI 10")

    # Back to the global mode.
    _configure("vni 10\nno flooding head-end-replication\n")
    _expect_flooded_vnis([20], "VNI 10 back to the global mode")

    # The global mode applies to the VNIs that inherit it only.
    _configure("flooding head-end-replication\n")
    _expect_flooded_vnis([10, 20, 30], "global head-end replication")

    _configure("vni 20\nflooding disable\n")
    _expect_flooded_vnis([10, 30], "flooding disabled on VNI 20")
    _relearn_remote_vteps("flooding disabled on VNI 20")
    _expect_flooded_vnis([10, 30], "flooding disabled on VNI 20, relearnt")

    # Back to the initial configuration.
    _configure("vni 20\nflooding head-end-replication\n")
    _configure("flooding disable\n")
    _expect_flooded_vnis([20], "initial configuration")
    _relearn_remote_vteps("initial configuration")
    _expect_flooded_vnis([20], "initial configuration, relearnt")

    # "no vni" puts the VNI back to the global mode.
    _configure("vni 30\nflooding head-end-replication\n")
    _expect_flooded_vnis([20, 30], "head-end replication on VNI 30")
    _configure("no vni 30\n")
    _expect_flooded_vnis([20], "VNI 30 unconfigured")
    _configure("vni 30\nexit-vni\n")

    # A mode removed while its VNI is down must not stay in zebra.
    _configure("flooding head-end-replication\n")
    _configure("vni 20\nflooding disable\n")
    _expect_flooded_vnis([10, 30], "flooding disabled on VNI 20")
    r1.run("ip link set dev vxlan20 down")
    _expect_json(
        "show bgp l2vpn evpn vni 20 json", {"inKernel": "False"}, "VNI 20 down"
    )
    _configure("vni 20\nno flooding disable\n")
    r1.run("ip link set dev vxlan20 up")
    _expect_flooded_vnis([10, 20, 30], "VNI 20 back to the global mode while down")

    # Back to the initial configuration.
    _configure("vni 20\nflooding head-end-replication\n")
    _configure("flooding disable\n")
    _expect_flooded_vnis([20], "initial configuration")

    # The mode of a VNI is kept in the configuration, even if it is the same
    # as the one of the BGP instance of the VRF of the VNI (VNI 40 in vrf-red,
    # which has an L3VNI).
    _expect_json("show bgp vrf vrf-red vni json", {"l2Vnis": [40]}, "VNI 40 in vrf-red")
    _configure("vni 40\nflooding head-end-replication\n")
    _expect_vni_config(40, "   flooding head-end-replication", "VNI 40 configuration")
    _configure("no vni 40\n")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
