#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Test SRv6 L3VPN multi-NLRI handling: a single BGP UPDATE carrying
# multiple VPN prefixes must preserve srv6_l3service for every prefix.

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("ce")
    tgen.add_router("pe1")
    tgen.add_router("pe2")

    # ce <-> pe1 (vrf side)
    tgen.add_link(tgen.gears["ce"], tgen.gears["pe1"], "eth0", "eth1")
    # pe1 <-> pe2 (interface peering, IPv6)
    tgen.add_link(tgen.gears["pe1"], tgen.gears["pe2"], "eth0", "eth0")


def setup_module(mod):
    result = required_linux_kernel_version("5.14")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        setup = os.path.join(CWD, "{}/setup.sh".format(rname))
        if os.path.exists(setup):
            router.run("/bin/bash {}".format(setup))
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file, count=120, wait=1):
    def _check():
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    _, result = topotest.run_and_expect(_check, None, count, wait)
    assert result is None, "Failed: {} {}".format(name, cmd)


def test_multi_nlri_vpn_rib():
    """All 10 prefixes carried in the multi-NLRI UPDATE must appear in PE2's VPN RIB."""
    check_rib("pe2", "show bgp ipv4 vpn json", "pe2/vpnv4_rib.json")


def test_multi_nlri_vrf_rib():
    """All 10 prefixes must be installed in PE2's VRF; without the fix only the
    first prefix gets its srv6_l3service and the rest are dropped during VPN-to-VRF
    leak, leaving a single VRF entry instead of 10."""
    check_rib("pe2", "show ip route vrf Vrf1 json", "pe2/vrf1_rib.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
