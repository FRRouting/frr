#!/usr/bin/env python

#
# bgp_evpn_autort.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Alexandre Derumier <aderumier@odiso.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
bgp_evpn_autort.py:

"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo


class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        for routern in range(1, 3):
            tgen.add_router("r{}".format(routern))

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    router = tgen.gears["r2"]

    cmds_r2 = [  # config routing 101
        "ip link add name bridge-101 up type bridge stp_state 0",
        "ip link set bridge-101 master {}-vrf-101",
        "ip link set dev bridge-101 up",
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r2-eth0 local 192.168.255.2",
        "ip link set dev vxlan-101 master bridge-101",
        "ip link set vxlan-101 up type bridge_slave learning off flood off mcast_flood off",
    ]

    for cmd in cmds_r2:
        logger.info("cmd to r2: " + cmd.format("r2"))
        output = router.run(cmd.format("r2"))
        logger.info("result: " + output)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_evpn_autort():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _verify_vni_65000(router):
        output = json.loads(router.vtysh_cmd("sh bgp l2vpn evpn vni 101 json"))
        expected = {
            "vni":101,
            "type":"L2",
            "inKernel":"True",
            "rd":"192.168.255.2:2",
            "originatorIp":"192.168.255.2",
            "mcastGroup":"0.0.0.0",
            "advertiseGatewayMacip":"Disabled",
            "advertiseSviMacIp":"Disabled",
            "importRts":[
              "65000:101"
            ],
            "exportRts":[
              "65000:101"
            ]
        }
        return topotest.json_cmp(output, expected)

    def _verify_vni_65001(router):
        output = json.loads(router.vtysh_cmd("sh bgp l2vpn evpn vni 101 json"))
        expected = {
            "vni":101,
            "type":"L2",
            "inKernel":"True",
            "rd":"192.168.255.2:2",
            "originatorIp":"192.168.255.2",
            "mcastGroup":"0.0.0.0",
            "advertiseGatewayMacip":"Disabled",
            "advertiseSviMacIp":"Disabled",
            "importRts":[
              "65001:101"
            ],
            "exportRts":[
              "65001:101"
            ]
        }
        return topotest.json_cmp(output, expected)

    def _verify_vni_65001_rfc8365(router):
        output = json.loads(router.vtysh_cmd("sh bgp l2vpn evpn vni 101 json"))
        expected = {
            "vni":101,
            "type":"L2",
            "inKernel":"True",
            "rd":"192.168.255.2:2",
            "originatorIp":"192.168.255.2",
            "mcastGroup":"0.0.0.0",
            "advertiseGatewayMacip":"Disabled",
            "advertiseSviMacIp":"Disabled",
            "importRts":[
              "65001:268435557"
            ],
            "exportRts":[
              "65001:268435557"
            ]
        }
        return topotest.json_cmp(output, expected)

    def _remove_autort_as(router):
        router.vtysh_cmd(
            """
          configure terminal
            router bgp 65001
              address-family l2vpn evpn
                no autort as 65000
        """
        )

    def _add_autort_as(router):
        router.vtysh_cmd(
            """
          configure terminal
            router bgp 65001
              address-family l2vpn evpn
                autort as 65000
        """
        )

    def _add_autort_rfc8365(router):
        router.vtysh_cmd(
            """
          configure terminal
            router bgp 65001
              address-family l2vpn evpn
                autort rfc8365-compatible
        """
        )

    def _remove_autort_rfc8365(router):
        router.vtysh_cmd(
            """
          configure terminal
            router bgp 65001
              address-family l2vpn evpn
                no autort rfc8365-compatible
        """
        )

    router = tgen.gears["r2"]

    test_func = functools.partial(_verify_vni_65001, router)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'wrong auto route-target "{}"'.format(
        router
    )

    _add_autort_as(router)

    test_func = functools.partial(_verify_vni_65000, router)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'wrong auto route-target "{}"'.format(router)

    _remove_autort_as(router)

    test_func = functools.partial(_verify_vni_65001, router)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'wrong auto route-target "{}"'.format(
        router
    )

    _add_autort_rfc8365(router)

    test_func = functools.partial(_verify_vni_65001_rfc8365, router)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'wrong auto route-target "{}"'.format(router)

    _remove_autort_rfc8365(router)

    test_func = functools.partial(_verify_vni_65001, router)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'wrong auto route-target "{}"'.format(
        router
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
