"""
test_zebra_static_opcode_sid.py

Test if works the following commands:
segment-routing
    srv6
        locators
            locator loc1
                prefix fd00:201:201::/48 block-len 32 node-len 16 func-bits 16
                    opcode ::fff1:11:0:0:0 end-dt46 vrf Vrf1
                    opcode ::fff1:12:0:0:0 end-dt46 vrf Vrf2
                    opcode ::fff1:14:0:0:0 end-dt4  vrf Vrf3
                    opcode ::fff1:16:0:0:0 end-dt6  vrf Vrf3
                    opcode ::fff1:18:0:0:0 end

Test contains two parts:
- Verify that the static opcode is configured and generates mySID correctly.
- Ensure that the opcode and the corresponding SID can be removed properly.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
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


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_static_opcode_sid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears['r1']

    def _zebra_conf_static_opcode(router, locator_conf_args):
        router.vtysh_cmd(locator_conf_args)


    def _zebra_check_static_opcode_sids(router, cmd_args, expected_args):
        output = json.loads(router.vtysh_cmd(cmd_args))
        return topotest.json_cmp(output, expected_args)


    locator_conf_args = """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fd00:202:202::/48 block-len 32 node-len 16 func-bits 16
              opcode ::fff1:11:0:0:0 end-dt46 vrf Vrf1
              opcode ::fff1:12:0:0:0 end-dt46 vrf Vrf2
              opcode ::fff1:14:0:0:0 end-dt4  vrf Vrf3
              opcode ::fff1:16:0:0:0 end-dt6  vrf Vrf3
              opcode ::fff1:18:0:0:0 end
    """
    locator_rm_conf_args = """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fd00:202:202::/48 block-len 32 node-len 16 func-bits 16
              no opcode ::fff1:11:0:0:0
              no opcode ::fff1:12:0:0:0
              no opcode ::fff1:14:0:0:0
              no opcode ::fff1:16:0:0:0
              no opcode ::fff1:18:0:0:0
    """
    cmd_args = "show segment-routing srv6 locator loc1 detail json"
    expected_sids_args = {
        "name":"loc1",
            "prefix":"fd00:202:202::/48",
            "blockBitsLength":32,
            "nodeBitsLength":16,
            "functionBitsLength":16,
            "argumentBitsLength":0,
            "algoNum":0,
            "statusUp":True,
            "chunks":[
                {
                    "prefix":"fd00:202:202::/48",
                    "blockBitsLength":0,
                    "nodeBitsLength":0,
                    "functionBitsLength":0,
                    "argumentBitsLength":0,
                    "keep":0,
                    "proto":"system",
                    "instance":0,
                    "sessionId":0
                }
            ],
            "sids":[
                {
                    "opcode":"::fff1:11:0:0:0/128",
                    "sidaction":"End.DT46",
                    "vrf":"Vrf1"
                },
                {
                    "opcode":"::fff1:12:0:0:0/128",
                    "sidaction":"End.DT46",
                    "vrf":"Vrf2"
                },
                {
                    "opcode":"::fff1:14:0:0:0/128",
                    "sidaction":"End.DT4",
                    "vrf":"Vrf3"
                },
                {
                    "opcode":"::fff1:16:0:0:0/128",
                    "sidaction":"End.DT6",
                    "vrf":"Vrf3"
                },
                {
                    "opcode":"::fff1:18:0:0:0/128",
                    "sidaction":"End",
                    "vrf":"default"
                }
            ]
        }
    expected_no_sids_args = {
        "name":"loc1",
        "prefix":"fd00:202:202::/48",
        "blockBitsLength":32,
        "nodeBitsLength":16,
        "functionBitsLength":16,
        "argumentBitsLength":0,
        "algoNum":0,
        "statusUp":True,
        "chunks":[
            {
            "prefix":"fd00:202:202::/48",
            "blockBitsLength":0,
            "nodeBitsLength":0,
            "functionBitsLength":0,
            "argumentBitsLength":0,
            "keep":0,
            "proto":"system",
            "instance":0,
            "sessionId":0
            }
        ],
        "sids":[
        ]
    }


    step("Configure the static opcode for locator loc1 on router1")
    _zebra_conf_static_opcode(r1, locator_conf_args)

    step("Check mySID (ADD)")
    test_func = functools.partial(_zebra_check_static_opcode_sids, r1,
                                  cmd_args, expected_sids_args)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=5)

    assert result is None, 'Failed to add static opcode'

    step("Remove the static opcode for locator loc1 on router1")
    _zebra_conf_static_opcode(r1, locator_rm_conf_args)

    step("Check mySID (DEL)")
    test_func = functools.partial(_zebra_check_static_opcode_sids, r1,
                                  cmd_args, expected_no_sids_args)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=5)

    assert result is None, 'Failed to remove static opcode'


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))