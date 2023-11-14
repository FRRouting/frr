#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#

"""
test_bgp_bmp.py: Test BGP BMP functionalities

    +------+            +------+               +------+
    |      |            |      |               |      |
    | BMP1 |------------|  R1  |---------------|  R2  |
    |      |            |      |               |      |
    +------+            +------+               +------+

Setup two routers R1 and R2 with one link configured with IPv4 and
IPv6 addresses.
Configure BGP in R1 and R2 to exchange prefixes from
the latter to the first router.
Setup a link between R1 and the BMP server, activate the BMP feature in R1
and ensure the monitored BGP sessions logs are well present on the BMP server.
"""

from functools import partial
from ipaddress import ip_network
import json
import os
import platform
import pytest
import sys

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

# remember the last sequence number of the logging messages
SEQ = 0

PRE_POLICY = "pre-policy"
POST_POLICY = "post-policy"
LOC_RIB = "loc-rib"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_bmp_server("bmp1", ip="192.0.178.10", defaultRoute="via 192.0.178.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["bmp1"])

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth1", "r2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            "-M bmp",
        )

    tgen.start_router()

    logger.info("starting BMP servers")
    for _, server in tgen.get_bmp_servers().items():
        server.start()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_bgp_convergence_from_running_config(tgen, dut="r1")
    assert result is True, "BGP is not converging"


def get_bmp_messages():
    """
    Read the BMP logging messages.
    """
    messages = []
    tgen = get_topogen()
    text_output = tgen.gears["bmp1"].run("cat /var/log/bmp.log")

    for m in text_output.splitlines():
        # some output in the bash can break the message decoding
        try:
            messages.append(json.loads(m))
        except Exception as e:
            logger.warning(str(e) + " message: {}".format(str(m)))
            continue

    if not messages:
        logger.error("Bad BMP log format, check your BMP server")

    return messages


def check_for_prefixes(expected_prefixes, bmp_log_type, policy):
    """
    Check for the presence of the given prefixes in the BMP server logs with
    the given message type and the set policy.
    """
    global SEQ
    # we care only about the new messages
    messages = [
        m for m in sorted(get_bmp_messages(), key=lambda d: d["seq"]) if m["seq"] > SEQ
    ]

    # get the list of pairs (prefix, policy, seq) for the given message type
    prefixes = [
        m["ip_prefix"]
        for m in messages
        if "ip_prefix" in m.keys()
        and "bmp_log_type" in m.keys()
        and m["bmp_log_type"] == bmp_log_type
        and m["policy"] == policy
    ]

    # check for prefixes
    for ep in expected_prefixes:
        if ep not in prefixes:
            msg = "The prefix {} is not present in the {} log messages."
            logger.debug(msg.format(ep, bmp_log_type))
            return False

    SEQ = messages[-1]["seq"]
    return True


def set_bmp_policy(tgen, node, asn, target, safi, policy, vrf=None):
    """
    Configure the bmp policy.
    """
    vrf = " vrf {}" if vrf else ""
    cmd = [
        "con t\n",
        "router bgp {}{}\n".format(asn, vrf),
        "bmp targets {}\n".format(target),
        "bmp monitor ipv4 {} {}\n".format(safi, policy),
        "bmp monitor ipv6 {} {}\n".format(safi, policy),
        "end\n",
    ]
    tgen.gears[node].vtysh_cmd("".join(cmd))


def configure_prefixes(tgen, node, asn, safi, prefixes, vrf=None, update=True):
    """
    Configure the bgp prefixes.
    """
    withdraw = "no " if not update else ""
    vrf = " vrf {}" if vrf else ""
    for p in prefixes:
        ip = ip_network(p)
        cmd = [
            "conf t\n",
            "router bgp {}{}\n".format(asn, vrf),
            "address-family ipv{} {}\n".format(ip.version, safi),
            "{}network {}\n".format(withdraw, ip),
            "exit-address-family\n",
        ]
        logger.debug("setting prefix: ipv{} {} {}".format(ip.version, safi, ip))
        tgen.gears[node].vtysh_cmd("".join(cmd))


def unicast_prefixes(policy):
    """
    Setup the BMP  monitor policy, Add and withdraw ipv4/v6 prefixes.
    Check if the previous actions are logged in the BMP server with the right
    message type and the right policy.
    """
    tgen = get_topogen()
    set_bmp_policy(tgen, "r1", 65501, "bmp1", "unicast", policy)

    prefixes = ["172.31.0.15/32", "2111::1111/128"]
    # add prefixes
    configure_prefixes(tgen, "r2", 65502, "unicast", prefixes)

    logger.info("checking for updated prefixes")
    # check
    test_func = partial(check_for_prefixes, prefixes, "update", policy)
    success, _ = topotest.run_and_expect(test_func, True, wait=0.5)
    assert success, "Checking the updated prefixes has been failed !."

    # withdraw prefixes
    configure_prefixes(tgen, "r2", 65502, "unicast", prefixes, update=False)
    logger.info("checking for withdrawed prefxies")
    # check
    test_func = partial(check_for_prefixes, prefixes, "withdraw", policy)
    success, _ = topotest.run_and_expect(test_func, True, wait=0.5)
    assert success, "Checking the withdrawed prefixes has been failed !."


def test_bmp_server_logging():
    """
    Assert the logging of the bmp server.
    """

    def check_for_log_file():
        tgen = get_topogen()
        output = tgen.gears["bmp1"].run("ls /var/log/")
        if "bmp.log" not in output:
            return False
        return True

    success, _ = topotest.run_and_expect(check_for_log_file, True, wait=0.5)
    assert success, "The BMP server is not logging"


def test_bmp_bgp_unicast():
    """
    Add/withdraw bgp unicast prefixes and check the bmp logs.
    """
    logger.info("*** Unicast prefixes pre-policy logging ***")
    unicast_prefixes(PRE_POLICY)
    logger.info("*** Unicast prefixes post-policy logging ***")
    unicast_prefixes(POST_POLICY)
    logger.info("*** Unicast prefixes loc-rib logging ***")
    unicast_prefixes(LOC_RIB)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
