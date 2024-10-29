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

UPDATE_EXPECTED_JSON = False
DEBUG_PCAP = False


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_bmp_server("bmp1", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["bmp1"])

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth1", "r2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    if DEBUG_PCAP:
        tgen.gears["r1"].run("rm /tmp/bmp.pcap")
        tgen.gears["r1"].run(
            "tcpdump -nni r1-eth0 -s 0 -w /tmp/bmp.pcap &", stdout=None
        )

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
    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


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
    text_output = tgen.gears["bmp1"].run(
        "cat {}".format(os.path.join(tgen.logdir, "bmp1", "bmp.log"))
    )

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


def update_seq():
    global SEQ

    messages = get_bmp_messages()

    if len(messages):
        SEQ = messages[-1]["seq"]


def update_expected_files(bmp_actual, expected_prefixes, bmp_log_type, policy, step):
    tgen = get_topogen()

    with open(f"/tmp/bmp-{bmp_log_type}-{policy}-step{step}.json", "w") as json_file:
        json.dump(bmp_actual, json_file, indent=4)

    if step == 2:  # vpn
        rd = "444:2"
        out = tgen.gears["r1"].vtysh_cmd("show bgp ipv4 vpn json", isjson=True)
        filtered_out = {
            "routes": {
                "routeDistinguishers": {
                    rd: {
                        prefix: route_info
                        for prefix, route_info in out["routes"]
                        .get("routeDistinguishers", {})
                        .get(rd, {})
                        .items()
                        if prefix in expected_prefixes
                    }
                }
            }
        }
        if bmp_log_type == "withdraw":
            for pfx in expected_prefixes:
                if "::" in pfx:
                    continue
                filtered_out["routes"]["routeDistinguishers"][rd][pfx] = None

        # ls /tmp/show*json | while read file; do egrep -v 'prefix|network|metric|ocPrf|version|weight|peerId|vrf|Version|valid|Reason|fe80' $file >$(basename $file); echo >> $(basename $file); done
        with open(
            f"/tmp/show-bgp-ipv4-{bmp_log_type}-step{step}.json", "w"
        ) as json_file:
            json.dump(filtered_out, json_file, indent=4)

        rd = "555:2"
        out = tgen.gears["r1"].vtysh_cmd("show bgp ipv6 vpn json", isjson=True)
        filtered_out = {
            "routes": {
                "routeDistinguishers": {
                    rd: {
                        prefix: route_info
                        for prefix, route_info in out["routes"]
                        .get("routeDistinguishers", {})
                        .get(rd, {})
                        .items()
                        if prefix in expected_prefixes
                    }
                }
            }
        }
        if bmp_log_type == "withdraw":
            for pfx in expected_prefixes:
                if "::" not in pfx:
                    continue
                filtered_out["routes"]["routeDistinguishers"][rd][pfx] = None
        with open(
            f"/tmp/show-bgp-ipv6-{bmp_log_type}-step{step}.json", "w"
        ) as json_file:
            json.dump(filtered_out, json_file, indent=4)

        return

    out = tgen.gears["r1"].vtysh_cmd("show bgp ipv4 json", isjson=True)
    filtered_out = {
        "routes": {
            prefix: route_info
            for prefix, route_info in out["routes"].items()
            if prefix in expected_prefixes
        }
    }
    if bmp_log_type == "withdraw":
        for pfx in expected_prefixes:
            if "::" in pfx:
                continue
            filtered_out["routes"][pfx] = None

    # ls /tmp/show*json | while read file; do egrep -v 'prefix|network|metric|ocPrf|version|weight|peerId|vrf|Version|valid|Reason|fe80' $file >$(basename $file); echo >> $(basename $file); done
    with open(f"/tmp/show-bgp-ipv4-{bmp_log_type}-step{step}.json", "w") as json_file:
        json.dump(filtered_out, json_file, indent=4)

    out = tgen.gears["r1"].vtysh_cmd("show bgp ipv6 json", isjson=True)
    filtered_out = {
        "routes": {
            prefix: route_info
            for prefix, route_info in out["routes"].items()
            if prefix in expected_prefixes
        }
    }
    if bmp_log_type == "withdraw":
        for pfx in expected_prefixes:
            if "::" not in pfx:
                continue
            filtered_out["routes"][pfx] = None
    with open(f"/tmp/show-bgp-ipv6-{bmp_log_type}-step{step}.json", "w") as json_file:
        json.dump(filtered_out, json_file, indent=4)


def check_for_prefixes(expected_prefixes, bmp_log_type, policy, step):
    """
    Check for the presence of the given prefixes in the BMP server logs with
    the given message type and the set policy.

    """
    global SEQ

    # we care only about the new messages
    messages = [
        m for m in sorted(get_bmp_messages(), key=lambda d: d["seq"]) if m["seq"] > SEQ
    ]

    # create empty initial files
    # for step in $(seq 2); do
    #     for i in "update" "withdraw"; do
    #         for j in "pre-policy" "post-policy" "loc-rib"; do
    #             echo '{"null": {}}'> bmp-$i-$j-step$step.json
    #         done
    #     done
    # done

    ref_file = f"{CWD}/bmp1/bmp-{bmp_log_type}-{policy}-step{step}.json"
    expected = json.loads(open(ref_file).read())

    # Build actual json from logs
    actual = {}
    for m in messages:
        if (
            "bmp_log_type" in m.keys()
            and "ip_prefix" in m.keys()
            and m["ip_prefix"] in expected_prefixes
            and m["bmp_log_type"] == bmp_log_type
            and m["policy"] == policy
        ):
            policy_dict = actual.setdefault(m["policy"], {})
            bmp_log_type_dict = policy_dict.setdefault(m["bmp_log_type"], {})

            # Add or update the ip_prefix dictionary with filtered key-value pairs
            bmp_log_type_dict[m["ip_prefix"]] = {
                k: v
                for k, v in sorted(m.items())
                # filter out variable keys
                if k not in ["timestamp", "seq", "nxhp_link-local"]
                and (
                    # When policy is loc-rib, the peer-distinguisher is 0:0
                    # for the default VRF or the RD if any or the 0:<vrf_id>.
                    # 0:<vrf_id> is used to distinguished. RFC7854 says: "If the
                    # peer is a "Local Instance Peer", it is set to a unique,
                    # locally defined value." The value is not tested because it
                    # is variable.
                    k != "peer_distinguisher"
                    or policy != LOC_RIB
                    or v == "0:0"
                    or not v.startswith("0:")
                )
            }

    # build expected JSON files
    if (
        UPDATE_EXPECTED_JSON
        and actual
        and set(actual.get(policy, {}).get(bmp_log_type, {}).keys())
        == set(expected_prefixes)
    ):
        update_expected_files(actual, expected_prefixes, bmp_log_type, policy, step)

    return topotest.json_cmp(actual, expected, exact=True)


def check_for_peer_message(expected_peers, bmp_log_type):
    """
    Check for the presence of a peer up message for the peer
    """
    global SEQ
    # we care only about the new messages
    messages = [
        m for m in sorted(get_bmp_messages(), key=lambda d: d["seq"]) if m["seq"] > SEQ
    ]

    # get the list of pairs (prefix, policy, seq) for the given message type
    peers = [
        m["peer_ip"]
        for m in messages
        if "peer_ip" in m.keys() and m["bmp_log_type"] == bmp_log_type
    ]

    # check for prefixes
    for ep in expected_peers:
        if ep not in peers:
            msg = "The peer {} is not present in the {} log messages."
            logger.debug(msg.format(ep, bmp_log_type))
            return False

    SEQ = messages[-1]["seq"]
    return True


def configure_prefixes(tgen, node, asn, safi, prefixes, vrf=None, update=True):
    """
    Configure the bgp prefixes.
    """
    withdraw = "no " if not update else ""
    vrf = " vrf {}".format(vrf) if vrf else ""
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


def _test_prefixes(policy, vrf=None, step=0):
    """
    Setup the BMP  monitor policy, Add and withdraw ipv4/v6 prefixes.
    Check if the previous actions are logged in the BMP server with the right
    message type and the right policy.
    """
    tgen = get_topogen()

    safi = "vpn" if vrf else "unicast"

    prefixes = ["172.31.0.15/32", "2001::1111/128"]

    for type in ("update", "withdraw"):
        update_seq()

        configure_prefixes(
            tgen, "r2", 65502, "unicast", prefixes, vrf=vrf, update=(type == "update")
        )

        logger.info(f"checking for prefixes {type}")

        for ipver in [4, 6]:
            if UPDATE_EXPECTED_JSON:
                continue
            ref_file = "{}/r1/show-bgp-ipv{}-{}-step{}.json".format(
                CWD, ipver, type, step
            )
            expected = json.loads(open(ref_file).read())

            test_func = partial(
                topotest.router_json_cmp,
                tgen.gears["r1"],
                f"show bgp ipv{ipver} {safi} json",
                expected,
            )
            _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = f"r1: BGP IPv{ipver} convergence failed"
            assert res is None, assertmsg

        # check
        test_func = partial(check_for_prefixes, prefixes, type, policy, step)
        success, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert success, "Checking the updated prefixes has failed ! %s" % res


def test_bmp_server_logging():
    """
    Assert the logging of the bmp server.
    """

    def check_for_log_file():
        tgen = get_topogen()
        output = tgen.gears["bmp1"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1"))
        )
        if "bmp.log" not in output:
            return False
        return True

    success, _ = topotest.run_and_expect(check_for_log_file, True, count=30, wait=1)
    assert success, "The BMP server is not logging"


def test_peer_up():
    """
    Checking for BMP peers up messages
    """

    peers = ["192.168.0.2", "192:168::2"]

    logger.info("checking for BMP peers up messages")

    test_func = partial(check_for_peer_message, peers, "peer up")
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


def test_bmp_bgp_unicast():
    """
    Add/withdraw bgp unicast prefixes and check the bmp logs.
    """
    logger.info("*** Unicast prefixes pre-policy logging ***")
    _test_prefixes(PRE_POLICY, step=1)
    logger.info("*** Unicast prefixes post-policy logging ***")
    _test_prefixes(POST_POLICY, step=1)
    logger.info("*** Unicast prefixes loc-rib logging ***")
    _test_prefixes(LOC_RIB, step=1)


def test_bmp_bgp_vpn():
    # check for the prefixes in the BMP server logging file
    logger.info("***** VPN prefixes pre-policy logging *****")
    _test_prefixes(PRE_POLICY, vrf="vrf1", step=2)
    logger.info("***** VPN prefixes post-policy logging *****")
    _test_prefixes(POST_POLICY, vrf="vrf1", step=2)
    logger.info("***** VPN prefixes loc-rib logging *****")
    _test_prefixes(LOC_RIB, vrf="vrf1", step=2)


def test_peer_down():
    """
    Checking for BMP peers down messages
    """
    tgen = get_topogen()

    tgen.gears["r2"].vtysh_cmd("clear bgp *")

    peers = ["192.168.0.2", "192:168::2"]

    logger.info("checking for BMP peers down messages")

    test_func = partial(check_for_peer_message, peers, "peer down")
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
