#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright 2023, 6wind
import json
import os
from functools import partial

from lib import topotest
from lib.bgp import bgp_configure_prefixes
from lib.topogen import get_topogen
from lib.topolog import logger

# BMP type message
BMP_UPDATE = "update"
BMP_WITHDRAW = "withdraw"
ADJ_IN_PRE_POLICY = "rib-in-pre-policy"
ADJ_IN_POST_POLICY = "rib-in-post-policy"
ADJ_OUT_PRE_POLICY = "rib-out-pre-policy"
ADJ_OUT_POST_POLICY = "rib-out-post-policy"
LOC_RIB = "loc-rib"

UPDATE_EXPECTED_JSON = False

# remember the last sequence number of the logging messages
SEQ = 0


def bmp_reset_seq(seq_param=0):
    global SEQ
    SEQ = seq_param


def bmp_get_seq():
    return SEQ


def bmp_display_seq():
    logger.info(f"SEQ is {SEQ}")


def get_bmp_messages(bmp_collector, bmp_log_file):
    """
    Read the BMP logging messages.
    """
    messages = []
    text_output = bmp_collector.run(f"cat {bmp_log_file}")

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


def bmp_update_seq(bmp_collector, bmp_log_file):
    global SEQ

    messages = get_bmp_messages(bmp_collector, bmp_log_file)

    if len(messages):
        SEQ = messages[-1]["seq"]


def bmp_update_expected_files(
    bmp_actual,
    expected_prefixes,
    bmp_log_type,
    policy,
    step,
    bmp_client,
    bmp_log_folder,
):
    tgen = get_topogen()

    with open(
        f"{bmp_log_folder}/tmp/bmp-{bmp_log_type}-{policy}-step{step}.json", "w"
    ) as json_file:
        json.dump(bmp_actual, json_file, indent=4)

    out = bmp_client.vtysh_cmd("show bgp vrf vrf1 ipv4 json", isjson=True)
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

    # ls {bmp_log_folder}/tmp/show*json | while read file; do egrep -v 'prefix|network|metric|ocPrf|version|weight|peerId|vrf|Version|valid|Reason|fe80' $file >$(basename $file); echo >> $(basename $file); done
    with open(
        f"{bmp_log_folder}/tmp/show-bgp-ipv4-{bmp_log_type}-step{step}.json", "w"
    ) as json_file:
        json.dump(filtered_out, json_file, indent=4)

    out = tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 ipv6 json", isjson=True)
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

    with open(
        f"{bmp_log_folder}/tmp/show-bgp-ipv6-{bmp_log_type}-step{step}.json", "w"
    ) as json_file:
        json.dump(filtered_out, json_file, indent=4)


def bmp_check_for_prefixes(
    expected_prefixes,
    bmp_log_type,
    policy,
    step,
    bmp_collector,
    bmp_log_folder,
    bmp_client,
    expected_json_path,
    update_expected_json,
    loc_rib,
):
    """
    Check for the presence of the given prefixes in the BMP server logs with
    the given message type and the set policy.

    """
    global SEQ

    bmp_log_file = f"{bmp_log_folder}/bmp.log"
    # we care only about the new messages
    messages = [
        m
        for m in sorted(
            get_bmp_messages(bmp_collector, bmp_log_file), key=lambda d: d["seq"]
        )
        if m["seq"] > SEQ
    ]

    # create empty initial files
    # for step in $(seq 1); do
    #     for i in "update" "withdraw"; do
    #         for j in "pre-policy" "post-policy" "loc-rib"; do
    #             echo '{"null": {}}'> bmp-$i-$j-step$step.json
    #         done
    #     done
    # done

    ref_file = f"{expected_json_path}/bmp-{bmp_log_type}-{policy}-step{step}.json"
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
            }

    # build expected JSON files
    if (
        update_expected_json
        and actual
        and set(actual.get(policy, {}).get(bmp_log_type, {}).keys())
        == set(expected_prefixes)
    ):
        bmp_update_expected_files(
            actual,
            expected_prefixes,
            bmp_log_type,
            policy,
            step,
            bmp_client,
            bmp_log_folder,
        )

    return topotest.json_cmp(actual, expected, exact=True)


def bmp_check_for_peer_message(
    expected_peers,
    bmp_log_type,
    bmp_collector,
    bmp_log_file,
    is_rd_instance=False,
    peer_bgp_id=None,
    peer_distinguisher=None,
    bgp_open_as=None,
    bgp_open_bgp_id=None,
):
    """
    Check for the presence of a peer up message for the peer
    """
    global SEQ
    last_seq = SEQ

    # we care only about the new messages
    messages = [
        m
        for m in sorted(
            get_bmp_messages(bmp_collector, bmp_log_file), key=lambda d: d["seq"]
        )
        if m["seq"] > SEQ
    ]

    # get the list of pairs (prefix, policy, seq) for the given message type
    peers = []
    for m in messages:
        if is_rd_instance and m["peer_distinguisher"] == "0:0":
            continue
        if peer_distinguisher and m["peer_distinguisher"] != peer_distinguisher:
            continue
        if peer_bgp_id and m["peer_bgp_id"] != peer_bgp_id:
            continue
        if bgp_open_as:
            if not m.get("open_tx", {}).get("my_as", None):
                continue
            if m["open_tx"]["my_as"] != bgp_open_as:
                continue
            if not m.get("open_rx", {}).get("my_as", None):
                continue
            if m["open_rx"]["my_as"] != bgp_open_as:
                continue

        if bgp_open_bgp_id:
            if not m.get("open_tx", {}).get("bgp_id", None):
                continue
            if m["open_tx"]["bgp_id"] != bgp_open_bgp_id:
                continue
            if not m.get("open_rx", {}).get("bgp_id", None):
                continue
            if m["open_rx"]["bgp_id"] != bgp_open_bgp_id:
                continue
        if (
            "peer_ip" in m.keys()
            and m["peer_ip"] != "0.0.0.0"
            and m["bmp_log_type"] == bmp_log_type
        ):
            if is_rd_instance and m["peer_type"] != "route distinguisher instance":
                continue
            peers.append((m["peer_ip"], m["seq"]))
        elif m["policy"] == "loc-rib" and m["bmp_log_type"] == bmp_log_type:
            peers.append(("0.0.0.0", m["seq"]))

    # check for prefixes
    for ep in expected_peers:
        for _ip, _seq in peers:
            if ep == _ip:
                msg = "The peer {} is present in the {} log messages."
                logger.debug(msg.format(ep, bmp_log_type))
                if _seq > last_seq:
                    last_seq = _seq
                break
        else:
            msg = "The peer {} is not present in the {} log messages."
            logger.debug(msg.format(ep, bmp_log_type))
            return False

    SEQ = last_seq
    return True


def _test_prefixes(
    policy,
    prefixes,
    r_conf,
    r_check,
    bmp,
    cur_dir,
    vrf_conf=None,
    vrf_check=None,
    asn=65002,
    safi="unicast",
    step=0,
):
    """
    Setup the BMP  monitor policy, Add and withdraw ipv4/v6 prefixes.
    Check if the previous actions are logged in the BMP server with the right
    message type and the right policy.
    """
    tgen = get_topogen()

    vrf = f"vrf {vrf_check}" if vrf_check else ""

    for type in (BMP_UPDATE, BMP_WITHDRAW):
        bmp_update_seq(tgen.gears[bmp], os.path.join(tgen.logdir, bmp, "bmp.log"))

        bgp_configure_prefixes(
            tgen.gears[r_conf],
            asn,
            "unicast",
            prefixes,
            vrf=vrf_conf,
            update=(type == BMP_UPDATE),
        )

        logger.info(f"checking for prefixes %s {type}" % prefixes)

        for ipver in [4, 6]:
            if UPDATE_EXPECTED_JSON:
                continue
            ref_file = "{}/{}/show-bgp-ipv{}-{}-step{}.json".format(
                cur_dir, r_check, ipver, type, step
            )
            expected = json.loads(open(ref_file).read())

            logger.debug(f"checking ipv{ipver} {policy} {type}s for step={step}")
            test_func = partial(
                topotest.router_json_cmp,
                tgen.gears[r_check],
                f"show bgp {vrf} ipv{ipver} {safi} json",
                expected,
            )
            _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = f"{r_check}: BGP IPv{ipver} convergence failed"
            assert res is None, assertmsg

        # check
        test_func = partial(
            bmp_check_for_prefixes,
            prefixes,
            type,
            policy,
            step,
            tgen.gears[bmp],
            os.path.join(tgen.logdir, bmp),
            tgen.gears[r_check],
            f"{cur_dir}/{bmp}",
            UPDATE_EXPECTED_JSON,
            LOC_RIB,
        )
        success, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert success, "Checking the updated prefixes has failed ! %s" % res
