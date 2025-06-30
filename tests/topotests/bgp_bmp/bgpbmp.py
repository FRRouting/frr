#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright 2023, 6wind
import json
import os
from functools import partial, reduce

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


class BMPSequenceContext:
    """
    Context class to manage BMP sequence numbers for a test run.
    This eliminates the need for global state that can be shared across test runs.
    """

    def __init__(self, initial_seq=0):
        self.seq = initial_seq

    def get_seq(self):
        return self.seq

    def set_seq(self, seq):
        self.seq = seq

    def reset_seq(self, seq=0):
        self.seq = seq

    def display_seq(self):
        logger.info(f"SEQ is {self.seq}")


def bmp_reset_seq(seq_context, seq_param=0):
    """
    Reset the sequence number in the given context.

    Args:
        seq_context: BMPSequenceContext instance
        seq_param: New sequence number (default 0)
    """
    logger.info(f"bmp_reset_seq: SEQ is now: {seq_param}")
    seq_context.reset_seq(seq_param)


def bmp_get_seq(seq_context):
    """
    Get the current sequence number from the context.

    Args:
        seq_context: BMPSequenceContext instance

    Returns:
        Current sequence number
    """
    return seq_context.get_seq()


def bmp_display_seq(seq_context):
    """
    Display the current sequence number.

    Args:
        seq_context: BMPSequenceContext instance
    """
    seq_context.display_seq()


def get_bmp_messages(bmp_collector, bmp_log_file):
    """
    Read the BMP logging messages.
    """
    messages = []

    with open(bmp_log_file, "r") as f:
        for m in f:
            try:
                messages.append(json.loads(m.strip()))
            except Exception as e:
                logger.warning(str(e) + " message: {}".format(str(m)))
                continue

    if not messages:
        logger.error("Bad BMP log format, check your BMP server")

    return messages


def bmp_update_seq(bmp_collector, bmp_log_file, seq_context):
    """
    Update the sequence number based on the BMP log file.

    Args:
        bmp_collector: BMP collector instance
        bmp_log_file: Path to BMP log file
        seq_context: BMPSequenceContext instance
    """
    logger.info("bmp_update_seq: SEQ is now: {}".format(seq_context.get_seq()))

    messages = get_bmp_messages(bmp_collector, bmp_log_file)

    if len(messages):
        seq_context.set_seq(messages[-1]["seq"])
    logger.info("bmp_update_seq: SEQ is now: {}".format(seq_context.get_seq()))


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
    seq_context,
):
    """
    Check for the presence of the given prefixes in the BMP server logs with
    the given message type and the set policy.

    """
    logger.info("SEQ is now: {}".format(seq_context.get_seq()))

    bmp_log_file = f"{bmp_log_folder}/bmp.log"
    # we care only about the new messages
    messages = [
        m
        for m in sorted(
            get_bmp_messages(bmp_collector, bmp_log_file), key=lambda d: d["seq"]
        )
        if m["seq"] > seq_context.get_seq()
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


def bmp_check_for_addpath(
    prefixes,
    policy,
    bmp_collector,
    bmp_log_file,
    nexthops,
    peer_bgp_id,
    seq_context,
    id_per_prefix=True,
    m_type="update",
    safi=None,
):
    """
    For each prefix in the prefix list, check its addpath id.
    In rx case, peer can receive the same addpath rx id for multiple prefixes,
    while in loc-rib and tx case, one addpath id is allocated for one prefix.
    Use id_per_prefix to distinguish these cases.
    """

    messages = [
        m
        for m in sorted(
            get_bmp_messages(bmp_collector, bmp_log_file), key=lambda d: d["seq"]
        )
        if m["seq"] > seq_context.get_seq()
    ]
    addpath_set = {4: set(), 6: set()}

    for i in range(len(prefixes)):
        addpath_ids = addpath_set[4]
        prefix = prefixes[i]
        p_messages = list(
            filter(
                lambda m: m.get("ip_prefix") == prefix
                and m["policy"] == policy
                and m["bmp_log_type"] == m_type,
                messages,
            )
        )

        if peer_bgp_id:
            p_messages = list(
                filter(lambda m: m["peer_bgp_id"] == peer_bgp_id, p_messages)
            )

        if safi:
            p_messages = list(filter(lambda m: m.get("safi") == safi, p_messages))

        if not p_messages:
            return "No bmp log for %s" % prefix

        nexthop_key = "bgp_nexthop"
        # nexthop key is diffrent for MP_REACH_NLRI
        if ":" in prefix or safi:
            addpath_ids = addpath_set[6]
            nexthop_key = "nxhp_ip"

        if m_type == "withdraw":
            for m in p_messages:
                addpath_ids.add(m["path_id"])

            continue

        t_nexthop = nexthops[i]
        for nexthop in t_nexthop:
            m_nexthop = list(
                filter(lambda m: m.get(nexthop_key) == nexthop, p_messages)
            )
            if not m_nexthop:
                return "prefix %s does not have %s as nexthop" % (prefix, nexthop)

            m_nexthop = reduce(
                lambda m1, m2: m1 if m1["seq"] > m2["seq"] else m2, m_nexthop
            )
            if m_nexthop.get("path_id", 0) == 0:
                return "prefix %s, nexthop %s have a null addpath tx id" % (
                    prefix,
                    nexthop,
                )

            if m_nexthop["path_id"] in addpath_ids and id_per_prefix:
                return "same addpath id %d for prefix %s " % (
                    m_nexthop["path_id"],
                    prefix,
                )

            addpath_ids.add(m_nexthop["path_id"])

    return addpath_set


def bmp_check_for_peer_message(
    expected_peers,
    bmp_log_type,
    bmp_collector,
    bmp_log_file,
    seq_context,
    is_rd_instance=False,
    peer_bgp_id=None,
    peer_distinguisher=None,
    bgp_open_as=None,
    bgp_open_bgp_id=None,
):
    """
    Check for the presence of a peer up message for the peer
    """
    last_seq = seq_context.get_seq()

    logger.info(
        "bmp_check_for_peer_message: SEQ is now: {}".format(seq_context.get_seq())
    )
    # we care only about the new messages
    messages = [
        m
        for m in sorted(
            get_bmp_messages(bmp_collector, bmp_log_file), key=lambda d: d["seq"]
        )
        if m["seq"] > seq_context.get_seq()
    ]

    # get the list of pairs (prefix, policy, seq) for the given message type
    peers = []
    for m in messages:
        logger.info("LOOKING AT MESSAGE:")
        logger.info("m: {}".format(m))
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
                msg = "The peer {} is present in the {} log messages sequence is {}."
                logger.debug(msg.format(ep, bmp_log_type, _seq))
                if _seq > last_seq:
                    last_seq = _seq
                break
        else:
            msg = "The peer {} is not present in the {} log messages."
            logger.debug(msg.format(ep, bmp_log_type))
            return False

    seq_context.set_seq(last_seq)
    logger.info(
        "bmp_check_for_peer_message: SEQ is now: {}".format(seq_context.get_seq())
    )
    return True


def _test_prefixes(
    policy,
    prefixes,
    r_conf,
    r_check,
    bmp,
    cur_dir,
    bmp_seq_context,
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
        bmp_update_seq(
            tgen.gears[bmp], os.path.join(tgen.logdir, bmp, "bmp.log"), bmp_seq_context
        )

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
            bmp_seq_context,
        )
        success, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert success, "Checking the updated prefixes has failed ! %s" % res
