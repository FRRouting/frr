#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Network Education Foundation, Inc. ("NetDEF")
#                    Rafael Zalamena

"""
test_pim_bsr_rp_install.py: Test PIM BSR learned RPs installation.

A BSR router (played by a script sending the BSMs) advertises two C-RPs
for 224.0.0.0/4 to a FRR router without any RP configured: check that
the BSR learned RPs are installed in `show ip pim rp-info` and kept
consistent with the static RP configuration. R1 also runs pim6d for the
IPv6 static RP configuration checks.

    +----------------------------------------------+
    | bsr (BSM sender)                             |
    |   lo: 10.192.99.1    -> BSR, priority 210,   |
    |                         hash-mask-len 30     |
    |   lo: 172.31.99.100  -> C-RP, priority 100   |
    |   lo: 172.31.99.99   -> C-RP, priority 10    |
    +----------------------------------------------+
                  | bsr-eth0 10.192.91.178/29
                  |
                  | r1-eth0 10.192.91.177/29
    +----------------------------------------------+
    | r1 (FRR)                                     |
    |   static routes to BSR and C-RPs via r1-eth0 |
    +----------------------------------------------+
                  | r1-eth1 10.0.1.1/24 (IGMP)
                  |
                  | h1-eth0 10.0.1.2/24
    +----------------------------------------------+
    | h1: receiver for 239.1.1.1                   |
    |     source for 239.2.2.2                     |
    +----------------------------------------------+
"""

import json
import os
import subprocess
import sys
import time
import pytest
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.pimd, pytest.mark.pim6d, pytest.mark.staticd]

BSR_ADDRESS = "10.192.99.1"
BSR_PRIORITY = 210
BSR_HASH_MASK_LENGTH = 30
CRP_HIGH = "172.31.99.100"
CRP_LOW = "172.31.99.99"
# No route to these addresses: never reachable.
UNREACHABLE_RP = "192.0.2.1"
OTHER_RP = "192.0.2.2"
GROUP_RANGE = "224.0.0.0/4"
GROUP = "239.1.1.1"
SOURCE_GROUP = "239.2.2.2"
SOURCE = "10.0.1.2"
# R1 own address, to make it the RP.
LOCAL_RP = "10.0.1.1"
# No route to this address: MSDP is only enabled for its local SAs.
MSDP_PEER = "192.0.2.10"
# Short C-RP hold time so the BSR loss can be observed through expiration.
RP_HOLD_TIME = 30

bsm_sender = None
bsm_sender_starts = 0
receiver = None
source = None


def build_topo(tgen):
    tgen.add_router("bsr")
    tgen.add_router("r1")
    tgen.add_host("h1", "10.0.1.2/24", "via 10.0.1.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["bsr"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["bsr"].load_frr_config()
    # pim6d for the IPv6 RP configuration tests.
    tgen.gears["r1"].load_frr_config(extra_daemons=["pim6d"])

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()

    stop_bsm_sender()
    for process in [receiver, source]:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()

    tgen.stop_topology()


def start_bsm_sender(crps=((CRP_HIGH, 100), (CRP_LOW, 10))):
    """
    Start the BSR imitation with the (C-RP, priority) `crps`, replacing
    the running one, if any.
    """
    global bsm_sender, bsm_sender_starts

    stop_bsm_sender()
    tgen = get_topogen()
    bsm_sender_starts += 1
    log_path = os.path.join(tgen.logdir, f"bsr-send_bsm-{bsm_sender_starts}.log")
    with open(log_path, "w") as bsm_log:
        bsm_sender = tgen.gears["bsr"].popen(
            [
                sys.executable,
                os.path.join(CWD, "send_bsm.py"),
                "10.192.91.178",
                BSR_ADDRESS,
                f"--bsr-priority={BSR_PRIORITY}",
                f"--hash-mask-length={BSR_HASH_MASK_LENGTH}",
                f"--group={GROUP_RANGE}",
                *[f"--rp={crp},{priority},{RP_HOLD_TIME}" for crp, priority in crps],
                "--interval=5",
            ],
            stdout=bsm_log,
            stderr=subprocess.STDOUT,
        )

    def sent_first_bsm():
        if bsm_sender.poll() is not None:
            return f"send_bsm.py exited with {bsm_sender.returncode}"
        with open(log_path) as bsm_log:
            if "sent BSM #1" in bsm_log.read():
                return None
        return "no BSM sent yet"

    _, result = topotest.run_and_expect(sent_first_bsm, None, count=15, wait=1)
    assert result is None, f"{result}, see {log_path}"


def stop_bsm_sender():
    "Stop the BSR imitation, if running."
    if bsm_sender is not None and bsm_sender.poll() is None:
        bsm_sender.terminate()
        bsm_sender.wait()
        # Let R1 process a BSM sent right before, so it can't come after
        # the next commands.
        time.sleep(1)


def pim_config(*lines, af="ip"):
    "Apply `lines` in the R1 `router pim` (or `router pim6`) node."
    router = "router pim" if af == "ip" else "router pim6"
    return (
        get_topogen()
        .gears["r1"]
        .vtysh_cmd("\n".join(["configure terminal", router, *lines]))
    )


def show_json(command):
    """
    Return R1 `command` JSON output, or None when it is not JSON (like when
    the daemon is not running): an empty output must not pass for an empty
    table.
    """
    output = get_topogen().gears["r1"].vtysh_cmd(command)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def expect_json(router, command, expected, count=30, wait=1):
    tgen = get_topogen()
    test_func = partial(topotest.router_json_cmp, tgen.gears[router], command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert result is None, f'"{router}" unexpected "{command}" output: {result}'


def expect_upstream_joined(rp, interface, count=30):
    """
    The receiver's (*,G) must be joined via `interface`, `rp` being the
    group RP.

    `rpfAddress` is looked up from the RP table when displayed, and both
    C-RPs are reached via the same interface: this tells that the group RP
    is reachable, not which RP the join was sent towards.
    """
    expect_json(
        "r1",
        "show ip pim upstream json",
        {
            GROUP: {
                "*": {
                    "rpfAddress": rp,
                    "inboundInterface": interface,
                    "joinState": "Joined",
                }
            }
        },
        count=count,
    )


def expect_upstream_not_joined(count=30):
    "The receiver's (*,G) must exist but not be joined towards any RP."
    tgen = get_topogen()

    def check_upstream():
        output = tgen.gears["r1"].vtysh_cmd("show ip pim upstream json", isjson=True)
        entry = output.get(GROUP, {}).get("*")
        if entry is None:
            return f"no (*,{GROUP}) upstream: {output}"
        if entry.get("joinState") == "Joined":
            return f"(*,{GROUP}) still joined: {entry}"
        return None

    _, result = topotest.run_and_expect(check_upstream, None, count=count, wait=1)
    assert result is None, f'"r1" {result}'


def expect_rp_info_bsr():
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {
            CRP_LOW: [
                {
                    "rpAddress": CRP_LOW,
                    "group": GROUP_RANGE,
                    "source": "BSR",
                    "outboundInterface": "r1-eth0",
                }
            ]
        },
    )


def expect_rp_address_ranges(rp, expected, af="ip"):
    """
    `rp` must be the RP for exactly the `expected` (range, source) list,
    the range being a group range or prefix-list.
    """

    def check_rp_info():
        output = show_json(f"show {af} pim rp-info json")
        if output is None:
            return f"no show {af} pim rp-info JSON output"
        ranges = sorted(
            (entry.get("group", entry.get("prefixList")), entry["source"])
            for entry in output.get(rp, [])
        )
        if ranges != sorted(expected):
            return f"unexpected {rp} RP ranges: {ranges}"
        return None

    _, result = topotest.run_and_expect(check_rp_info, None, count=30, wait=1)
    assert result is None, f'"r1" {result}'


def expect_range_without_rp(count=30):
    "The RP table must have no `GROUP_RANGE` RP."

    def check_rp_info():
        output = show_json("show ip pim rp-info json")
        if output is None:
            return "no show ip pim rp-info JSON output"
        sources = [
            entry["source"]
            for entries in output.values()
            for entry in entries
            if entry.get("group") == GROUP_RANGE
        ]
        if sources:
            return f"unexpected {GROUP_RANGE} RP sources: {sources}"
        return None

    _, result = topotest.run_and_expect(check_rp_info, None, count=count, wait=1)
    assert result is None, f'"r1" {result}'


def check_local_sa(present):
    "R1 MSDP SA cache must (or must not) have the local source SA."
    output = show_json("show ip msdp sa json")
    if output is None:
        return "no show ip msdp sa JSON output"
    entry = output.get(SOURCE_GROUP, {}).get(SOURCE)
    local = entry is not None and entry.get("local") == "yes"
    if local != present:
        return f"unexpected ({SOURCE},{SOURCE_GROUP}) SA: {entry}"
    return None


def expect_local_sa(present):
    _, result = topotest.run_and_expect(partial(check_local_sa, present), None)
    assert result is None, f'"r1" {result}'


def test_pim_neighbor():
    "R1 must see the BSR router as PIM neighbor."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_json(
        "r1",
        "show ip pim neighbor json",
        {"r1-eth0": {"10.192.91.178": {"interface": "r1-eth0"}}},
        count=60,
    )


def test_pim_rpf_to_bsr():
    "R1 must resolve the BSR and C-RP addresses via static routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for address in [BSR_ADDRESS, CRP_HIGH, CRP_LOW]:
        expect_json(
            "r1",
            "show ip route json",
            {
                f"{address}/32": [
                    {
                        "protocol": "static",
                        "selected": True,
                        "nexthops": [
                            {"ip": "10.192.91.178", "interfaceName": "r1-eth0"}
                        ],
                    }
                ]
            },
        )


def test_receiver_join():
    "Start the receiver: R1 must learn its group membership."
    global receiver

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    receiver = tgen.gears["h1"].popen(
        [
            sys.executable,
            os.path.join(CWD, "../lib/mcast-tester.py"),
            GROUP,
            "h1-eth0",
        ]
    )
    expect_json(
        "r1",
        "show ip pim upstream json",
        {GROUP: {"*": {"sourceIgmp": True}}},
    )


def test_pim_bsm_send():
    "Start the BSR imitation."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    start_bsm_sender()


def test_pim_bsr_elected():
    "R1 must accept the BSR router as the elected BSR."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_json(
        "r1",
        "show ip pim bsr json",
        {"bsr": BSR_ADDRESS, "priority": BSR_PRIORITY, "state": "ACCEPT_PREFERRED"},
    )


def test_pim_bsrp_info():
    "R1 must have learned both C-RPs from the BSR."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_json(
        "r1",
        "show ip pim bsrp-info json",
        {
            "BSR Address": BSR_ADDRESS,
            GROUP_RANGE: {
                CRP_LOW: {"Rp Address": CRP_LOW, "Rp Priority": 10},
                CRP_HIGH: {"Rp Address": CRP_HIGH, "Rp Priority": 100},
                "Pending RP count": 0,
            },
        },
    )


def test_pim_rp_info_bsr():
    """
    The BSR elected RP (lowest priority value: 172.31.99.99) must be
    installed in the RP table and used to join the receiver's group.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_rp_info_bsr()
    expect_upstream_joined(CRP_LOW, "r1-eth0")


def test_pim_bsr_data_clear():
    """
    Forget the BSR learned RPs (with the BSR stopped so no BSM installs
    them again meanwhile): the range must be left without RP, and the BSR
    RP must be installed again once BSMs are received again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_bsm_sender()
    tgen.gears["r1"].vtysh_cmd("clear ip pim bsr-data")
    expect_range_without_rp()
    expect_upstream_not_joined()

    start_bsm_sender()
    expect_rp_info_bsr()
    expect_upstream_joined(CRP_LOW, "r1-eth0")


def test_pim_prefix_list_rp_removal():
    """
    Removing a prefix-list static RP while BSR RPs exist for 224.0.0.0/4
    must delete it, and the BSR learned 224.0.0.0/4 RP must be kept (with
    the BSR stopped, so no BSM installs it again), also when the
    prefix-list matches 224.0.0.0/4.

    Regressions: the removal installed the 224.0.0.0/4 BSR RP instead and
    returned, leaving the RP behind without its prefix-list. With a
    prefix-list matching 224.0.0.0/4, the 224.0.0.0/4 pseudo-RP lookup
    returned the prefix-list RP: `clear ip pim bsr-data` freed the BSR
    learned pseudo-RP and the BSR RP could no longer be installed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for plist in ["238.0.0.0/8 le 32", f"{GROUP_RANGE} le 32"]:
        r1.vtysh_cmd(
            f"configure terminal\nip prefix-list RP-PLIST seq 5 permit {plist}"
        )
        pim_config(f"rp {CRP_HIGH} prefix-list RP-PLIST")
        expect_json(
            "r1",
            "show ip pim rp-info json",
            {CRP_HIGH: [{"prefixList": "RP-PLIST", "source": "Static"}]},
        )

        r1.vtysh_cmd("clear ip pim bsr-data")
        expect_rp_info_bsr()

        stop_bsm_sender()
        pim_config(f"no rp {CRP_HIGH} prefix-list RP-PLIST")
        expect_rp_address_ranges(CRP_HIGH, [])
        expect_rp_info_bsr()
        r1.vtysh_cmd("configure terminal\nno ip prefix-list RP-PLIST")
        start_bsm_sender()

    assert r1.check_router_running() == "", "r1 daemons stopped running"


def test_pim_static_rp_over_bsr_rp_with_prefix_list_rp():
    """
    With a prefix-list RP covering 224.0.0.0/4, a static 224.0.0.0/4 RP
    must replace the BSR learned 224.0.0.0/4 RP. With the BSR stopped, so
    no BSM installs the BSR RP again, removing the prefix-list RP must keep
    the static RP, and removing the static RP must install the BSR RP
    again.

    Regressions: the 224.0.0.0/4 range was taken as covered by the
    prefix-list RP and the static RP was rejected when applied, although
    kept in the configuration. The prefix-list RP removal replaced the
    static 224.0.0.0/4 RP with the BSR RP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        f"configure terminal\nip prefix-list RP-PLIST seq 5 permit {GROUP_RANGE} le 32"
    )
    pim_config(f"rp {CRP_HIGH} prefix-list RP-PLIST")
    expect_rp_address_ranges(CRP_HIGH, [("RP-PLIST", "Static")])
    expect_rp_info_bsr()

    pim_config(f"rp {OTHER_RP} {GROUP_RANGE}")
    expect_rp_address_ranges(OTHER_RP, [(GROUP_RANGE, "Static")])
    expect_rp_address_ranges(CRP_LOW, [])

    stop_bsm_sender()
    pim_config(f"no rp {CRP_HIGH} prefix-list RP-PLIST")
    r1.vtysh_cmd("configure terminal\nno ip prefix-list RP-PLIST")
    expect_rp_address_ranges(CRP_HIGH, [])
    expect_rp_address_ranges(OTHER_RP, [(GROUP_RANGE, "Static")])
    expect_rp_address_ranges(CRP_LOW, [])

    pim_config(f"no rp {OTHER_RP} {GROUP_RANGE}")
    expect_rp_address_ranges(OTHER_RP, [])
    expect_rp_info_bsr()

    start_bsm_sender()


def test_pim_static_rp_removal_restores_bsr_rp():
    """
    Override the BSR RP with a static RP for the range, stop the BSR and
    remove the static RP: the BSR RP (still within its hold time) must be
    installed again right away.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pim_config(f"rp {CRP_HIGH} {GROUP_RANGE}")
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {CRP_HIGH: [{"group": GROUP_RANGE, "source": "Static"}]},
    )
    # The static RP replaced the BSR RP.
    expect_rp_address_ranges(CRP_LOW, [])

    stop_bsm_sender()
    pim_config(f"no rp {CRP_HIGH} {GROUP_RANGE}")
    # Only the static RP removal can install it, before the C-RPs hold time
    # expiration removes it.
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {CRP_LOW: [{"group": GROUP_RANGE, "source": "BSR"}]},
        count=15,
    )


def test_pim_rp_info_after_bsr_loss():
    """
    With the BSR stopped, once the C-RPs hold time expires no RP must
    remain for the range and the receiver's group must no longer be
    joined.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_bsm_sender()

    expect_range_without_rp(count=RP_HOLD_TIME + 30)
    expect_upstream_not_joined()


def test_pim_bsr_rp_expiry_with_prefix_list_rp_address():
    """
    With a prefix-list RP, the BSR changes its elected 224.0.0.0/4 RP to
    the same RP address: once the C-RP hold time expires, the BSR RP must
    be removed and the prefix-list RP kept.

    Regression: the BSR RP removal looked the RP up by address and group,
    and found the prefix-list RP (with a 224.0.0.0/4 group too), which the
    pseudo-RP moved after when changing its address: the prefix-list RP
    was deleted instead, and the BSR RP kept.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\nip prefix-list RP-PLIST seq 5 permit 238.0.0.0/8 le 32"
    )
    pim_config(f"rp {CRP_LOW} prefix-list RP-PLIST")
    expect_rp_address_ranges(CRP_LOW, [("RP-PLIST", "Static")])

    # Elect CRP_HIGH first, so the pseudo-RP address changes to CRP_LOW.
    start_bsm_sender(crps=[(CRP_HIGH, 10)])
    expect_rp_address_ranges(CRP_HIGH, [(GROUP_RANGE, "BSR")])
    start_bsm_sender()
    expect_rp_address_ranges(CRP_LOW, [("RP-PLIST", "Static"), (GROUP_RANGE, "BSR")])

    stop_bsm_sender()
    expect_range_without_rp(count=RP_HOLD_TIME + 30)
    expect_rp_address_ranges(CRP_LOW, [("RP-PLIST", "Static")])

    pim_config(f"no rp {CRP_LOW} prefix-list RP-PLIST")
    r1.vtysh_cmd("configure terminal\nno ip prefix-list RP-PLIST")
    r1.vtysh_cmd("clear ip pim bsr-data")
    expect_rp_address_ranges(CRP_LOW, [])


def test_pim_static_pseudo_rp_with_prefix_list_rp():
    """
    With a prefix-list RP covering all of 224.0.0.0/4, a static
    224.0.0.0/4 RP must be accepted, and removing it must not break the
    224.0.0.0/4 pseudo-RP.

    Regression: the 224.0.0.0/4 pseudo-RP lookup returned the prefix-list
    RP, so the static 224.0.0.0/4 RP was rejected when configured after
    the prefix-list RP. When configured before it, its removal freed the
    pseudo-RP: removing the prefix-list RP then left the receiver's group
    without RP, and pimd crashed pruning it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        f"configure terminal\nip prefix-list RP-PLIST seq 5 permit {GROUP_RANGE} le 32"
    )

    # Static RP configured before the prefix-list RP.
    pim_config(f"rp {CRP_LOW} {GROUP_RANGE}")
    expect_rp_address_ranges(CRP_LOW, [(GROUP_RANGE, "Static")])
    pim_config(f"rp {CRP_HIGH} prefix-list RP-PLIST")
    expect_rp_address_ranges(CRP_HIGH, [("RP-PLIST", "Static")])
    pim_config(f"no rp {CRP_LOW} {GROUP_RANGE}")
    expect_rp_address_ranges(CRP_LOW, [])
    pim_config(f"no rp {CRP_HIGH} prefix-list RP-PLIST")
    assert r1.check_router_running() == "", "r1 daemons stopped running"
    expect_rp_address_ranges(CRP_HIGH, [])
    pim_config(f"rp {OTHER_RP} 237.0.0.0/8")
    expect_rp_address_ranges(OTHER_RP, [("237.0.0.0/8", "Static")])
    pim_config(f"no rp {OTHER_RP} 237.0.0.0/8")
    expect_rp_address_ranges(OTHER_RP, [])

    # Static RP configured after the prefix-list RP.
    pim_config(f"rp {CRP_HIGH} prefix-list RP-PLIST")
    expect_rp_address_ranges(CRP_HIGH, [("RP-PLIST", "Static")])
    pim_config(f"rp {CRP_LOW} {GROUP_RANGE}")
    expect_rp_address_ranges(CRP_LOW, [(GROUP_RANGE, "Static")])

    pim_config(
        f"no rp {CRP_LOW} {GROUP_RANGE}", f"no rp {CRP_HIGH} prefix-list RP-PLIST"
    )
    r1.vtysh_cmd("configure terminal\nno ip prefix-list RP-PLIST")
    expect_rp_address_ranges(CRP_LOW, [])
    expect_rp_address_ranges(CRP_HIGH, [])


def test_pim_bsr_rp_with_prefix_list_rp_after_static_pseudo_rp():
    """
    Unset the 224.0.0.0/4 pseudo-RP by removing a static 224.0.0.0/4 RP,
    then configure a prefix-list RP covering all of 224.0.0.0/4: the BSR
    learned 224.0.0.0/4 RP must be installed.

    Regression: the 224.0.0.0/4 pseudo-RP lookup returned the prefix-list
    RP, so the BSM processing took the unset pseudo-RP, its source still
    static, for a static RP and ignored the BSR RP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    pim_config(f"rp {OTHER_RP} {GROUP_RANGE}")
    expect_rp_address_ranges(OTHER_RP, [(GROUP_RANGE, "Static")])
    pim_config(f"no rp {OTHER_RP} {GROUP_RANGE}")
    expect_range_without_rp()

    r1.vtysh_cmd(
        f"configure terminal\nip prefix-list RP-PLIST seq 5 permit {GROUP_RANGE} le 32"
    )
    pim_config(f"rp {CRP_HIGH} prefix-list RP-PLIST")
    expect_rp_address_ranges(CRP_HIGH, [("RP-PLIST", "Static")])

    start_bsm_sender()
    expect_rp_info_bsr()

    stop_bsm_sender()
    r1.vtysh_cmd("clear ip pim bsr-data")
    pim_config(f"no rp {CRP_HIGH} prefix-list RP-PLIST")
    r1.vtysh_cmd("configure terminal\nno ip prefix-list RP-PLIST")
    expect_range_without_rp()
    expect_rp_address_ranges(CRP_HIGH, [])


def test_pim_rp_info_pseudo_rp_order():
    """
    An RP for 224.0.0.0/4 and another range must have both ranges listed
    in `show ip pim rp-info json`, also with an RP address between them.

    Regression: the 224.0.0.0/4 pseudo-RP stayed first in the RP list when
    taking an RP address, and the RP entry listed after the other RP
    replaced its 224.0.0.0/4 range.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # CRP_LOW sorts before UNREACHABLE_RP.
    pim_config(
        f"rp {CRP_LOW} 237.0.0.0/8",
        f"rp {UNREACHABLE_RP} 238.0.0.0/8",
        f"rp {UNREACHABLE_RP} {GROUP_RANGE}",
    )
    expect_rp_address_ranges(
        UNREACHABLE_RP, [(GROUP_RANGE, "Static"), ("238.0.0.0/8", "Static")]
    )
    expect_rp_address_ranges(CRP_LOW, [("237.0.0.0/8", "Static")])

    pim_config(
        f"no rp {UNREACHABLE_RP} {GROUP_RANGE}",
        f"no rp {UNREACHABLE_RP} 238.0.0.0/8",
        f"no rp {CRP_LOW} 237.0.0.0/8",
    )
    expect_range_without_rp()
    expect_rp_address_ranges(UNREACHABLE_RP, [])
    expect_rp_address_ranges(CRP_LOW, [])


def test_pim_pseudo_rp_nexthop_cleared():
    """
    Unset the 224.0.0.0/4 pseudo-RP holding a reachable RP, by removing the
    static RP and by forgetting the BSR RP, then put an unreachable RP in
    it: the unreachable RP must have no outbound interface.

    Regression: the pseudo-RP kept the removed RP nexthop, and the
    unreachable RP (already tracked as the RP of another range, so no
    nexthop update came for it) was shown as reachable through it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    unreachable_rp_info = {
        UNREACHABLE_RP: [{"group": GROUP_RANGE, "outboundInterface": "Unknown"}]
    }
    pim_config(f"rp {UNREACHABLE_RP} 238.0.0.0/8")
    expect_rp_address_ranges(UNREACHABLE_RP, [("238.0.0.0/8", "Static")])
    # Zebra sends its answer when processing the registration: wait for it,
    # so pimd gets it (several commands later) before the pseudo-RP takes
    # the address, as a later answer would clear the pseudo-RP nexthop.
    expect_json(
        "r1",
        "show ip nht json",
        {
            "default": {
                "ipv4": {
                    UNREACHABLE_RP: {
                        "resolutions": [
                            {"unresolved": True, "clientList": [{"protocol": "pim"}]}
                        ]
                    }
                }
            }
        },
    )

    # Through the static RP removal.
    pim_config(f"rp {CRP_LOW} {GROUP_RANGE}")
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {CRP_LOW: [{"group": GROUP_RANGE, "outboundInterface": "r1-eth0"}]},
    )
    pim_config(f"no rp {CRP_LOW} {GROUP_RANGE}")
    expect_range_without_rp()
    pim_config(f"rp {UNREACHABLE_RP} {GROUP_RANGE}")
    expect_json("r1", "show ip pim rp-info json", unreachable_rp_info)
    pim_config(f"no rp {UNREACHABLE_RP} {GROUP_RANGE}")
    expect_range_without_rp()

    # Through the BSR RP removal.
    start_bsm_sender()
    expect_rp_info_bsr()
    stop_bsm_sender()
    r1.vtysh_cmd("clear ip pim bsr-data")
    expect_range_without_rp()
    pim_config(f"rp {UNREACHABLE_RP} {GROUP_RANGE}")
    expect_json("r1", "show ip pim rp-info json", unreachable_rp_info)

    pim_config(
        f"no rp {UNREACHABLE_RP} {GROUP_RANGE}", f"no rp {UNREACHABLE_RP} 238.0.0.0/8"
    )
    expect_range_without_rp()
    expect_rp_address_ranges(UNREACHABLE_RP, [])


def test_pim_rp_overlap():
    """
    A second RP for the group range of another RP must be rejected, but a
    configuration file can still move the range of an RP to another RP.

    Regression: the second RP was accepted in the configuration but pimd
    kept only the first one, so the running configuration lost the second
    one.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    pim_config(f"rp {OTHER_RP} {GROUP_RANGE}")
    expect_rp_address_ranges(OTHER_RP, [(GROUP_RANGE, "Static")])

    output = pim_config(f"rp {UNREACHABLE_RP} {GROUP_RANGE}")
    assert "already has RP" in output, f"second RP not rejected: {output}"
    expect_rp_address_ranges(OTHER_RP, [(GROUP_RANGE, "Static")])
    expect_rp_address_ranges(UNREACHABLE_RP, [])

    pim_config("rp 2001:db8::1 ff0f::/16", af="ipv6")
    output = pim_config("rp 2001:db8::2 FF0F::0/16", af="ipv6")
    assert "already has RP" in output, f"second IPv6 RP not rejected: {output}"
    expect_rp_address_ranges("2001:db8::1", [("ff0f::/16", "Static")], af="ipv6")
    expect_rp_address_ranges("2001:db8::2", [], af="ipv6")
    pim_config("no rp 2001:db8::1 ff0f::/16", af="ipv6")
    expect_rp_address_ranges("2001:db8::1", [], af="ipv6")

    # The check reads the candidate configuration, where the previous
    # command of the file already removed the range from OTHER_RP.
    pim_config(f"rp {UNREACHABLE_RP} 238.0.0.0/8", f"rp {OTHER_RP} 237.0.0.0/8")
    swap = os.path.join(tgen.logdir, "r1", "rp-swap.conf")
    with open(swap, "w") as f:
        f.write(
            "router pim\n"
            f" no rp {OTHER_RP} {GROUP_RANGE}\n"
            f" rp {UNREACHABLE_RP} {GROUP_RANGE}\n"
            "exit\n"
        )
    r1.cmd(f"vtysh -f {swap}")
    expect_rp_address_ranges(
        UNREACHABLE_RP, [(GROUP_RANGE, "Static"), ("238.0.0.0/8", "Static")]
    )
    expect_rp_address_ranges(OTHER_RP, [("237.0.0.0/8", "Static")])

    pim_config(
        f"no rp {OTHER_RP} 237.0.0.0/8",
        f"no rp {UNREACHABLE_RP} 238.0.0.0/8",
        f"no rp {UNREACHABLE_RP} {GROUP_RANGE}",
    )
    expect_range_without_rp()
    expect_rp_address_ranges(UNREACHABLE_RP, [])
    assert r1.check_router_running() == "", "r1 daemons stopped running"


def test_pim_static_rp_removal_unreachable_bsr_rp():
    """
    Override an unreachable BSR RP with a static RP, stop the BSR and
    remove the static RP: the BSR RP (still within its hold time) must be
    installed again, and the receiver's group must no longer be joined.
    The next test checks the mappings refresh of this unreachable RP
    install.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    start_bsm_sender(crps=[(UNREACHABLE_RP, 10)])
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {UNREACHABLE_RP: [{"group": GROUP_RANGE, "source": "BSR"}]},
    )
    expect_upstream_not_joined()

    pim_config(f"rp {CRP_LOW} {GROUP_RANGE}")
    expect_upstream_joined(CRP_LOW, "r1-eth0")

    stop_bsm_sender()
    pim_config(f"no rp {CRP_LOW} {GROUP_RANGE}")
    # Only the static RP removal can install it, before the C-RP hold time
    # expiration removes it.
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {UNREACHABLE_RP: [{"group": GROUP_RANGE, "source": "BSR"}]},
        count=15,
    )
    expect_upstream_not_joined(count=15)

    r1.vtysh_cmd("clear ip pim bsr-data")
    expect_range_without_rp()


def test_pim_static_local_rp_removal_unreachable_bsr_rp():
    """
    Override an unreachable BSR RP with R1 itself as static RP, R1 being
    the first hop router of a source: R1 originates the source local MSDP
    SA. Stop the source (its keepalive timer keeps the SA) and remove the
    static RP: the BSR RP must be installed again and R1 must withdraw the
    SA right away.

    Regression: the unreachable BSR RP install did not refresh the group
    to RP mappings, and the SA stayed until the source keepalive timer was
    restarted by packets (seen by the periodic source activity check, up
    to 31 seconds later), or expired.
    """
    global source

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    pim_config(f"msdp peer {MSDP_PEER} source {LOCAL_RP}")
    start_bsm_sender(crps=[(UNREACHABLE_RP, 10)])
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {UNREACHABLE_RP: [{"group": GROUP_RANGE, "source": "BSR"}]},
    )

    pim_config(f"rp {LOCAL_RP} {GROUP_RANGE}")
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {LOCAL_RP: [{"group": GROUP_RANGE, "source": "Static", "iAmRP": True}]},
    )

    # Start the source once its group has an RP: R1 ignores it otherwise.
    source = tgen.gears["h1"].popen(
        [
            sys.executable,
            os.path.join(CWD, "../lib/mcast-tester.py"),
            SOURCE_GROUP,
            "h1-eth0",
            "--send=0.5",
        ]
    )
    expect_json(
        "r1",
        "show ip pim upstream json",
        {SOURCE_GROUP: {SOURCE: {"firstHopRouter": True}}},
    )
    expect_local_sa(True)
    source.terminate()
    source.wait()
    result = check_local_sa(True)
    assert result is None, f'"r1" {result}'

    # The removal is applied when the command returns: check right away,
    # polling would also give time to the periodic source activity check.
    pim_config(f"no rp {LOCAL_RP} {GROUP_RANGE}")
    result = check_local_sa(False)
    assert result is None, f'"r1" SA not withdrawn: {result}'
    expect_json(
        "r1",
        "show ip pim rp-info json",
        {UNREACHABLE_RP: [{"group": GROUP_RANGE, "source": "BSR", "iAmRP": False}]},
    )

    stop_bsm_sender()
    pim_config(f"no msdp peer {MSDP_PEER}")
    r1.vtysh_cmd("clear ip pim bsr-data")
    expect_range_without_rp()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
