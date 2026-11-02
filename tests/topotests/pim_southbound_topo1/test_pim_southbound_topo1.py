#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_southbound_topo1.py
#
# Copyright (c) 2026 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_southbound_topo1.py: PIM-SM through the vendor southbound, emulated
by `pysbd` (lib/pysbd).

        +----+    10.0.12.0/24   +----+
  h1 ---| r1 |-------------------| r2 | (RP 10.254.0.2)
        +----+                   +----+
           \\                      /
 10.0.13.0/24 \\                  / 10.0.23.0/24
                \\    +----+     /
                 ----| r3 |-----
                     +----+
                        |
                       h2 (source 192.168.3.10)

h1 joins 224.100.0.1 and h2 sends to it. Every router runs `pysbd`, which owns
the kernel multicast routing table: `zebra` hands it multicast routes over
FPM and `pimd` (loaded with the `pim_southbound` module) exchanges IGMP/PIM
packets and data plane events with it.

Traffic first flows down the RPT (r3 -> r2 -> r1). Asking r1's data plane to
signal JOIN_SPT (the way a vendor data plane would) then moves it to the
shortest path tree (r3 -> r1). A DATA_START on the SPT interface sets the SPT
bit, so r1 prunes (S,G,rpt) and the RP stops forwarding the source to it.

Without its emulation (`-a`) `pysbd` only raises DATA_START on its own for
kernel cache misses (NOCACHE), so JOIN_SPT and the SPT DATA_START are sent as
commands.

Finally r1 gets IGMP `join-group` and `static-group` entries (ASM and SSM)
on h1's interface, without h1 joining those groups. The southbound turns a
`join-group` into IGMP reports injected into pimd; a `static-group` goes
straight into the TIB. Either way r1 must forward the groups onto h1's link
and stop once the entries are removed.

Then the data plane reports the traffic stopping (DATA_STOP): r3 must keep
the (S,G) r1 still joins, r1 must ignore it on an interface never multicast
enabled, and fall back to the RPT otherwise. An IGMPv2 `join-group` must send
its report to the group and its leave to all routers. An mtrace from r1 must
be answered by r3 (mtrace stays with the operating system sockets). Last,
pimd crashes on r1: zebra must withdraw its routes from the data plane, and
the restarted pimd must install them again.
"""

import math
import os
import select
import socket
import struct
import subprocess
import sys
import time
from functools import partial

import pytest

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.pim import McastTesterHelper
from lib.pysbd.helper import Pysbd
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

GROUP = "224.100.0.1"
SOURCE = "192.168.3.10"
# IGMP static joins configured on r1's h1 interface: (kind, group, source).
# h1 itself never joins these groups.
STATIC_JOINS = [
    ("join-group", "224.100.0.2", None),
    ("static-group", "224.100.0.3", None),
    ("join-group", "232.1.1.2", SOURCE),
    ("static-group", "232.1.1.3", SOURCE),
]
# `McastTesterHelper.run_traffic()` sends one packet every 0.7 seconds.
SEND_INTERVAL = 0.7

# Captures what r1 sends on h1's link with scapy (tcpdump is often missing in
# CI images). See `r1_capture()` for the arguments and the output lines.
SNIFF_SCRIPT = """
import socket
import sys

from scapy.all import IP, UDP, Ether, sniff

# IGMP message types (queries are left out).
IGMP_TYPES = {0x12: "v1-report", 0x16: "v2-report", 0x17: "leave", 0x22: "v3-report"}

iface, mac, kind, dst, count, timeout = sys.argv[1:]


def describe(pkt):
    # Frames from r1's MAC address are the ones r1 sends (its egress).
    if Ether not in pkt or pkt[Ether].src.lower() != mac or IP not in pkt:
        return None
    if pkt[IP].dst != dst:
        return None
    if kind == "udp" and UDP in pkt:
        return "udp {} {}".format(pkt[IP].src, dst)
    if kind == "igmp" and pkt[IP].proto == 2:
        # Decoded by hand: scapy only knows IGMP with its contrib module.
        payload = bytes(pkt[IP].payload)
        if len(payload) >= 8 and payload[0] in IGMP_TYPES:
            group = socket.inet_ntoa(payload[4:8])
            return "igmp {} {} {}".format(IGMP_TYPES[payload[0]], dst, group)
    return None


# Filter in Python (lfilter): scapy compiles BPF filters with tcpdump.
sniff(
    iface=iface,
    count=int(count),
    timeout=float(timeout),
    store=False,
    lfilter=lambda pkt: describe(pkt) is not None,
    prn=lambda pkt: print(describe(pkt), flush=True),
    started_callback=lambda: print("ready", flush=True),
)
"""

pysbd = {}
app_helper = McastTesterHelper()


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    tgen.add_host("h1", "192.168.1.10/24", "via 192.168.1.1")
    tgen.add_host("h2", "192.168.3.10/24", "via 192.168.3.1")

    # r1-eth0 <-> r2-eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-eth1 <-> r3-eth0
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r2-eth1 <-> r3-eth1
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # r1-eth2 <-> h1-eth0
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # r3-eth2 <-> h2-eth0
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["h2"])


def pysbd_command(rname, command):
    "Send a data plane command to `pysbd`: fails if it can't be delivered."
    pysbd[rname].command(command)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The data plane runs before FRR: it follows the interfaces and the
    # addresses zebra configures.
    for router in tgen.routers().values():
        pysbd[router.name] = Pysbd(
            router, ["-p", "ipv4:127.0.0.1", "-f", "ipv4:127.0.0.1"]
        )
        pysbd[router.name].start()

    for router in tgen.routers().values():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(router.name)),
            daemons=[
                ("zebra", "-M dplane_fpm_nl"),
                "mgmtd",
                "staticd",
                ("pimd", "-M southbound:ipv4c:127.0.0.1"),
            ],
        )

    tgen.start_router()

    for sbd in pysbd.values():
        sbd.wait_connected("pim")
        sbd.wait_connected("fpm")

    app_helper.init(tgen)


def teardown_module(mod):
    tgen = get_topogen()

    app_helper.cleanup()
    tgen.stop_topology()

    for sbd in pysbd.values():
        sbd.stop()


def kernel_mroutes(router):
    """
    Return the kernel multicast routing table programmed by `pysbd` as
    {(source, group): {"iif": name, "oifs": [names], "packets": count}}.
    """
    vifs = {}
    for line in router.cmd("cat /proc/net/ip_mr_vif").splitlines()[1:]:
        fields = line.split()
        vifs[fields[0]] = fields[1]

    def _address(hexaddr):
        return socket.inet_ntoa(struct.pack("<I", int(hexaddr, 16)))

    routes = {}
    for line in router.cmd("cat /proc/net/ip_mr_cache").splitlines()[1:]:
        fields = line.split()
        routes[(_address(fields[1]), _address(fields[0]))] = {
            "iif": vifs.get(fields[2], "vif" + fields[2]),
            "packets": int(fields[3]),
            "oifs": sorted(
                vifs.get(oif.split(":")[0], "vif" + oif) for oif in fields[6:]
            ),
        }
    return routes


def expect_kernel_mroute(router, source, group, iif, oifs):
    "Wait for the kernel (pysbd) route to use `iif` and forward to `oifs`."
    want = {"iif": iif, "oifs": sorted(oifs)}

    def _check():
        route = kernel_mroutes(router).get((source, group))
        if route is None:
            return "no kernel route ({}, {})".format(source, group)
        got = {"iif": route["iif"], "oifs": route["oifs"]}
        if got != want:
            return "({}, {}) is {}, want {}".format(source, group, got, want)
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "{}: {}".format(router.name, result)


def h1_receive(duration=5):
    "Count the packets h1 receives from the source during `duration` seconds."
    report = app_helper.collect_receiver_sources(
        "h1", GROUP, "h1-eth0", duration=duration
    )
    return report["sources"].get(SOURCE, 0)


def expect_h1_traffic(duration=5):
    "Wait for h1 to receive the source's traffic, and return how much it got."

    def _check():
        received = h1_receive(duration)
        if received == 0:
            return "h1 got no packets from {} in {}s".format(SOURCE, duration)
        return received

    _, result = topotest.run_and_expect_type(_check, int, count=12, wait=1)
    assert isinstance(result, int), result
    return result


def test_pim_neighbors():
    "Wait for PIM adjacencies formed over the pysbd encapsulation."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    neighbors = {
        "r1": {"r1-eth0": "10.0.12.2", "r1-eth1": "10.0.13.3"},
        "r2": {"r2-eth0": "10.0.12.1", "r2-eth1": "10.0.23.3"},
        "r3": {"r3-eth0": "10.0.13.1", "r3-eth1": "10.0.23.2"},
    }
    for rname, expected in neighbors.items():
        expected = {
            ifname: {address: {"interface": ifname, "neighbor": address}}
            for ifname, address in expected.items()
        }
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rname],
            "show ip pim neighbor json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: PIM neighbors did not come up".format(rname)


def test_igmp_join():
    "h1 joins the group, r1 learns it through pysbd and joins the RPT."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_join("h1", GROUP, join_intf="h1-eth0")

    expected = {
        "r1-eth2": {"name": "r1-eth2", "groups": [{"group": GROUP}]},
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ip igmp groups json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1: IGMP group {} not learned".format(GROUP)

    # r2 is the RP: the (*,G) join from r1 must reach it.
    expected = {GROUP: {"*": {"inboundInterface": "lo"}}}
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r2"],
        "show ip pim upstream json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2: (*,{}) join from r1 not received".format(GROUP)


def test_rpt_traffic():
    "h2 starts sending: traffic registers at r2 and reaches h1 over the RPT."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_traffic("h2", GROUP, bind_intf="h2-eth0")

    expect_h1_traffic()

    # RPT: r3 -> r2 -> r1 -> h1.
    expect_kernel_mroute(tgen.gears["r3"], SOURCE, GROUP, "r3-eth2", ["r3-eth1"])
    expect_kernel_mroute(tgen.gears["r2"], SOURCE, GROUP, "r2-eth1", ["r2-eth0"])
    expect_kernel_mroute(
        tgen.gears["r1"], "0.0.0.0", GROUP, "r1-eth0", ["r1-eth0", "r1-eth2"]
    )


def test_spt_switch():
    "r1's data plane signals JOIN_SPT: traffic moves to r3 -> r1 directly."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rpt_ifindex = r1.cmd_raises("cat /sys/class/net/r1-eth0/ifindex").strip()
    pysbd_command("r1", "mrt join-spt {} {} {}".format(SOURCE, GROUP, rpt_ifindex))

    # r1 joins (S,G) towards the source through r3.
    expected = {
        GROUP: {
            SOURCE: {
                "inboundInterface": "r1-eth1",
                "rpfAddress": SOURCE,
                "joinState": "Joined",
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1: (S,G) did not switch to the SPT"

    # SPT: r3 -> r1 -> h1.
    expect_kernel_mroute(r1, SOURCE, GROUP, "r1-eth1", ["r1-eth2"])

    def _spt_forwarding():
        count = kernel_mroutes(r1).get((SOURCE, GROUP), {}).get("packets", 0)
        if count < 10:
            return "r1 (S,G) forwarded {} packets over the SPT".format(count)
        return None

    _, result = topotest.run_and_expect(_spt_forwarding, None, count=30, wait=1)
    assert result is None, result

    expect_h1_traffic()


def test_spt_rpt_pruned():
    "Once on the SPT, r1 prunes (S,G,rpt) so the RP stops forwarding to it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # The (S,G) route asks the data plane to watch the SPT interface
    # (notification interface): report the traffic arriving there, which a
    # vendor data plane does on its own (`pysbd` only does it with `-a`).
    r1 = tgen.gears["r1"]
    spt_ifindex = r1.cmd_raises("cat /sys/class/net/r1-eth1/ifindex").strip()
    pysbd_command("r1", "mrt data-start {} {} {}".format(SOURCE, GROUP, spt_ifindex))

    expected = {GROUP: {SOURCE: {"sptBit": 1}}}
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1: (S,G) SPT bit not set"

    # r2 (RP) no longer forwards (S,G) down the RPT towards r1.
    expect_kernel_mroute(tgen.gears["r2"], SOURCE, GROUP, "r2-eth1", [])

    # r3 only feeds r1 directly.
    expect_kernel_mroute(tgen.gears["r3"], SOURCE, GROUP, "r3-eth2", ["r3-eth0"])

    # h1 still receives, and no more than the source sends: a copy arriving
    # over the RPT as well would double the count.
    duration = 5
    received = expect_h1_traffic(duration)
    sent = math.floor(duration / SEND_INTERVAL) + 1
    assert received <= sent, "h1 got {} packets in {}s, source sent at most {}".format(
        received, duration, sent
    )


def static_join_config(remove=False):
    "Configure (or remove) every entry of `STATIC_JOINS` on r1's h1 interface."
    no = "no " if remove else ""
    commands = ["configure terminal", "interface r1-eth2"]
    for kind, group, source in STATIC_JOINS:
        commands.append(
            "{}ip igmp {} {}{}".format(no, kind, group, " " + source if source else "")
        )
    get_topogen().gears["r1"].vtysh_multicmd(commands)


def read_ready(fd, timeout):
    """
    Wait up to `timeout` seconds for the "ready" line on `fd`. It is read byte
    by byte so no packet line gets buffered outside `communicate()`'s reach.
    """
    line = b""
    while not line.endswith(b"\n"):
        if not select.select([fd], [], [], timeout)[0]:
            return False
        byte = os.read(fd, 1)
        if not byte:
            return False
        line += byte
    return line.strip() == b"ready"


def r1_capture(kind, dst, commands=None, count=0, timeout=10):
    """
    Capture the packets r1 sends to `dst` on h1's link (r1-eth2) for
    `timeout` seconds, or until `count` packets (0: no limit). `commands` run
    on r1 once the capture listens. Return one line per packet:
    "udp <source> <dst>" (`kind` "udp") or "igmp <type> <dst> <group>"
    (`kind` "igmp", type: v1-report, v2-report, leave or v3-report).
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    script = os.path.join(tgen.logdir, "r1", "sniff.py")
    with open(script, "w") as f:
        f.write(SNIFF_SCRIPT)
    mac = r1.cmd_raises("cat /sys/class/net/r1-eth2/address").strip().lower()
    python = tgen.net.get_exec_path(["python3", "python"])

    capture = r1.popen(
        [python, script, "r1-eth2", mac, kind, dst, str(count), str(timeout)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        started = read_ready(capture.stdout.fileno(), 60)
        if not started:
            capture.kill()
        elif commands:
            r1.vtysh_multicmd(commands)
        output, error = capture.communicate(timeout=timeout + 30)
    finally:
        if capture.poll() is None:
            capture.kill()
            capture.communicate()

    logger.info("r1 capture of %s to %s:\n%s%s", kind, dst, output, error)
    # A capture that can't run must fail rather than report no packets.
    assert started and capture.returncode == 0, "r1: capture failed (rc {}): {}".format(
        capture.returncode, error
    )
    return output.splitlines()


def r1_egress_capture(group, count=3, timeout=15):
    """
    Count the packets r1 sends to `group` on h1's link. The capture runs on
    r1-eth2 rather than on h1: h1 never joins the static groups, so the
    snooping bridge between them does not forward those packets to h1.
    """
    return len(r1_capture("udp", group, count=count, timeout=timeout))


def test_static_join_config():
    "Configure IGMP join-group and static-group (ASM and SSM) on r1."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    static_join_config()

    for kind in ["join-group", "static-group"]:
        groups = [
            {"source": source or "*", "group": group}
            for entry_kind, group, source in STATIC_JOINS
            if entry_kind == kind
        ]
        expected = {"r1-eth2": {"name": "r1-eth2", "groups": groups}}
        test_func = partial(
            topotest.router_json_cmp,
            r1,
            "show ip igmp {} json".format(kind),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r1: IGMP {} entries missing".format(kind)

    # The southbound turns a join-group into IGMP reports injected into
    # pimd, so r1 learns those groups as if h1 had joined them.
    expected = {
        "r1-eth2": {
            "name": "r1-eth2",
            "groups": [
                {"group": group}
                for kind, group, _ in STATIC_JOINS
                if kind == "join-group"
            ],
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp groups json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1: join-group memberships not learned"


def test_static_join_upstream():
    "Static joins pull the RPT (ASM) or the SPT towards r3 (SSM)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for kind, group, source in STATIC_JOINS:
        if source is None:
            expected = {group: {"*": {"inboundInterface": "lo"}}}
            router = tgen.gears["r2"]
        else:
            expected = {
                group: {source: {"inboundInterface": "r1-eth1", "joinState": "Joined"}}
            }
            router = r1
        test_func = partial(
            topotest.router_json_cmp, router, "show ip pim upstream json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: no upstream for {} {} {}".format(
            router.name, kind, source or "*", group
        )


def test_static_join_traffic():
    "h2 sends to the static groups: r1 forwards them to h1's link."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_traffic(
        "h2", [group for _, group, _ in STATIC_JOINS], bind_intf="h2-eth0"
    )

    r1 = tgen.gears["r1"]
    for kind, group, source in STATIC_JOINS:
        if source is None:
            # RPT: r3 -> r2 -> r1 -> h1 (no JOIN_SPT without emulation).
            expect_kernel_mroute(
                r1, "0.0.0.0", group, "r1-eth0", ["r1-eth0", "r1-eth2"]
            )
        else:
            # SSM: r3 -> r1 -> h1.
            expect_kernel_mroute(r1, source, group, "r1-eth1", ["r1-eth2"])
            expect_kernel_mroute(
                tgen.gears["r3"], source, group, "r3-eth2", ["r3-eth0"]
            )

        def _captured(group=group):
            if r1_egress_capture(group) == 0:
                return "r1 sent no packets for {} to r1-eth2".format(group)
            return None

        _, result = topotest.run_and_expect(_captured, None, count=4, wait=1)
        assert result is None, "{} {}: {}".format(kind, group, result)


def test_static_join_removal():
    "Removing the static joins stops r1 from forwarding to h1's link."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    static_join_config(remove=True)

    for kind in ["join-group", "static-group"]:
        test_func = partial(
            topotest.router_json_cmp,
            r1,
            "show ip igmp {} json".format(kind),
            {"r1-eth2": None},
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r1: IGMP {} entries not removed".format(kind)

    def _not_forwarded():
        routes = kernel_mroutes(r1)
        for _, group, source in STATIC_JOINS:
            route = routes.get((source or "0.0.0.0", group))
            if route and "r1-eth2" in route["oifs"]:
                return "r1 still forwards {} to r1-eth2: {}".format(group, route)
        return None

    _, result = topotest.run_and_expect(_not_forwarded, None, count=60, wait=1)
    assert result is None, result

    for _, group, _ in STATIC_JOINS:
        assert (
            r1_egress_capture(group, count=1, timeout=5) == 0
        ), "r1 still sends packets for {} to r1-eth2".format(group)

    # The original h1 membership is untouched.
    expect_h1_traffic()


def test_data_stop_fhr():
    "DATA_STOP on r3 (FHR) releases the traffic reference only: r1 still joins."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    ifindex = r3.cmd_raises("cat /sys/class/net/r3-eth2/ifindex").strip()
    pysbd_command("r3", "mrt data-stop {} {} {}".format(SOURCE, GROUP, ifindex))

    # The (S,G) join from r1 keeps the entry (and its downstream state).
    expected = {GROUP: {SOURCE: {"joinState": "Joined", "sourceStream": False}}}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r3: (S,G) not kept after DATA_STOP"

    expect_h1_traffic()


def test_data_stop_unknown_interface():
    """
    DATA_STOP on an interface index never multicast enabled is ignored: its
    VRF is unknown, so it can't release the traffic reference of a flow.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    expected = {GROUP: {SOURCE: {"joinState": "Joined"}}}
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1: no (S,G) before DATA_STOP"

    pysbd_command("r1", "mrt data-stop {} {} 4000".format(SOURCE, GROUP))

    # Give pimd time to (wrongly) release the flow.
    time.sleep(3)
    result = test_func()
    assert result is None, "r1: (S,G) released by DATA_STOP on interface 4000"


def test_data_stop_lhr():
    "DATA_STOP on r1's SPT releases SRC_LHR: traffic falls back to the RPT."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ifindex = r1.cmd_raises("cat /sys/class/net/r1-eth1/ifindex").strip()
    pysbd_command("r1", "mrt data-stop {} {} {}".format(SOURCE, GROUP, ifindex))

    # Nothing else holds r1's (S,G): it goes away.
    expected = {GROUP: {SOURCE: None}}
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1: (S,G) not removed after DATA_STOP"

    # The (*,G) keeps forwarding the source to h1.
    expect_h1_traffic()


def test_igmpv2_static_join():
    "IGMPv2 join-group: the report goes to the group, the leave to all routers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    group = "224.100.0.9"
    interface = ["configure terminal", "interface r1-eth2"]
    tgen.gears["r1"].vtysh_multicmd(interface + ["ip igmp version 2"])
    try:
        packets = r1_capture("igmp", group, interface + ["ip igmp join-group " + group])
        assert (
            "igmp v2-report {} {}".format(group, group) in packets
        ), "r1 sent no IGMPv2 report for {}: {}".format(group, packets)

        packets = r1_capture(
            "igmp", "224.0.0.2", interface + ["no ip igmp join-group " + group]
        )
        assert (
            "igmp leave 224.0.0.2 {}".format(group) in packets
        ), "r1 sent no IGMPv2 leave for {}: {}".format(group, packets)
    finally:
        tgen.gears["r1"].vtysh_multicmd(interface + ["ip igmp version 3"])


def test_mtrace():
    """
    mtrace from r1 to the source: r3 receives the query on a data plane
    interface from the operating system (`pysbd`, like a vendor data plane,
    leaves mtrace out of the encapsulation) and answers it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # mtracebis is optional (it is only installed in some builds).
    if not tgen.gears["r1"].run("command -v mtracebis").strip():
        pytest.skip("mtracebis is not installed")

    # The full trace goes unanswered: r3 takes the directly connected source
    # as the previous hop and forwards the request to it, so mtracebis
    # switches to hop by hop, where r3 answers the first hop. Without an
    # answer mtracebis keeps trying, so `timeout` ends it and it is only
    # retried once.
    for _ in range(2):
        output = tgen.gears["r1"].run("timeout 30 mtracebis {}".format(SOURCE))
        logger.info("mtracebis %s:\n%s", SOURCE, output)
        if "(10.0.13.3) PIM" in output and "Round trip time" in output:
            return

    assert False, "r1: mtrace to {} not answered by r3: {}".format(SOURCE, output)


def pysbd_routes(rname):
    "Return the (source, group) of the multicast routes zebra sent to `pysbd`."
    return sorted(
        (route["source"], route["group"]) for route in pysbd[rname].show("routes")
    )


def test_pimd_crash():
    """
    pimd crashes on r1 while zebra keeps running: zebra withdraws the routes
    pimd installed in the data plane, and the restarted pimd installs them
    again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    assert pysbd_routes("r1"), "r1: no data plane routes before pimd crashed"

    # SIGKILL: pimd can't remove its routes.
    r1.killDaemons(["pimd"])

    def _check():
        return pysbd_routes("r1") or None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "r1: routes kept after pimd crashed: {}".format(result)

    r1.startDaemons(["pimd"])
    pysbd["r1"].wait_connected("pim")

    def _restored():
        return None if pysbd_routes("r1") else "no data plane routes"

    _, result = topotest.run_and_expect(_restored, None, count=60, wait=1)
    assert result is None, "r1: {} after pimd restarted".format(result)
    expect_h1_traffic()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
