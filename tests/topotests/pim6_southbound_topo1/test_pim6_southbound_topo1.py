#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim6_southbound_topo1.py
#
# Copyright (c) 2026 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim6_southbound_topo1.py: PIMv6-SM through the vendor southbound,
emulated by `pysbd` (lib/pysbd).

        +----+   2001:db8:12::/64  +----+
  h1 ---| r1 |---------------------| r2 | (RP 2001:db8:ffff::2)
        +----+                     +----+
           \\                        /
 2001:db8:13::/64                  / 2001:db8:23::/64
                \\     +----+      /
                 -----| r3 |------
                      +----+
                         |
                        h2 (source 2001:db8:3::10)

h1 joins ff05::100 and h2 sends to it. Every router runs `pysbd`, which owns
the kernel IPv6 multicast routing table: `zebra` hands it multicast routes
over FPM and `pim6d` (loaded with the `pim6_southbound` module) exchanges
MLD/PIM packets and data plane events with it.

Traffic first flows down the RPT (r3 -> r2 -> r1). Asking r1's data plane to
signal JOIN_SPT (the way a vendor data plane would) then moves it to the
shortest path tree (r3 -> r1). A DATA_START on the SPT interface sets the SPT
bit, so r1 prunes (S,G,rpt) and the RP stops forwarding the source to it.

Without its emulation (`-a`) `pysbd` only raises DATA_START on its own for
kernel cache misses (NOCACHE), so JOIN_SPT and the SPT DATA_START are sent as
commands.

Then r1 gets MLD `join-group` and `static-group` entries (ASM and SSM) on
h1's interface, without h1 joining those groups. The southbound turns a
`join-group` into MLD reports injected into pim6d; a `static-group` goes
straight into the TIB. Either way r1 must forward the groups onto h1's link
and stop once the entries are removed.

Finally h1 joins embedded RP groups (RFC 3956). One embeds r3 as its RP, so
r1 and r3 learn it from the group address and the tree bypasses the static RP
(r2). The other embeds an RP that the `embedded-rp group-list` rejects, so it
stays on the static RP. Leaving the first group makes r1 forget its RP.

Last, a `join-group` with more sources than fit in a MLDv2 report must be
split over several reports, and a MLDv1 `join-group` must send its report to
the group and its done to all routers.
"""

import ipaddress
import json
import math
import os
import select
import subprocess
import sys
from functools import partial

import pytest

pytestmark = [pytest.mark.pim6d]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.pim import McastTesterHelper
from lib.pysbd.helper import Pysbd
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

GROUP = "ff05::100"
SOURCE = "2001:db8:3::10"
ANY = "::"
# MLD static joins configured on r1's h1 interface: (kind, group, source).
# h1 itself never joins these groups.
STATIC_JOINS = [
    ("join-group", "ff05::102", None),
    ("static-group", "ff05::103", None),
    ("join-group", "ff35::102", SOURCE),
    ("static-group", "ff35::103", SOURCE),
]
# Embedded RP groups (RFC 3956): ff7X:0RPL:<RP prefix>::<group ID>, where the
# RP is the first PL (0x30 = 48) bits of the prefix with R as its last nibble.
# EMBEDDED_GROUP embeds r3 (2001:db8:ffff::3) and FILTERED_GROUP embeds r1
# (2001:db8:ffff::1). Every router only accepts embedded RPs in
# ff75:330:2001:db8:ffff::/80, so FILTERED_GROUP uses the static RP (r2).
EMBEDDED_RP = "2001:db8:ffff::3"
EMBEDDED_GROUP = "ff75:330:2001:db8:ffff::200"
FILTERED_RP = "2001:db8:ffff::1"
FILTERED_GROUP = "ff75:130:2001:db8:ffff::200"
# `McastTesterHelper.run_traffic()` sends one packet every 0.7 seconds.
SEND_INTERVAL = 0.7

# Captures what r1 sends on h1's link with scapy (tcpdump is often missing in
# CI images). See `r1_capture()` for the arguments and the output lines.
SNIFF_SCRIPT = """
import ipaddress
import sys

from scapy.all import (
    UDP,
    Ether,
    ICMPv6MLDone,
    ICMPv6MLReport,
    ICMPv6MLReport2,
    IPv6,
    sniff,
)

iface, mac, kind, dst, count, timeout = sys.argv[1:]
dst = ipaddress.ip_address(dst)


def describe(pkt):
    # Frames from r1's MAC address are the ones r1 sends (its egress).
    if Ether not in pkt or pkt[Ether].src.lower() != mac or IPv6 not in pkt:
        return None
    if ipaddress.ip_address(pkt[IPv6].dst) != dst:
        return None
    if kind == "udp" and UDP in pkt:
        return "udp {} {}".format(pkt[IPv6].src, dst)
    if kind == "mld":
        for layer, name in (
            (ICMPv6MLReport, "report"),
            (ICMPv6MLDone, "done"),
            (ICMPv6MLReport2, "report2"),
        ):
            if layer in pkt:
                group = getattr(pkt[layer], "mladdr", "::")
                return "mld {} {} {}".format(name, dst, ipaddress.ip_address(group))
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

# Added before the daemons start (zebra configures them too) so the IPv6
# addresses skip the duplicate address detection.
ADDRESSES = {
    "r1": [
        ("lo", "10.254.0.1/32", "2001:db8:ffff::1/128"),
        ("r1-eth0", "10.0.12.1/24", "2001:db8:12::1/64"),
        ("r1-eth1", "10.0.13.1/24", "2001:db8:13::1/64"),
        ("r1-eth2", "192.168.1.1/24", "2001:db8:1::1/64"),
    ],
    "r2": [
        ("lo", "10.254.0.2/32", "2001:db8:ffff::2/128"),
        ("r2-eth0", "10.0.12.2/24", "2001:db8:12::2/64"),
        ("r2-eth1", "10.0.23.2/24", "2001:db8:23::2/64"),
    ],
    "r3": [
        ("lo", "10.254.0.3/32", "2001:db8:ffff::3/128"),
        ("r3-eth0", "10.0.13.3/24", "2001:db8:13::3/64"),
        ("r3-eth1", "10.0.23.3/24", "2001:db8:23::3/64"),
        ("r3-eth2", "192.168.3.1/24", "2001:db8:3::1/64"),
    ],
}

pysbd = {}
app_helper = McastTesterHelper()


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    tgen.add_host("h1", "2001:db8:1::10/64", "via 2001:db8:1::1")
    tgen.add_host("h2", "2001:db8:3::10/64", "via 2001:db8:3::1")

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


def add_addresses(router):
    "Add the router addresses (the IPv6 ones without DAD)."
    for ifname, address, address6 in ADDRESSES[router.name]:
        router.cmd_raises("ip addr add {} dev {}".format(address, ifname))
        router.cmd_raises("ip -6 addr add {} dev {} nodad".format(address6, ifname))


def pysbd_command(rname, command):
    "Send a data plane command to `pysbd`: fails if it can't be delivered."
    pysbd[rname].command(command)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The data plane runs before FRR.
    for router in tgen.routers().values():
        add_addresses(router)
        pysbd[router.name] = Pysbd(router, ["-q", "ipv6:[::1]", "-f", "ipv4:127.0.0.1"])
        pysbd[router.name].start()

    for router in tgen.routers().values():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(router.name)),
            daemons=[
                ("zebra", "-M dplane_fpm_nl"),
                "mgmtd",
                "staticd",
                ("pim6d", "-M southbound:ipv6c:[::1]"),
            ],
        )

    tgen.start_router()

    for sbd in pysbd.values():
        sbd.wait_connected("pim6")
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
    Return the kernel IPv6 multicast routing table programmed by `pysbd` as
    {(source, group): {"iif": name, "oifs": [names], "packets": count}}.
    """
    mifs = {}
    for line in router.cmd("cat /proc/net/ip6_mr_vif").splitlines()[1:]:
        fields = line.split()
        mifs[fields[0]] = fields[1]

    def _address(address):
        return str(ipaddress.IPv6Address(address))

    routes = {}
    for line in router.cmd("cat /proc/net/ip6_mr_cache").splitlines()[1:]:
        fields = line.split()
        routes[(_address(fields[1]), _address(fields[0]))] = {
            "iif": mifs.get(fields[2], "mif" + fields[2]),
            "packets": int(fields[3]),
            "oifs": sorted(
                mifs.get(oif.split(":")[0], "mif" + oif) for oif in fields[6:]
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


def h1_receive(duration=5, group=GROUP):
    "Count the packets h1 receives from the source during `duration` seconds."
    report = app_helper.collect_receiver_sources(
        "h1", group, "h1-eth0", duration=duration
    )
    return report["sources"].get(SOURCE, 0)


def expect_h1_traffic(duration=5, group=GROUP):
    "Wait for h1 to receive the source's traffic, and return how much it got."

    def _check():
        received = h1_receive(duration, group)
        if received == 0:
            return "h1 got no {} packets from {} in {}s".format(group, SOURCE, duration)
        return received

    _, result = topotest.run_and_expect_type(_check, int, count=12, wait=1)
    assert isinstance(result, int), result
    return result


def link_local(router, ifname):
    "Return the link-local address of the router interface `ifname`."
    output = router.cmd_raises("ip -j -6 addr show dev {}".format(ifname))
    for link in json.loads(output):
        for address in link.get("addr_info", []):
            if address.get("scope") == "link":
                return address["local"]
    return None


def test_pim_neighbors():
    "Wait for PIMv6 adjacencies formed over the pysbd encapsulation."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # PIMv6 neighbors are known by their link-local addresses.
    neighbors = {
        "r1": {"r1-eth0": ("r2", "r2-eth0"), "r1-eth1": ("r3", "r3-eth0")},
        "r2": {"r2-eth0": ("r1", "r1-eth0"), "r2-eth1": ("r3", "r3-eth1")},
        "r3": {"r3-eth0": ("r1", "r1-eth1"), "r3-eth1": ("r2", "r2-eth1")},
    }
    for rname, peers in neighbors.items():

        def _check(rname=rname, peers=peers):
            expected = {}
            for ifname, (peer, peer_ifname) in peers.items():
                address = link_local(tgen.gears[peer], peer_ifname)
                if address is None:
                    return "{} has no link-local address".format(peer_ifname)
                expected[ifname] = {address: {"interface": ifname, "neighbor": address}}
            return topotest.router_json_cmp(
                tgen.gears[rname], "show ipv6 pim neighbor json", expected
            )

        _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
        assert result is None, "{}: PIMv6 neighbors did not come up".format(rname)


def test_mld_join():
    "h1 joins the group, r1 learns it through pysbd and joins the RPT."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_join("h1", GROUP, join_intf="h1-eth0")

    expected = {"default": {"r1-eth2": {GROUP: {"*": {"state": "JOIN"}}}}}
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ipv6 mld joins json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1: MLD group {} not learned".format(GROUP)

    # r2 is the RP: the (*,G) join from r1 must reach it.
    expected = {GROUP: {"*": {"inboundInterface": "lo"}}}
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r2"],
        "show ipv6 pim upstream json",
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

    # RPT: r3 -> r2 -> r1 -> h1. The kernel (*,G) lists its input interface
    # too (it only matches the packets of the interfaces in that list).
    expect_kernel_mroute(tgen.gears["r3"], SOURCE, GROUP, "r3-eth2", ["r3-eth1"])
    expect_kernel_mroute(tgen.gears["r2"], SOURCE, GROUP, "r2-eth1", ["r2-eth0"])
    expect_kernel_mroute(
        tgen.gears["r1"], ANY, GROUP, "r1-eth0", ["r1-eth0", "r1-eth2"]
    )


def test_spt_switch():
    "r1's data plane signals JOIN_SPT: traffic moves to r3 -> r1 directly."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rpt_ifindex = r1.cmd_raises("cat /sys/class/net/r1-eth0/ifindex").strip()
    pysbd_command("r1", "mrt6 join-spt {} {} {}".format(SOURCE, GROUP, rpt_ifindex))

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
        topotest.router_json_cmp, r1, "show ipv6 pim upstream json", expected
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
    pysbd_command("r1", "mrt6 data-start {} {} {}".format(SOURCE, GROUP, spt_ifindex))

    expected = {GROUP: {SOURCE: {"sptBit": 1}}}
    test_func = partial(
        topotest.router_json_cmp, r1, "show ipv6 pim upstream json", expected
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
            "{}ipv6 mld {} {}{}".format(no, kind, group, " " + source if source else "")
        )
    get_topogen().gears["r1"].vtysh_multicmd(commands)


def r1_running_static_joins():
    "Return the MLD static join lines in r1's running configuration."
    output = get_topogen().gears["r1"].vtysh_cmd("show running-config")
    return sorted(
        line.strip()
        for line in output.splitlines()
        if line.strip().startswith(("ipv6 mld join-group", "ipv6 mld static-group"))
    )


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
    "udp <source> <dst>" (`kind` "udp") or "mld <report|done|report2> <dst>
    <group>" (`kind` "mld").
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
    "Configure MLD join-group and static-group (ASM and SSM) on r1."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    static_join_config()

    want = sorted(
        "ipv6 mld {} {}{}".format(kind, group, " " + source if source else "")
        for kind, group, source in STATIC_JOINS
    )
    assert r1_running_static_joins() == want, "r1: MLD static joins not configured"

    # The southbound turns a join-group into MLD reports injected into
    # pim6d, so r1 learns those groups as if h1 had joined them.
    expected = {
        "default": {
            "r1-eth2": {
                group: {source or "*": {"state": "JOIN"}}
                for kind, group, source in STATIC_JOINS
                if kind == "join-group"
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ipv6 mld joins json", expected
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
            topotest.router_json_cmp, router, "show ipv6 pim upstream json", expected
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
            expect_kernel_mroute(r1, ANY, group, "r1-eth0", ["r1-eth0", "r1-eth2"])
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

    assert r1_running_static_joins() == [], "r1: MLD static joins not removed"

    def _not_forwarded():
        routes = kernel_mroutes(r1)
        for _, group, source in STATIC_JOINS:
            route = routes.get((source or ANY, group))
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


def expect_rp_info(router, rp, group, interface=None, missing=False):
    "Wait for `router` to use (or not) `rp` for exactly `group`."
    if missing:
        expected = {rp: None}
    else:
        expected = {rp: [{"group": "{}/128".format(group)}]}
        if interface is not None:
            expected[rp][0]["outboundInterface"] = interface

    test_func = partial(
        topotest.router_json_cmp, router, "show ipv6 pim rp-info json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "{}: RP {} for {} {}".format(
        router.name, rp, group, "still present" if missing else "not learned"
    )


def expect_upstream(router, group, source, expected):
    "Wait for `router`'s (source, group) upstream to match `expected`."
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ipv6 pim upstream json",
        {group: {source: expected}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "{}: ({}, {}) upstream is not {}".format(
        router.name, source, group, expected
    )


embedded_rp_join = None


def test_embedded_rp_join():
    "h1 joins embedded RP groups: r1 learns the RP from the MLD report."
    global embedded_rp_join

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    # Keep the embedded group's receiver apart so it can leave later on.
    embedded_rp_join = app_helper.run("h1", [EMBEDDED_GROUP, "h1-eth0"])
    app_helper.run_join("h1", FILTERED_GROUP, join_intf="h1-eth0")

    # r1 learns r3 as the RP from the group address, overriding the static
    # RP, and joins (*,G) towards it. r3 learns itself from that join.
    expect_rp_info(r1, EMBEDDED_RP, EMBEDDED_GROUP, interface="r1-eth1")
    expect_upstream(r1, EMBEDDED_GROUP, "*", {"inboundInterface": "r1-eth1"})
    expect_rp_info(r3, EMBEDDED_RP, EMBEDDED_GROUP, interface="lo")
    expect_upstream(r3, EMBEDDED_GROUP, "*", {"inboundInterface": "lo"})

    # The static RP never hears about the embedded group.
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ipv6 pim upstream json",
        {EMBEDDED_GROUP: None},
    )
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, "r2: joined the embedded RP group"

    # The group-list rejects r1 as an embedded RP: the static RP (r2) is used.
    expect_upstream(r2, FILTERED_GROUP, "*", {"inboundInterface": "lo"})
    for router in (r1, r2, r3):
        expect_rp_info(router, FILTERED_RP, FILTERED_GROUP, missing=True)


def test_embedded_rp_traffic():
    "h2 sends to the embedded RP groups: r3 (the embedded RP) feeds r1."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]
    app_helper.run_traffic("h2", [EMBEDDED_GROUP, FILTERED_GROUP], bind_intf="h2-eth0")

    # RPT through the embedded RP: r3 -> r1 -> h1, bypassing r2.
    expect_kernel_mroute(r3, SOURCE, EMBEDDED_GROUP, "r3-eth2", ["r3-eth0"])
    expect_kernel_mroute(r1, ANY, EMBEDDED_GROUP, "r1-eth1", ["r1-eth1", "r1-eth2"])
    expect_h1_traffic(group=EMBEDDED_GROUP)
    for (_, group), route in kernel_mroutes(r2).items():
        assert group != EMBEDDED_GROUP, "r2: forwards the embedded group: {}".format(
            route
        )

    # RPT through the static RP: r3 -> r2 -> r1 -> h1.
    expect_kernel_mroute(r2, SOURCE, FILTERED_GROUP, "r2-eth1", ["r2-eth0"])
    expect_kernel_mroute(r1, ANY, FILTERED_GROUP, "r1-eth0", ["r1-eth0", "r1-eth2"])
    expect_h1_traffic(group=FILTERED_GROUP)


def test_embedded_rp_leave():
    "h1 leaves the embedded RP group: r1 forgets the embedded RP."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    app_helper.host_procs["h1"] = [
        entry for entry in app_helper.host_procs["h1"] if entry[0] != embedded_rp_join
    ]
    embedded_rp_join.terminate()
    embedded_rp_join.wait()

    expect_rp_info(r1, EMBEDDED_RP, EMBEDDED_GROUP, missing=True)

    def _not_forwarded():
        route = kernel_mroutes(r1).get((ANY, EMBEDDED_GROUP))
        if route and "r1-eth2" in route["oifs"]:
            return "r1 still forwards {} to r1-eth2: {}".format(EMBEDDED_GROUP, route)
        return None

    _, result = topotest.run_and_expect(_not_forwarded, None, count=60, wait=1)
    assert result is None, result

    # h1's other memberships are untouched.
    expect_h1_traffic(group=FILTERED_GROUP)
    expect_h1_traffic()


def test_mld_many_sources():
    "A group with more sources than fit a MLDv2 report is split over reports."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "ff35::200"
    # 100 sources need two reports on a 1500 bytes MTU.
    sources = ["2001:db8:3::{:x}".format(0x1000 + i) for i in range(100)]
    interface = ["configure terminal", "interface r1-eth2"]
    r1.vtysh_multicmd(
        interface
        + ["ipv6 mld join-group {} {}".format(group, source) for source in sources],
    )

    def _learned():
        output = json.loads(r1.vtysh_cmd("show ipv6 mld joins json"))
        learned = output.get("default", {}).get("r1-eth2", {}).get(group, {})
        missing = sorted(set(sources) - set(learned))
        if missing:
            return "{} of {} sources missing (e.g. {})".format(
                len(missing), len(sources), missing[0]
            )
        return None

    _, result = topotest.run_and_expect(_learned, None, count=30, wait=1)
    assert result is None, "r1: {}".format(result)

    r1.vtysh_multicmd(
        interface
        + ["no ipv6 mld join-group {} {}".format(group, source) for source in sources],
    )


def test_mldv1_static_join():
    "MLDv1 join-group: the report goes to the group, the done to all routers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    group = "ff05::109"
    interface = ["configure terminal", "interface r1-eth2"]
    tgen.gears["r1"].vtysh_multicmd(interface + ["ipv6 mld version 1"])
    try:
        packets = r1_capture("mld", group, interface + ["ipv6 mld join-group " + group])
        assert (
            "mld report {} {}".format(group, group) in packets
        ), "r1 sent no MLDv1 report to {}: {}".format(group, packets)

        packets = r1_capture(
            "mld", "ff02::2", interface + ["no ipv6 mld join-group " + group]
        )
        assert (
            "mld done ff02::2 {}".format(group) in packets
        ), "r1 sent no MLDv1 done to ff02::2: {}".format(packets)
    finally:
        tgen.gears["r1"].vtysh_multicmd(interface + ["ipv6 mld version 2"])


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
