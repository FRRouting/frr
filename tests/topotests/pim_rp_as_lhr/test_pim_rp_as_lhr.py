#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_pim_rp_as_lhr.py
#
# Copyright (c) 2025 by Vijayalaxmi Basavaraj, Nvidia Inc.
#

"""
test_pim_rp_as_lhr.py: FHR co-located with LHR state, RP is also the LHR.

Models the reported "L3 multicast dropping on SVI interfaces" setup, where the
DUT is the first hop router for a source that shares its segment with a
receiver, while the RP is the DR, and therefore the last hop router, on the
segment holding the second receiver.

                        vlan100                        vlan200
    h1  11.0.0.1 (source ixia1) ----+                +---- rp  22.0.0.20
                                    |                |         lo 200.200.200.200
    h3  11.0.0.3 (receiver ixia3) --+-- sw100 -- dut -+-- sw200
                                        11.0.0.2 (eth0)  |
                                        22.0.0.2 (eth1)  +---- h2  22.0.0.10
                                        lo 100.100.100.100      (receiver ixia2)

Mapping to the reported topology: dut is sw2, rp is sw3 and holds the RP
address, h1/h3 are ixia1/ixia3 in vlan100 behind sw1/sw4, and h2 is ixia2 in
vlan200.  Addresses match the captured state so the output of this test can be
diffed against it directly.

Two DR outcomes drive the whole scenario and are asserted before anything else:

- dut is the DR on vlan100, so it is the FHR for h1 and it accepts h3's
  membership, which gives it a (*,G) and makes it a LHR at the same time.
- the RP wins the DR election on vlan200 (22.0.0.20 > 22.0.0.2), so dut is
  non-DR there and must not forward to h2 itself; the RP has to do it.

That leaves the RP as the only router that can serve h2, and it can only do so
once dut registers the source and the RP pulls the traffic back down.  The
failure being reproduced is dut ending up with an (S,G) that has no OIF and no
kernel entry, so nothing reaches h2:

    11.0.0.1  225.1.1.1  SFT  none  vlan100  none  0  --:--:--

The reported symptom is that traffic works and then stops, so a single check
after convergence would pass and prove nothing.  The state is therefore sampled
at three offsets from the moment traffic starts (see SAMPLE_OFFSETS), and PIM on
the dut-rp link is captured for the whole run so the join/prune exchange can be
read directly rather than inferred from router state.
"""

import os
import re
import sys
import time
import pytest
import functools

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.pim import McastTesterHelper

MCAST_GROUP = "225.1.1.1"
SOURCE = "11.0.0.1"
RP_ADDRESS = "200.200.200.200"

# The vlan200 segment, where the DUT has to forward natively for h2 to be served
DUT_VLAN200 = "dut-eth1"
DUT_VLAN200_ADDR = "22.0.0.2"
RP_VLAN200 = "rp-eth0"
RP_VLAN200_ADDR = "22.0.0.20"
ALL_PIM_ROUTERS = "224.0.0.13"

# Both routers run the default join period and holdtime, matching the capture.
JOIN_PRUNE_PERIOD = 60
JOIN_HOLDTIME = 210

# Offsets, in seconds from the start of traffic, at which forwarding state is
# sampled.  Each one asks a different question:
#
#   10s   the FHR is still encapsulating to the RP, so traffic can be flowing
#         over the register tunnel alone.  Nothing here says the native path
#         works, but a failure here means it never came up at all.
#   90s   past the 60 second register-stop suppression window and past one join
#         refresh period, so the native path has to be standing on its own.
#   215s  just past the 210 second join holdtime, which is the point where a
#         join that was sent once and never refreshed has expired.
SAMPLE_OFFSETS = (10, 90, 215)

# Auto-RP groups that may appear in PIM/IGMP output; ignore them in comparisons
_IGNORED_MCAST_GROUPS = {"224.0.1.39", "224.0.1.40"}

app_helper = McastTesterHelper()

# Set when traffic starts, so the samples below can be placed relative to it
traffic_start = None

# tcpdump handle and output path for the PIM capture on the dut-rp link
pim_capture = None
pim_capture_path = None


def _filter_ignored_mcast_groups(data):
    """Remove 224.0.1.39 and 224.0.1.40 from parsed JSON at every level."""
    if isinstance(data, dict):
        out = {}
        for key, val in data.items():
            if key in _IGNORED_MCAST_GROUPS:
                continue
            out[key] = _filter_ignored_mcast_groups(val)
        return out
    if isinstance(data, list):
        out = []
        for item in data:
            filtered = _filter_ignored_mcast_groups(item)
            # Drop dicts that represent an ignored group (e.g. {"group": "224.0.1.39"})
            if (
                isinstance(filtered, dict)
                and filtered.get("group") in _IGNORED_MCAST_GROUPS
            ):
                continue
            out.append(filtered)
        return out
    return data


def _router_json_cmp_no_autorp(router, cmd, expected):
    """Like router_json_cmp but filters out 224.0.1.39 and 224.0.1.40 from output."""
    got = router.vtysh_cmd(cmd, isjson=True)
    filtered = _filter_ignored_mcast_groups(got)
    return topotest.json_cmp(filtered, expected, exact=False)


def _expect_json(router, cmd, expected, assertmsg, count=30, wait=1):
    test_func = functools.partial(_router_json_cmp_no_autorp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert result is None, "{}: {}\n{}".format(router.name, assertmsg, result)


# State worth reading side by side with the reported capture.  upstream-join-desired
# is included because JoinDesired(S,G) is what decides whether a router keeps
# refreshing its join, and it is the one value the capture does not contain.
_STATE_CMDS = (
    "show ip pim upstream",
    "show ip pim join",
    "show ip pim upstream-join-desired",
    "show ip mroute",
    "show ip igmp groups",
)


def _log_multicast_state(tgen, when):
    """Dump the state that the reported capture contains, for side by side reading."""
    for rname in ("dut", "rp"):
        router = tgen.gears[rname]
        for cmd in _STATE_CMDS:
            logger.info("%s: %s (%s):\n%s", rname, cmd, when, router.vtysh_cmd(cmd))


def build_topo(tgen):
    """Build function"""

    tgen.add_router("dut")
    tgen.add_router("rp")

    # ixia1: source, in vlan100
    tgen.add_host("h1", ip="11.0.0.1/24", defaultRoute="via 11.0.0.2")
    # ixia3: receiver sharing vlan100 with the source
    tgen.add_host("h3", ip="11.0.0.3/24", defaultRoute="via 11.0.0.2")
    # ixia2: receiver in vlan200, served by the RP as DR of that segment
    tgen.add_host("h2", ip="22.0.0.10/24", defaultRoute="via 22.0.0.20")

    # vlan100 (11.0.0.0/24): source and a receiver on the same segment as dut
    sw100 = tgen.add_switch("sw100")
    sw100.add_link(tgen.gears["h1"])
    sw100.add_link(tgen.gears["h3"])
    sw100.add_link(tgen.gears["dut"])

    # vlan200 (22.0.0.0/24): dut, the RP and the second receiver
    sw200 = tgen.add_switch("sw200")
    sw200.add_link(tgen.gears["dut"])
    sw200.add_link(tgen.gears["rp"])
    sw200.add_link(tgen.gears["h2"])


def _start_pim_capture(tgen):
    """Capture PIM on the dut side of vlan200 for the duration of the run.

    Text output rather than a pcap: what matters is the upstream-neighbor field
    of each join/prune, and tcpdump already decodes it.  A join that names an
    address other than the DUT is discarded by the DUT without touching any
    state, which looks identical to the RP having gone silent.
    """
    global pim_capture, pim_capture_path

    dut = tgen.gears["dut"]

    if not dut.run("command -v tcpdump").strip():
        logger.warning("tcpdump is not available, skipping the PIM capture")
        return

    pim_capture_path = os.path.join(tgen.logdir, "dut", "pim-vlan200.txt")
    # -l keeps the decode flushed line by line so the file is readable even if
    # the run is interrupted; exec replaces the shell so terminate() hits tcpdump.
    pim_capture = dut.popen(
        "exec tcpdump -i {} -n -vvv -l ip proto 103 > {} 2>&1".format(
            DUT_VLAN200, pim_capture_path
        )
    )
    logger.info("capturing PIM on %s into %s", DUT_VLAN200, pim_capture_path)


def _stop_pim_capture():
    """Stop the capture and return its decoded text, or None if there is none."""
    global pim_capture

    if pim_capture is not None:
        pim_capture.terminate()
        try:
            pim_capture.wait(timeout=5)
        except Exception:
            pim_capture.kill()
        pim_capture = None

    if not pim_capture_path or not os.path.isfile(pim_capture_path):
        return None

    with open(pim_capture_path) as capfile:
        return capfile.read()


def setup_module(mod):
    """Sets up the pytest environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The bridges come up with IGMP snooping enabled, which would make L2
    # forwarding decisions part of an L3 test.  The reported failure happens
    # with snooping off, so keep both segments flooding.
    for swname in ("sw100", "sw200"):
        tgen.gears[swname].cmd(
            "ip link set dev {} type bridge mcast_snooping 0".format(swname)
        )

    app_helper.init(tgen)

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_PIM, None),
                (TopoRouter.RD_OSPF, None),
            ],
        )

    tgen.start_router()

    # The register and trace debugs record which SPTbit clause the RP takes and
    # whether it decides join is no longer desired, neither of which shows up in
    # any show command after the fact.  Deliberately no mroute debugging: the
    # symptom is data packets being punted to the CPU, so it would log once per
    # packet for the length of the run.
    for rname in ("dut", "rp"):
        tgen.gears[rname].vtysh_cmd(
            "\n".join(
                [
                    "debug pim events",
                    "debug pim trace",
                    "debug pim packets joins",
                    "debug pim packets register",
                    "debug pim zebra",
                ]
            )
        )

    _start_pim_capture(tgen)


def teardown_module():
    """Teardown the pytest environment"""
    tgen = get_topogen()

    _stop_pim_capture()
    app_helper.cleanup()

    tgen.stop_topology()


def test_pim_convergence():
    """Verify PIM neighbors and the unicast path to the RP"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying PIM adjacency on the vlan200 segment")

    expected = {DUT_VLAN200: {RP_VLAN200_ADDR: {"interface": DUT_VLAN200}}}
    _expect_json(
        tgen.gears["dut"],
        "show ip pim neighbor json",
        expected,
        "no PIM neighbor towards the RP",
    )

    expected = {RP_VLAN200: {DUT_VLAN200_ADDR: {"interface": RP_VLAN200}}}
    _expect_json(
        tgen.gears["rp"],
        "show ip pim neighbor json",
        expected,
        "no PIM neighbor towards the DUT",
    )

    # Both unicast directions have to be in place before PIM can be blamed for
    # anything: the RP needs a route back to the source to RPF towards it, and
    # the DUT needs a route to the RP address to register at all.  OSPF gets a
    # wider budget than PIM because default intervals are kept, so the broadcast
    # segment sits out a 40 second wait timer for DR election before adjacency.
    expected = {"11.0.0.0/24": [{"protocol": "ospf"}]}
    _expect_json(
        tgen.gears["rp"],
        "show ip route json",
        expected,
        "no unicast route to the source segment, cannot RPF towards the source",
        count=60,
    )

    expected = {"{}/32".format(RP_ADDRESS): [{"protocol": "ospf"}]}
    _expect_json(
        tgen.gears["dut"],
        "show ip route json",
        expected,
        "no unicast route to the RP address, cannot register the source",
        count=60,
    )


def test_dr_election():
    """Verify the DR layout the whole scenario depends on"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying dut is DR on vlan100 and non-DR on vlan200")

    # pimDesignatedRouterLocal is only emitted when this router is the DR, so
    # asking for it to be absent on dut-eth1 is what pins down the non-DR side.
    expected = {
        "dut-eth0": {
            "pimDesignatedRouter": "11.0.0.2",
            "pimDesignatedRouterLocal": True,
        },
        DUT_VLAN200: {
            "pimDesignatedRouter": RP_VLAN200_ADDR,
            "pimDesignatedRouterLocal": None,
        },
    }
    _expect_json(
        tgen.gears["dut"],
        "show ip pim interface json",
        expected,
        "unexpected DR layout, the scenario is not being reproduced",
    )

    expected = {
        RP_VLAN200: {
            "pimDesignatedRouter": RP_VLAN200_ADDR,
            "pimDesignatedRouterLocal": True,
        }
    }
    _expect_json(
        tgen.gears["rp"],
        "show ip pim interface json",
        expected,
        "RP is not the DR on the vlan200 segment",
    )


def test_pim_rp_info():
    """Verify the static RP is known on both routers"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, i_am_rp in (("dut", False), ("rp", True)):
        expected = {
            RP_ADDRESS: [
                {
                    "rpAddress": RP_ADDRESS,
                    "iAmRP": i_am_rp,
                    "group": "224.0.0.0/4",
                    "source": "Static",
                    "groupType": "ASM",
                }
            ]
        }
        _expect_json(
            tgen.gears[rname],
            "show ip pim rp-info json",
            expected,
            "RP info not found",
        )


def test_receivers_join():
    """Verify both receivers register their membership as in the reported state"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Joining %s from h3 (vlan100) and h2 (vlan200)", MCAST_GROUP)
    assert app_helper.run_join("h3", MCAST_GROUP, join_intf="h3-eth0") is True
    assert app_helper.run_join("h2", MCAST_GROUP, join_intf="h2-eth0") is True

    # h3 shares the segment with the source, so this membership is what gives
    # dut its (*,G) and makes it a LHR while it is also the FHR.
    expected = {MCAST_GROUP: {"*": {"sourceIgmp": True, "group": MCAST_GROUP}}}
    _expect_json(
        tgen.gears["dut"],
        "show ip pim upstream json",
        expected,
        "no (*,G) from the vlan100 membership, dut is not a LHR",
    )

    # The RP is DR on vlan200, so it is the router that owns h2's membership.
    _expect_json(
        tgen.gears["rp"],
        "show ip pim upstream json",
        expected,
        "RP did not take h2's membership, it is not acting as LHR",
    )


def test_fhr_role():
    """Verify dut takes the FHR role for the source sharing its LHR interface"""
    global traffic_start

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Sending %s traffic from h1", MCAST_GROUP)
    assert app_helper.run_traffic("h1", MCAST_GROUP, bind_intf="h1-eth0") is True
    traffic_start = time.time()

    # dut is a LHR for this group but the source is directly connected, so the
    # (S,G) has to come up as first hop router on the source interface rather
    # than as a last hop router entry inbound on pimreg.  firstHopRouter with an
    # inbound interface of dut-eth0 is what separates those two branches of
    # pim_mroute_msg_wholepkt(), so lastHopRouter is deliberately not asserted
    # here: dut owns h3's membership on vlan100, so once the RP's (S,G) join
    # arrives recv_join() legitimately takes a SRC_LHR reference as well.
    expected = {
        MCAST_GROUP: {
            SOURCE: {
                "firstHopRouter": True,
                "inboundInterface": "dut-eth0",
                "source": SOURCE,
                "group": MCAST_GROUP,
            }
        }
    }
    _expect_json(
        tgen.gears["dut"],
        "show ip pim upstream json",
        expected,
        "did not take the FHR role for directly connected {}".format(SOURCE),
        count=20,
    )

    _log_multicast_state(tgen, "after traffic start")


def test_rp_learns_source():
    """Verify the RP learns the source, i.e. registration got through"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        MCAST_GROUP: {
            SOURCE: {
                "source": SOURCE,
                "group": MCAST_GROUP,
                "inboundInterface": RP_VLAN200,
            }
        }
    }
    _expect_json(
        tgen.gears["rp"],
        "show ip pim upstream json",
        expected,
        "never learned source {}, registration did not get through".format(SOURCE),
        count=20,
    )


def _sg_oifs(mroute_json):
    """Outgoing interfaces of the (S,G) entry as the mroute JSON reports them.

    The per-source object carries scalars (iif, installed, oilSize) next to an
    "oil" object holding one entry per outgoing interface, keyed by name.  Muted
    OIFs are not emitted at all, so an interface that is also the IIF, as on the
    RP here, correctly does not show up.
    """
    sg = mroute_json.get(MCAST_GROUP, {}).get(SOURCE, {})
    return sorted(
        name
        for name, val in sg.get("oil", {}).items()
        if isinstance(val, dict) and val.get("outboundInterface")
    )


def _join_state(join_json, ifname, source=SOURCE):
    """ifjoin state of the plain (S,G) channel on one interface, or None if absent.

    NOINFO here is the reported state: it holds no join, so it contributes no
    OIF, and the transition into it tears down forwarding.
    """
    return (
        join_json.get(ifname, {})
        .get(MCAST_GROUP, {})
        .get(source, {})
        .get("channelJoinName")
    )


def _sg_rpt_state(join_json, ifname, source=SOURCE):
    """ifjoin state of the (S,G,rpt) channel, which the JSON keys separately.

    Worth reporting on its own: an (S,G,rpt) prune vetoes the interface as an
    OIF before the (*,G) membership is considered at all, so a router holding
    one cannot inherit that interface into the (S,G) OIL no matter how healthy
    the group membership on it is.
    """
    return (
        join_json.get(ifname, {})
        .get(MCAST_GROUP, {})
        .get("{},S,Grpt".format(source), {})
        .get("channelJoinName")
    )


def _wait_until_offset(offset):
    """Sleep until `offset` seconds after traffic started, and report the actual."""
    assert traffic_start is not None, "traffic was never started"

    elapsed = time.time() - traffic_start
    if elapsed < offset:
        time.sleep(offset - elapsed)
        elapsed = time.time() - traffic_start
    elif elapsed > offset + 5:
        logger.warning(
            "t+%ds sample is late, earlier checks took %.0fs", offset, elapsed
        )

    return elapsed


def _snapshot(tgen, label):
    """Record forwarding and join state on both routers at one instant.

    No retrying here: a retry would blur the timing, which is the whole point
    of sampling.
    """
    dut = tgen.gears["dut"]
    rp = tgen.gears["rp"]

    dut_join = dut.vtysh_cmd("show ip pim join json", isjson=True)
    rp_join = rp.vtysh_cmd("show ip pim join json", isjson=True)

    snap = {
        "label": label,
        "dut_oifs": _sg_oifs(dut.vtysh_cmd("show ip mroute json", isjson=True)),
        "dut_join": _join_state(dut_join, DUT_VLAN200),
        "dut_sg_rpt": _sg_rpt_state(dut_join, DUT_VLAN200),
        "rp_join": _join_state(rp_join, RP_VLAN200),
        "rp_sg_rpt": _sg_rpt_state(rp_join, RP_VLAN200),
        "rp_upstream": rp.vtysh_cmd("show ip pim upstream json", isjson=True)
        .get(MCAST_GROUP, {})
        .get(SOURCE, {}),
    }

    logger.info(
        "%s: dut (S,G) OIFs %s; dut vlan200 join %s, sgrpt %s; "
        "rp vlan200 join %s, sgrpt %s",
        label,
        snap["dut_oifs"] or "none",
        snap["dut_join"] or "no channel",
        snap["dut_sg_rpt"] or "no channel",
        snap["rp_join"] or "no channel",
        snap["rp_sg_rpt"] or "no channel",
    )
    logger.info("%s: rp (S,G) upstream: %s", label, snap["rp_upstream"])
    _log_multicast_state(tgen, label)

    return snap


def test_native_forwarding_is_sustained():
    """Verify dut keeps vlan200 in the (S,G) OIL, not just right after convergence.

    The reported failure is that traffic runs and then stops once the RP sends
    its register-stop, so the same state is checked at three offsets and all
    three have to hold.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    samples = []
    for offset in SAMPLE_OFFSETS:
        elapsed = _wait_until_offset(offset)
        snap = _snapshot(tgen, "t+{}s".format(offset))
        snap["elapsed"] = elapsed
        snap["forwarding"] = DUT_VLAN200 in snap["dut_oifs"]
        samples.append(snap)

    good = [s["label"] for s in samples if s["forwarding"]]
    bad = [s["label"] for s in samples if not s["forwarding"]]

    if not bad:
        logger.info("dut forwarded to vlan200 at every sample: %s", good)
        return

    if not good:
        verdict = "the native path never came up"
    else:
        verdict = (
            "the native path came up and then collapsed, which is the reported symptom"
        )

    detail = "\n".join(
        "  t+{:.0f}s: dut OIFs {}, dut {} join {}/sgrpt {}, "
        "rp {} join {}/sgrpt {}".format(
            s["elapsed"],
            s["dut_oifs"] or "none",
            DUT_VLAN200,
            s["dut_join"] or "-",
            s["dut_sg_rpt"] or "-",
            RP_VLAN200,
            s["rp_join"] or "-",
            s["rp_sg_rpt"] or "-",
        )
        for s in samples
    )

    # An (S,G,rpt) prune on the RP is expected, since the DUT keeps sending
    # Join(*,G) + Prune(S,G,rpt).  What matters is whether the RP still wants to
    # join despite it; JoinDesired false alongside the prune is the reported bug,
    # where the prune cancelled the local membership as well.
    rp_pruned = [s["label"] for s in samples if s["rp_sg_rpt"]]
    no_jd = [
        s["label"]
        for s in samples
        if not s["rp_upstream"].get("evaluateJoinDesired")
    ]
    if rp_pruned and no_jd:
        cause = (
            "The RP holds an (S,G,rpt) channel on {} at {} and JoinDesired(S,G) "
            "is false at {}. The prune is cancelling the (*,G) membership too, so "
            "the RP cannot inherit {} into the (S,G) OIL and never joins the SPT "
            "towards the source, which is why the DUT is never asked to "
            "forward.".format(RP_VLAN200, rp_pruned, no_jd, RP_VLAN200)
        )
    elif no_jd:
        cause = (
            "JoinDesired(S,G) is false on the RP at {} with no (S,G,rpt) prune to "
            "explain it, so look at the (*,G) membership and the RP's RPF towards "
            "the source.".format(no_jd)
        )
    else:
        cause = (
            "The RP wants to join (JoinDesired is true), so the break is further "
            "along: check that its (S,G) join reached the DUT and which upstream "
            "neighbor it named."
        )

    assert not bad, "dut has no OIF towards the RP at {}: {}\n{}\n{}".format(
        bad, verdict, detail, cause
    )


def test_traffic_reaches_vlan200_receiver():
    """Verify h2 actually gets the stream, not just that the OIL looks right"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying h2 receives %s from %s", MCAST_GROUP, SOURCE)
    received, report = _receiver_counts("h2", "h2-eth0")

    if not received:
        _log_multicast_state(tgen, "h2 receiving nothing")

    assert received > 0, "h2 (ixia2) received nothing for {} from {}: {}".format(
        MCAST_GROUP, SOURCE, report
    )
    logger.info("h2 received %d packets from %s", received, SOURCE)


def _receiver_counts(host, intf, retries=3, duration=5):
    """Count datagrams a host gets for the group, retrying while the tree settles."""
    report = {}

    for _ in range(retries):
        report = app_helper.collect_receiver_sources(
            host, MCAST_GROUP, intf, duration=duration
        )
        received = report.get("sources", {}).get(SOURCE, 0)
        if received:
            return received, report

    return 0, report


# tcpdump -vvv prints one join/prune across several lines, so records are split
# on the timestamp that starts every packet and then searched as a block.
_PKT_START = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d+ ")
_SENDER = re.compile(r"(\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): PIMv2")
_UPSTREAM = re.compile(r"upstream-neighbor: (\d+\.\d+\.\d+\.\d+)")
_GROUP = re.compile(r"group #\d+: (\d+\.\d+\.\d+\.\d+)")
_JOINED_SRC = re.compile(r"joined source #\d+: (\d+\.\d+\.\d+\.\d+)")


def _parse_join_prunes(text):
    """Pull sender, upstream-neighbor, groups and joined sources out of the decode."""
    records = []
    current = []

    for line in text.splitlines():
        if _PKT_START.match(line) and current:
            records.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        records.append("\n".join(current))

    joins = []
    for record in records:
        if "Join / Prune" not in record:
            continue

        sender = _SENDER.search(record)
        upstream = _UPSTREAM.search(record)
        joins.append(
            {
                "sender": sender.group(1) if sender else None,
                "upstream": upstream.group(1) if upstream else None,
                "groups": _GROUP.findall(record),
                "joined_sources": _JOINED_SRC.findall(record),
            }
        )

    return joins


def test_rp_refreshes_the_sg_join():
    """Verify the RP keeps joining the SPT and addresses those joins to the DUT.

    Reading this off the wire separates the two ways the DUT can end up without
    a join: the RP stopped sending them, or the RP is sending them named at
    someone other than the DUT, in which case the DUT drops them silently.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    decode = _stop_pim_capture()
    if decode is None:
        pytest.skip("no PIM capture was taken")

    joins = _parse_join_prunes(decode)
    logger.info("%d join/prune messages seen on %s", len(joins), DUT_VLAN200)

    from_rp = [
        jp
        for jp in joins
        if jp["sender"] == RP_VLAN200_ADDR
        and MCAST_GROUP in jp["groups"]
        and SOURCE in jp["joined_sources"]
    ]
    to_dut = [jp for jp in from_rp if jp["upstream"] == DUT_VLAN200_ADDR]
    misaddressed = [jp for jp in from_rp if jp["upstream"] != DUT_VLAN200_ADDR]

    logger.info(
        "RP sent %d (S,G) joins, %d addressed to the DUT, upstream-neighbor values seen: %s",
        len(from_rp),
        len(to_dut),
        sorted({jp["upstream"] for jp in from_rp}) or "none",
    )

    if misaddressed:
        logger.warning(
            "%d (S,G) joins name an upstream neighbor other than %s and are "
            "therefore discarded by the DUT without creating or refreshing state",
            len(misaddressed),
            DUT_VLAN200_ADDR,
        )

    # The run spans well over three join periods, so a healthy RP sends several.
    # Exactly one means it joined at flow start and then stopped, which leaves
    # the DUT holding a channel whose holdtime quietly runs down.
    assert len(to_dut) >= 2, (
        "RP sent {} (S,G) join(s) addressed to {} over {} seconds with a {} second "
        "join period; {} more were addressed elsewhere ({}). A single join means the "
        "RP stopped refreshing the SPT join after the register-stop.".format(
            len(to_dut),
            DUT_VLAN200_ADDR,
            SAMPLE_OFFSETS[-1],
            JOIN_PRUNE_PERIOD,
            len(misaddressed),
            sorted({jp["upstream"] for jp in misaddressed}) or "none",
        )
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
