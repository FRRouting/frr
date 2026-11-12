#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_frr_reload_bgp_bfd_profile.py
#

"""
test_frr_reload_bgp_bfd_profile.py: test that frr-reload.py does not
remove BFD from a BGP neighbor configured only with
"neighbor X bfd profile P" or "neighbor X bfd check-control-plane-failure".

Both commands also enable BFD for the neighbor, so bgpd writes an extra
"neighbor X bfd" line in the running configuration. That line is not in the
configuration file, so frr-reload.py used to send "no neighbor X bfd" when
reloading the same, unchanged file. This removed the BFD session.

1. Start r1 with both neighbors configured without "neighbor X bfd".
2. frr-reload.py --test must not delete "neighbor X bfd".
3. frr-reload.py --reload of the unchanged file must keep the BFD sessions
   (same local discriminator) and must not reset the BGP sessions.
"""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd]

R1_CONF = os.path.join(CWD, "r1/frr.conf")
NEIGHBORS = {
    "192.168.1.2": "neighbor 192.168.1.2 bfd profile fast",
    "192.168.2.2": "neighbor 192.168.2.2 bfd check-control-plane-failure",
}


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def frr_reload(router, mode):
    tgen = get_topogen()
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    rc, out, err = router.net.cmd_status(
        "{}/frr-reload.py {} --stdout {}".format(frrdir, mode, R1_CONF), warn=False
    )
    assert rc == 0, "frr-reload.py {} failed (rc={}):\n{}\n{}".format(
        mode, rc, out, err
    )
    return out


def bfd_peers(router):
    output = json.loads(router.vtysh_cmd("show bfd peers json"))
    return {peer["peer"]: peer for peer in output}


def bgp_neighbors(router):
    return json.loads(router.vtysh_cmd("show bgp neighbors json"))


def check_sessions_up(router):
    bgp = bgp_neighbors(router)
    bfd = bfd_peers(router)
    for nbr in NEIGHBORS:
        if bgp.get(nbr, {}).get("bgpState") != "Established":
            return "BGP neighbor {} is not established".format(nbr)
        if bfd.get(nbr, {}).get("status") != "up":
            return "BFD peer {} is not up".format(nbr)
        if bgp[nbr].get("peerBfdInfo", {}).get("status") != "Up":
            return "BGP neighbor {} does not see BFD up".format(nbr)
    return None


def test_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _, result = topotest.run_and_expect(
        partial(check_sessions_up, r1), None, count=60, wait=1
    )
    assert result is None, result

    # bgpd shows "neighbor X bfd" in addition to the configured line
    running = r1.vtysh_cmd("show running-config bgpd").splitlines()
    running = [line.strip() for line in running]
    for nbr, line in NEIGHBORS.items():
        assert line in running, "{} missing from running config".format(line)
        assert "neighbor {} bfd".format(nbr) in running


def test_reload_test_keeps_neighbor_bfd():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    out = frr_reload(tgen.gears["r1"], "--test")
    to_delete = out.split("Lines To Delete")[-1].split("Lines To Add")[0]
    for nbr in NEIGHBORS:
        assert "neighbor {} bfd".format(nbr) not in to_delete, (
            "frr-reload.py wants to delete BFD from {}:\n{}".format(nbr, out)
        )


def test_reload_keeps_sessions():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    bfd_before = bfd_peers(r1)
    bgp_before = bgp_neighbors(r1)

    frr_reload(r1, "--reload")

    _, result = topotest.run_and_expect(
        partial(check_sessions_up, r1), None, count=10, wait=1
    )
    assert result is None, result

    bfd_after = bfd_peers(r1)
    bgp_after = bgp_neighbors(r1)
    for nbr in NEIGHBORS:
        assert bfd_after[nbr]["id"] == bfd_before[nbr]["id"], (
            "BFD session to {} was recreated".format(nbr)
        )
        assert (
            bgp_after[nbr]["connectionsEstablished"]
            == bgp_before[nbr]["connectionsEstablished"]
        ), "BGP session to {} was reset".format(nbr)

    running = [
        line.strip() for line in r1.vtysh_cmd("show running-config bgpd").splitlines()
    ]
    for nbr, line in NEIGHBORS.items():
        assert line in running, "{} lost after reload".format(line)
        assert "neighbor {} bfd".format(nbr) in running


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
