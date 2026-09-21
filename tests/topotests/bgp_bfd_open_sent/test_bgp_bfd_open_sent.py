#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Verify a BFD source rebuild cannot reset BGP in OpenSent."""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, rname, "frr.conf"),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def neighbor_json(router, peer):
    output = router.vtysh_cmd(f"show ip bgp neighbor {peer} json", isjson=True)
    return output[peer]


def wait_for_bfd_up(router, peer):
    def _check():
        output = router.vtysh_cmd("show bfd peers json", isjson=True)
        for session in output:
            if session.get("peer") == peer and session.get("status") == "up":
                return None
        return output

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"BFD session with {peer} did not reach Up"


def set_neighbor_shutdown(router, peer, shutdown):
    command = f"neighbor {peer} shutdown"
    if not shutdown:
        command = f"no {command}"
    router.vtysh_cmd(
        f"""
        configure terminal
         router bgp
          {command}
        """
    )


def test_source_rebuild_does_not_reset_open_sent():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    peer = "192.0.2.2"
    bgp_payload_blocked = False

    step("Bring BFD Up before allowing BGP to connect")
    wait_for_bfd_up(r1, peer)
    wait_for_bfd_up(r2, "192.0.2.1")

    # Discard setup-time BFD transitions so the transition checked below must
    # be produced by this BGP connection's source update.
    r1.cmd_raises("truncate -s 0 bgpd.log")

    try:
        step("Allow the TCP handshake but hold BGP in OpenSent")
        r1.cmd_raises(
            "iptables -I INPUT -p tcp --sport 179 "
            "-m length --length 70:65535 -j DROP"
        )
        bgp_payload_blocked = True

        set_neighbor_shutdown(r2, "192.0.2.1", False)
        set_neighbor_shutdown(r1, peer, False)

        def _open_sent():
            return neighbor_json(r1, peer).get("bgpState")

        _, result = topotest.run_and_expect(
            _open_sent, "OpenSent", count=20, wait=1
        )
        assert result == "OpenSent", "R1 did not reach OpenSent"

        step("Wait for the source rebuild BFD Up-to-Down callback")

        def _bfd_rebuilt():
            output = r1.net.cmd_nostatus(
                "grep -F 'bfd_session_status_update: neighbor 192.0.2.2' "
                "bgpd.log | grep -F 'bfd state Up -> Down'",
                warn=False,
            )
            return bool(output.strip())

        _, result = topotest.run_and_expect(
            _bfd_rebuilt, True, count=20, wait=1
        )
        assert result is True, "BFD source rebuild did not report Up-to-Down"

        topotest.sleep(1, "allow any erroneous BFD reset to be processed")
        neighbor = neighbor_json(r1, peer)
        assert neighbor.get("bgpState") == "OpenSent", neighbor
        assert neighbor.get("lastResetDueTo") != "BFD down initiated", neighbor

        notification = r1.net.cmd_nostatus(
            "grep -F 'Cease/BFD Down' bgpd.log", warn=False
        )
        assert not notification.strip(), notification

        step("Release BGP OPEN traffic and verify normal establishment")
        r1.cmd_raises(
            "iptables -D INPUT -p tcp --sport 179 "
            "-m length --length 70:65535 -j DROP"
        )
        bgp_payload_blocked = False

        def _established():
            output = neighbor_json(r1, peer)
            expected = {
                "bgpState": "Established",
                "peerBfdInfo": {"status": "Up"},
            }
            return topotest.json_cmp(output, expected)

        _, result = topotest.run_and_expect(
            _established, None, count=30, wait=1
        )
        assert result is None, "BGP did not establish after releasing OPEN traffic"
    finally:
        if bgp_payload_blocked:
            r1.run(
                "iptables -D INPUT -p tcp --sport 179 "
                "-m length --length 70:65535 -j DROP"
            )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
