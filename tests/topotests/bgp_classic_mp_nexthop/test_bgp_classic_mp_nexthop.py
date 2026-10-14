# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Qipeng Ding
"""Classic IPv4 and MP IPv6 NLRI must keep their own next-hop contexts."""

import json
import os
import subprocess
import time

import pytest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]
CWD = os.path.dirname(os.path.realpath(__file__))
V4, V6 = "198.51.100.61/32", "2001:db8:2361::/64"


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in ["r1", "r2", "r3"]:
        switch.add_link(tgen.add_router(name))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.cmd(
            "sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0"
        )
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def wait_for(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("required native BGP observation missing")


def test_mixed_nlri_context(tmp_path):
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors
    r1, r2, r3 = [tgen.gears[name] for name in ["r1", "r2", "r3"]]
    pids = {
        name: tgen.gears[name].cmd("cat /var/run/frr/bgpd.pid").strip()
        for name in ["r1", "r3"]
    }

    def routes(router, family):
        result = router.vtysh_cmd(
            "show bgp {} unicast json".format(family), isjson=True
        )
        assert "routes" in result, result
        return result["routes"]

    def present(router):
        return V4 in routes(router, "ipv4") and V6 in routes(router, "ipv6")

    def absent(router):
        return V4 not in routes(router, "ipv4") and V6 not in routes(router, "ipv6")

    def accepted():
        if not present(r3):
            return False
        return all(
            len(routes(r3, family)[prefix]) == 1
            and routes(r3, family)[prefix][0].get("valid") is True
            for family, prefix in [("ipv4", V4), ("ipv6", V6)]
        )

    def drops():
        return {
            address: r1.vtysh_cmd(
                "show bgp neighbor {} json".format(address), isjson=True
            )[address]["connectionsDropped"]
            for address in ["192.0.2.13", "192.0.2.30"]
        }

    peer_log = tmp_path / "peer.log"
    snapshots = []
    with peer_log.open("w") as peer_output:
        peer = None
        try:
            peer = r2.popen(
                ["python3", os.path.join(CWD, "valid_peer.py")],
                stdin=subprocess.PIPE,
                stdout=peer_output,
                stderr=peer_output,
            )
            wait_for(lambda: "ESTABLISHED" in peer_log.read_text())
            wait_for(
                lambda: r1.vtysh_cmd("show bgp neighbor 192.0.2.30 json", isjson=True)[
                    "192.0.2.30"
                ]["bgpState"]
                == "Established"
            )
            assert absent(r1) and absent(r3)
            initial_drops = drops()
            for cycle in range(2):
                peer.stdin.write("announce\n")
                peer.stdin.flush()
                wait_for(lambda: present(r1))
                local4, local6 = routes(r1, "ipv4")[V4], routes(r1, "ipv6")[V6]
                snapshots.append(
                    {"cycle": cycle, "local_v4": local4, "local_v6": local6}
                )
                (tmp_path / "observations.json").write_text(
                    json.dumps(snapshots, indent=2)
                )
                assert len(local4) == len(local6) == 1
                assert (
                    local4[0]["nexthops"][0]["ip"] == "192.0.2.13"
                ), "classic NLRI used the MP next-hop context: {}".format(local4)
                assert local6[0]["nexthops"][0]["ip"] == "2001:db8:1::13", local6
                wait_for(accepted)
                for family, prefix in [("ipv4", V4), ("ipv6", V6)]:
                    observed = routes(r3, family)[prefix]
                    assert len(observed) == 1 and observed[0]["valid"] is True, observed
                    assert observed[0]["path"] == "65010 65020", observed
                peer.stdin.write("withdraw\n")
                peer.stdin.flush()
                wait_for(lambda: absent(r1) and absent(r3))
                assert drops() == initial_drops
            for name in ["r1", "r3"]:
                assert (
                    tgen.gears[name].cmd("cat /var/run/frr/bgpd.pid").strip()
                    == pids[name]
                )
        finally:
            if peer is not None and peer.poll() is None:
                try:
                    peer.stdin.write("stop\n")
                    peer.stdin.flush()
                    peer.wait(timeout=10)
                except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                    peer.terminate()
                    try:
                        peer.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        peer.kill()
                        peer.wait(timeout=3)
        assert peer is not None and peer.returncode == 0
