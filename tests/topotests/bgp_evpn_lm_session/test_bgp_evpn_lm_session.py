#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026, Cisco Systems, Inc.
# Nageswara Soma <nsoma@cisco.com>

"""
EVPN config must survive a client disconnect, and be replayed afterwards.

bgpd keeps a second, synchronous zserv session (session_id 1) for the
label manager. That session does not own advertise-all-vni,
advertise-default-gw, or advertise-svi-ip. On bgpd exit both sessions
close: the primary close retains those knobs for graceful restart, and
the label-manager close used to take the same cleanup path and zero
them again.

Retaining that config means a reconnecting client re-sends a value zebra
already holds, so there is no transition for zebra to act on. Zebra has
to replay what it kept instead: the VNIs, and the BUM flooding mode the
same message carries. These tests restart bgpd with graceful restart
configured, which is the case where the config is retained, and check
each of those comes back.

The label-manager test itself opens a BGP zserv session with the
label-manager identity, waits until zebra has accepted the hello, then
closes it. The knobs must stay set. A following close of a session_id 0
BGP client must still clear them, so it runs last.
"""

import os
import re
import subprocess
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

HELPER = os.path.join(CWD, "zserv_bgp_session.py")
ZSERV_SOCK = "/var/run/frr/zserv.api"


L2VNI = 100
L3VNI = 1000
VTEP_IP = {"r1": "10.100.0.1", "r2": "10.100.0.2"}
PEER_IP = {"r1": "10.0.1.2", "r2": "10.0.1.1"}
SVI_IP = {"r1": "192.168.50.1/24", "r2": "192.168.50.2/24"}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # L2VNI 100 on a bridge that doubles as the SVI, plus L3VNI 1000 in
    # vrf-blue. That covers the EVPN config a reconnecting client has to
    # be told about again: VNIs, SVI MAC-IPs and the BUM flooding mode.
    for name in ("r1", "r2"):
        node = tgen.net[name]
        node.cmd_raises("ip link add vrf-blue type vrf table 10")
        node.cmd_raises("ip link set dev vrf-blue up")

        node.cmd_raises(
            "ip link add vxlan%d type vxlan id %d dstport 4789 local %s"
            % (L2VNI, L2VNI, VTEP_IP[name])
        )
        node.cmd_raises("ip link add name br%d type bridge stp_state 0" % L2VNI)
        node.cmd_raises("ip link set dev vxlan%d master br%d" % (L2VNI, L2VNI))
        node.cmd_raises("ip addr add %s dev br%d" % (SVI_IP[name], L2VNI))
        node.cmd_raises("ip link set up dev br%d" % L2VNI)
        node.cmd_raises("ip link set up dev vxlan%d" % L2VNI)
        node.cmd_raises("ip link set dev br%d master vrf-blue" % L2VNI)

        node.cmd_raises(
            "ip link add vxlan%d type vxlan id %d dstport 4789 local %s"
            % (L3VNI, L3VNI, VTEP_IP[name])
        )
        node.cmd_raises("ip link add name br%d type bridge stp_state 0" % L3VNI)
        node.cmd_raises("ip link set dev vxlan%d master br%d" % (L3VNI, L3VNI))
        node.cmd_raises("ip link set up dev br%d" % L3VNI)
        node.cmd_raises("ip link set up dev vxlan%d" % L3VNI)
        node.cmd_raises("ip link set dev br%d master vrf-blue" % L3VNI)

        node.cmd_raises("sysctl -w net.ipv4.ip_forward=1")

    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _bgp_zserv_count(router, session_id):
    output = router.vtysh_cmd("show zebra client")
    if session_id:
        return output.count("Client: bgp [%d]" % session_id)
    return len(re.findall(r"(?m)^Client: bgp$", output))


def _evpn_knobs(router):
    data = router.vtysh_cmd("show evpn json", isjson=True)
    if not isinstance(data, dict):
        return "show evpn json returned %r" % (data,)
    gateway = data.get("advertiseGatewayMacip")
    svi = data.get("advertiseSviMacip")
    if gateway != "Yes" or svi != "Yes":
        return "advertiseGatewayMacip=%s advertiseSviMacip=%s" % (gateway, svi)
    return None


def _evpn_knobs_cleared(router):
    data = router.vtysh_cmd("show evpn json", isjson=True)
    if not isinstance(data, dict):
        return "show evpn json returned %r" % (data,)
    gateway = data.get("advertiseGatewayMacip")
    svi = data.get("advertiseSviMacip")
    if gateway == "Yes" or svi == "Yes":
        return "advertiseGatewayMacip=%s advertiseSviMacip=%s" % (gateway, svi)
    return None


def _count_is(router, session_id, expected):
    count = _bgp_zserv_count(router, session_id)
    if count != expected:
        return "bgp session_id %s count %s, want %s" % (session_id, count, expected)
    return None


class _ZservHold:
    """BGP zserv session that stays up until release()."""

    def __init__(self, router, session_id):
        self.router = router
        self.session_id = session_id
        tag = "evpn-lm-%s" % session_id
        self.ready = "/var/run/frr/%s.ready" % tag
        self.release_path = "/var/run/frr/%s.release" % tag
        self.log_path = os.path.join(router.logdir, "%s.log" % tag)
        self.proc = None
        self.logf = None

    def start(self):
        self.router.cmd("rm -f %s %s" % (self.ready, self.release_path))
        self.logf = open(self.log_path, "w", encoding="utf-8")
        self.proc = self.router.popen(
            [
                sys.executable,
                HELPER,
                ZSERV_SOCK,
                str(self.session_id),
                self.ready,
                self.release_path,
            ],
            stdout=self.logf,
            stderr=subprocess.STDOUT,
        )

    def wait_until_accepted(self, baseline):
        """Wait until zebra shows this session in addition to baseline."""
        want = baseline + 1

        def check():
            if self.proc.poll() is not None:
                return "helper exited %s before zebra accepted the hello: %s" % (
                    self.proc.returncode,
                    _log_tail(self.log_path),
                )
            return _count_is(self.router, self.session_id, want)

        _, result = topotest.run_and_expect(check, None)
        assert result is None, result

    def release(self):
        if self.proc is None:
            return
        self.router.cmd("touch %s" % self.release_path)
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        if self.logf is not None:
            self.logf.close()
            self.logf = None
        self.proc = None


def _log_tail(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as logf:
            return logf.read()[-500:]
    except OSError as error:
        return str(error)


def _evpn_peer_established(router):
    data = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
    if not isinstance(data, dict):
        return "show bgp l2vpn evpn summary json returned %r" % (data,)
    peer = data.get("peers", {}).get(PEER_IP[router.name], {})
    if peer.get("state") != "Established":
        return "peer %s state %s" % (PEER_IP[router.name], peer.get("state"))
    return None


def _bgp_knows_vnis(router, vnis):
    """bgpd learns its VNIs from zebra, so this is the replay seen by BGP."""
    data = router.vtysh_cmd("show bgp l2vpn evpn vni json", isjson=True)
    if not isinstance(data, dict):
        return "show bgp l2vpn evpn vni json returned %r" % (data,)
    missing = [vni for vni in vnis if str(vni) not in data]
    if missing:
        return "bgpd is missing VNIs %s, has %s" % (
            missing,
            sorted(key for key in data if key.isdigit()),
        )
    return None


def _bgp_has_macip_route(router, ip):
    """Gateway and SVI MAC-IPs reach bgpd as type-2 routes carrying the IP.

    The MAC replay skips ZEBRA_MAC_DEF_GW entries, so these only come back
    from the explicit gateway MAC-IP walk the replay does.
    """
    data = router.vtysh_cmd("show bgp l2vpn evpn route type macip json", isjson=True)
    if not isinstance(data, dict):
        return "show bgp l2vpn evpn route type macip json returned %r" % (data,)
    seen = []
    for routes in data.values():
        if not isinstance(routes, dict):
            continue
        for prefix in routes:
            if not isinstance(prefix, str) or not prefix.startswith("["):
                continue
            seen.append(prefix)
            if ip in prefix:
                return None
    return "no MAC-IP route for %s, have %s" % (ip, seen)


def _hrep_installed(router, vtep_ip):
    """HREP shows up as an all-zero MAC pointing at the remote VTEP."""
    output = router.cmd("bridge fdb show dev vxlan%d" % L2VNI)
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "00:00:00:00:00:00":
            continue
        if "dst" in fields and vtep_ip in fields:
            return None
    return "no HREP entry for %s: %s" % (vtep_ip, output.replace("\n", " | "))


def _restart_bgpd(tgen, name):
    """Restart bgpd without rewriting the config it will be given back."""
    kill_router_daemons(tgen, name, ["bgpd"], save_config=False)
    start_router_daemons(tgen, name, ["bgpd"])

    router = tgen.gears[name]
    _, result = topotest.run_and_expect(
        lambda: _evpn_peer_established(router), None, count=40, wait=2
    )
    assert result is None, "EVPN session did not come back on %s: %s" % (
        name,
        result,
    )


def test_evpn_state_replayed_after_bgpd_restart():
    """Zebra must re-send its VNIs and MAC-IPs to a bgpd that reconnects.

    With graceful restart the EVPN config survives the disconnect, so the
    returning bgpd re-sends an unchanged advertise-all-vni. Zebra has to
    replay the VNIs anyway, or bgpd comes back believing it has none. The
    gateway and SVI MAC-IPs ride a separate walk and are checked too, so
    dropping either half of the replay fails this test.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    svi_ip = SVI_IP["r1"].split("/")[0]

    _, result = topotest.run_and_expect(
        lambda: _bgp_knows_vnis(router, (L2VNI, L3VNI)), None, count=40, wait=2
    )
    assert result is None, "VNIs were not learned before the restart: %s" % result

    _, result = topotest.run_and_expect(
        lambda: _bgp_has_macip_route(router, svi_ip), None, count=40, wait=2
    )
    assert result is None, "MAC-IP was not advertised before the restart: %s" % result

    logger.info("Restarting bgpd on r1 with its EVPN config retained")
    _restart_bgpd(tgen, "r1")

    _, result = topotest.run_and_expect(
        lambda: _bgp_knows_vnis(router, (L2VNI, L3VNI)), None, count=40, wait=2
    )
    assert result is None, "VNIs were not replayed after the restart: %s" % result

    _, result = topotest.run_and_expect(
        lambda: _bgp_has_macip_route(router, svi_ip), None, count=40, wait=2
    )
    assert result is None, "MAC-IP was not replayed after the restart: %s" % result


def test_bum_flood_mode_applied_after_bgpd_restart():
    """advertise-all-vni carries the BUM mode and it must still be applied.

    r1 starts with flooding disabled, so no HREP entry exists. bgpd is then
    brought back without that config, which means the only place it states
    head-end replication is the advertise-all-vni message zebra would
    otherwise ignore as unchanged.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    _, result = topotest.run_and_expect(
        lambda: _evpn_peer_established(router), None, count=40, wait=2
    )
    assert result is None, "EVPN session is not up: %s" % result

    assert (
        _hrep_installed(router, VTEP_IP["r2"]) is not None
    ), "HREP entry is present while flooding is disabled"

    logger.info("Restarting bgpd on r1 without 'flooding disable'")
    kill_router_daemons(tgen, "r1", ["bgpd"], save_config=False)
    router.run("sed -i '/flooding disable/d' /etc/frr/frr.conf")
    start_router_daemons(tgen, "r1", ["bgpd"])

    _, result = topotest.run_and_expect(
        lambda: _evpn_peer_established(router), None, count=40, wait=2
    )
    assert result is None, "EVPN session did not come back: %s" % result

    _, result = topotest.run_and_expect(
        lambda: _hrep_installed(router, VTEP_IP["r2"]), None, count=40, wait=2
    )
    assert result is None, "head-end replication was not restored: %s" % result


def test_evpn_config_survives_label_manager_close():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    _, result = topotest.run_and_expect(lambda: _evpn_knobs(router), None)
    assert result is None, "EVPN knobs were not installed: %s" % result

    _, result = topotest.run_and_expect(lambda: _count_is(router, 1, 1), None)
    assert result is None, "label-manager session did not connect: %s" % result

    logger.info("Closing a BGP zserv session with session_id 1")
    label_sessions = _bgp_zserv_count(router, 1)
    hold = _ZservHold(router, 1)
    hold.start()
    try:
        hold.wait_until_accepted(label_sessions)
    finally:
        hold.release()

    _, result = topotest.run_and_expect(lambda: _count_is(router, 1, 1), None)
    assert result is None, "label-manager session did not remain: %s" % result
    assert _bgp_zserv_count(router, 0) == 1, "primary BGP zserv session dropped"
    assert _evpn_knobs(router) is None, _evpn_knobs(router)

    logger.info("Closing a BGP zserv session with session_id 0")
    primary_sessions = _bgp_zserv_count(router, 0)
    hold = _ZservHold(router, 0)
    hold.start()
    try:
        hold.wait_until_accepted(primary_sessions)
    finally:
        hold.release()

    _, result = topotest.run_and_expect(
        lambda: _count_is(router, 0, primary_sessions), None
    )
    assert result is None, "primary BGP session count did not settle: %s" % result
    _, result = topotest.run_and_expect(lambda: _evpn_knobs_cleared(router), None)
    assert result is None, result
