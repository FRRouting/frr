#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright 2024 6WIND S.A.
#


"""
Test BGP OPEN NOTIFY (Configuration mismatch) followed by snmpwalk.
"""

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib import topotest

pytestmark = [pytest.mark.bgpd, pytest.mark.snmp]


def build_topo(tgen):
    """Build function"""

    tgen.add_router("r2")
    tgen.add_router("rr")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["rr"])


def setup_module(mod):
    snmpd = os.system("which snmpd")
    if snmpd:
        error_msg = "SNMP not installed - skipping"
        pytest.skip(error_msg)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            "-M snmp",
        )
        router.load_config(
            TopoRouter.RD_SNMP,
            os.path.join(CWD, "{}/snmpd.conf".format(rname)),
            "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX",
        )
        # Numbered instances only. No ospfd.vty, so vtysh's default ospfd
        # client stays disconnected while ospfd-1.vty and ospfd-2.vty are up.
        if rname == "r2":
            router.load_config(TopoRouter.RD_OSPF, instance="1")
            router.load_config(TopoRouter.RD_OSPF, instance="2")

    # load_config(snmpd) writes this file, and bgpd's subagent reads it.
    # The compiled-in ping is 15s, which is also the reconnect delay, and a
    # master that is still down after 30s causes the queue to be discarded.
    # One second leaves the restart inside that hold.
    tgen.gears["r2"].cmd("echo agentxPingInterval 1 >> /etc/snmp/frr.conf")
    if os.path.isfile("/usr/sbin/snmptrapd"):
        tgen.gears["r2"].load_config(
            TopoRouter.RD_TRAP,
            os.path.join(CWD, "r2/snmptrapd.conf"),
            " -On -OQ ",
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_agentx_debug_config():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    r2.vtysh_multicmd(
        """
configure terminal
debug agentx
"""
    )

    running = r2.vtysh_cmd("show running-config")
    assert "debug agentx" in running, "debug agentx missing from running-config"

    # bgpd's "show debugging [bgp]" is DEFUN_NOSH, so vtysh does not accept
    # the "bgp" keyword. "show debugging" is vtysh's command; it asks bgpd,
    # which prints the lib debug flags.
    debugs = r2.vtysh_cmd("show debugging")
    assert "SNMP AgentX debugging is on" in debugs, "debug agentx not reported"


def test_agentx_show():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    output = json.loads(r2.vtysh_cmd("show agentx status json"))
    bgpd = output["bgpd"]
    assert bgpd["moduleLoaded"] is True
    assert bgpd["enabled"] is True
    assert isinstance(bgpd["connected"], bool)
    assert bgpd["pendingNotifications"] >= 0
    assert bgpd["droppedNotifications"] >= 0
    if bgpd["connected"]:
        assert bgpd["socketFd"] >= 0
        assert bgpd["socketSendMaximum"] > 0
        assert bgpd["socketSendQueued"] >= 0
    else:
        assert "socketFd" not in bgpd
        assert "socketSendMaximum" not in bgpd
        assert "socketSendQueued" not in bgpd

    assert output["zebra"]["moduleLoaded"] is False

    text = r2.vtysh_cmd("show agentx status")
    assert "AgentX status for bgpd:" in text
    assert "Pending notifications:" in text
    assert "Dropped notifications:" in text


def test_agentx_show_ospf_instances():
    """Numbered ospfd clients stay visible, each as its own JSON value.

    r2 runs ospfd --instance 1 and --instance 2 and not the default ospfd.
    The default client's fd stays negative. A show that skips the whole
    ospfd chain in that case drops both instances. A show that queries the
    chain in one call prints both objects under one key, which is not JSON.
    """
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    output = json.loads(r2.vtysh_cmd("show agentx status json"))
    assert "ospfd" not in output
    for name in ("ospfd-1", "ospfd-2"):
        assert output[name]["moduleLoaded"] is False

    text = r2.vtysh_cmd("show agentx status")
    assert "AgentX status for ospfd-1:" in text
    assert "AgentX status for ospfd-2:" in text
    assert "AgentX status for ospfd:" not in text


def test_bgp_open_notification_change_configuration():
    tgen = get_topogen()

    tgen.gears["rr"].vtysh_multicmd(
        """
configure terminal
router bgp 65004
neighbor 192.168.12.2  password 8888"
"""
    )
    tgen.net["r2"].cmd("snmpwalk -v 2c -c public 127.0.0.1 .1.3.6.1.4.1.7336.4.2.1")
    tgen.gears["rr"].vtysh_multicmd(
        """
configure terminal
router bgp 65004
no neighbor 192.168.12.2  password 8888"
"""
    )

    def _check_bgp_session():
        r2 = tgen.gears["r2"]

        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {"peers": {"192.168.12.4": {"state": "Established"}}}
        }

        return topotest.json_cmp(output, expected)

    test_func1 = functools.partial(_check_bgp_session)
    _, result1 = topotest.run_and_expect(test_func1, None, count=120, wait=0.5)

    assert result1 is None, "Failed to verify the bgp session"


def _check_r2_established():
    r2 = get_topogen().gears["r2"]
    output = json.loads(r2.vtysh_cmd("show bgp summary json"))
    expected = {"ipv4Unicast": {"peers": {"192.168.12.4": {"state": "Established"}}}}

    return topotest.json_cmp(output, expected)


def test_agentx_debug_traps_logged():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    def _check_trap_logs():
        log = r2.net.getLog("log", "bgpd")
        for line in ("AgentX: queue trap", "AgentX: send trap to snmpd"):
            if line not in log:
                return "missing '{}' in bgpd.log".format(line)
        return None

    _, result = topotest.run_and_expect(_check_trap_logs, None, count=30, wait=1)
    assert result is None, result


PEER = "192.168.12.4"
# snmpTrapOID values. RFC 4273 bgpTraps 1 and 2.
_TRAP_BACKWARD = "1.3.6.1.2.1.15.0.2"
_TRAP_ESTABLISHED = "1.3.6.1.2.1.15.0.1"


def _bgpd_agentx(router):
    raw = router.vtysh_cmd("show agentx status json")
    try:
        output = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    bgpd = output.get("bgpd")
    if not isinstance(bgpd, dict):
        return raw
    return bgpd


def _rfc4273_sequence(text):
    """backward/established for PEER, in the order snmptrapd logged them."""
    sequence = []
    for line in text.splitlines():
        if PEER not in line:
            continue
        if re.search(re.escape(_TRAP_BACKWARD) + r"(?!\d)", line):
            sequence.append("backward")
        elif re.search(re.escape(_TRAP_ESTABLISHED) + r"(?!\d)", line):
            sequence.append("established")
    return sequence


def _stop_snmpd(router):
    """Kill snmpd only. killDaemons("snmpd") also matches snmptrapd.pid."""
    pid = router.cmd("cat /var/run/frr/snmpd.pid").strip()
    assert pid.isdigit(), "snmpd pid: {}".format(pid)
    router.cmd("kill -KILL {}".format(pid))
    # The listener is gone. Drop the pid file and the stale socket so the
    # restarted master can bind the same AgentX path.
    router.cmd("rm -f /var/run/frr/snmpd.pid /etc/frr/agentx")


def _start_snmpd(router):
    # startDaemons() finishes with "vtysh -f frr.conf". Re-applying the BGP
    # config can reset the session and add traps that this test did not queue.
    router.net.skip_unified_vtysh = True
    try:
        result = router.startDaemons(["snmpd"])
    finally:
        router.net.skip_unified_vtysh = False
    return result


def test_agentx_traps_held_across_master_restart():
    """Stop snmpd, queue a down then an up, and see both arrive in that order.

    Two notifications do not fill the AgentX send buffer, so pausing snmpd
    would still accept them and pendingNotifications would stay 0. Stopping
    the master is what holds them. The queue is discarded after 30s down, so
    the master is restored as soon as both are pending.
    """
    if not os.path.isfile("/usr/sbin/snmptrapd"):
        pytest.skip("snmptrapd not installed - skipping")

    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    def _idle_and_up():
        session = _check_r2_established()
        if session is not None:
            return session
        status = _bgpd_agentx(r2)
        if not isinstance(status, dict):
            return status
        if status.get("connected") is not True:
            return "master not connected: {}".format(status)
        if status.get("pendingNotifications") != 0:
            return "pending {}".format(status.get("pendingNotifications"))
        return None

    _, result = topotest.run_and_expect(_idle_and_up, None, count=30, wait=1)
    assert result is None, result

    dropped = _bgpd_agentx(r2)["droppedNotifications"]
    # Fail before snmpd is killed if snmptrapd never opened its log.
    r2.net.getLog("log", "snmptrapd")

    stopped = False
    try:
        _stop_snmpd(r2)
        stopped = True

        def _master_down():
            status = _bgpd_agentx(r2)
            if not isinstance(status, dict):
                return status
            if status.get("connected") is not False:
                return "master still connected"
            if status.get("pendingNotifications") != 0:
                return "pending {} at disconnect".format(
                    status.get("pendingNotifications")
                )
            if status.get("droppedNotifications") != dropped:
                return "dropped {} (baseline {})".format(
                    status.get("droppedNotifications"), dropped
                )
            return None

        _, result = topotest.run_and_expect(_master_down, None, count=20, wait=1)
        assert result is None, result

        # snmpd is dead, so anything already forwarded is in the log. The
        # mark is here, not before the kill, so a trap still in flight from
        # an earlier test is not counted as one this clear queued.
        trap_mark = len(r2.net.getLog("log", "snmptrapd"))

        # Leaving Established queues bgpBackwardTransition. The session
        # comes back from OpenConfirm and queues bgpEstablished. Nothing
        # else in this topology sends an RFC 4273 trap.
        r2.vtysh_cmd("clear bgp {}".format(PEER))

        def _both_held():
            session = _check_r2_established()
            if session is not None:
                return session
            status = _bgpd_agentx(r2)
            if not isinstance(status, dict):
                return status
            if status.get("connected") is not False:
                return "master came back before the held traps were counted"
            pending = status.get("pendingNotifications")
            if pending != 2:
                return "pending {}, want the down and the up held".format(pending)
            if status.get("droppedNotifications") != dropped:
                return "dropped {} while holding (baseline {})".format(
                    status.get("droppedNotifications"), dropped
                )
            return None

        _, result = topotest.run_and_expect(_both_held, None, count=40, wait=0.5)
        assert result is None, result

        restart = _start_snmpd(r2)
        assert restart == "", "snmpd did not restart: {}".format(restart)
        stopped = False

        def _queue_empty():
            session = _check_r2_established()
            if session is not None:
                return session
            status = _bgpd_agentx(r2)
            if not isinstance(status, dict):
                return status
            if status.get("connected") is not True:
                return "master not back"
            if status.get("pendingNotifications") != 0:
                return "pending {}".format(status.get("pendingNotifications"))
            if status.get("droppedNotifications") != dropped:
                return "dropped {} after restart (baseline {})".format(
                    status.get("droppedNotifications"), dropped
                )
            return None

        _, result = topotest.run_and_expect(_queue_empty, None, count=30, wait=1)
        assert result is None, result

        def _arrived_in_order():
            text = r2.net.getLog("log", "snmptrapd")[trap_mark:]
            sequence = _rfc4273_sequence(text)
            if sequence != ["backward", "established"]:
                return "trap order {}, want backward then established\n{}".format(
                    sequence, text
                )
            return None

        _, result = topotest.run_and_expect(_arrived_in_order, None, count=15, wait=1)
        assert result is None, result
    finally:
        if stopped:
            restart = _start_snmpd(r2)
            assert restart == "", "snmpd was left stopped: {}".format(restart)


def test_agentx_debug_disable():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    r2.vtysh_multicmd(
        """
configure terminal
no debug agentx
"""
    )

    running = r2.vtysh_cmd("show running-config")
    assert "debug agentx" not in running, "debug agentx still in running-config"

    # Same command as test_agentx_debug_config(). "show debugging bgp" is
    # not a vtysh command: bgpd registers it DEFUN_NOSH. The error text
    # does not contain the AgentX line, so that negative check always passed.
    debugs = r2.vtysh_cmd("show debugging")
    assert "Unknown command" not in debugs, debugs
    assert "SNMP AgentX debugging is on" not in debugs, "debug agentx still on"

    # The peer transition queues its trap synchronously, so once the session
    # is back up any debug line for it would already be in the log.
    log_offset = len(r2.net.getLog("log", "bgpd"))
    r2.vtysh_cmd("clear bgp 192.168.12.4")
    _, result = topotest.run_and_expect(
        _check_r2_established, None, count=120, wait=0.5
    )
    assert result is None, "Failed to verify the bgp session"

    new_log = r2.net.getLog("log", "bgpd")[log_offset:]
    assert "AgentX: queue trap" not in new_log, "AgentX debug logged while disabled"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
