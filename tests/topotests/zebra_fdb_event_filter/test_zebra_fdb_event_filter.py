#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
zebra filters the kernel bridge fdb events (AF_BRIDGE RTM_NEWNEIGH and
RTM_DELNEIGH) on its dataplane netlink socket: they reach zebra only while
EVPN is enabled and only from ports of bridges with a VXLAN port.

The events that the filter drops are not visible in any show command, so
the test looks for zebra's "debug zebra kernel" line for the MAC.  To make
the absence of that line meaningful, an IPv4 neighbor (which the filter
passes) is added after the MAC: once zebra has logged the neighbor, it
has read everything that was queued on the socket before it.
"""

import os
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

VNI = 100
MARKER_PREFIX = "192.0.2."


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.cmd_raises(f"/bin/bash {CWD}/setup.sh")
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _zebra_log(tgen):
    path = os.path.join(tgen.logdir, "r1", "zebra.log")
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as logf:
        return logf.read()


def _fdb_event_logged(log, mac):
    return any(
        "AF_BRIDGE" in line and f"MAC {mac}" in line for line in log.splitlines()
    )


_marker = [10]


def _mac_reaches_zebra(tgen, port, mac):
    """
    Add a static fdb entry for mac on port and return whether zebra read
    the kernel event for it.  Removes the entry again.
    """
    r1 = tgen.gears["r1"]
    _marker[0] += 1
    marker_ip = f"{MARKER_PREFIX}{_marker[0]}"

    r1.cmd_raises(f"bridge fdb add {mac} dev {port} master static")
    r1.cmd_raises(
        f"ip neigh replace {marker_ip} lladdr 02:00:5e:00:00:{_marker[0]:02x} "
        "dev br200 nud permanent"
    )

    def _marker_seen():
        return f"IP {marker_ip} " in _zebra_log(tgen)

    _, seen = topotest.run_and_expect(_marker_seen, True, count=30, wait=1)
    assert seen, f"zebra did not log the IPv4 neighbor {marker_ip}"

    reached = _fdb_event_logged(_zebra_log(tgen), mac)
    r1.cmd_raises(f"bridge fdb del {mac} dev {port} master static")
    r1.cmd_raises(f"ip neigh del {marker_ip} dev br200")
    return reached


def _check_local_mac(router, mac, port):
    cmd = f"show evpn mac vni {VNI} mac {mac} json"
    return topotest.router_json_cmp(
        router, cmd, {mac: {"type": "local", "intf": port}}
    )


def _wait_local_mac(router, mac, port):
    test_func = functools.partial(_check_local_mac, router, mac, port)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"MAC {mac} on {port} is not a local EVPN MAC: {result}"


def _set_evpn(router, enable):
    router.vtysh_cmd(
        f"""
        configure terminal
        router bgp 65000
         address-family l2vpn evpn
          {"" if enable else "no "}advertise-all-vni
        """
    )


def test_no_evpn_no_fdb_events():
    """Without EVPN no bridge fdb event reaches zebra."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert not _mac_reaches_zebra(tgen, "acc200", "02:00:5e:00:01:01")
    assert not _mac_reaches_zebra(tgen, "acc100", "02:00:5e:00:01:02")


def test_evpn_fdb_events_of_vxlan_bridges():
    """With EVPN, events from ports of bridges with a VXLAN port reach zebra."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _set_evpn(r1, True)

    test_func = functools.partial(
        topotest.router_json_cmp, r1, f"show evpn vni {VNI} json", {"vni": VNI}
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"VNI {VNI} not known to zebra: {result}"

    mac = "02:00:5e:00:02:01"
    r1.cmd_raises(f"bridge fdb add {mac} dev acc100 master static")
    _wait_local_mac(r1, mac, "acc100")
    r1.cmd_raises(f"bridge fdb del {mac} dev acc100 master static")

    # A bridge without a VXLAN port stays filtered
    assert not _mac_reaches_zebra(tgen, "acc200", "02:00:5e:00:02:02")


def test_evpn_new_bridge_port():
    """A MAC learned right after a port joins an EVPN bridge is not lost."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    mac = "02:00:5e:00:03:01"
    r1.cmd_raises(
        "ip link add acc101 type dummy && ip link set acc101 master br100 && "
        f"ip link set acc101 up && bridge fdb add {mac} dev acc101 master static"
    )
    _wait_local_mac(r1, mac, "acc101")
    r1.cmd_raises(f"bridge fdb del {mac} dev acc101 master static")
    r1.cmd_raises("ip link del acc101")


def test_evpn_disable_no_fdb_events():
    """After EVPN is disabled, fdb events are filtered again."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _set_evpn(r1, False)

    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show evpn json",
        {"advertiseGatewayMacip": None},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"EVPN still enabled: {result}"

    assert not _mac_reaches_zebra(tgen, "acc100", "02:00:5e:00:04:01")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
