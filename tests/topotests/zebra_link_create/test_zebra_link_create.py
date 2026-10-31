#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_link_create.py
#
# Test zebra creating Linux interfaces (bridge, veth, vlan, gre) via netlink
# using the interface "link-type" and "master" configuration commands.
#

"""
test_zebra_link_create.py: configure link-type / master on interfaces and
verify the kernel state, dependency ordering, re-creation and removal.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

pytestmark = [pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Sets up the pytest environment"
    tgen = Topogen({"s1": ("r1")}, request.module.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def conf(r1, *cmds):
    r1.vtysh_cmd("configure terminal\n" + "\n".join(cmds))


def link(r1, name):
    "Return kernel link info dict for NAME, or None if it does not exist."
    out = r1.cmd("ip -d -j link show dev {} 2>/dev/null".format(name))
    try:
        return json.loads(out)[0]
    except (ValueError, IndexError):
        return None


def wait_link(r1, name, expect, timeout=15):
    "Wait until link NAME matches EXPECT (a dict subset, or None for absent)."

    def check():
        got = link(r1, name)
        if expect is None:
            return None if got is None else got
        if got is None:
            return "missing"
        return topotest.json_cmp(got, expect)

    _, result = topotest.run_and_expect(check, None, count=timeout * 2, wait=0.5)
    return result


def kind_supported(r1, kind, args="", parent=False):
    """
    Probe whether the test host kernel supports link KIND.

    A link with a parent (VLAN) needs an Ethernet-capable device to sit
    on; loopback is not one, so use a throw-away bridge.  "link PARENT"
    is an option of the link itself and must precede "type".
    """
    link = ""
    if parent:
        r1.cmd("ip link add probep0 type bridge 2>/dev/null")
        link = "link probep0"
    ok = r1.cmd(
        "ip link add {} probe0 type {} {} 2>&1 && echo OK; "
        "ip link del probe0 2>/dev/null; ip link del probep0 2>/dev/null".format(
            link, kind, args
        )
    )
    return "OK" in ok


def test_bridge(tgen):
    r1 = tgen.gears["r1"]
    conf(r1, "interface br0", "link-type bridge")
    assert wait_link(r1, "br0", {"linkinfo": {"info_kind": "bridge"}}) is None


def test_veth_and_master(tgen):
    r1 = tgen.gears["r1"]
    conf(r1, "interface vA", "link-type veth peer vB", "master br0")
    assert (
        wait_link(r1, "vA", {"linkinfo": {"info_kind": "veth"}, "master": "br0"})
        is None
    )
    assert wait_link(r1, "vB", {"linkinfo": {"info_kind": "veth"}}) is None


def test_master_generic(tgen):
    "master works on interfaces zebra did not create"
    r1 = tgen.gears["r1"]
    r1.cmd("ip link add dum9 type dummy")
    conf(r1, "interface dum9", "master br0")
    assert wait_link(r1, "dum9", {"master": "br0"}) is None
    conf(r1, "interface dum9", "no master")
    def no_master():
        return None if "master" not in link(r1, "dum9") else "still enslaved"

    _, res = topotest.run_and_expect(no_master, None, count=30, wait=0.5)
    assert res is None
    r1.cmd("ip link del dum9")
    conf(r1, "no interface dum9")


def test_vlan_dependency_and_encap(tgen):
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "vlan", "id 5", parent=True):
        pytest.skip("kernel lacks vlan support")

    # Configured before the parent exists: must wait, then be created.
    conf(r1, "interface br1.10", "link-type vlan parent br1 id 10")
    assert link(r1, "br1.10") is None
    conf(r1, "interface br1", "link-type bridge")
    exp = {
        "link": "br1",
        "linkinfo": {
            "info_kind": "vlan",
            "info_data": {"protocol": "802.1Q", "id": 10},
        },
    }
    assert wait_link(r1, "br1.10", exp) is None

    conf(
        r1,
        "interface br1.20",
        "link-type vlan parent br1 id 20 encapsulation q-in-q",
    )
    exp["linkinfo"]["info_data"] = {"protocol": "802.1ad", "id": 20}
    assert wait_link(r1, "br1.20", exp) is None


def test_gre(tgen):
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "gre", "local 10.0.0.1 remote 10.0.0.2"):
        pytest.skip("kernel lacks gre support")

    conf(
        r1,
        "interface gre1",
        "link-type gre local 10.255.0.1 remote 10.255.0.2 key 42 ttl 16 tos 4",
    )
    exp = {
        "linkinfo": {
            "info_kind": "gre",
            "info_data": {
                "local": "10.255.0.1",
                "remote": "10.255.0.2",
                "ttl": 16,
                "tos": "0x4",
                # both directions carry the configured key
                "ikey": "0.0.0.42",
                "okey": "0.0.0.42",
            },
        }
    }
    assert wait_link(r1, "gre1", exp) is None

    # remote "any" with a bound device
    conf(r1, "interface gre2", "link-type gre dev r1-eth0 remote any")
    assert wait_link(r1, "gre2", {"linkinfo": {"info_kind": "gre"}}) is None


def test_param_change_recreates(tgen):
    r1 = tgen.gears["r1"]
    if link(r1, "gre1") is None:
        pytest.skip("gre not available")
    conf(r1, "interface gre1", "link-type gre local 10.255.0.1 remote 10.255.0.9 ttl 8")
    exp = {"linkinfo": {"info_data": {"remote": "10.255.0.9", "ttl": 8}}}
    assert wait_link(r1, "gre1", exp) is None


def test_validation(tgen):
    "Invalid configuration is rejected and nothing is created."
    r1 = tgen.gears["r1"]
    # veth peer == own name; gre without local/dev; vlan id out of range
    for cmds in (
        ("interface bad0", "link-type veth peer bad0"),
        ("interface bad1", "link-type gre remote 1.2.3.4"),
        ("interface bad2", "link-type vlan parent br0 id 5000"),
    ):
        conf(r1, *cmds)
    for n in ("bad0", "bad1", "bad2"):
        assert link(r1, n) is None


def test_recreate_when_deleted_externally(tgen):
    r1 = tgen.gears["r1"]
    r1.cmd("ip link del vA")
    assert wait_link(r1, "vA", {"linkinfo": {"info_kind": "veth"}, "master": "br0"}) is None


def test_running_config(tgen):
    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show running-config")
    assert "interface br0\n link-type bridge" in out
    assert "link-type veth peer vB" in out
    assert " master br0" in out


def test_dummy(tgen):
    "link-type dummy: create, recreate when removed behind our back, remove"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "dummy"):
        pytest.skip("kernel lacks dummy support")

    conf(r1, "interface dm0", "link-type dummy", "exit", "interface dm1", "link-type dummy")
    assert wait_link(r1, "dm0", {"linkinfo": {"info_kind": "dummy"}}) is None
    assert wait_link(r1, "dm1", {"linkinfo": {"info_kind": "dummy"}}) is None

    # a dummy can be a bridge port like any interface
    conf(r1, "interface br4", "link-type bridge", "exit", "interface dm0", "master br4")
    assert wait_link(r1, "dm0", {"master": "br4"}) is None

    # removed behind our back: created again, and enslaved again
    r1.cmd("ip link del dm0")
    assert (
        wait_link(r1, "dm0", {"linkinfo": {"info_kind": "dummy"}, "master": "br4"})
        is None
    )

    # replacing the kind removes the dummy and creates the new link
    conf(r1, "interface dm1", "link-type bridge")
    assert wait_link(r1, "dm1", {"linkinfo": {"info_kind": "bridge"}}) is None

    out = r1.vtysh_cmd("show running-config")
    assert " link-type dummy" in out

    conf(r1, "interface dm0", "no link-type", "no master")
    assert wait_link(r1, "dm0", None) is None
    conf(r1, "interface dm1", "no link-type")
    conf(r1, "interface br4", "no link-type")
    assert wait_link(r1, "dm1", None) is None
    assert wait_link(r1, "br4", None) is None
    conf(r1, "no interface dm0", "no interface dm1", "no interface br4")

def link_is_up(r1, name):
    got = link(r1, name)
    return bool(got) and "UP" in got.get("flags", [])


def wait_admin_state(r1, name, up, timeout=15):
    "Wait until the administrative state (IFF_UP) of NAME is UP."

    def check():
        return (
            None
            if link_is_up(r1, name) == up
            else "{} is not {}".format(name, "up" if up else "down")
        )

    _, result = topotest.run_and_expect(check, None, count=timeout * 2, wait=0.5)
    return result


def test_link_admin_up(tgen):
    "links zebra creates are brought up without an address; shutdown keeps one down"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge") or not kind_supported(
        r1, "veth", "peer name probe1"
    ):
        pytest.skip("kernel lacks bridge or veth support")

    conf(r1, "interface up0", "link-type bridge")
    conf(r1, "interface up1", "link-type veth peer up2")
    conf(r1, "interface up3", "shutdown", "link-type bridge")
    assert wait_admin_state(r1, "up0", True) is None
    assert wait_admin_state(r1, "up1", True) is None
    # the other end of a pair is ours as well
    assert wait_admin_state(r1, "up2", True) is None
    assert wait_link(r1, "up3", {"ifname": "up3"}) is None
    assert wait_admin_state(r1, "up3", False) is None

    conf(r1, "interface up3", "no shutdown")
    assert wait_admin_state(r1, "up3", True) is None

    # re-created behind our back: up again
    r1.cmd("ip link del up0")
    assert wait_admin_state(r1, "up0", True) is None

    # a link that already exists is brought up when it is configured
    r1.cmd("ip link add up4 type bridge")
    assert wait_admin_state(r1, "up4", False) is None
    conf(r1, "interface up4", "link-type bridge")
    assert wait_admin_state(r1, "up4", True) is None

    for name in ("up0", "up1", "up3", "up4"):
        conf(r1, "interface " + name, "no link-type")
        assert wait_link(r1, name, None) is None
    conf(
        r1,
        "no interface up0",
        "no interface up1",
        "no interface up2",
        "no interface up3",
        "no interface up4",
    )

def test_address_waits_for_master(tgen):
    "addresses are not activated before the interface is in its master"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge") or not kind_supported(
        r1, "veth", "peer name probe1"
    ):
        pytest.skip("kernel lacks bridge or veth support")

    def has_addr(name):
        return "10.99.1.1" in r1.cmd("ip -4 addr show dev {} 2>/dev/null".format(name))

    # Address and master are configured, the master does not exist yet
    conf(r1, "interface aw1", "ip address 10.99.1.1/24", "master awbr")
    conf(r1, "interface aw1", "link-type veth peer aw2")
    assert wait_link(r1, "aw1", {"ifname": "aw1"}) is None
    # give a (wrong) early wakeup the chance to happen
    time.sleep(3)
    assert not has_addr("aw1"), "address installed before the master"
    assert wait_admin_state(r1, "aw1", False) is None

    # The master arrives: enslaved first, then raised, then addressed
    conf(r1, "interface awbr", "link-type bridge")
    assert wait_link(r1, "aw1", {"master": "awbr"}) is None
    assert wait_admin_state(r1, "aw1", True) is None
    _, res = topotest.run_and_expect(
        lambda: None if has_addr("aw1") else "no address", None, count=30, wait=0.5
    )
    assert res is None

    # Same wait, released by removing the master requirement instead
    conf(r1, "interface aw3", "ip address 10.99.1.1/24", "master awgone")
    conf(r1, "interface aw3", "link-type veth peer aw4")
    assert wait_link(r1, "aw3", {"ifname": "aw3"}) is None
    time.sleep(3)
    assert not has_addr("aw3"), "address installed before the master"
    conf(r1, "interface aw3", "no master")
    _, res = topotest.run_and_expect(
        lambda: None if has_addr("aw3") else "no address", None, count=30, wait=0.5
    )
    assert res is None

    for name in ("aw1", "aw3", "awbr"):
        conf(r1, "interface " + name, "no link-type")
        assert wait_link(r1, name, None) is None
    conf(r1, "no interface aw1", "no interface aw2", "no interface aw3")
    conf(r1, "no interface aw4", "no interface awbr")


def test_address_held_across_master_removal(tgen):
    "an address held for a pending master is not lost when the master is removed"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge") or not kind_supported(
        r1, "veth", "peer name probe1"
    ):
        pytest.skip("kernel lacks bridge or veth support")

    conf(r1, "interface ah0", "link-type bridge")
    r1.cmd("ip link add ah1 type veth peer name ah2")
    assert wait_link(r1, "ah1", {"ifname": "ah1"}) is None

    # An existing interface without link-type: the master is set, the
    # address is configured while that is pending, then the master goes.
    # Whatever the timing, the address must end up installed.
    conf(
        r1,
        "interface ah1",
        "master ah0",
        "ip address 10.99.5.1/24",
        "no master",
    )

    def has_addr():
        out = r1.cmd("ip -4 addr show dev ah1 2>/dev/null")
        return None if "10.99.5.1" in out else "no address"

    _, res = topotest.run_and_expect(has_addr, None, count=30, wait=0.5)
    assert res is None

    conf(r1, "no interface ah1", "no interface ah2")
    r1.cmd("ip link del ah1")
    conf(r1, "interface ah0", "no link-type")
    assert wait_link(r1, "ah0", None) is None
    conf(r1, "no interface ah0")


def test_rejected_master_keeps_link_held(tgen):
    "a master the kernel rejects keeps the link down, without addresses"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "veth", "peer name probe1"):
        pytest.skip("kernel lacks veth support")

    # A veth is not a device that can have ports: enslaving to it is rejected
    conf(r1, "interface rj0", "link-type veth peer rj1")
    assert wait_link(r1, "rj0", {"ifname": "rj0"}) is None
    conf(r1, "interface rj2", "ip address 10.99.6.1/24", "master rj0")
    conf(r1, "interface rj2", "link-type veth peer rj3")
    assert wait_link(r1, "rj2", {"ifname": "rj2"}) is None
    time.sleep(3)
    assert "master" not in link(r1, "rj2")
    assert wait_admin_state(r1, "rj2", False) is None
    assert "10.99.6.1" not in r1.cmd("ip -4 addr show dev rj2")

    # Removing the master from the configuration releases it
    conf(r1, "interface rj2", "no master")
    assert wait_admin_state(r1, "rj2", True) is None

    def has_addr():
        out = r1.cmd("ip -4 addr show dev rj2 2>/dev/null")
        return None if "10.99.6.1" in out else "no address"

    _, res = topotest.run_and_expect(has_addr, None, count=30, wait=0.5)
    assert res is None

    for name in ("rj0", "rj2"):
        conf(r1, "interface " + name, "no link-type")
        assert wait_link(r1, name, None) is None
    conf(
        r1,
        "no interface rj0",
        "no interface rj1",
        "no interface rj2",
        "no interface rj3",
    )


def test_master_restored_after_external_detach(tgen):
    "a port detached behind zebra's back is enslaved to its master again"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge") or not kind_supported(
        r1, "veth", "peer name probe1"
    ):
        pytest.skip("kernel lacks bridge or veth support")

    conf(r1, "interface dt0", "link-type bridge")
    conf(r1, "interface dt1", "master dt0", "link-type veth peer dt2")
    assert wait_link(r1, "dt1", {"master": "dt0"}) is None

    r1.cmd("ip link set dev dt1 nomaster")
    assert wait_link(r1, "dt1", {"master": "dt0"}) is None

    for name in ("dt0", "dt1"):
        conf(r1, "interface " + name, "no link-type")
        assert wait_link(r1, name, None) is None
    conf(r1, "no interface dt0", "no interface dt1", "no interface dt2")


def test_veth_peer_must_be_the_real_peer(tgen):
    "a named peer that is not the veth's other end is not brought up"
    r1 = tgen.gears["r1"]
    if not kind_supported(r1, "bridge") or not kind_supported(
        r1, "veth", "peer name probe1"
    ):
        pytest.skip("kernel lacks bridge or veth support")

    r1.cmd("ip link add vp1 type veth peer name vp2")
    r1.cmd("ip link add vpo type bridge")
    assert wait_admin_state(r1, "vpo", False) is None

    # vp1 already exists, so nothing is created; vpo is not its peer
    conf(r1, "interface vp1", "link-type veth peer vpo")
    assert wait_admin_state(r1, "vp1", True) is None
    time.sleep(3)
    assert wait_admin_state(r1, "vpo", False) is None

    conf(r1, "interface vp1", "no link-type")
    assert wait_link(r1, "vp1", None) is None
    r1.cmd("ip link del vpo")
    conf(r1, "no interface vp1", "no interface vpo")


def test_removal(tgen):
    r1 = tgen.gears["r1"]
    # no link-type deletes the kernel link; then the interface can be removed.
    conf(r1, "interface vA", "no link-type")
    assert wait_link(r1, "vA", None) is None
    conf(r1, "interface br0", "no link-type")
    assert wait_link(r1, "br0", None) is None
    conf(r1, "no interface vA", "no interface br0")
    out = r1.vtysh_cmd("show running-config")
    assert "interface vA" not in out and "interface br0" not in out


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
