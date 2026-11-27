#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_fpm_evpn_topo1.py: Test the EVPN entries zebra sends to the FPM.

Topology:

            peer1
              |  s1
    h1 ---- r1 ---- r2 ---- h2
        s4  r1 ---- r2  s2
               s3   |
                    |  s5
                    h3

r1 and r2 are EVPN VTEPs (iBGP, VTEP IPs on the s1 link) with a VLAN
aware bridge, the L2VNI 1000 on VLAN 10 and the L3VNI 4001 (VRF vrf1)
on VLAN 100. h2 is a host in the VNI 1000 behind r2. The s3 link carries
an unnumbered (IPv6 link local) IPv4 unicast session, for which zebra
installs the 169.254.0.1 neighbor. peer1 is an ExaBGP EVPN peer of r1
playing a third VTEP of the VNI 1000, whose flood mode the test changes.
h1 is a host in the VNI 1000 behind r1, down until it takes h2's MAC and
IP address to move them behind r1. h3 is a host in the VNI 1000 behind
r2's hostbond1, the EVPN-MH ES the test configures, which peer1 can join
too.

r1's zebra runs the FPM module connected to fpm_listener. The test
checks that the listener receives the entries r1 installs for r2's
routes, both when they are learnt and when zebra replays them on a new
FPM connection:

- the flood list entry (type-3) of r2, with its VNI and VLAN;
- the remote MAC (type-2) of h2;
- the remote neighbor (type-2 with IP) of h2 on the VNI SVI;
- the router MAC of r2 (type-5);
- the L3VNI next hop of r2 on the L3VNI SVI.

It also checks that:

- they are removed when r2's routes are withdrawn;
- the remote MAC and neighbor of h2 are removed when they move behind r1
  (become local), and sent again when they move back behind r2;
- the flood list entry of a remote VTEP no longer asking for head-end
  replication is removed, and installed again when it asks again;
- an access VLAN change moves the flood list and remote MAC entries to
  the new VLAN, without removing the kernel flood entry, and removes the
  remote neighbor from the old VLAN's SVI;
- the bridge coming up again without VLAN filtering moves the flood list
  and remote MAC entries to no VLAN, without removing the kernel flood
  entry, and leaves no router MAC with the L3VNI VLAN, removing it from
  the FPM once, and getting its VLAN filtering back moves them back;
- a vxlan interface going down removes its remote MACs, flood list
  entries, neighbors and router MACs from the FPM, live and on a new
  connection, and an SVI going down removes the remote neighbors or L3VNI
  next hops on it;
- the remote MAC of h3, once behind the ES, points to the ES next hop
  group, which the FPM gets after the FDB next hops of the ES VTEPs (r2,
  and peer1 when it joins the ES), and before the MAC, live and on a new
  connection, and whose removal it gets with the ES (the MAC going back
  to r2's VTEP). The vxlan interface going down removes the MAC from the
  FPM, and the MAC moving behind r1 removes its vxlan entry from the
  kernel and the FPM. This needs a kernel that takes a dynamic FDB entry
  using a next hop group (not one with upstream 98fc57d16744 but without
  its fix, 7308ef8b4a67);
- the 169.254.0.1 neighbor of the unnumbered session (not an EVPN
  entry) is never sent to the FPM.

The tests run in order, each one starting from the state the previous ones
left (e.g. the L2VNI access VLAN, or peer1's type-3 route withdrawn).
"""

import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from functools import partial

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.evpn import vxlan_dynamic_nh_fdb_skip_reason
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn, pytest.mark.fpm, pytest.mark.staticd]

R1_VTEP = "192.168.1.1"
R2_VTEP = "192.168.1.2"
PEER1_VTEP = "192.168.1.3"
R2_RMAC = "02:00:00:00:00:02"
H2_MAC = "02:00:00:00:00:64"
H2_IP = "10.10.10.100"
H1_IP = "10.10.10.200"
H3_MAC = "02:00:00:00:00:67"
H3_IP = "10.10.10.103"
# The EVPN-MH ES of h3 on r2 (type 3 ESI: system MAC and local
# discriminator), which peer1 joins with the same ESI (see exa-evpn.py).
ES_ID = 1
ES_SYS_MAC = "44:38:39:ff:ff:01"
ESI = "03:44:38:39:ff:ff:01:00:00:01"
L2VNI = 1000
L2VNI_VLAN = 10
L2VNI_NEW_VLAN = 20
L3VNI = 4001
L3VNI_VLAN = 100
IPV4_LL = "169.254.0.1"

# The routes r1 adds as markers in the FPM message stream (see _fpm_sync()):
# no other route may be in 192.0.2.0/24.
MARKER_ROUTE = "192.0.2.{}/32"
# The static FDB entry r1 adds on its scratch bridge brmon (see
# _kernel_flood_monitor_start())
MONITOR_MAC = "02:00:00:00:00:fe"

# Neighbor flags (linux/neighbour.h)
NTF_SELF = 0x02
NTF_MASTER = 0x04
NTF_EXT_LEARNED = 0x10


def build_topo(tgen):
    "Build function"

    for name in ["r1", "r2", "h2"]:
        tgen.add_router(name)

    # r1-eth0 <-> r2-eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # peer1-eth0 on s1: ExaBGP EVPN peer of r1
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="{}/24".format(PEER1_VTEP), defaultRoute="via 192.168.1.1"
    )
    switch.add_link(peer1)

    # r2-eth1 <-> h2-eth0
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h2"])

    # r1-eth1 <-> r2-eth2: unnumbered IPv4 unicast session
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-eth2 <-> h1-eth0
    tgen.add_host("h1", "{}/24".format(H1_IP), "via 10.10.10.1")
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # r2-eth3 (in hostbond1) <-> h3-eth0
    tgen.add_host("h3", "{}/24".format(H3_IP), "via 10.10.10.2")
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h3"])


def _setup_vtep(router, num):
    "Create the VRF, VLAN aware bridge, VXLAN interfaces and SVIs of a VTEP"

    router.cmd_raises(
        """
ip link add vrf1 type vrf table 1001
ip link set vrf1 up
ip link add br0 address 02:00:00:00:00:{num:02x} type bridge vlan_filtering 1 stp_state 0
bridge vlan add vid {l2vlan} dev br0 self
bridge vlan add vid {l3vlan} dev br0 self
ip link set br0 up
ip link add lo1 type dummy
ip link set lo1 master vrf1
ip addr add 10.100.0.{num}/32 dev lo1
ip link set lo1 up
""".format(
            num=num, l2vlan=L2VNI_VLAN, l3vlan=L3VNI_VLAN
        )
    )

    for vni, vlan in [(L2VNI, L2VNI_VLAN), (L3VNI, L3VNI_VLAN)]:
        router.cmd_raises(
            """
ip link add vxlan{vni} type vxlan id {vni} dstport 4789 local 192.168.1.{num} nolearning
ip link set vxlan{vni} master br0
bridge vlan del vid 1 dev vxlan{vni}
bridge vlan add vid {vlan} dev vxlan{vni} pvid untagged
bridge link set dev vxlan{vni} learning off
ip link set vxlan{vni} up
ip link add link br0 name vlan{vlan} type vlan id {vlan}
ip link set vlan{vlan} master vrf1
ip link set vlan{vlan} up
""".format(
                vni=vni, vlan=vlan, num=num
            )
        )

    router.cmd_raises("ip addr add 10.10.10.{}/24 dev vlan{}".format(num, L2VNI_VLAN))


def setup_module(mod):
    "Sets up the pytest environment"

    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    if not topotest.platform_has_evpn():
        pytest.skip("platform does not support EVPN")

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip('EVPN tests need kernel 4.18 or newer (have "{}")'.format(krel))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    h1 = tgen.gears["h1"]
    h2 = tgen.gears["h2"]

    _setup_vtep(r1, 1)
    _setup_vtep(r2, 2)

    # h1 and h2 are connected to an access port of r1's and r2's bridge in
    # the VNI VLAN. h1 stays down until it takes h2's addresses.
    h1.cmd_raises("ip link set h1-eth0 down")
    for router, port in [(r1, "r1-eth2"), (r2, "r2-eth1")]:
        router.cmd_raises(
            """
ip link set {port} master br0
bridge vlan del vid 1 dev {port}
bridge vlan add vid {vlan} dev {port} pvid untagged
ip link set {port} up
""".format(
                port=port, vlan=L2VNI_VLAN
            )
        )
    h2.cmd_raises("ip link set h2-eth0 address {}".format(H2_MAC))

    # h3 is connected to r2's hostbond1, a bond being what zebra accepts as
    # an ES interface, in the VNI VLAN.
    h3 = tgen.gears["h3"]
    h3.cmd_raises(
        """
ip link set h3-eth0 down
ip link set h3-eth0 address {}
ip link set h3-eth0 up
""".format(
            H3_MAC
        )
    )
    r2.cmd_raises(
        """
ip link add hostbond1 type bond mode active-backup miimon 100
ip link set r2-eth3 down
ip link set r2-eth3 master hostbond1
ip link set r2-eth3 up
ip link set hostbond1 master br0
bridge vlan del vid 1 dev hostbond1
bridge vlan add vid {vlan} dev hostbond1 pvid untagged
ip link set hostbond1 up
""".format(
            vlan=L2VNI_VLAN
        )
    )

    # A bridge without any vxlan interface, for r1 to make FDB updates the
    # kernel reports but zebra ignores.
    r1.cmd_raises(
        """
ip link add brmon type bridge
ip link add monport type dummy
ip link set monport master brmon
ip link set monport up
ip link set brmon up
"""
    )

    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        extra_daemons=[
            ("zebra", "-M dplane_fpm_nl"),
            "staticd",
            (
                TopoRouter.RD_FPM_LISTENER,
                "-z {} -o {}".format(_fpm_dump_path(r1), _fpm_log_path(r1)),
            ),
        ],
    )
    r2.load_frr_config(os.path.join(CWD, "r2/frr.conf"))
    h2.load_frr_config(os.path.join(CWD, "h2/frr.conf"), daemons=["zebra"])

    tgen.start_router()

    tgen.gears["peer1"].start(
        os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env")
    )

    r1.vtysh_cmd(
        """
configure terminal
 fpm address 127.0.0.1
"""
    )


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


#
# FPM listener helpers
#


def _fpm_dump_path(router):
    return os.path.join(router.gearlogdir, "fpm_test.data")


def _fpm_log_path(router):
    "The log of every message fpm_listener received"
    return os.path.join(router.gearlogdir, "fpm_listener.log")


def _fpm_listener_dump(router):
    """
    Make fpm_listener dump its tables and return the dump as a string, or
    None when no dump was produced (see the same helper in
    fpm_testing_topo1).
    """
    pid_file = os.path.join(router.gearlogdir, "fpm_listener.pid")
    dump_file = _fpm_dump_path(router)

    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
    except (OSError, ValueError) as error:
        logger.info("fpm_listener pid file is not usable: {}".format(error))
        return None

    try:
        os.unlink(dump_file)
    except FileNotFoundError:
        pass

    rc, _, err = router.net.cmd_status("kill -USR1 {}".format(pid), warn=False)
    if rc:
        logger.info("fpm_listener (pid {}) not signalled: {}".format(pid, err.strip()))
        return None

    for _ in range(20):
        try:
            with open(dump_file, "r") as f:
                return f.read()
        except FileNotFoundError:
            time.sleep(0.1)

    logger.info("fpm_listener (pid {}) did not write {}".format(pid, dump_file))
    return None


def _fpm_nhgs(dump):
    """
    The next hop group table of the fpm_listener `dump`, as {<ID>: {"fdb":
    <FDB next hop or group>, "gateway": <gateway or None>, "members":
    [<next hop ID>, ...]}}, or None when the dump has no such table.
    """
    parts = dump.split("=== Nexthop Group Hash Dump ===", 1)
    if len(parts) != 2:
        return None
    section = parts[1].split("=====================", 1)[0]

    nhgs = {}
    for line in section.splitlines():
        nhg_id = re.match(r"^  ID: (\d+),", line)
        if nhg_id is None:
            continue
        gateway = re.search(r", Gateway: ([0-9a-f.:]+)", line)
        members = re.search(r"NexthopIDs: (.*)$", line)
        nhgs[int(nhg_id.group(1))] = {
            "fdb": ", FDB" in line,
            "gateway": gateway.group(1) if gateway else None,
            "members": (
                sorted(
                    int(m) for m in re.findall(r"(\d+)(?:\(w:\d+\))?", members.group(1))
                )
                if members
                else []
            ),
        }

    return nhgs


def _fpm_tables(router):
    """
    Return the neighbor and next hop group tables of the fpm_listener dump
    as {"connection": <FPM connection number>, "neighbors": [<entry>, ...],
    "nhgs": <see _fpm_nhgs()>}, each neighbor entry being a dict of the
    "Key: value" pairs the listener prints (see fpm_neigh_snprint() in
    zebra/fpm_listener.c), or None when there is no dump. The listener
    flushes both tables on a new connection.
    """
    dump = _fpm_listener_dump(router)
    if dump is None:
        return None

    nhgs = _fpm_nhgs(dump)
    if nhgs is None:
        return None

    parts = dump.split("=== Neighbor Table Dump ===", 1)
    if len(parts) != 2:
        return None
    section = parts[1].split("=====================", 1)[0]

    connection = re.search(r"^Connection: (\d+)$", section, re.MULTILINE)
    if connection is None:
        return None

    neighbors = []
    for line in section.splitlines():
        line = line.strip()
        if line.startswith("Neigh: "):
            neighbors.append(
                dict(re.findall(r"(\w+): ([^,]+)", line[len("Neigh: ") :]))
            )

    return {
        "connection": int(connection.group(1)),
        "neighbors": neighbors,
        "nhgs": nhgs,
    }


def _fpm_has_route(router, prefix):
    "If the fpm_listener route table has `prefix`"
    dump = _fpm_listener_dump(router)
    if dump is None:
        return False

    parts = dump.split("=== Route Tree Dump ===", 1)
    if len(parts) != 2:
        return False
    section = parts[1].split("=====================", 1)[0]

    return (
        re.search(
            r"^\s+Table \d+, NHG \d+: {}$".format(re.escape(prefix)),
            section,
            re.MULTILINE,
        )
        is not None
    )


_fpm_markers = 0


def _fpm_sync(router, replay=None):
    """
    Wait for the listener to have every message zebra sent to it so far:
    add a route, which zebra sends to the FPM after them, and wait for the
    listener to have it, the FPM messages arriving in order.

    With the `replay` of `_fpm_reconnect()`, first wait for zebra to finish
    the EVPN walk of that new connection, the last walk of a replay: zebra
    sent the whole replay by then.
    """
    global _fpm_markers

    if replay is not None:

        def _evpn_walk_finished():
            log = router.net.getLog("log", "zebra")
            return "EVPN walk finished" in log[replay["log_offset"] :]

        _, result = topotest.run_and_expect(_evpn_walk_finished, True, count=60, wait=1)
        assert result, "zebra did not finish the EVPN walk of the new FPM connection"

    _fpm_markers += 1
    prefix = MARKER_ROUTE.format(_fpm_markers)
    router.vtysh_cmd(
        """
configure terminal
 ip route {} blackhole
""".format(
            prefix
        )
    )
    test_func = partial(_fpm_has_route, router, prefix)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result, "FPM did not get the marker route {}".format(prefix)

    router.vtysh_cmd(
        """
configure terminal
 no ip route {} blackhole
""".format(
            prefix
        )
    )


def _ifindex(router, ifname):
    return int(router.run("cat /sys/class/net/{}/ifindex".format(ifname)).strip())


def _evpn_entries(router, l2vni_vlan=L2VNI_VLAN):
    """
    The FPM entries r1 installs for r2's EVPN routes, by description. The
    "Flags" value lists the neighbor flags that must be set.
    """
    vxlan_l2 = _ifindex(router, "vxlan{}".format(L2VNI))
    vxlan_l3 = _ifindex(router, "vxlan{}".format(L3VNI))
    bridge = _ifindex(router, "br0")

    return {
        "flood list entry (type-3)": {
            "Family": "bridge",
            "Ifindex": vxlan_l2,
            "Lladdr": "00:00:00:00:00:00",
            "Dst": R2_VTEP,
            "Vlan": l2vni_vlan,
            "Vni": L2VNI,
        },
        "remote MAC (type-2)": {
            "Family": "bridge",
            "Ifindex": vxlan_l2,
            "Lladdr": H2_MAC,
            "Dst": R2_VTEP,
            "Vlan": l2vni_vlan,
            "Vni": L2VNI,
            "Master": bridge,
            "Flags": NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED,
        },
        "remote neighbor (type-2)": {
            "Family": "inet",
            "Ifindex": _ifindex(router, "vlan{}".format(L2VNI_VLAN)),
            "Lladdr": H2_MAC,
            "Dst": H2_IP,
            "Flags": NTF_EXT_LEARNED,
        },
        "router MAC (type-5)": {
            "Family": "bridge",
            "Ifindex": vxlan_l3,
            "Lladdr": R2_RMAC,
            "Dst": R2_VTEP,
            "Vlan": L3VNI_VLAN,
            "Vni": L3VNI,
            "Master": bridge,
            "Flags": NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED,
        },
        "L3VNI next hop (type-5)": {
            "Family": "inet",
            "Ifindex": _ifindex(router, "vlan{}".format(L3VNI_VLAN)),
            "Lladdr": R2_RMAC,
            "Dst": R2_VTEP,
            "Flags": NTF_EXT_LEARNED,
        },
    }


def _entry_matches(neighbor, expected):
    for key, value in expected.items():
        if key not in neighbor:
            return False
        if key == "Flags":
            if int(neighbor[key], 16) & value != value:
                return False
        elif neighbor[key] != str(value):
            return False
    return True


def _check_fpm_entries(router, present, absent=None, min_connection=0):
    """
    Return a description of what does not match yet, or None when the
    listener has all the `present` entries and none of the `absent` ones,
    on a connection numbered `min_connection` or more.
    """
    table = _fpm_tables(router)
    if table is None:
        return "no fpm_listener dump"

    if table["connection"] < min_connection:
        return "still on FPM connection {}, waiting for {}".format(
            table["connection"], min_connection
        )

    errors = []
    for name, expected in present.items():
        if not any(_entry_matches(n, expected) for n in table["neighbors"]):
            errors.append("missing {}: {}".format(name, expected))
    for name, expected in (absent or {}).items():
        if any(_entry_matches(n, expected) for n in table["neighbors"]):
            errors.append("unexpected {}: {}".format(name, expected))

    if not errors:
        return None

    return "{}\nFPM neighbors (connection {}):\n{}".format(
        "\n".join(errors),
        table["connection"],
        "\n".join(str(n) for n in table["neighbors"]),
    )


def _wait_fpm_entries(router, present, absent=None, replay=None, what=""):
    """
    Wait for the listener to have all the `present` entries and none of the
    `absent` ones. With the `replay` of `_fpm_reconnect()`, check them on
    that new connection, once zebra sent it the whole replay: the listener
    starts a new connection with an empty table, where an entry missing
    before the end of the replay may still come.
    """
    min_connection = 0
    if replay is not None:
        min_connection = replay["connection"]
        _fpm_sync(router, replay)

    test_func = partial(_check_fpm_entries, router, present, absent, min_connection)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "{}:\n{}".format(what, result)


def _fpm_reconnect(router):
    """
    Make zebra connect again to the FPM, which sends the whole state again,
    and return what `_wait_fpm_entries()` needs to check that replay: the
    connection number the listener will report, and where zebra's log
    (with `debug zebra fpm`) will report the end of its walks.
    """
    _, table = topotest.run_and_expect_type(
        partial(_fpm_tables, router), dict, count=30, wait=1
    )
    assert table is not None, "no fpm_listener dump"
    log_offset = len(router.net.getLog("log", "zebra"))

    router.vtysh_cmd(
        """
configure terminal
 fpm address 127.0.0.1
"""
    )

    return {"connection": table["connection"] + 1, "log_offset": log_offset}


def _h2_traffic():
    "Make r2 learn h2's MAC and IP address (again)"
    tgen = get_topogen()
    tgen.gears["h2"].run("ping -c 2 -W 1 10.10.10.2")


def _wait_bgp_evpn(router, peer=R2_VTEP, name="r2"):
    "Wait for the EVPN session between r1 and `peer` (named `name`)"
    expected = {"peers": {peer: {"state": "Established"}}}
    test_func = partial(
        topotest.router_json_cmp, router, "show bgp l2vpn evpn summary json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 EVPN session to {} is not up".format(name)


def _mac_type(router, mac):
    "The type zebra has for the MAC `mac` of the L2VNI, or None"
    output = router.vtysh_cmd(
        "show evpn mac vni {} mac {} json".format(L2VNI, mac), isjson=True
    )
    return output.get(mac, {}).get("type")


def _access_vlan(router):
    "The access VLAN (PVID) of the L2VNI vxlan interface, or None"
    output = json.loads(router.run("bridge -j vlan show dev vxlan{}".format(L2VNI)))
    for dev in output:
        for vlan in dev.get("vlans", []):
            if "PVID" in vlan.get("flags", []):
                return vlan["vlan"]
    return None


def _peer1_flood_mode(mode):
    "Make peer1 advertise its type-3 route with the flood mode `mode`"
    peer1 = get_topogen().gears["peer1"]
    peer1.cmd_raises(
        "echo {0} > /etc/exabgp/flood-mode && chmod 644 /etc/exabgp/flood-mode".format(
            mode
        )
    )


def _remote_vtep_flood(router, vtep):
    "The flood mode zebra has for the remote VTEP `vtep`, or None"
    output = router.vtysh_cmd("show evpn vni {} json".format(L2VNI), isjson=True)
    for remote in output.get("remoteVteps", []):
        if remote.get("ip") == vtep:
            return remote.get("flood")
    return None


def _kernel_flood_entry(router, vtep):
    "If the kernel has the flood list entry of `vtep`"
    output = router.run("bridge fdb show dev vxlan{}".format(L2VNI))
    return (
        re.search(
            r"^00:00:00:00:00:00 dst {} ".format(re.escape(vtep)), output, re.MULTILINE
        )
        is not None
    )


def _kernel_flood_monitor_start(router):
    """
    Start recording the kernel FDB updates, and return the recording once
    the monitor gets them: when it reports an FDB entry added on the
    scratch bridge brmon (zebra ignores it, brmon having no vxlan
    interface).
    """
    proc = router.popen(
        ["bridge", "monitor", "fdb"],
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    lines = []

    def _read():
        for line in proc.stdout:
            lines.append(line)

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    monitor = {"proc": proc, "reader": reader, "lines": lines}

    def _ready():
        # Add the entry again each time: only a change is reported.
        router.run(
            "bridge fdb del {0} dev monport master 2>/dev/null; "
            "bridge fdb add {0} dev monport master static".format(MONITOR_MAC)
        )
        return any(MONITOR_MAC in line for line in list(lines))

    try:
        _, result = topotest.run_and_expect(_ready, True, count=10, wait=1)
        router.run("bridge fdb del {} dev monport master".format(MONITOR_MAC))
    except Exception:
        _kernel_flood_monitor_stop(monitor)
        raise
    if not result:
        _kernel_flood_monitor_stop(monitor)
        assert False, "bridge monitor did not report FDB updates:\n{}".format(
            "".join(lines)
        )

    return monitor


def _kernel_flood_monitor_stop(monitor):
    "Stop recording the kernel FDB updates"
    monitor["proc"].terminate()
    try:
        monitor["proc"].wait(timeout=10)
    except subprocess.TimeoutExpired:
        monitor["proc"].kill()
        monitor["proc"].wait()
    monitor["reader"].join(timeout=10)


def _kernel_flood_monitor_check(router, monitor):
    """
    Check that the kernel flood entry of r2 was never removed while
    recording (stopped by `_kernel_flood_monitor_stop()`): moving it to
    another VLAN only concerns the FPM.
    """
    deleted = [
        line.rstrip("\n")
        for line in list(monitor["lines"])
        if re.match(
            r"Deleted 00:00:00:00:00:00 dev vxlan{} .*dst {}\b".format(
                L2VNI, re.escape(R2_VTEP)
            ),
            line,
        )
    ]
    assert not deleted, "kernel flood entry of r2 was removed:\n{}".format(
        "\n".join(deleted)
    )

    assert _kernel_flood_entry(
        router, R2_VTEP
    ), "kernel flood entry of r2 is missing:\n{}".format(
        router.run("bridge fdb show dev vxlan{}".format(L2VNI))
    )


#
# Tests
#


def test_bgp_evpn_converge():
    "Wait for the EVPN session between r1 and r2"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _wait_bgp_evpn(tgen.gears["r1"])


def test_fpm_evpn_entries():
    "The FPM gets the EVPN entries as they are installed"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _h2_traffic()
    _wait_fpm_entries(
        r1, _evpn_entries(r1), what="FPM did not get the EVPN entries of r2"
    )


def test_fpm_evpn_entries_replay():
    "A new FPM connection gets the EVPN entries again"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _h2_traffic()
    replay = _fpm_reconnect(r1)
    _wait_fpm_entries(
        r1,
        _evpn_entries(r1),
        replay=replay,
        what="FPM did not get the EVPN entries of r2 on a new connection",
    )


def test_fpm_evpn_entries_withdraw():
    "The FPM entries are removed when r2's routes are withdrawn"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    entries = _evpn_entries(r1)
    _h2_traffic()
    _wait_fpm_entries(r1, entries, what="FPM did not get the EVPN entries of r2")

    r1.vtysh_cmd(
        """
configure terminal
 router bgp 65000
  neighbor {} shutdown
""".format(
            R2_VTEP
        )
    )
    _wait_fpm_entries(
        r1, {}, absent=entries, what="FPM kept EVPN entries of r2 after withdraw"
    )

    r1.vtysh_cmd(
        """
configure terminal
 router bgp 65000
  no neighbor {} shutdown
""".format(
            R2_VTEP
        )
    )
    _wait_bgp_evpn(r1)
    _h2_traffic()
    _wait_fpm_entries(r1, entries, what="FPM did not get the EVPN entries of r2 back")


def test_fpm_evpn_remote_to_local():
    """
    h2's MAC and IP address moving behind r1 (h1 taking them) remove the
    remote MAC and neighbor from the FPM, while the kernel replaces them
    with local ones, and moving back behind r2 sends them again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    entries = _evpn_entries(r1)
    remote = {
        name: entries[name]
        for name in ["remote MAC (type-2)", "remote neighbor (type-2)"]
    }
    _wait_fpm_entries(r1, remote, what="FPM did not get the remote entries of h2")

    # h2 stays quiet behind r2 while h1 takes its addresses behind r1.
    h1.cmd_raises(
        """
ip addr flush dev h1-eth0
ip link set h1-eth0 address {mac}
ip addr add {ip}/24 dev h1-eth0
ip link set h1-eth0 up
""".format(
            mac=H2_MAC, ip=H2_IP
        )
    )
    h1.run("ping -c 2 -W 1 10.10.10.1")

    test_func = partial(_mac_type, r1, H2_MAC)
    _, result = topotest.run_and_expect(test_func, "local", count=30, wait=1)
    assert result == "local", "h2 MAC is {} on r1, not local".format(result)
    _wait_fpm_entries(
        r1, {}, absent=remote, what="FPM kept the remote entries of h2 now local"
    )

    # Back behind r2.
    h1.cmd_raises("ip link set h1-eth0 down")
    _h2_traffic()

    _, result = topotest.run_and_expect(test_func, "remote", count=30, wait=1)
    assert result == "remote", "h2 MAC is {} on r1, not remote".format(result)
    _wait_fpm_entries(r1, remote, what="FPM did not get the remote entries of h2 back")


def test_fpm_evpn_flood_mode_change():
    """
    The flood list entry of a remote VTEP no longer asking for head-end
    replication (PMSI tunnel type) is removed, from the kernel and the FPM,
    and installed again when it asks for it again. FRR always advertises
    ingress replication, so the remote VTEP is the ExaBGP peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    flood_entry = {
        "Family": "bridge",
        "Ifindex": _ifindex(r1, "vxlan{}".format(L2VNI)),
        "Lladdr": "00:00:00:00:00:00",
        "Dst": PEER1_VTEP,
        "Vni": L2VNI,
    }
    entry = {"peer1 flood list entry (type-3)": flood_entry}

    _wait_bgp_evpn(r1, PEER1_VTEP, "peer1")

    # (peer1 advertisement, zebra flood mode, flood list entry installed)
    steps = [
        ("ingress-replication", "HER", True),
        ("no-tunnel", "-", False),
        ("ingress-replication", "HER", True),
    ]
    for mode, flood, installed in steps:
        _peer1_flood_mode(mode)

        test_func = partial(_remote_vtep_flood, r1, PEER1_VTEP)
        _, result = topotest.run_and_expect(test_func, flood, count=30, wait=1)
        assert result == flood, "peer1 VTEP flood mode is {}, not {}".format(
            result, flood
        )

        if installed:
            _wait_fpm_entries(
                r1, entry, what="FPM did not get the flood list entry of peer1"
            )
        else:
            _wait_fpm_entries(
                r1,
                {},
                absent=entry,
                what="FPM kept the flood list entry of peer1 not using HER",
            )

        test_func = partial(_kernel_flood_entry, r1, PEER1_VTEP)
        _, result = topotest.run_and_expect(test_func, installed, count=30, wait=1)
        assert result == installed, "kernel flood list entry of peer1 is {}".format(
            "missing" if installed else "still installed"
        )

    # The VTEP is removed with its route.
    _peer1_flood_mode("withdraw")
    test_func = partial(_remote_vtep_flood, r1, PEER1_VTEP)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "peer1 VTEP was not removed"
    _wait_fpm_entries(
        r1, {}, absent=entry, what="FPM kept the flood list entry of peer1"
    )
    assert not _kernel_flood_entry(r1, PEER1_VTEP), "kernel kept peer1 flood entry"


def test_fpm_evpn_vxlan_down():
    """
    A vxlan interface going down makes the kernel flush the remote MACs and
    router MACs from it, so that their removal from the kernel fails
    afterwards: the FPM gets their removal anyway, live and on a new
    connection, and gets them back when the interface comes back up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    entries = _evpn_entries(r1)
    l2 = {
        name: entries[name]
        for name in [
            "flood list entry (type-3)",
            "remote MAC (type-2)",
            "remote neighbor (type-2)",
        ]
    }
    l3 = {name: entries[name] for name in ["router MAC (type-5)"]}

    _h2_traffic()
    _wait_fpm_entries(r1, entries, what="FPM did not get the EVPN entries of r2")

    # (vxlan interface going down, its entries, entries of the other one)
    for vni, removed, kept in [(L2VNI, l2, l3), (L3VNI, l3, l2)]:
        r1.cmd_raises("ip link set vxlan{} down".format(vni))
        _wait_fpm_entries(
            r1,
            {},
            absent=removed,
            what="FPM kept entries of vxlan{} after it went down".format(vni),
        )

        replay = _fpm_reconnect(r1)
        _wait_fpm_entries(
            r1,
            kept,
            absent=removed,
            replay=replay,
            what="FPM got entries of the down vxlan{} on a new connection".format(vni),
        )

        r1.cmd_raises("ip link set vxlan{} up".format(vni))
        _wait_bgp_evpn(r1)
        _h2_traffic()
        _wait_fpm_entries(
            r1,
            entries,
            what="FPM did not get the EVPN entries back with vxlan{} up".format(vni),
        )


def test_fpm_evpn_svi_down():
    """
    An SVI going down makes the kernel remove the remote neighbors or L3VNI
    next hops on it: the FPM gets their removal, and gets them back when the
    SVI comes back up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    entries = _evpn_entries(r1)
    _h2_traffic()
    _wait_fpm_entries(r1, entries, what="FPM did not get the EVPN entries of r2")

    for vlan, name in [
        (L2VNI_VLAN, "remote neighbor (type-2)"),
        (L3VNI_VLAN, "L3VNI next hop (type-5)"),
    ]:
        removed = {name: entries[name]}
        r1.cmd_raises("ip link set vlan{} down".format(vlan))
        _wait_fpm_entries(
            r1,
            {},
            absent=removed,
            what="FPM kept the {} after vlan{} went down".format(name, vlan),
        )

        r1.cmd_raises("ip link set vlan{} up".format(vlan))
        _h2_traffic()
        _wait_fpm_entries(
            r1,
            entries,
            what="FPM did not get the EVPN entries back with vlan{} up".format(vlan),
        )


def test_fpm_evpn_access_vlan_change():
    """
    An access VLAN change of the L2VNI moves its flood list and remote MAC
    entries to the new VLAN, live and on a new FPM connection. The remote
    neighbor is removed from the old VLAN's SVI (the new VLAN has none).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    l2_entries = ["flood list entry (type-3)", "remote MAC (type-2)"]
    old_entries = _evpn_entries(r1)
    new_entries = _evpn_entries(r1, L2VNI_NEW_VLAN)
    old = {name: old_entries[name] for name in l2_entries}
    new = {name: new_entries[name] for name in l2_entries}
    old["remote neighbor (type-2)"] = old_entries["remote neighbor (type-2)"]

    _h2_traffic()
    _wait_fpm_entries(r1, old, what="FPM did not get the old access VLAN entries")

    monitor = _kernel_flood_monitor_start(r1)
    try:
        r1.cmd_raises(
            """
bridge vlan add vid {new} dev br0 self
bridge vlan add vid {new} dev vxlan{vni} pvid untagged
bridge vlan del vid {old} dev vxlan{vni}
""".format(
                new=L2VNI_NEW_VLAN, old=L2VNI_VLAN, vni=L2VNI
            )
        )
        _wait_fpm_entries(
            r1, new, absent=old, what="FPM entries did not move to the new access VLAN"
        )
    finally:
        _kernel_flood_monitor_stop(monitor)
    _kernel_flood_monitor_check(r1, monitor)

    replay = _fpm_reconnect(r1)
    _wait_fpm_entries(
        r1,
        new,
        absent=old,
        replay=replay,
        what="FPM did not get the new access VLAN entries on a new connection",
    )


def test_fpm_evpn_bridge_vlan_filtering_change():
    """
    The bridge coming up again without VLAN filtering moves the flood list
    and remote MAC entries to no VLAN, live and on a new FPM connection.
    The router MAC (moved too, until BGP withdraws it as its L3VNI goes
    down with the bridge) is not left with the L3VNI VLAN, and the FPM gets
    its removal with that VLAN once: on its own, the kernel alone getting
    its own removal.

    Both vxlan interfaces are then in one bridge without VLAN filtering,
    which zebra does not support beyond moving the entries: the bridge
    gets its VLAN filtering back, with the entries back on their VLANs,
    before the next test.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    l2_entries = ["flood list entry (type-3)", "remote MAC (type-2)"]
    vlan = _access_vlan(r1)
    assert vlan is not None, "vxlan{} has no access VLAN".format(L2VNI)
    old_entries = _evpn_entries(r1, vlan)
    new_entries = _evpn_entries(r1, 0)
    old = {name: old_entries[name] for name in l2_entries}
    new = {name: new_entries[name] for name in l2_entries}
    old["router MAC (type-5)"] = old_entries["router MAC (type-5)"]

    _h2_traffic()
    _wait_fpm_entries(r1, old, what="FPM did not get the VLAN aware entries")

    with open(_fpm_log_path(r1), "r") as f:
        log_start = len(f.readlines())

    monitor = _kernel_flood_monitor_start(r1)
    try:
        r1.cmd_raises(
            """
ip link set br0 down
ip link set br0 type bridge vlan_filtering 0
ip link set br0 up
"""
        )
        _wait_fpm_entries(
            r1, new, absent=old, what="FPM entries did not move to no VLAN"
        )
    finally:
        _kernel_flood_monitor_stop(monitor)
    _kernel_flood_monitor_check(r1, monitor)

    replay = _fpm_reconnect(r1)
    _wait_fpm_entries(
        r1,
        new,
        absent=old,
        replay=replay,
        what="FPM did not get the entries without VLAN on a new connection",
    )

    # Count the removals once the listener has everything zebra sent since
    # the change, the replay included: a removal sent again by the L3VNI
    # going down, after the move, is counted too.
    _fpm_sync(r1)
    with open(_fpm_log_path(r1), "r") as f:
        removals = [
            line
            for line in f.readlines()[log_start:]
            if "Del Neighbor" in line
            and "Lladdr: {},".format(R2_RMAC) in line
            and "Vlan: {},".format(L3VNI_VLAN) in line
        ]
    assert len(removals) == 1, "FPM got {} removals of the router MAC:\n{}".format(
        len(removals), "".join(removals)
    )

    # Back to the supported setup.
    r1.cmd_raises(
        """
ip link set br0 down
ip link set br0 type bridge vlan_filtering 1
ip link set br0 up
"""
    )
    _wait_bgp_evpn(r1)
    _h2_traffic()
    _wait_fpm_entries(
        r1,
        old,
        absent=new,
        what="FPM entries did not get back to their VLAN with VLAN filtering",
    )


def _h3_traffic():
    "Make r2 learn h3's MAC address (again)"
    get_topogen().gears["h3"].run("ping -c 2 -W 1 10.10.10.2")


def _r2_es(enable):
    """
    Configure (or remove) the ES of h3 on r2's hostbond1, and make r2 learn
    h3's MAC again: zebra only sets (or clears) the ES of a local MAC when
    it learns it, not when its interface is made (or no longer) an ES.
    """
    r2 = get_topogen().gears["r2"]
    no = "" if enable else "no "
    r2.vtysh_cmd(
        """
configure terminal
 interface hostbond1
  {no}evpn mh es-id {es_id}
  {no}evpn mh es-sys-mac {sys_mac}
""".format(
            no=no, es_id=ES_ID, sys_mac=ES_SYS_MAC
        )
    )

    def _local_es():
        output = r2.vtysh_cmd("show evpn es {} json".format(ESI), isjson=True)
        return "local" in output.get("flags", [])

    _, result = topotest.run_and_expect(_local_es, enable, count=30, wait=1)
    assert result == enable, "r2 {} the local ES {}".format(
        "does not have" if enable else "still has", ESI
    )

    # Learnt again by the caller's traffic from h3.
    r2.run("bridge fdb del {} dev hostbond1 master vlan {}".format(H3_MAC, L2VNI_VLAN))


def _peer1_es_mode(mode):
    "Make peer1 join (`attach`) or leave (`detach`) the ES of h3"
    peer1 = get_topogen().gears["peer1"]
    peer1.cmd_raises(
        "echo {0} > /etc/exabgp/es-mode && chmod 644 /etc/exabgp/es-mode".format(mode)
    )


def _zebra_es_vteps(router):
    """
    The ES of h3 as r1's zebra has it: (<next hop group ID>, {<VTEP>: <next
    hop ID>}), or None when zebra has no such ES
    """
    output = router.vtysh_cmd("show evpn es {} json".format(ESI), isjson=True)
    if output.get("esi") != ESI:
        return None

    vteps = {v["vtep"]: v.get("nexthopId") for v in output.get("vteps", [])}
    return output.get("nexthopGroup"), vteps


def _check_fpm_es(router, vteps, min_connection=0):
    """
    Return a description of what does not match yet, or None when zebra has
    the ES of h3 with exactly the `vteps` VTEPs, and the listener (on a
    connection numbered `min_connection` or more) has:

    - with `vteps`: an FDB next hop to each of them, an FDB next hop group
      with exactly these next hops, no other FDB next hop or group, and the
      remote MAC of h3 pointing to that group (NDA_NH_ID, no VTEP);
    - without: no FDB next hop or group, zebra having no ES, and the remote
      MAC of h3 with r2's VTEP.
    """
    es = _zebra_es_vteps(router)
    if vteps:
        if es is None:
            return "zebra has no ES {}".format(ESI)
        nhg_id, zebra_vteps = es
        if sorted(zebra_vteps) != sorted(vteps) or None in zebra_vteps.values():
            return "zebra ES {} VTEPs are {}, waiting for {}".format(
                ESI, zebra_vteps, vteps
            )
        if not nhg_id:
            return "zebra ES {} has no next hop group".format(ESI)
    elif es is not None:
        return "zebra still has the ES {}: {}".format(ESI, es)

    table = _fpm_tables(router)
    if table is None:
        return "no fpm_listener dump"
    if table["connection"] < min_connection:
        return "still on FPM connection {}, waiting for {}".format(
            table["connection"], min_connection
        )

    nhgs = table["nhgs"]
    mac = {
        "Family": "bridge",
        "Ifindex": _ifindex(router, "vxlan{}".format(L2VNI)),
        "Lladdr": H3_MAC,
        "Vlan": _access_vlan(router),
        "Vni": L2VNI,
        "Master": _ifindex(router, "br0"),
        "Flags": NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED,
    }

    errors = []
    if vteps:
        for vtep, nh_id in zebra_vteps.items():
            expected = {"fdb": True, "gateway": vtep, "members": []}
            if nhgs.get(nh_id) != expected:
                errors.append(
                    "FDB next hop {} of {}: {}, expected {}".format(
                        nh_id, vtep, nhgs.get(nh_id), expected
                    )
                )

        expected = {
            "fdb": True,
            "gateway": None,
            "members": sorted(zebra_vteps.values()),
        }
        if nhgs.get(nhg_id) != expected:
            errors.append(
                "FDB next hop group {}: {}, expected {}".format(
                    nhg_id, nhgs.get(nhg_id), expected
                )
            )

        # No FDB next hop of a VTEP that left the ES.
        expected_ids = set(zebra_vteps.values()) | {nhg_id}
        stale = {i: n for i, n in nhgs.items() if n["fdb"] and i not in expected_ids}
        if stale:
            errors.append("unexpected FDB next hops or groups: {}".format(stale))

        mac.update({"Dst": "none", "Nhid": nhg_id})
    else:
        fdb = {i: n for i, n in nhgs.items() if n["fdb"]}
        if fdb:
            errors.append("unexpected FDB next hops or groups: {}".format(fdb))

        mac.update({"Dst": R2_VTEP, "Nhid": 0})

    if not any(_entry_matches(n, mac) for n in table["neighbors"]):
        errors.append("missing remote MAC of h3: {}".format(mac))

    if not errors:
        return None

    return "{}\nFPM next hop groups (connection {}):\n{}\nFPM neighbors:\n{}".format(
        "\n".join(errors),
        table["connection"],
        "\n".join("{}: {}".format(i, n) for i, n in sorted(nhgs.items())),
        "\n".join(str(n) for n in table["neighbors"]),
    )


def _fpm_log_lines(router):
    "The messages fpm_listener logged so far (see `_fpm_log_path()`)"
    with open(_fpm_log_path(router), "r") as f:
        return f.readlines()


def _fpm_log_mark(router):
    """
    The line of the listener log the next message will be logged at (the
    listener does not buffer it)
    """
    return len(_fpm_log_lines(router))


# The fpm_listener log lines of a next hop (group), and of the remote MAC of
# h3 pointing to a next hop group
_LOG_NHG_RE = re.compile(r"\] (New|Del) Nexthop Group ID: (\d+),")
_LOG_H3_MAC_RE = re.compile(
    r"\] New Neighbor .*Lladdr: {},.* Nhid: (\d+),".format(re.escape(H3_MAC))
)


def _check_fpm_es_order(router, log_start):
    """
    Return a description of what the FPM got out of order, or None, for the
    ES of h3 as r1's zebra has it and the messages the listener logged from
    line `log_start`: the last ES next hop group sent there must come after
    the FDB next hops it uses, and each remote MAC of h3 sent there pointing
    to the group after that group, on the same FPM connection (a new
    connection starting with an empty table).
    """
    nhg_id, vteps = _zebra_es_vteps(router)
    lines = _fpm_log_lines(router)

    def _sent_before(index, nh_id):
        "If the last message about `nh_id` before line `index` added it"
        for line in reversed(lines[:index]):
            if line.startswith("Done serving client"):
                return False
            match = _LOG_NHG_RE.search(line)
            if match and int(match.group(2)) == nh_id:
                return match.group(1) == "New"
        return False

    errors = []
    groups = []
    for i in range(log_start, len(lines)):
        match = _LOG_NHG_RE.search(lines[i])
        if match and match.group(1) == "New" and int(match.group(2)) == nhg_id:
            groups.append(i)
    if groups:
        for vtep, nh_id in vteps.items():
            if not _sent_before(groups[-1], nh_id):
                errors.append(
                    "next hop group {} sent before its next hop {} to {}".format(
                        nhg_id, nh_id, vtep
                    )
                )

    for i in range(log_start, len(lines)):
        match = _LOG_H3_MAC_RE.search(lines[i])
        if match and int(match.group(1)) == nhg_id and not _sent_before(i, nhg_id):
            errors.append(
                "remote MAC of h3 sent before its next hop group {}".format(nhg_id)
            )

    if not errors:
        return None

    return "{}\nFPM messages:\n{}".format("\n".join(errors), "".join(lines[log_start:]))


def _wait_fpm_es(router, vteps, replay=None, log_start=None, what=""):
    """
    Wait for `_check_fpm_es()` to match, on the new connection of `replay`
    (see `_wait_fpm_entries()`) when given. Then, with `vteps` and the
    `log_start` line of the listener log (the replay's when not given),
    check the order of the messages logged since (`_check_fpm_es_order()`).
    """
    min_connection = 0
    if replay is not None:
        min_connection = replay["connection"]
        if log_start is None:
            log_start = replay["fpm_log_start"]
        _fpm_sync(router, replay)

    test_func = partial(_check_fpm_es, router, vteps, min_connection)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "{}:\n{}".format(what, result)

    if vteps and log_start is not None:
        # The log (unbuffered) has every message the last dump reflects.
        result = _check_fpm_es_order(router, log_start)
        assert result is None, "{} (order):\n{}".format(what, result)


def _fpm_es_reconnect(router, vteps):
    "Check that a new FPM connection gets the ES with the VTEPs `vteps` again"
    fpm_log_start = _fpm_log_mark(router)
    replay = _fpm_reconnect(router)
    replay["fpm_log_start"] = fpm_log_start
    _wait_fpm_es(
        router,
        vteps,
        replay=replay,
        what="FPM did not get the ES with the VTEPs {} on a new connection".format(
            vteps
        ),
    )


def _check_fpm_no_h3_mac(router, min_connection=0):
    """
    Return a description of what does not match yet, or None, when the
    listener (on a connection numbered `min_connection` or more) has no
    remote MAC of h3.
    """
    table = _fpm_tables(router)
    if table is None:
        return "no fpm_listener dump"
    if table["connection"] < min_connection:
        return "still on FPM connection {}, waiting for {}".format(
            table["connection"], min_connection
        )

    # The remote MAC, not a remote neighbor with h3's MAC on an SVI.
    macs = [
        n
        for n in table["neighbors"]
        if n.get("Family") == "bridge" and n.get("Lladdr") == H3_MAC
    ]
    if macs:
        return "FPM still has the remote MAC of h3: {}".format(macs)
    return None


def _kernel_es_mac_entry(router):
    "The vxlan FDB entry of h3's MAC to a next hop group r1's kernel has, or None"
    output = router.run("bridge fdb show dev vxlan{}".format(L2VNI))
    for line in output.splitlines():
        if line.startswith(H3_MAC + " ") and " nhid " in line:
            return line
    return None


def _fpm_es_vxlan_down(router, vteps):
    """
    The vxlan interface of the L2VNI going down removes the remote MAC of h3
    behind the ES from the FPM, live and on a new connection, and it comes
    back with the interface.
    """
    router.cmd_raises("ip link set vxlan{} down".format(L2VNI))
    test_func = partial(_check_fpm_no_h3_mac, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "FPM kept the ES MAC of h3 with vxlan{} down:\n{}".format(
        L2VNI, result
    )

    replay = _fpm_reconnect(router)
    _fpm_sync(router, replay)
    test_func = partial(_check_fpm_no_h3_mac, router, replay["connection"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "FPM got the ES MAC of h3 with vxlan{} down on a new connection:\n{}".format(
        L2VNI, result
    )

    log_start = _fpm_log_mark(router)
    router.cmd_raises("ip link set vxlan{} up".format(L2VNI))
    _wait_bgp_evpn(router)
    _h3_traffic()
    _wait_fpm_es(
        router,
        vteps,
        log_start=log_start,
        what="FPM did not get the ES MAC of h3 back with vxlan{} up".format(L2VNI),
    )


def _fpm_es_mac_to_local(router, vteps):
    """
    The remote MAC of h3 behind the ES moving behind r1 (h1 taking it)
    removes its vxlan entry to the ES next hop group from the kernel, where
    it would stay otherwise (a later install of the MAC behind a single VTEP
    does not replace it), and from the FPM. It comes back behind the ES with
    h3's traffic.
    """
    tgen = get_topogen()
    h1 = tgen.gears["h1"]
    vlan = _access_vlan(router)

    assert _kernel_es_mac_entry(router), "kernel has no ES entry for h3:\n{}".format(
        router.run("bridge fdb show dev vxlan{}".format(L2VNI))
    )

    # h1's port in the current access VLAN of the L2VNI (an earlier test
    # moved it), where h3 stays quiet while h1 takes its MAC address. h3
    # must not answer h1, which would take the MAC back behind r2: h1 keeps
    # its own IP address, and has no IPv6, whose link local address (from
    # the MAC) would be h3's, which h3 defends against h1's DAD.
    router.cmd_raises("bridge vlan add vid {} dev r1-eth2 pvid untagged".format(vlan))
    h1.cmd_raises(
        """
ip link set h1-eth0 down
sysctl -q -w net.ipv6.conf.h1-eth0.disable_ipv6=1
ip addr flush dev h1-eth0
ip link set h1-eth0 address {mac}
ip addr add {ip}/24 dev h1-eth0
ip link set h1-eth0 up
""".format(
            mac=H3_MAC, ip=H1_IP
        )
    )
    h1.run("ping -c 2 -W 1 10.10.10.1")

    test_func = partial(_mac_type, router, H3_MAC)
    _, result = topotest.run_and_expect(test_func, "local", count=30, wait=1)
    assert result == "local", "h3 MAC is {} on r1, not local".format(result)

    _, result = topotest.run_and_expect(
        partial(_kernel_es_mac_entry, router), None, count=30, wait=1
    )
    assert result is None, "kernel kept the ES entry of h3 now local: {}".format(result)
    test_func = partial(_check_fpm_no_h3_mac, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "FPM kept the ES MAC of h3 now local:\n{}".format(result)

    # Back behind the ES: r1 forgets the local MAC, h3 talks again.
    log_start = _fpm_log_mark(router)
    h1.cmd_raises("ip link set h1-eth0 down")
    router.run("bridge fdb del {} dev r1-eth2 master vlan {}".format(H3_MAC, vlan))
    if vlan != L2VNI_VLAN:
        router.cmd_raises(
            """
bridge vlan add vid {old} dev r1-eth2 pvid untagged
bridge vlan del vid {vlan} dev r1-eth2
""".format(
                old=L2VNI_VLAN, vlan=vlan
            )
        )
    _h3_traffic()

    test_func = partial(_mac_type, router, H3_MAC)
    _, result = topotest.run_and_expect(test_func, "remote", count=30, wait=1)
    assert result == "remote", "h3 MAC is {} on r1, not remote".format(result)
    _wait_fpm_es(
        router,
        vteps,
        log_start=log_start,
        what="FPM did not get the ES MAC of h3 back behind the ES",
    )


def test_fpm_evpn_mh_es():
    """
    The remote MAC of h3, once behind the EVPN-MH ES of r2, points to the
    ES next hop group: the FPM gets the group, after the FDB next hops of
    the ES VTEPs, and the MAC after the group, both live and on a new
    connection, as VTEPs join and leave the ES, and gets their removal with
    the ES, the MAC going back to r2's VTEP. While two VTEPs are in the ES:

    - the vxlan interface going down removes the MAC from the FPM, live and
      on a new connection, and it comes back with the interface;
    - the MAC moving behind r1 removes its vxlan entry from the kernel and
      the FPM, and it comes back behind the ES.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    krel = platform.release()
    if topotest.version_cmp(krel, "5.8") < 0:
        pytest.skip(
            'EVPN-MH FDB next hops need kernel 5.8 or newer (have "{}")'.format(krel)
        )
    skip = vxlan_dynamic_nh_fdb_skip_reason()
    if skip:
        pytest.skip(skip)

    r1 = tgen.gears["r1"]
    _wait_bgp_evpn(r1)
    _wait_bgp_evpn(r1, PEER1_VTEP, "peer1")

    # h3 is single-homed to r2 until its port is an ES.
    _h3_traffic()
    _wait_fpm_es(r1, [], what="FPM did not get the remote MAC of h3 behind r2")

    # (step, ES VTEPs on r1, check a new connection too)
    steps = [
        (partial(_r2_es, True), [R2_VTEP], False),
        (partial(_peer1_es_mode, "attach"), [R2_VTEP, PEER1_VTEP], True),
        (partial(_fpm_es_vxlan_down, r1, [R2_VTEP, PEER1_VTEP]), None, False),
        (partial(_fpm_es_mac_to_local, r1, [R2_VTEP, PEER1_VTEP]), None, False),
        (partial(_peer1_es_mode, "detach"), [R2_VTEP], True),
        (partial(_r2_es, False), [], True),
    ]
    for step, vteps, reconnect in steps:
        log_start = _fpm_log_mark(r1)
        step()
        if vteps is None:
            # The step checked its own outcome.
            continue

        _h3_traffic()
        _wait_fpm_es(
            r1,
            vteps,
            log_start=log_start,
            what="FPM did not get the ES with the VTEPs {}".format(vteps),
        )

        if reconnect:
            _fpm_es_reconnect(r1, vteps)


def _wait_bgp_unnumbered(router):
    "Wait for the unnumbered session between r1 and r2"
    expected = {"ipv4Unicast": {"peers": {"r1-eth1": {"state": "Established"}}}}
    test_func = partial(
        topotest.router_json_cmp, router, "show bgp summary json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 unnumbered session to r2 is not up"


def test_fpm_no_link_local_neighbor():
    """
    The 169.254.0.1 neighbor zebra installs for the unnumbered session is
    not an EVPN entry: the FPM never gets it, nor its removal (zebra
    removes it and installs it again when the kernel marks it invalid).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _wait_bgp_unnumbered(r1)

    # The FPM must be connected to get the updates, if they were sent.
    def _fpm_connected():
        table = _fpm_tables(r1)
        return table is not None and len(table["neighbors"]) > 0

    _, result = topotest.run_and_expect(_fpm_connected, True, count=60, wait=1)
    assert result, "FPM did not get any entry"

    # A removal only goes on to the FPM when the kernel removal succeeds:
    # make sure the kernel has the entry before marking it invalid.
    r2_mac = r2.run("cat /sys/class/net/r2-eth2/address").strip()
    r1.cmd_raises(
        "ip neigh replace {} lladdr {} dev r1-eth1 nud permanent".format(
            IPV4_LL, r2_mac
        )
    )
    r1.cmd_raises("ip neigh replace {} dev r1-eth1 nud incomplete".format(IPV4_LL))

    # zebra removes the entry and installs it again with r2's MAC address,
    # which the kernel may refuse (zebra adds it with an EVPN-MH extended
    # flag that recent kernels reject): wait for either, not just for the
    # entry to no longer be incomplete (failed).
    def _handled():
        output = r1.run("ip -4 neigh show {} dev r1-eth1".format(IPV4_LL)).strip()
        if not output:
            return True
        return "lladdr {}".format(r2_mac) in output and "INCOMPLETE" not in output

    _, result = topotest.run_and_expect(_handled, True, count=30, wait=1)
    assert result, "zebra did not remove or install again the {} neighbor".format(
        IPV4_LL
    )

    # The FPM gets the dataplane updates right after the kernel: once the
    # listener has everything zebra sent so far, check nothing about the
    # neighbor ever reached it.
    _fpm_sync(r1)
    with open(_fpm_log_path(r1), "r") as f:
        lines = [line for line in f if "Dst: {},".format(IPV4_LL) in line]
    assert not lines, "FPM got the {} neighbor:\n{}".format(IPV4_LL, "".join(lines))


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
