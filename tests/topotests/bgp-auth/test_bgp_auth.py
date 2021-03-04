#!/usr/bin/env python

#
# test_bgp_auth.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_auth.py: Test BGP Md5 Authentication

                             +------+
                    +--------|      |--------+
                    | +------|  R1  |------+ |
                    | | -----|      |----+ | |
                    | | |    +------+    | | |
                    | | |                | | |
                   +------+            +------+
                   |      |------------|      |
                   |  R2  |------------|  R3  |
                   |      |------------|      |
                   +------+            +------+


setup is 3 routers with 3 links between each each link in a different vrf
Default, blue and red respectively
Tests check various fiddling with passwords and checking that the peer
establishment is as expected and passwords are not leaked across sockets 
for bgp instances
"""

import os
import sys
import json
import platform
from functools import partial
import pytest
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

from lib.common_config import apply_raw_config

ERROR_LIST = ["Malformed", "Failure", "Unknown", "Incomplete"]


class InvalidCLIError(Exception):
    """Raise when the CLI command is wrong"""

    pass


class TemplateTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        #
        # Create routers
        tgen.add_router("R1")
        tgen.add_router("R2")
        tgen.add_router("R3")

        # R1-R2 1
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["R1"])
        switch.add_link(tgen.gears["R2"])

        # R1-R3 1
        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["R1"])
        switch.add_link(tgen.gears["R3"])

        # R2-R3 1
        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["R2"])
        switch.add_link(tgen.gears["R3"])

        # R1-R2 2
        switch = tgen.add_switch("s4")
        switch.add_link(tgen.gears["R1"])
        switch.add_link(tgen.gears["R2"])

        # R1-R3 2
        switch = tgen.add_switch("s5")
        switch.add_link(tgen.gears["R1"])
        switch.add_link(tgen.gears["R3"])

        # R2-R3 2
        switch = tgen.add_switch("s6")
        switch.add_link(tgen.gears["R2"])
        switch.add_link(tgen.gears["R3"])

        # R1-R2 3
        switch = tgen.add_switch("s7")
        switch.add_link(tgen.gears["R1"])
        switch.add_link(tgen.gears["R2"])

        # R1-R3 2
        switch = tgen.add_switch("s8")
        switch.add_link(tgen.gears["R1"])
        switch.add_link(tgen.gears["R3"])

        # R2-R3 2
        switch = tgen.add_switch("s9")
        switch.add_link(tgen.gears["R2"])
        switch.add_link(tgen.gears["R3"])


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(TemplateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    # blue vrf
    r1.run("ip link add blue type vrf table 1001")
    r1.run("ip link set up dev blue")
    r2.run("ip link add blue type vrf table 1001")
    r2.run("ip link set up dev blue")
    r3.run("ip link add blue type vrf table 1001")
    r3.run("ip link set up dev blue")

    r1.run("ip link add lo1 type dummy")
    r1.run("ip link set lo1 master blue")
    r1.run("ip link set up dev lo1")
    r2.run("ip link add lo1 type dummy")
    r2.run("ip link set up dev lo1")
    r2.run("ip link set lo1 master blue")
    r3.run("ip link add lo1 type dummy")
    r3.run("ip link set up dev lo1")
    r3.run("ip link set lo1 master blue")

    r1.run("ip link set R1-eth2 master blue")
    r1.run("ip link set R1-eth3 master blue")
    r2.run("ip link set R2-eth2 master blue")
    r2.run("ip link set R2-eth3 master blue")
    r3.run("ip link set R3-eth2 master blue")
    r3.run("ip link set R3-eth3 master blue")

    r1.run("ip link set up dev  R1-eth2")
    r1.run("ip link set up dev  R1-eth3")
    r2.run("ip link set up dev  R2-eth2")
    r2.run("ip link set up dev  R2-eth3")
    r3.run("ip link set up dev  R3-eth2")
    r3.run("ip link set up dev  R3-eth3")

    # red vrf
    r1.run("ip link add red type vrf table 1002")
    r1.run("ip link set up dev red")
    r2.run("ip link add red type vrf table 1002")
    r2.run("ip link set up dev red")
    r3.run("ip link add red type vrf table 1002")
    r3.run("ip link set up dev red")

    r1.run("ip link add lo2 type dummy")
    r1.run("ip link set lo2 master red")
    r1.run("ip link set up dev lo2")
    r2.run("ip link add lo2 type dummy")
    r2.run("ip link set up dev lo2")
    r2.run("ip link set lo2 master red")
    r3.run("ip link add lo2 type dummy")
    r3.run("ip link set up dev lo2")
    r3.run("ip link set lo2 master red")

    r1.run("ip link set R1-eth4 master red")
    r1.run("ip link set R1-eth5 master red")
    r2.run("ip link set R2-eth4 master red")
    r2.run("ip link set R2-eth5 master red")
    r3.run("ip link set R3-eth4 master red")
    r3.run("ip link set R3-eth5 master red")

    r1.run("ip link set up dev  R1-eth4")
    r1.run("ip link set up dev  R1-eth5")
    r2.run("ip link set up dev  R2-eth4")
    r2.run("ip link set up dev  R2-eth5")
    r3.run("ip link set up dev  R3-eth4")
    r3.run("ip link set up dev  R3-eth5")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def vrf_str(vrf):
    if vrf == "":
        vrf_str = ""
    else:
        vrf_str = "vrf {}".format(vrf)

    return vrf_str


def peer_name(rtr, prefix, vrf):
    "generate VRF string for CLI"
    if vrf == "":
        vrf_str = ""
    else:
        vrf_str = "_" + vrf

    if prefix == "yes":
        if rtr == "R2":
            return "TWO_GROUP" + vrf_str
        else:
            return "THREE_GROUP" + vrf_str
    else:
        if rtr == "R2":
            return "2.2.2.2"
        else:
            return "3.3.3.3"


def print_diag(vrf):
    "print failure disagnostics"
    
    tgen = get_topogen()
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        print(rname + ":")
        print(router.vtysh_cmd("show run"))
        print(router.vtysh_cmd("show ip route {}".format(vrf_str(vrf))))
        print(router.vtysh_cmd("show bgp {} neighbor".format(vrf_str(vrf))))


def configure(conf_file):
    "configure from a file"

    tgen = get_topogen()
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        with open(
            os.path.join(CWD, "{}/{}").format(router.name, conf_file), "r+"
        ) as cfg:
            new_config = cfg.read()

            output = router.vtysh_multicmd(new_config, pretty_output=False)
            for out_err in ERROR_LIST:
                if out_err.lower() in output.lower():
                    raise InvalidCLIError("%s" % output)


def clear_bgp(vrf=""):
    " clear bgp configuration for a vrf"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    router_list = tgen.routers()
    if vrf == "":
        r1.vtysh_cmd("conf t\nno router bgp 65001")
        r2.vtysh_cmd("conf t\nno router bgp 65002")
        r2.vtysh_cmd("conf t\nno router bgp 65003")
    else:
        r1.vtysh_cmd("conf t\nno router bgp 65001 vrf {}".format(vrf))
        r2.vtysh_cmd("conf t\nno router bgp 65002 vrf {}".format(vrf))
        r3.vtysh_cmd("conf t\nno router bgp 65003 vrf {}".format(vrf))


def clear_ospf(vrf=""):
    "clear ospf configuration for a vrf"

    tgen = get_topogen()
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        if vrf == "":
            router.vtysh_cmd("conf t\nno router ospf")
        else:
            router.vtysh_cmd("conf t\nno router ospf vrf {}".format(vrf))


def check_neigh_state(router, peer, state, vrf=""):
    "check BGP neighbor state on a router"
    
    count = 0
    matched = False
    neigh_output = ""
    while count < 125:
        if vrf == "":
            neigh_output = router.vtysh_cmd("show bgp neighbors {} json".format(peer))
        else:
            neigh_output = router.vtysh_cmd(
                "show bgp vrf {} neighbors {} json".format(vrf, peer)
            )
        neigh_output_json = json.loads(neigh_output)
        if neigh_output_json[peer]["bgpState"] == state:
            matched = True
            break
        count += 1
        sleep(1)

    assertmsg = "{} could not peer {} state expected {} got {} ".format(
        router.name, peer, state, neigh_output_json[peer]["bgpState"]
    )
    if matched != True:
        print_diag(vrf)
    assert matched == True, assertmsg


def check_all_peers_established(vrf=""):
    "standard check for extablished peers per vrf"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]
    # do r1 last as he might be the dynamic one
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)


def check_vrf_peer_remove_passwords(vrf="", prefix="no"):
    "selectively remove passwords checking state"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nno neighbor {} password".format(
            vrf_str(vrf), peer_name("R2", prefix, vrf)
        )
    )

    check_neigh_state(r2, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nno neighbor 1.1.1.1 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nno neighbor {} password".format(
            vrf_str(vrf), peer_name("R3", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "3.3.3.3", "Connect", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nno neighbor 1.1.1.1 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nno neighbor 3.3.3.3 password".format(vrf_str(vrf))
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Connect", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nno neighbor 2.2.2.2 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)


def check_vrf_peer_change_passwords(vrf="", prefix="no"):
    "selectively change passwords checking state"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nneighbor {} password change1".format(
            vrf_str(vrf), peer_name("R2", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nneighbor 1.1.1.1 password change1".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nneighbor {} password change2".format(
            vrf_str(vrf), peer_name("R3", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "3.3.3.3", "Connect", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nneighbor 1.1.1.1 password change2".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nneighbor 3.3.3.3 password change3".format(
            vrf_str(vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Connect", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nneighbor 2.2.2.2 password change3".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)


def test_default_peer_established():
    "default vrf 3 peers same password"

    check_all_peers_established()
    clear_bgp()
    # tgen.mininet_cli()


def test_default_peer_remove_passwords():
    "selectively remove passwords checking state"

    configure("bgpd.conf")
    check_vrf_peer_remove_passwords()
    clear_bgp()


def test_default_peer_change_passwords():
    "selectively change passwords checking state"

    configure("bgpd.conf")
    check_vrf_peer_change_passwords()
    clear_bgp()


def test_default_prefix_peer_established():
    "default vrf 3 peers same password with prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    configure("bgpd_prefix.conf")
    check_all_peers_established()
    clear_bgp()
    # tgen.mininet_cli()


def test_prefix_peer_remove_passwords():
    "selectively remove passwords checking state with prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return
    configure("bgpd_prefix.conf")
    check_vrf_peer_remove_passwords(prefix="yes")
    clear_bgp()


def test_prefix_peer_change_passwords():
    "selecively change passwords checkig state with prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return
    configure("bgpd_prefix.conf")
    check_vrf_peer_change_passwords(prefix="yes")
    clear_bgp()
    clear_ospf()


def test_vrf_peer_established():
    "default vrf 3 peers same password with VRF config"

    # clean routers and load vrf config
    configure("bgpd_vrf.conf")
    configure("ospfd_vrf.conf")

    check_all_peers_established("blue")
    clear_bgp("blue")
    # tgen.mininet_cli()


def test_vrf_peer_remove_passwords():
    "selectively remove passwords checking state with VRF config"

    configure("bgpd_vrf.conf")
    check_vrf_peer_remove_passwords(vrf="blue")
    clear_bgp("blue")


def test_vrf_peer_change_passwords():
    "selectively change passwords checking state with VRF config"

    configure("bgpd_vrf.conf")
    check_vrf_peer_change_passwords(vrf="blue")
    clear_bgp("blue")


def test_vrf_prefix_peer_established():
    "default vrf 3 peers same password with VRF prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        clear_bgp("blue")
        return

    configure("bgpd_vrf_prefix.conf")
    check_all_peers_established("blue")
    clear_bgp("blue")


def test_vrf_prefix_peer_remove_passwords():
    "selectively remove passwords checking state with VRF prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    configure("bgpd_vrf_prefix.conf")
    check_vrf_peer_remove_passwords(vrf="blue", prefix="yes")
    clear_bgp("blue")


def test_vrf_prefix_peer_change_passwords():
    "selectively change passwords checking state with VRF prefix config"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        clear_ospf("blue")
        return

    configure("bgpd_vrf_prefix.conf")
    check_vrf_peer_change_passwords(vrf="blue", prefix="yes")
    clear_bgp("blue")
    clear_ospf("blue")


def test_multiple_vrf_peer_established():
    "default vrf 3 peers same password with multiple VRFs"

    configure("bgpd_multi_vrf.conf")
    configure("ospfd_multi_vrf.conf")
    check_all_peers_established("blue")
    check_all_peers_established("red")
    clear_bgp("blue")
    clear_bgp("red")
    # tgen.mininet_cli()


def test_multiple_vrf_peer_remove_passwords():
    "selectively remove passwords checking state with multiple VRFs"

    configure("bgpd_multi_vrf.conf")
    check_vrf_peer_remove_passwords("blue")
    check_all_peers_established("red")
    check_vrf_peer_remove_passwords("red")
    check_all_peers_established("blue")
    clear_bgp("blue")
    clear_bgp("red")
    # tgen.mininet_cli()


def test_multiple_vrf_peer_change_passwords():
    "selectively change passwords checking state with multiple VRFs"

    configure("bgpd_multi_vrf.conf")
    check_vrf_peer_change_passwords("blue")
    check_all_peers_established("red")
    check_vrf_peer_change_passwords("red")
    check_all_peers_established("blue")
    clear_bgp("blue")
    clear_bgp("red")
    # tgen.mininet_cli()


def test_multiple_vrf_prefix_peer_established():
    "default vrf 3 peers same password with multilpe VRFs and prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    configure("bgpd_multi_vrf.conf")
    configure("ospfd_multi_vrf.conf")
    check_all_peers_established("blue")
    check_all_peers_established("red")
    clear_bgp("blue")
    clear_bgp("red")
    # tgen.mininet_cli()


def test_multiple_vrf_prefix_peer_remove_passwords():
    "selectively remove passwords checking state with multiple vrfs and prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    configure("bgpd_multi_vrf_prefix.conf")
    tgen = get_topogen()
    check_vrf_peer_remove_passwords(vrf="blue", prefix="yes")
    check_all_peers_established("red")
    check_vrf_peer_remove_passwords(vrf="red", prefix="yes")
    check_all_peers_established("blue")
    clear_bgp("blue")
    clear_bgp("red")
    # tgen.mininet_cli()


def test_multiple_vrf_prefix_peer_change_passwords():
    "selectively change passwords checking state with multiple vrfs and prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        clear_bgp("blue")
        clear_bgp("red")
        clear_ospf("blue")
        clear_ospf("red")
        return

    configure("bgpd_multi_vrf_prefix.conf")
    check_vrf_peer_change_passwords(vrf="blue", prefix="yes")
    check_all_peers_established("red")
    check_vrf_peer_change_passwords(vrf="red", prefix="yes")
    check_all_peers_established("blue")
    clear_bgp("blue")
    clear_bgp("red")
    clear_ospf("blue")
    clear_ospf("red")
    # tgen.mininet_cli()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
