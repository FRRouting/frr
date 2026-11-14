#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Test: L3VNI access VLAN change must move remote VTEP state
#
# When the access VLAN of an L3VNI changes, zebra re-maps the L3VNI to
# the SVI of the new VLAN. The remote VTEP state zebra programmed for
# the old VLAN must move along with it.
#
# Topology:
#   PE1 ---[s1]--- P1 ---[s2]--- PE2
#
#   P1:  spine / iBGP route reflector (OSPF + BGP EVPN)
#   PE1, PE2:  VTEP leaves with VRF vrf-blue, L3VNI 3109 on VLAN 60
#   PE2 advertises 10.77.77.3/32 in vrf-blue as an EVPN type-5 route.
#

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import create_address_on_interface
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

REMOTE_VTEP = "10.30.30.30"


def setup_module(mod):
    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    if not topotest.platform_has_evpn():
        pytest.skip("platform does not support EVPN")

    topodef = {
        "s1": ("PE1", "P1"),
        "s2": ("P1", "PE2"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()

    for pe, addr in (("PE1", "10.99.99.1/24"), ("PE2", "10.99.99.3/24")):
        tgen.gears[pe].run(f"/bin/bash {CWD}/{pe}/setup.sh")
        create_address_on_interface(tgen, pe, "vlan60", addr)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _remote_rmac(pe):
    output = pe.vtysh_cmd("show evpn next-hops vni 3109 json", isjson=True)
    return output.get(REMOTE_VTEP, {}).get("routerMac")


def _check_nh_neigh(pe, svi):
    rmac = _remote_rmac(pe)
    if not rmac:
        return f"no next-hop {REMOTE_VTEP} for L3VNI 3109"

    output = pe.run(f"ip -j neigh show {REMOTE_VTEP}")
    try:
        neighs = json.loads(output) if output.strip() else []
    except ValueError:
        return f"bad ip neigh output: {output}"

    devs = sorted(n["dev"] for n in neighs if n.get("lladdr") == rmac)
    if devs != [svi]:
        return f"neigh {REMOTE_VTEP} lladdr {rmac} on {devs}, expected [{svi}]"
    return None


def test_nh_neigh_on_initial_svi():
    """Remote VTEP next-hop neighbor is installed on SVI vlan60."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    test_func = functools.partial(_check_nh_neigh, pe1, "vlan60")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_access_vlan_change():
    """Move L3VNI 3109 to VLAN 61 and check that zebra uses SVI vlan61."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    pe1.run("ip link add link br3109 name vlan61 type vlan id 61")
    pe1.run("ip link set dev vlan61 master vrf-blue")
    pe1.run("ip link set dev vlan61 up")
    pe1.run("bridge vlan add vid 61 dev br3109 self")
    pe1.run("bridge vlan add vid 61 dev vxlan3109 pvid untagged")

    def _check_svi():
        output = pe1.vtysh_cmd("show evpn vni 3109 json", isjson=True)
        if output.get("sviIntf") != "vlan61":
            return f"L3VNI 3109 SVI is {output.get('sviIntf')}, expected vlan61"
        return None

    _, result = topotest.run_and_expect(_check_svi, None, count=30, wait=1)
    assert result is None, result


def test_nh_neigh_moves_to_new_svi():
    """Remote VTEP next-hop neighbor moves from vlan60 to vlan61."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    test_func = functools.partial(_check_nh_neigh, pe1, "vlan61")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_rmac_fdb_moves_to_new_vlan():
    """Remote router-MAC FDB entry moves from VLAN 60 to VLAN 61."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    def _check_rmac_fdb():
        rmac = _remote_rmac(pe1)
        if not rmac:
            return f"no next-hop {REMOTE_VTEP} for L3VNI 3109"

        output = pe1.run("bridge -j fdb show dev vxlan3109")
        try:
            fdb = json.loads(output) if output.strip() else []
        except ValueError:
            return f"bad bridge fdb output: {output}"

        vlans = sorted(e["vlan"] for e in fdb if e.get("mac") == rmac and "vlan" in e)
        if vlans != [61]:
            return f"RMAC {rmac} FDB on VLANs {vlans}, expected [61]"
        return None

    _, result = topotest.run_and_expect(_check_rmac_fdb, None, count=30, wait=1)
    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
