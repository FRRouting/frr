#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_pim_register_no_rp.py
#
# Copyright (c) 2026 Nvidia Inc.
#               Donald Sharp
#

"""
test_pim_register_no_rp.py: FHR register state when RP(G) changes

RFC 7761 section 4.4.1 says that "RP changed" moves the (S,G) register
machine from Prune to Join and cancels the Register-Stop timer.

    r2 (source) ---- r1 (FHR) ---- rp
                     10.0.2.1       10.0.1.3
                        |
                        +--------- rp1
                                   10.0.3.3
"""

import json
import os
import sys
import pytest

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

GROUP = "239.1.1.1"
SOURCE = "10.0.2.2"
RP_ADDR = "10.0.1.3"
RP1_ADDR = "10.0.3.3"
# Covered by rp1's 239.2.0.0/16, then moved to rp by a /32.
GROUP_RP1 = "239.2.2.2"
RP1_RANGE = "239.2.0.0/16"
RP_SPECIFIC = "239.2.2.2/32"


def build_topo(tgen):
    """
    r2 (source) ---- r1 (FHR) ---- rp
                       |
                       +--------- rp1
    """

    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("rp")
    tgen.add_router("rp1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["rp"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["rp1"])


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(extra_daemons=["staticd"])

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _upstream(router, group=GROUP, source=SOURCE):
    # "*" is not an A.B.C.D token, so the filtered form cannot select (*,G).
    if source == "*":
        output = router.vtysh_cmd("show ip pim upstream json")
    else:
        output = router.vtysh_cmd(
            "show ip pim upstream {} {} json".format(source, group)
        )
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return None, output
    upstream = data.get(group, {}).get(source)
    if not upstream:
        return None, output
    return upstream, None


def _mroute_oil(router, group=GROUP):
    output = router.vtysh_cmd("show ip mroute json")
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return None, output
    entry = data.get(group, {}).get(SOURCE)
    if not entry:
        return None, output
    return entry.get("oil", {}), None


def _vtysh_config(router, config):
    output = router.vtysh_cmd(config)
    assert "Unknown command" not in output, output
    return output


def test_register_prune_cleared_on_no_rp():
    "Register Prune goes to Join when the RP mapping is deleted"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _pim_neighbor():
        output = r1.vtysh_cmd("show ip pim neighbor json")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return output
        if "r1-eth0" not in data:
            return data
        return None

    logger.info("Checking r1 has a PIM neighbor toward the RP")
    _, result = topotest.run_and_expect(_pim_neighbor, None, count=40, wait=1)
    assert result is None, "r1: PIM neighbor with rp did not converge"

    mcast_tx = os.path.join(CWD, "../pim_basic/mcast-tx.py")
    p_tx = r2.popen(
        [mcast_tx, "--ttl", "10", "--count", "1000000000", "--interval", "500", GROUP, "r2-eth0"]
    )

    def _reg_prune():
        upstream, err = _upstream(r1)
        if not upstream:
            return err
        if upstream.get("regState") != "RegPrune":
            return "regState is {}, want RegPrune".format(upstream.get("regState"))
        if not upstream.get("firstHopRouter"):
            return "r1 is not the FHR: {}".format(upstream)
        oil, err = _mroute_oil(r1)
        if oil is None:
            return err
        if "pimreg" in oil:
            return "pimreg still in OIL while register state is Prune"
        return None

    logger.info("Checking (%s,%s) register state is Prune", SOURCE, GROUP)
    _, result = topotest.run_and_expect(_reg_prune, None, count=40, wait=1)
    assert result is None, "r1: (S,G) did not reach RegPrune: {}".format(result)

    logger.info("Deleting RP %s on r1", RP_ADDR)
    output = r1.vtysh_cmd(
        """
        configure terminal
        router pim
        no rp {}
        """.format(
            RP_ADDR
        )
    )
    assert "Unknown command" not in output, output

    def _reg_join():
        upstream, err = _upstream(r1)
        if not upstream:
            return err
        if upstream.get("regState") != "RegJoined":
            return "regState is {}, want RegJoined".format(upstream.get("regState"))
        if upstream.get("resetTimer") != "--:--:--":
            return "Register-Stop timer still running: {}".format(
                upstream.get("resetTimer")
            )
        oil, err = _mroute_oil(r1)
        if oil is None:
            return err
        if "pimreg" not in oil:
            return "pimreg was not added back to the OIL"
        return None

    logger.info("Checking (%s,%s) register state is Join after no rp", SOURCE, GROUP)
    _, result = topotest.run_and_expect(_reg_join, None, count=20, wait=1)
    assert result is None, "r1: (S,G) did not leave RegPrune for RegJoined: {}".format(
        result
    )

    p_tx.terminate()
    p_tx.wait()


def test_more_specific_rp_joins_sg():
    """A more-specific RP with a receiver pulls a pruned (S,G) to Joined.

    r1's broad mapping points at rp1, so the stream is register-pruned there.
    rp then becomes RP for the group and gains a (*,G) join. That must not
    move r1, because r1 still resolves the group to rp1. A longer prefix on
    r1 pointing at rp is an RP change: rp has the (*,G) join, so it joins
    the (S,G) and r1's upstream goes to Joined.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    rp = tgen.gears["rp"]
    rp1 = tgen.gears["rp1"]

    def _rp1_ready():
        output = r1.vtysh_cmd("show ip pim neighbor json")
        try:
            neighbors = json.loads(output)
        except json.JSONDecodeError:
            return output
        if "r1-eth2" not in neighbors:
            return "r1 has no PIM neighbor on r1-eth2 toward rp1"

        output = rp1.vtysh_cmd("show ip route {}".format(SOURCE))
        if "10.0.3.1" not in output:
            return "rp1 has no route to source {}: {}".format(SOURCE, output)

        output = rp1.vtysh_cmd("show ip pim rp-info json")
        try:
            rp_info = json.loads(output)
        except json.JSONDecodeError:
            return output
        rows = rp_info.get(RP1_ADDR, [])
        for row in rows:
            if row.get("group") == RP1_RANGE and row.get("iAmRP") is True:
                return None
        return "rp1 is not RP for {}: {}".format(RP1_RANGE, rp_info)

    logger.info("Checking rp1 is reachable and is RP for %s", RP1_RANGE)
    _, result = topotest.run_and_expect(_rp1_ready, None, count=40, wait=1)
    assert result is None, result

    logger.info("Pointing %s on r1 at rp1 %s", RP1_RANGE, RP1_ADDR)
    _vtysh_config(
        r1,
        """
        configure terminal
        router pim
        rp {} {}
        """.format(
            RP1_ADDR, RP1_RANGE
        ),
    )

    mcast_tx = os.path.join(CWD, "../pim_basic/mcast-tx.py")
    p_tx = r2.popen(
        [
            mcast_tx,
            "--ttl",
            "10",
            "--count",
            "1000000000",
            "--interval",
            "500",
            GROUP_RP1,
            "r2-eth0",
        ]
    )

    def _reg_prune_toward_rp1():
        upstream, err = _upstream(r1, GROUP_RP1)
        if not upstream:
            return err
        if upstream.get("regState") != "RegPrune":
            return "regState is {}, want RegPrune".format(upstream.get("regState"))
        if upstream.get("rpfAddress") != RP1_ADDR:
            return "r1 RP is {}, want {}".format(upstream.get("rpfAddress"), RP1_ADDR)
        if not upstream.get("firstHopRouter"):
            return "r1 is not the FHR: {}".format(upstream)
        return None

    try:
        logger.info("Checking (%s,%s) is register-pruned toward rp1", SOURCE, GROUP_RP1)
        _, result = topotest.run_and_expect(_reg_prune_toward_rp1, None, count=40, wait=1)
        assert result is None, "r1: (S,G) did not reach RegPrune toward rp1: {}".format(
            result
        )

        logger.info("Marking rp %s as RP for %s", RP_ADDR, RP_SPECIFIC)
        _vtysh_config(
            rp,
            """
            configure terminal
            router pim
            rp {} {}
            """.format(
                RP_ADDR, RP_SPECIFIC
            ),
        )

        logger.info("Requesting (*,%s) join on rp", GROUP_RP1)
        _vtysh_config(
            rp,
            """
            configure terminal
            interface lo
            ip address 10.255.0.1/32
            ip igmp
            ip pim passive
            ip igmp join {}
            """.format(
                GROUP_RP1
            ),
        )

        def _rp_star_join():
            output = rp.vtysh_cmd("show ip igmp join json")
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                return output
            groups = data.get("lo", {}).get("groups", [])
            joined = any(
                entry.get("group") == GROUP_RP1 and entry.get("source") == "*"
                for entry in groups
            )
            if not joined:
                return "rp has no (*,{}) IGMP join: {}".format(GROUP_RP1, data)
            upstream, err = _upstream(rp, GROUP_RP1, "*")
            if not upstream:
                return err or "rp has no (*,G) upstream"
            return None

        logger.info("Checking rp has a (*,%s) join", GROUP_RP1)
        _, result = topotest.run_and_expect(_rp_star_join, None, count=20, wait=1)
        assert result is None, result

        logger.info("Checking r1 is still register-pruned toward rp1")
        _, result = topotest.run_and_expect(_reg_prune_toward_rp1, None, count=5, wait=1)
        assert result is None, (
            "r1 left RegPrune while its RP was still rp1: {}".format(result)
        )

        logger.info("Pointing %s on r1 at rp %s", RP_SPECIFIC, RP_ADDR)
        _vtysh_config(
            r1,
            """
            configure terminal
            router pim
            rp {} {}
            """.format(
                RP_ADDR, RP_SPECIFIC
            ),
        )

        def _sg_joined():
            upstream, err = _upstream(r1, GROUP_RP1)
            if not upstream:
                return err
            if upstream.get("joinState") != "Joined":
                return "r1 joinState is {}, want Joined".format(
                    upstream.get("joinState")
                )
            if upstream.get("rpfAddress") != RP_ADDR:
                return "r1 RP is {}, want {}".format(upstream.get("rpfAddress"), RP_ADDR)
            oil, err = _mroute_oil(r1, GROUP_RP1)
            if oil is None:
                return err
            joined_oif = oil.get("r1-eth0")
            if not joined_oif or not joined_oif.get("protocolPim"):
                return "join from rp is not on r1-eth0: {}".format(list(oil))
            rp_upstream, err = _upstream(rp, GROUP_RP1)
            if not rp_upstream:
                return err or "rp has no (S,G) upstream"
            if rp_upstream.get("joinState") != "Joined":
                return "rp joinState is {}, want Joined".format(
                    rp_upstream.get("joinState")
                )
            if rp_upstream.get("inboundInterface") != "rp-eth0":
                return "rp joined toward {}, want rp-eth0".format(
                    rp_upstream.get("inboundInterface")
                )
            return None

        logger.info(
            "Checking (%s,%s) is Joined after r1 selects rp", SOURCE, GROUP_RP1
        )
        _, result = topotest.run_and_expect(_sg_joined, None, count=30, wait=1)
        assert result is None, "r1: (S,G) did not become Joined: {}".format(result)
    finally:
        if p_tx:
            p_tx.terminate()
            p_tx.wait()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
