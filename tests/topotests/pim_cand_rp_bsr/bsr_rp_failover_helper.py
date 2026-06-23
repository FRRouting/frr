# SPDX-License-Identifier: ISC

# bsr_rp_failover_helper.py: Helper functions for BSR RP failover tests.
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#
import os
import sys

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.pim import verify_pim_rp_info
from lib.common_config import step

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.insert(0, CWD)

from test_pim_cand_rp_bsr import TOPOLOGY, build_topo  # noqa: E402

# Cand-RP holdtime is max(151, 2.5 * advertisement-interval).
CRP_FAILOVER_TIMEOUT = 180


def setup_module(mod):
    logger.info("PIM BSR RP failover:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def verify_rp_failover_after_daemon_stop(
    tgen,
    tc_name,
    addr_type,
    group,
    primary_rp,
    backup_rp,
    primary_daemon,
):
    step("Verify {} is the active RP for {} before failover".format(primary_rp, group))
    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        group,
        oif=None,
        rp=primary_rp,
        source="BSR",
        iamrp=False,
        addr_type=addr_type,
        expected=True,
        retry_timeout=90,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Stop {} on primary RP r3 to trigger holdtime expiry".format(primary_daemon))
    tgen.gears["r3"].killDaemons([primary_daemon], wait=True)

    step("Verify {} becomes RP for {} on r5".format(backup_rp, group))
    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        group,
        oif=None,
        rp=backup_rp,
        source="BSR",
        iamrp=False,
        addr_type=addr_type,
        expected=True,
        retry_timeout=CRP_FAILOVER_TIMEOUT,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify backup RP r4 sees itself as RP (#17588)")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        group,
        oif=None,
        rp=backup_rp,
        source="BSR",
        iamrp=True,
        addr_type=addr_type,
        expected=True,
        retry_timeout=CRP_FAILOVER_TIMEOUT,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
