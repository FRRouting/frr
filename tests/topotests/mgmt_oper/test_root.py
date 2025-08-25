#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# noqa: E501
#
"""
Test root level queries
"""
import pytest
from lib.topogen import Topogen
from oper import check_kernel_32, do_oper_test

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",), "s2": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Setup VRF red
        router.net.add_l3vrf("red", 10)
        router.net.add_loop("lo-red")
        router.net.attach_iface_to_l3vrf("lo-red", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth1", "red")
        router.load_frr_config("frr-root.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_oper_root(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    ds_mods = ["", "operational", "running", "candidate"]
    config_mods = ["", "with-config", "only-config"]
    query_results = []

    for ds in ds_mods:
        fds = "-" + ds if ds else ""
        cmd_ds = " datastore " + ds if ds else ""
        for cm in config_mods:
            fcm = "-" + cm if cm else ""
            cmd_cm = " " + cm if cm else ""
            query_results.append(
                ("/*", f"root-results/result{fds}{fcm}.json", cmd_ds + cmd_cm)
            )

    r1 = tgen.gears["r1"].net
    check_kernel_32(r1, "11.11.11.11", 1, "")
    do_oper_test(tgen, query_results, exact=False)


to_gen_new_results = """
scriptdir=~chopps/w/frr/tests/topotests/mgmt_oper
resdir=${scriptdir}/root-results
filter='jq pick(.["frr-backend:clients","frr-interface:lib","frr-logging:logging"])'
vtysh -c 'show mgmt get-data /*'                | $filter > ${resdir}/result.json
vtysh -c 'show mgmt get-data /* with-config'    | $filter > ${resdir}/result-with-config.json
vtysh -c 'show mgmt get-data /* only-config'    | $filter > ${resdir}/result-only-config.json
vtysh -c 'show mgmt get-data /* datastore candidate'                | $filter > ${resdir}/result-candidate.json
vtysh -c 'show mgmt get-data /* datastore candidate with-config'    | $filter > ${resdir}/result-candidate-with-config.json
vtysh -c 'show mgmt get-data /* datastore candidate only-config'    | $filter > ${resdir}/result-candidate-only-config.json
vtysh -c 'show mgmt get-data /* datastore running'                | $filter > ${resdir}/result-running.json
vtysh -c 'show mgmt get-data /* datastore running with-config'    | $filter > ${resdir}/result-running-with-config.json
vtysh -c 'show mgmt get-data /* datastore running only-config'    | $filter > ${resdir}/result-running-only-config.json
vtysh -c 'show mgmt get-data /* datastore operational'                | $filter > ${resdir}/result-operational.json
vtysh -c 'show mgmt get-data /* datastore operational with-config'    | $filter > ${resdir}/result-operational-with-config.json
vtysh -c 'show mgmt get-data /* datastore operational only-config'    | $filter > ${resdir}/result-operational-only-config.json

scriptdir=~chopps/w/frr/tests/topotests/mgmt_oper
resdir=${scriptdir}/root-results
# Verify operational is the default when generating
cmp ${resdir}/result.json ${resdir}/result-operational.json || echo == FAIL ==
cmp ${resdir}/result-with-config.json ${resdir}/result-operational-with-config.json || echo == FAIL ==
cmp ${resdir}/result-only-config.json ${resdir}/result-operational-only-config.json || echo == FAIL ==
# Verify running and candidate are the same when generating
cmp ${resdir}/result-running.json ${resdir}/result-candidate.json || echo == FAIL ==
cmp ${resdir}/result-running-only-config.json ${resdir}/result-candidate-only-config.json || echo == FAIL ==
cmp ${resdir}/result-running-with-config.json ${resdir}/result-candidate-with-config.json || echo == FAIL ==
# Verify running only-config and with-config are the same
cmp ${resdir}/result-running-only-config.json ${resdir}/result-running-with-config.json || echo == FAIL ==
# Verify candidate only-config and with-config are the same
cmp ${resdir}/result-candidate-only-config.json ${resdir}/result-candidate-with-config.json || echo == FAIL ==

scriptdir=~chopps/w/frr/tests/topotests/mgmt_oper
resdir=${scriptdir}/root-results
for f in ${resdir}/result*.json; do
   sed -i -e 's/"\(phy-address\|revision\|uptime\)": ".*"/"\1": "rubout"/' $f
   sed -i -e 's/"\(candidate\|running\)-config-version": ".*"/"\1-config-version": "rubout"/' $f
   sed -i -e 's/"\(id\|if-index\|mtu\|mtu6\|speed\)": [0-9][0-9]*/"\1": "rubout"/' $f
   sed -i -e 's,"vrf": "[0-9]*","vrf": "rubout",' $f
   sed -i -e 's,"module-set-id": "[0-9]*","module-set-id": "rubout",' $f
   sed -i -e 's,"\(apply\|edit\|prep\)-count": "[0-9]*","\1-count": "rubout",' $f
   sed -i -e 's,"avg-\(apply\|edit\|prep\)-time": "[0-9]*","avg-\1-time": "rubout",' $f
done
"""  # noqa: 501
