# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# January 14 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test YANG Datastore Notifications
"""
import json
import logging
import os
import re
import time

import pytest
from lib.topogen import Topogen
from lib.topotest import json_cmp
from munet.testing.util import waitline
from oper import check_kernel_32

pytestmark = [pytest.mark.ripd, pytest.mark.staticd, pytest.mark.mgmtd]

CWD = os.path.dirname(os.path.realpath(__file__))
FE_CLIENT = CWD + "/../lib/fe_client.py"


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1", "r2"),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def get_op_and_json(output):
    values = []
    op = ""
    path = ""
    data = ""
    for line in output.split("\n"):
        if not line:
            break
        m = re.match("#OP=([A-Z]*): (.*)", line)
        if op and m:
            values.append((op, path, data))
            data = ""
            path = ""
            op = ""
        if not op and m:
            op = m.group(1)
            path = m.group(2)
            continue
        data += line + "\n"
    if op:
        values.append((op, path, data))
    if not values:
        assert False, f"No notifcation op present in:\n{output}"
    return values


def test_frontend_datastore_notification(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    rc, _, _ = r1.cmd_status(FE_CLIENT + " --help")

    if rc:
        pytest.skip("No protoc or present cannot run test")

    # Start our FE client in the background
    p = r1.popen(
        [
            FE_CLIENT,
            "--datastore",
            "--notify-count=2",
            "--listen=/frr-interface:lib/interface/state",
        ]
    )
    assert waitline(p.stderr, "Connected", timeout=10)

    r1.cmd_raises("ip link set r1-eth0 mtu 1200")

    # {"frr-interface:lib":{"interface":[{"name":"r1-eth0","state":{"if-index":2,"mtu":1200,"mtu6":1200,"speed":10000,"metric":0,"phy-address":"ba:fd:de:b5:8b:90"}}]}}

    try:
        # Wait for FE client to exit
        output, error = p.communicate(timeout=10)
        notifs = get_op_and_json(output)
        op, path, data = notifs[1]

        assert op == "REPLACE"
        assert path.startswith("/frr-interface:lib/interface[name='r1-eth0']/state")

        jsout = json.loads(data)
        expected = json.loads(
            '{"frr-interface:lib":{"interface":[{"name":"r1-eth0","state":{"mtu":1200}}]}}'
        )
        result = json_cmp(jsout, expected)
        assert result is None
    finally:
        p.kill()
        r1.cmd_raises("ip link set r1-eth0 mtu 1500")


def test_backend_datastore_update(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    be_client_path = "/usr/lib/frr/mgmtd_testc"
    rc, _, _ = r1.cmd_status(be_client_path + " --help")

    if rc:
        pytest.skip("No mgmtd_testc")

    # Start our BE client in the background
    p = r1.popen(
        [
            be_client_path,
            "--timeout=20",
            "--log=file:/dev/stderr",
            "--datastore",
            "--listen",
            "/frr-interface:lib/interface",
        ]
    )
    assert waitline(p.stderr, "Got SUBSCR_REPLY success 1", timeout=10)

    r1.cmd_raises("ip link set r1-eth0 mtu 1200")
    try:
        expected = json.loads(
            '{"frr-interface:lib":{"interface":[{"name":"r1-eth0","state":{"mtu":1200}}]}}'
        )

        output, error = p.communicate(timeout=10)
        notifs = get_op_and_json(output)
        op, path, data = notifs[0]
        jsout = json.loads(data)
        result = json_cmp(jsout, expected)
        assert result is None
    finally:
        p.kill()
        r1.cmd_raises("ip link set r1-eth0 mtu 1500")


def test_backend_datastore_add_delete(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    be_client_path = "/usr/lib/frr/mgmtd_testc"
    rc, _, _ = r1.cmd_status(be_client_path + " --help")

    if rc:
        pytest.skip("No mgmtd_testc")

    # Start our BE client in the background
    p = r1.popen(
        [
            be_client_path,
            "--timeout=20",
            "--log=file:/dev/stderr",
            "--notify-count=2",
            "--datastore",
            "--listen",
            "/frr-interface:lib/interface",
        ]
    )
    assert waitline(p.stderr, "Got SUBSCR_REPLY success 1", timeout=10)

    r1.cmd_raises('vtysh -c "conf t" -c "int foobar"')
    try:
        assert waitline(
            p.stdout,
            re.escape('#OP=REPLACE: /frr-interface:lib/interface[name="foobar"]/state'),
            timeout=2,
        )

        r1.cmd_raises('vtysh -c "conf t" -c "no int foobar"')
        assert waitline(
            p.stdout,
            re.escape('#OP=DELETE: /frr-interface:lib/interface[name="foobar"]/state'),
            timeout=2,
        )
    finally:
        p.kill()
        r1.cmd_raises('vtysh -c "conf t" -c "no int foobar"')


def test_datastore_backend_filters(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    rc, _, _ = r1.cmd_status(FE_CLIENT + " --help")
    if rc:
        pytest.skip("No protoc or present cannot run test")

    # Start our FE client in the background
    p = r1.popen(
        [FE_CLIENT, "--datastore", "--listen=/frr-interface:lib/interface/state"]
    )
    assert waitline(p.stderr, "Connected", timeout=10)
    time.sleep(1)

    try:
        output = r1.cmd_raises(
            'vtysh -c "show mgmt get-data /frr-backend:clients/client/state/notify-selectors"'
        )
        jsout = json.loads(output)

        #
        # Verify only zebra has the notify selector as it's the only provider currently
        #
        state = {"notify-selectors": ["/frr-interface:lib/interface/state"]}
        expected = {
            "frr-backend:clients": {"client": [{"name": "zebra", "state": state}]}
        }

        result = json_cmp(jsout, expected, exact=True)
        assert result is None
    except Exception as error:
        logging.error("got exception: %s", error)
        raise
    finally:
        p.kill()
