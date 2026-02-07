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
from lib.common_config import step
from lib.topogen import Topogen
from lib.topotest import json_cmp
from munet.base import Timeout
from munet.testing.util import readline, retry, waitline
from oper import check_kernel_32

from lib import topotest

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

CWD = os.path.dirname(os.path.realpath(__file__))
FE_CLIENT = CWD + "/../lib/fe_client.py"
BE_CLIENT = "/usr/lib/frr/mgmtd_testc"


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr-ds.conf")

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


# Wait for specific OP, path and maybe json, path must match exactly,
# return the path and json data (or None for DELETE)
def wait_op_json(f, op, path, json_match=None, exact=False, timeout=30):
    to = Timeout(timeout)
    jexp = json.loads(json_match) if isinstance(json_match, str) else json_match
    while not to.is_expired():
        m = waitline(
            f, rf"#OP={op}: ({re.escape(path)})(\W|$)", timeout=int(to.remaining())
        )
        assert m, f"Did not find expected OP={op} for path={path}"
        path = m.group(1)
        if op == "DELETE":
            return op, path, None
        rawjson = readline(f, timeout=timeout)
        assert rawjson, f"Did not find expected JSON data for OP={op} path={path}"
        jo = json.loads(rawjson)
        if jexp is None:
            logging.debug("json match not required, returning: %s", jo)
            return op, path, jo
        result = json_cmp(jo, jexp, exact=exact)
        if result is None:
            logging.debug("json match: %s", jo)
            return op, path, jo
        logging.debug("no json match: %s: continue", jo)


def test_frontend_datastore_notification(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    # Start our FE client in the background
    p = r1.popen(
        [
            FE_CLIENT,
            "--datastore",
            "--notify-count=2",
            "--listen=/frr-interface:lib/interface/state",
        ]
    )
    assert waitline(p.stderr, "Connected", timeout=30)

    r1.cmd_raises("ip link set r1-eth0 mtu 1200")

    # {"frr-interface:lib":{"interface":[{"name":"r1-eth0","state":{"if-index":2,"mtu":1200,"mtu6":1200,"speed":10000,"metric":0,"phy-address":"ba:fd:de:b5:8b:90"}}]}}

    try:
        # Wait for FE client to exit
        output, error = p.communicate(timeout=30)
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

    rc, _, _ = r1.cmd_status(BE_CLIENT + " --help")
    if rc:
        pytest.skip("No mgmtd_testc")

    # Watch the mgmtd log for the BE subscribing
    mlogp = r1.popen(["/usr/bin/tail", "-n0", "-f", f"{r1.rundir}/mgmtd.log"])

    # Start our BE client in the background
    p = r1.popen(
        [
            BE_CLIENT,
            "--log=file:/dev/stderr",
            "--datastore",
            "--listen",
            "/frr-interface:lib/interface",
        ]
    )
    assert waitline(mlogp.stdout, 'now known as "mgmtd-testc"', timeout=30)
    mlogp.kill()

    r1.cmd_raises("ip link set r1-eth0 mtu 1200")
    try:
        expected = json.loads(
            '{"frr-interface:lib":{"interface":[{"name":"r1-eth0","state":{"mtu":1200}}]}}'
        )

        output, error = p.communicate(timeout=30)
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

    rc, _, _ = r1.cmd_status(BE_CLIENT + " --help")
    if rc:
        pytest.skip("No mgmtd_testc")

    # Watch the mgmtd log for the BE subscribing
    mlogp = r1.popen(["/usr/bin/tail", "-n0", "-f", f"{r1.rundir}/mgmtd.log"])

    # Start our BE client in the background
    p = r1.popen(
        [
            BE_CLIENT,
            "--log=file:/dev/stderr",
            "--notify-count=0",
            "--datastore",
            "--listen",
            "/frr-interface:lib/interface",
            "/frr-vrf:lib/vrf",
        ]
    )
    assert waitline(mlogp.stdout, 'now known as "mgmtd-testc"', timeout=30)
    mlogp.kill()

    def _check_backend_xpath_registry():
        output = r1.cmd_raises(
            'vtysh -c "show mgmt backend-yang-xpath-registry notify"'
        )
        if re.match("notify: /frr-vrf:lib/vrf:.*mgmtd-testc.*", output):
            return "missing mgmtd-testc notify registration for /frr-vrf:lib/vrf"
        return None

    _, result = topotest.run_and_expect(
        _check_backend_xpath_registry, None, count=20, wait=1
    )
    assert result is None, result

    r1.cmd_raises('vtysh -c "conf t" -c "int foobar"')
    try:
        assert waitline(
            p.stdout,
            re.escape('#OP=REPLACE: /frr-interface:lib/interface[name="foobar"]/state'),
            timeout=30,
        )

        r1.cmd_raises('vtysh -c "conf t" -c "no int foobar"')
        assert waitline(
            p.stdout,
            re.escape('#OP=DELETE: /frr-interface:lib/interface[name="foobar"]/state'),
            timeout=30,
        )

        # Now add/delete a VRF and watch for notifications
        # We are more picky here and validate the active state as well.
        r1.cmd_raises("ip link add red type vrf table 10")
        r1.cmd_raises('vtysh -c "conf t" -c "vrf red" -c "exit"')

        wait_op_json(
            p.stdout,
            "REPLACE",
            '/frr-vrf:lib/vrf[name="red"]/state',
            '{"frr-vrf:lib":{"vrf":[{"name":"red","state":{"active":true}}]}}',
        )

        r1.cmd_raises("ip link del red")
        r1.cmd_raises('vtysh -c "conf t" -c "no vrf red"')
        wait_op_json(p.stdout, "DELETE", '/frr-vrf:lib/vrf[name="red"]')
    finally:
        pass
        p.kill()
        r1.cmd_status('vtysh -c "conf t" -c "no vrf red"', warn=False)
        r1.cmd_status("ip link del red", warn=False)


@retry(retry_timeout=30, initial_wait=0.5)
def check_filters(r1, selectors):
    showcmd = 'vtysh -c "show mgmt get-data /frr-backend:clients/client/state/notify-selectors"'
    jsout = json.loads(r1.cmd_raises(showcmd))

    if not selectors:
        expected = {}
        result = json_cmp(jsout, expected, exact=True)
        assert result is None
        return
    state = {"notify-selectors": selectors}
    expected = {"frr-backend:clients": {"client": [{"name": "zebra", "state": state}]}}
    result = json_cmp(jsout, expected, exact=True)
    assert result is None


def test_datastore_backend_filters(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    rc, _, _ = r1.cmd_status(BE_CLIENT + " --help")
    if rc:
        pytest.skip("No mgmtd_testc")

    check_kernel_32(r1, "11.11.11.11", 1, "")

    p = None
    p2 = None
    try:
        step("Verify no backend notify selectors")
        check_filters(r1, [])

        step("Start FE client and verify notify selector present in zebra")
        p = r1.popen(
            [
                FE_CLIENT,
                "--notify-count=0",
                "--datastore",
                "--listen=/frr-interface:lib/interface/state",
            ]
        )
        check_filters(r1, ["/frr-interface:lib/interface/state"])

        step("Start BE client and verify both notify selectors present in zebra")
        mlogp = r1.popen(["/usr/bin/tail", "-n0", "-f", f"{r1.rundir}/mgmtd.log"])
        p2 = r1.popen(
            [
                BE_CLIENT,
                "--log=file:/dev/stderr",
                "--notify-count=0",
                "--datastore",
                "--listen",
                "/frr-interface:lib/interface",
            ]
        )
        assert waitline(mlogp.stdout, 'now known as "mgmtd-testc"', timeout=30)
        selectors = [
            "/frr-interface:lib/interface",
            "/frr-interface:lib/interface/state",
        ]
        check_filters(r1, selectors)

        step("Kill BE client and verify only FE notify selector present in zebra")
        p2.kill()
        p2 = None
        check_filters(r1, ["/frr-interface:lib/interface/state"])

        step("Kill FE client and verify no notify selectors present in zebra")
        p.kill()
        p = None
        check_filters(r1, [])
    except Exception as error:
        logging.error("got exception: %s", error)
        raise
    finally:
        if p2:
            p2.kill()
        if p:
            p.kill()
