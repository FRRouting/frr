#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#

"""
test_ospf_clientapi.py: Test the OSPF client API.
"""

import logging
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta

import pytest

from lib.common_config import retry, run_frr_cmd, step
from lib.micronet import comm_error
from lib.topogen import Topogen, TopoRouter
from lib.topotest import interface_set_status, json_cmp

pytestmark = [pytest.mark.ospfd]

CWD = os.path.dirname(os.path.realpath(__file__))
TESTDIR = os.path.abspath(CWD)

CLIENTDIR = os.path.abspath(os.path.join(CWD, "../../../ospfclient"))
if not os.path.exists(CLIENTDIR):
    CLIENTDIR = os.path.join(CWD, "/usr/lib/frr")

assert os.path.exists(
    os.path.join(CLIENTDIR, "ospfclient.py")
), "can't locate ospfclient.py"


# ----------
# Test Setup
# ----------


@pytest.fixture(scope="function", name="tgen")
def _tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"
    nrouters = request.param
    topodef = {f"sw{i}": (f"r{i}", f"r{i+1}") for i in range(1, nrouters)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_OSPF, "ospfd.conf")
        router.net.daemons_options["ospfd"] = "--apiserver"

    tgen.start_router()

    yield tgen

    tgen.stop_topology()


# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


# ------------
# Test Utility
# ------------


@retry(retry_timeout=45)
def verify_ospf_database(tgen, dut, input_dict, cmd="show ip ospf database json"):
    del tgen
    show_ospf_json = run_frr_cmd(dut, cmd, isjson=True)
    if not bool(show_ospf_json):
        return "ospf is not running"
    result = json_cmp(show_ospf_json, input_dict)
    return str(result) if result else None


def myreadline(f):
    buf = b""
    while True:
        # logging.info("READING 1 CHAR")
        c = f.read(1)
        if not c:
            return buf if buf else None
        buf += c
        # logging.info("READ CHAR: '%s'", c)
        if c == b"\n":
            return buf


def _wait_output(p, regex, timeout=120):
    retry_until = datetime.now() + timedelta(seconds=timeout)
    while datetime.now() < retry_until:
        # line = p.stdout.readline()
        line = myreadline(p.stdout)
        if not line:
            assert None, "Timeout waiting for '{}'".format(regex)
        line = line.decode("utf-8")
        line = line.rstrip()
        if line:
            logging.debug("GOT LINE: '%s'", line)
        m = re.search(regex, line)
        if m:
            return m
    assert None, "Failed to get output withint {}s".format(timeout)


# -----
# Tests
# -----


def _test_reachability(tgen, testbin):
    waitlist = [
        "192.168.0.1,192.168.0.2,192.168.0.4",
        "192.168.0.2,192.168.0.4",
        "192.168.0.1,192.168.0.2,192.168.0.4",
    ]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    wait_args = [f"--wait={x}" for x in waitlist]

    p = None
    try:
        step("reachable: check for initial reachability")
        p = r3.popen(
            ["/usr/bin/timeout", "120", testbin, "-v", *wait_args],
            encoding=None,  # don't buffer
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        _wait_output(p, "SUCCESS: {}".format(waitlist[0]))

        step("reachable: check for modified reachability")
        interface_set_status(r2, "r2-eth0", False)
        _wait_output(p, "SUCCESS: {}".format(waitlist[1]))

        step("reachable: check for restored reachability")
        interface_set_status(r2, "r2-eth0", True)
        _wait_output(p, "SUCCESS: {}".format(waitlist[2]))
    except Exception as error:
        logging.error("ERROR: %s", error)
        raise
    finally:
        if p:
            p.terminate()
            p.wait()


@pytest.mark.parametrize("tgen", [4], indirect=True)
def test_ospf_reachability(tgen):
    testbin = os.path.join(TESTDIR, "ctester.py")
    rc, o, e = tgen.gears["r2"].net.cmd_status([testbin, "--help"])
    logging.info("%s --help: rc: %s stdout: '%s' stderr: '%s'", testbin, rc, o, e)
    _test_reachability(tgen, testbin)


def _test_add_data(tgen, apibin):
    "Test adding opaque data to domain"

    r1 = tgen.gears["r1"]

    step("add opaque: add opaque link local")

    p = None
    try:
        p = r1.popen([apibin, "-v", "add,9,10.0.1.1,230,2,00000202"])
        input_dict = {
            "routerId": "192.168.0.1",
            "areas": {
                "1.2.3.4": {
                    "linkLocalOpaqueLsa": [
                        {
                            "lsId": "230.0.0.2",
                            "advertisedRouter": "192.168.0.1",
                            "sequenceNumber": "80000001",
                        }
                    ],
                }
            },
        }
        # Wait for it to show up
        assert verify_ospf_database(tgen, r1, input_dict) is None

        input_dict = {
            "linkLocalOpaqueLsa": {
                "areas": {
                    "1.2.3.4": [
                        {
                            "linkStateId": "230.0.0.2",
                            "advertisingRouter": "192.168.0.1",
                            "lsaSeqNumber": "80000001",
                            "opaqueData": "00000202",
                        },
                    ],
                }
            },
        }
        # verify content
        json_cmd = "show ip ospf da opaque-link json"
        assert verify_ospf_database(tgen, r1, input_dict, json_cmd) is None

        step("reset client, add opaque area, verify link local flushing")

        p.send_signal(signal.SIGINT)
        time.sleep(2)
        p.wait()
        p = None
        p = r1.popen([apibin, "-v", "add,10,1.2.3.4,231,1,00010101"])
        input_dict = {
            "routerId": "192.168.0.1",
            "areas": {
                "1.2.3.4": {
                    "linkLocalOpaqueLsa": [
                        {
                            "lsId": "230.0.0.2",
                            "advertisedRouter": "192.168.0.1",
                            "sequenceNumber": "80000001",
                            "lsaAge": 3600,
                        }
                    ],
                    "areaLocalOpaqueLsa": [
                        {
                            "lsId": "231.0.0.1",
                            "advertisedRouter": "192.168.0.1",
                            "sequenceNumber": "80000001",
                        },
                    ],
                }
            },
        }
        # Wait for it to show up
        assert verify_ospf_database(tgen, r1, input_dict) is None

        input_dict = {
            "areaLocalOpaqueLsa": {
                "areas": {
                    "1.2.3.4": [
                        {
                            "linkStateId": "231.0.0.1",
                            "advertisingRouter": "192.168.0.1",
                            "lsaSeqNumber": "80000001",
                            "opaqueData": "00010101",
                        },
                    ],
                }
            },
        }
        # verify content
        json_cmd = "show ip ospf da opaque-area json"
        assert verify_ospf_database(tgen, r1, input_dict, json_cmd) is None

        step("reset client, add opaque AS, verify area flushing")

        p.send_signal(signal.SIGINT)
        time.sleep(2)
        p.wait()
        p = None

        p = r1.popen([apibin, "-v", "add,11,232,3,deadbeaf01234567"])
        input_dict = {
            "routerId": "192.168.0.1",
            "areas": {
                "1.2.3.4": {
                    "areaLocalOpaqueLsa": [
                        {
                            "lsId": "231.0.0.1",
                            "advertisedRouter": "192.168.0.1",
                            "sequenceNumber": "80000001",
                            "lsaAge": 3600,
                        },
                    ],
                }
            },
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.3",
                    "advertisedRouter": "192.168.0.1",
                    "sequenceNumber": "80000001",
                },
            ],
        }
        # Wait for it to show up
        assert verify_ospf_database(tgen, r1, input_dict) is None

        input_dict = {
            "asExternalOpaqueLsa": [
                {
                    "linkStateId": "232.0.0.3",
                    "advertisingRouter": "192.168.0.1",
                    "lsaSeqNumber": "80000001",
                    "opaqueData": "deadbeaf01234567",
                },
            ]
        }
        # verify content
        json_cmd = "show ip ospf da opaque-as json"
        assert verify_ospf_database(tgen, r1, input_dict, json_cmd) is None

        step("stop client, verify AS flushing")

        p.send_signal(signal.SIGINT)
        time.sleep(2)
        p.wait()
        p = None

        input_dict = {
            "routerId": "192.168.0.1",
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.3",
                    "advertisedRouter": "192.168.0.1",
                    "sequenceNumber": "80000001",
                    "lsaAge": 3600,
                },
            ],
        }
        # Wait for it to be flushed
        assert verify_ospf_database(tgen, r1, input_dict) is None

        step("start client adding opaque domain, verify new sequence number and data")

        # Originate it again
        p = r1.popen([apibin, "-v", "add,11,232,3,ebadf00d"])
        input_dict = {
            "routerId": "192.168.0.1",
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.3",
                    "advertisedRouter": "192.168.0.1",
                    "sequenceNumber": "80000002",
                },
            ],
        }
        assert verify_ospf_database(tgen, r1, input_dict) is None

        input_dict = {
            "asExternalOpaqueLsa": [
                {
                    "linkStateId": "232.0.0.3",
                    "advertisingRouter": "192.168.0.1",
                    "lsaSeqNumber": "80000002",
                    "opaqueData": "ebadf00d",
                },
            ]
        }
        # verify content
        json_cmd = "show ip ospf da opaque-as json"
        assert verify_ospf_database(tgen, r1, input_dict, json_cmd) is None

        p.send_signal(signal.SIGINT)
        time.sleep(2)
        p.wait()
        p = None

    except Exception:
        if p:
            p.terminate()
            if p.wait():
                comm_error(p)
            p = None
        raise
    finally:
        if p:
            p.terminate()
            p.wait()


@pytest.mark.parametrize("tgen", [2], indirect=True)
def test_ospf_opaque_add_data3(tgen):
    apibin = os.path.join(CLIENTDIR, "ospfclient.py")
    rc, o, e = tgen.gears["r2"].net.cmd_status([apibin, "--help"])
    logging.info("%s --help: rc: %s stdout: '%s' stderr: '%s'", apibin, rc, o, e)
    _test_add_data(tgen, apibin)


def _test_opaque_add_del(tgen, apibin):
    "Test adding opaque data to domain"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    p = None
    pread = None
    try:
        step("reachable: check for add notification")
        pread = r2.popen(
            ["/usr/bin/timeout", "120", apibin, "-v"],
            encoding=None,  # don't buffer
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        p = r1.popen([apibin, "-v", "add,11,232,3,ebadf00d"])

        # Wait for add notification
        # RECV: LSA update msg for LSA 232.0.0.3 in area 0.0.0.0 seq 0x80000001 len 24 age 9

        ls_id = "232.0.0.3"
        waitfor = "RECV:.*update msg.*LSA {}.*age ([0-9]+)".format(ls_id)
        _ = _wait_output(pread, waitfor)

        p.terminate()
        if p.wait():
            comm_error(p)

        # step("reachable: check for flush/age out")
        # # Wait for max age notification
        # waitfor = "RECV:.*update msg.*LSA {}.*age 3600".format(ls_id)
        # _wait_output(pread, waitfor)

        step("reachable: check for delete")
        # Wait for delete notification
        waitfor = "RECV:.*delete msg.*LSA {}.*".format(ls_id)
        _wait_output(pread, waitfor)
    except Exception:
        if p:
            p.terminate()
            if p.wait():
                comm_error(p)
            p = None
        raise
    finally:
        if pread:
            pread.terminate()
            pread.wait()
        if p:
            p.terminate()
            p.wait()


@pytest.mark.parametrize("tgen", [2], indirect=True)
def test_ospf_opaque_delete_data3(tgen):
    apibin = os.path.join(CLIENTDIR, "ospfclient.py")
    rc, o, e = tgen.gears["r2"].net.cmd_status([apibin, "--help"])
    logging.info("%s --help: rc: %s stdout: '%s' stderr: '%s'", apibin, rc, o, e)
    _test_opaque_add_del(tgen, apibin)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
