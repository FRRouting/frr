#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2021-2022, LabN Consulting, L.L.C.
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

from lib.common_config import (
    retry,
    run_frr_cmd,
    step,
    kill_router_daemons,
    start_router_daemons,
    shutdown_bringup_interface,
)

from lib.micronet import Timeout, comm_error
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

#
#  r1 - r2
#  |    |
#  r4 - r3
#


@pytest.fixture(scope="function", name="tgen")
def _tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"
    nrouters = request.param
    topodef = {f"sw{i}": (f"r{i}", f"r{i+1}") for i in range(1, nrouters)}
    if nrouters == 4:
        topodef["sw4"] = ("r4", "r1")

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
        # logging.debug("READING 1 CHAR")
        c = f.read(1)
        if not c:
            return buf if buf else None
        buf += c
        # logging.debug("READ CHAR: '%s'", c)
        if c == b"\n":
            return buf


def _wait_output(p, regex, maxwait=120):
    timeout = Timeout(maxwait)
    while not timeout.is_expired():
        # line = p.stdout.readline()
        line = myreadline(p.stdout)
        if not line:
            assert None, "EOF waiting for '{}'".format(regex)
        line = line.decode("utf-8")
        line = line.rstrip()
        if line:
            logging.debug("GOT LINE: '%s'", line)
        m = re.search(regex, line)
        if m:
            return m
    assert None, "Failed to get output matching '{}' withint {} actual {}s".format(
        regex, maxwait, timeout.elapsed()
    )


# -----
# Tests
# -----


def _test_reachability(tgen, testbin):
    waitlist = [
        "1.0.0.0,2.0.0.0,4.0.0.0",
        "2.0.0.0,4.0.0.0",
        "1.0.0.0,2.0.0.0,4.0.0.0",
    ]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

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
        interface_set_status(r4, "r4-eth1", False)
        _wait_output(p, "SUCCESS: {}".format(waitlist[1]))

        step("reachable: check for restored reachability")
        interface_set_status(r2, "r2-eth0", True)
        interface_set_status(r4, "r4-eth1", True)
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
    logging.debug("%s --help: rc: %s stdout: '%s' stderr: '%s'", testbin, rc, o, e)
    _test_reachability(tgen, testbin)


def _test_router_id(tgen, testbin):
    r1 = tgen.gears["r1"]
    waitlist = [
        "1.0.0.0",
        "1.1.1.1",
        "1.0.0.0",
    ]

    mon_args = [f"--monitor={x}" for x in waitlist]

    p = None
    try:
        step("router id: check for initial router id")
        p = r1.popen(
            ["/usr/bin/timeout", "120", testbin, "-v", *mon_args],
            encoding=None,  # don't buffer
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        _wait_output(p, "SUCCESS: {}".format(waitlist[0]))

        step("router id: check for modified router id")
        r1.vtysh_multicmd("conf t\nrouter ospf\nospf router-id 1.1.1.1")
        _wait_output(p, "SUCCESS: {}".format(waitlist[1]))

        step("router id: check for restored router id")
        r1.vtysh_multicmd("conf t\nrouter ospf\nospf router-id 1.0.0.0")
        _wait_output(p, "SUCCESS: {}".format(waitlist[2]))
    except Exception as error:
        logging.error("ERROR: %s", error)
        raise
    finally:
        if p:
            p.terminate()
            p.wait()


@pytest.mark.parametrize("tgen", [2], indirect=True)
def test_ospf_router_id(tgen):
    testbin = os.path.join(TESTDIR, "ctester.py")
    rc, o, e = tgen.gears["r1"].net.cmd_status([testbin, "--help"])
    logging.debug("%s --help: rc: %s stdout: '%s' stderr: '%s'", testbin, rc, o, e)
    _test_router_id(tgen, testbin)


def _test_add_data(tgen, apibin):
    "Test adding opaque data to domain"

    r1 = tgen.gears["r1"]

    step("add opaque: add opaque link local")

    p = None
    try:
        p = r1.popen([apibin, "-v", "add,9,10.0.1.1,230,2,00000202"])
        input_dict = {
            "routerId": "1.0.0.0",
            "areas": {
                "1.2.3.4": {
                    "linkLocalOpaqueLsa": [
                        {
                            "lsId": "230.0.0.2",
                            "advertisedRouter": "1.0.0.0",
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
                            "advertisingRouter": "1.0.0.0",
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
            "routerId": "1.0.0.0",
            "areas": {
                "1.2.3.4": {
                    "linkLocalOpaqueLsa": [
                        {
                            "lsId": "230.0.0.2",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "lsaAge": 3600,
                        }
                    ],
                    "areaLocalOpaqueLsa": [
                        {
                            "lsId": "231.0.0.1",
                            "advertisedRouter": "1.0.0.0",
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
                            "advertisingRouter": "1.0.0.0",
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
            "routerId": "1.0.0.0",
            "areas": {
                "1.2.3.4": {
                    "areaLocalOpaqueLsa": [
                        {
                            "lsId": "231.0.0.1",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "lsaAge": 3600,
                        },
                    ],
                }
            },
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.3",
                    "advertisedRouter": "1.0.0.0",
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
                    "advertisingRouter": "1.0.0.0",
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
            "routerId": "1.0.0.0",
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.3",
                    "advertisedRouter": "1.0.0.0",
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
            "routerId": "1.0.0.0",
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.3",
                    "advertisedRouter": "1.0.0.0",
                    "sequenceNumber": "80000002",
                },
            ],
        }
        assert verify_ospf_database(tgen, r1, input_dict) is None

        input_dict = {
            "asExternalOpaqueLsa": [
                {
                    "linkStateId": "232.0.0.3",
                    "advertisingRouter": "1.0.0.0",
                    "lsaSeqNumber": "80000002",
                    "opaqueData": "ebadf00d",
                },
            ]
        }
        # verify content
        json_cmd = "show ip ospf da opaque-as json"
        assert verify_ospf_database(tgen, r1, input_dict, json_cmd) is None

        logging.debug("sending interrupt to writer api client")
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
            logging.debug("cleanup: sending interrupt to writer api client")
            p.terminate()
            p.wait()


@pytest.mark.parametrize("tgen", [2], indirect=True)
def test_ospf_opaque_add_data3(tgen):
    apibin = os.path.join(CLIENTDIR, "ospfclient.py")
    rc, o, e = tgen.gears["r2"].net.cmd_status([apibin, "--help"])
    logging.debug("%s --help: rc: %s stdout: '%s' stderr: '%s'", apibin, rc, o, e)
    _test_add_data(tgen, apibin)


def _test_opaque_add_del(tgen, apibin):
    "Test adding opaque data to domain"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    p = None
    pread = None
    # Log to our stdin, stderr
    pout = open(os.path.join(r1.net.logdir, "r1/add-del.log"), "a+")
    try:
        step("reachable: check for add notification")
        pread = r2.popen(
            ["/usr/bin/timeout", "120", apibin, "-v", "--logtag=READER", "wait,120"],
            encoding=None,  # don't buffer
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        p = r1.popen(
            [
                apibin,
                "-v",
                "add,9,10.0.1.1,230,1",
                "add,9,10.0.1.1,230,2,00000202",
                "wait,1",
                "add,10,1.2.3.4,231,1",
                "add,10,1.2.3.4,231,2,0102030405060708",
                "wait,1",
                "add,11,232,1",
                "add,11,232,2,ebadf00d",
                "wait,20",
                "del,9,10.0.1.1,230,2,0",
                "del,10,1.2.3.4,231,2,1",
                "del,11,232,1,1",
            ]
        )
        add_input_dict = {
            "areas": {
                "1.2.3.4": {
                    "linkLocalOpaqueLsa": [
                        {
                            "lsId": "230.0.0.1",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "checksum": "76bf",
                        },
                        {
                            "lsId": "230.0.0.2",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "checksum": "8aa2",
                        },
                    ],
                    "linkLocalOpaqueLsaCount": 2,
                    "areaLocalOpaqueLsa": [
                        {
                            "lsId": "231.0.0.1",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "checksum": "5bd8",
                        },
                        {
                            "lsId": "231.0.0.2",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "checksum": "7690",
                        },
                    ],
                    "areaLocalOpaqueLsaCount": 2,
                },
            },
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.1",
                    "advertisedRouter": "1.0.0.0",
                    "sequenceNumber": "80000001",
                    "checksum": "5ed5",
                },
                {
                    "lsId": "232.0.0.2",
                    "advertisedRouter": "1.0.0.0",
                    "sequenceNumber": "80000001",
                    "checksum": "d9bd",
                },
            ],
            "asExternalOpaqueLsaCount": 2,
        }

        step("reachable: check for add LSAs")
        json_cmd = "show ip ospf da json"
        assert verify_ospf_database(tgen, r1, add_input_dict, json_cmd) is None
        assert verify_ospf_database(tgen, r2, add_input_dict, json_cmd) is None

        numcs = 3
        json_cmds = [
            "show ip ospf da opaque-link json",
            "show ip ospf da opaque-area json",
            "show ip ospf da opaque-as json",
        ]
        add_detail_input_dict = [
            {
                "linkLocalOpaqueLsa": {
                    "areas": {
                        "1.2.3.4": [
                            {
                                "linkStateId": "230.0.0.1",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000001",
                                "checksum": "76bf",
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                            {
                                "linkStateId": "230.0.0.2",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000001",
                                "checksum": "8aa2",
                                "length": 24,
                                "opaqueId": 2,
                                "opaqueDataLength": 4,
                            },
                        ]
                    }
                }
            },
            {
                "areaLocalOpaqueLsa": {
                    "areas": {
                        "1.2.3.4": [
                            {
                                "linkStateId": "231.0.0.1",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000001",
                                "checksum": "5bd8",
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                            {
                                "linkStateId": "231.0.0.2",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000001",
                                "checksum": "7690",
                                "length": 28,
                                "opaqueDataLength": 8,
                            },
                        ],
                    },
                },
            },
            {
                "asExternalOpaqueLsa": [
                    {
                        "linkStateId": "232.0.0.1",
                        "advertisingRouter": "1.0.0.0",
                        "lsaSeqNumber": "80000001",
                        "checksum": "5ed5",
                        "length": 20,
                        "opaqueDataLength": 0,
                    },
                    {
                        "linkStateId": "232.0.0.2",
                        "advertisingRouter": "1.0.0.0",
                        "lsaSeqNumber": "80000001",
                        "checksum": "d9bd",
                        "length": 24,
                        "opaqueDataLength": 4,
                    },
                ],
            },
        ]
        i = 0
        while i < numcs:
            step("reachable: check for add LSA details: %s" % json_cmds[i])
            assert (
                verify_ospf_database(tgen, r1, add_detail_input_dict[i], json_cmds[i])
                is None
            )
            assert (
                verify_ospf_database(tgen, r2, add_detail_input_dict[i], json_cmds[i])
                is None
            )
            i += 1

        # Wait for add notification
        # RECV: LSA update msg for LSA 232.0.0.3 in area 0.0.0.0 seq 0x80000001 len 24 age 9

        ls_ids = [
            "230.0.0.1",
            "230.0.0.2",
            "231.0.0.1",
            "231.0.0.2",
            "232.0.0.1",
            "232.0.0.2",
        ]
        for ls_id in ls_ids:
            step("reachable: check for API add notification: %s" % ls_id)
            waitfor = "RECV:.*update msg.*LSA {}.*age ([0-9]+)".format(ls_id)
            _ = _wait_output(pread, waitfor)

        del_input_dict = {
            "areas": {
                "1.2.3.4": {
                    "linkLocalOpaqueLsa": [
                        {
                            "lsId": "230.0.0.1",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "checksum": "76bf",
                        },
                        {
                            "lsId": "230.0.0.2",
                            "advertisedRouter": "1.0.0.0",
                            "lsaAge": 3600,
                            "sequenceNumber": "80000001",
                            "checksum": "8aa2",
                        },
                    ],
                    "linkLocalOpaqueLsaCount": 2,
                    "areaLocalOpaqueLsa": [
                        {
                            "lsId": "231.0.0.1",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000001",
                            "checksum": "5bd8",
                        },
                        {
                            "lsId": "231.0.0.2",
                            "advertisedRouter": "1.0.0.0",
                            "lsaAge": 3600,
                            "sequenceNumber": "80000002",
                            "checksum": "4fe2",
                        },
                    ],
                    "areaLocalOpaqueLsaCount": 2,
                },
            },
            "asExternalOpaqueLsa": [
                {
                    "lsId": "232.0.0.1",
                    "advertisedRouter": "1.0.0.0",
                    "lsaAge": 3600,
                    "sequenceNumber": "80000001",
                    "checksum": "5ed5",
                },
                {
                    "lsId": "232.0.0.2",
                    "advertisedRouter": "1.0.0.0",
                    "sequenceNumber": "80000001",
                    "checksum": "d9bd",
                },
            ],
            "asExternalOpaqueLsaCount": 2,
        }

        step("reachable: check for explicit withdrawal LSAs")
        json_cmd = "show ip ospf da json"
        assert verify_ospf_database(tgen, r1, del_input_dict, json_cmd) is None
        assert verify_ospf_database(tgen, r2, del_input_dict, json_cmd) is None

        del_detail_input_dict = [
            {
                "linkLocalOpaqueLsa": {
                    "areas": {
                        "1.2.3.4": [
                            {
                                "linkStateId": "230.0.0.1",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000001",
                                "checksum": "76bf",
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                            {
                                "linkStateId": "230.0.0.2",
                                "advertisingRouter": "1.0.0.0",
                                "lsaAge": 3600,
                                "lsaSeqNumber": "80000001",
                                "checksum": "8aa2",
                                "length": 24,
                                "opaqueId": 2,
                                "opaqueDataLength": 4,
                            },
                        ]
                    }
                }
            },
            {
                "areaLocalOpaqueLsa": {
                    "areas": {
                        "1.2.3.4": [
                            {
                                "linkStateId": "231.0.0.1",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000001",
                                "checksum": "5bd8",
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                            {
                                "lsaAge": 3600,
                                "linkStateId": "231.0.0.2",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000002",
                                "checksum": "4fe2",
                                # data removed
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                        ],
                    },
                },
            },
            {
                "asExternalOpaqueLsa": [
                    {
                        "linkStateId": "232.0.0.1",
                        "advertisingRouter": "1.0.0.0",
                        "lsaAge": 3600,
                        "lsaSeqNumber": "80000001",
                        "checksum": "5ed5",
                        "length": 20,
                        "opaqueDataLength": 0,
                    },
                    {
                        "linkStateId": "232.0.0.2",
                        "advertisingRouter": "1.0.0.0",
                        "lsaSeqNumber": "80000001",
                        "checksum": "d9bd",
                        "length": 24,
                        "opaqueDataLength": 4,
                    },
                ],
            },
        ]
        i = 0
        while i < numcs:
            step("reachable: check for delete LSA details: %s" % json_cmds[i])
            assert (
                verify_ospf_database(tgen, r1, del_detail_input_dict[i], json_cmds[i])
                is None
            )
            assert (
                verify_ospf_database(tgen, r2, del_detail_input_dict[i], json_cmds[i])
                is None
            )
            i += 1

        p.terminate()
        if p.wait():
            comm_error(p)

        del_detail_input_dict = [
            {
                "linkLocalOpaqueLsa": {
                    "areas": {
                        "1.2.3.4": [
                            {
                                "linkStateId": "230.0.0.1",
                                "advertisingRouter": "1.0.0.0",
                                "lsaAge": 3600,
                                "lsaSeqNumber": "80000001",
                                "checksum": "76bf",
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                            {
                                "linkStateId": "230.0.0.2",
                                "advertisingRouter": "1.0.0.0",
                                "lsaAge": 3600,
                                "lsaSeqNumber": "80000001",
                                "checksum": "8aa2",
                                "length": 24,
                                "opaqueId": 2,
                                "opaqueDataLength": 4,
                            },
                        ]
                    }
                }
            },
            {
                "areaLocalOpaqueLsa": {
                    "areas": {
                        "1.2.3.4": [
                            {
                                "lsaAge": 3600,
                                "linkStateId": "231.0.0.1",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000001",
                                "checksum": "5bd8",
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                            {
                                "lsaAge": 3600,
                                "linkStateId": "231.0.0.2",
                                "advertisingRouter": "1.0.0.0",
                                "lsaSeqNumber": "80000002",
                                "checksum": "4fe2",
                                # data removed
                                "length": 20,
                                "opaqueDataLength": 0,
                            },
                        ],
                    },
                },
            },
            {
                "asExternalOpaqueLsa": [
                    {
                        "linkStateId": "232.0.0.1",
                        "advertisingRouter": "1.0.0.0",
                        "lsaAge": 3600,
                        "lsaSeqNumber": "80000001",
                        "checksum": "5ed5",
                        "length": 20,
                        "opaqueDataLength": 0,
                    },
                    {
                        "linkStateId": "232.0.0.2",
                        "advertisingRouter": "1.0.0.0",
                        "lsaAge": 3600,
                        "lsaSeqNumber": "80000001",
                        "checksum": "d9bd",
                        "length": 24,
                        "opaqueDataLength": 4,
                    },
                ],
            },
        ]
        i = 0
        while i < numcs:
            step(
                "reachable: check for post API shutdown delete LSA details: %s"
                % json_cmds[i]
            )
            assert (
                verify_ospf_database(tgen, r1, del_detail_input_dict[i], json_cmds[i])
                is None
            )
            assert (
                verify_ospf_database(tgen, r2, del_detail_input_dict[i], json_cmds[i])
                is None
            )
            i += 1

        # step("reachable: check for flush/age out")
        # # Wait for max age notification
        # waitfor = "RECV:.*update msg.*LSA {}.*age 3600".format(ls_id)
        # _wait_output(pread, waitfor)
        ls_ids = [
            "230.0.0.2",
            "231.0.0.2",
            "232.0.0.1",
            "230.0.0.1",
            "231.0.0.1",
            "232.0.0.2",
        ]
        for ls_id in ls_ids:
            step("reachable: check for API delete notification: %s" % ls_id)
            waitfor = "RECV:.*delete msg.*LSA {}.*age".format(ls_id)
            _ = _wait_output(pread, waitfor)
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
    logging.debug("%s --help: rc: %s stdout: '%s' stderr: '%s'", apibin, rc, o, e)
    _test_opaque_add_del(tgen, apibin)


def _test_opaque_add_restart_add(tgen, apibin):
    "Test adding an opaque LSA and then restarting ospfd"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    p = None
    pread = None
    # Log to our stdin, stderr
    pout = open(os.path.join(r1.net.logdir, "r1/add-del.log"), "a+")
    try:
        step("reachable: check for add notification")
        pread = r2.popen(
            ["/usr/bin/timeout", "120", apibin, "-v", "--logtag=READER", "wait,120"],
            encoding=None,  # don't buffer
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        p = r1.popen(
            [
                apibin,
                "-v",
                "add,10,1.2.3.4,231,1",
                "add,10,1.2.3.4,231,1,feedaceebeef",
                "wait, 5",
                "add,10,1.2.3.4,231,1,feedaceedeadbeef",
                "wait, 5",
                "add,10,1.2.3.4,231,1,feedaceebaddbeef",
                "wait, 5",
            ]
        )
        add_input_dict = {
            "areas": {
                "1.2.3.4": {
                    "areaLocalOpaqueLsa": [
                        {
                            "lsId": "231.0.0.1",
                            "advertisedRouter": "1.0.0.0",
                            "sequenceNumber": "80000004",
                            "checksum": "3128",
                        },
                    ],
                    "areaLocalOpaqueLsaCount": 1,
                },
            },
        }
        step("Check for add LSAs")
        json_cmd = "show ip ospf da json"
        assert verify_ospf_database(tgen, r1, add_input_dict, json_cmd) is None
        assert verify_ospf_database(tgen, r2, add_input_dict, json_cmd) is None

        step("Shutdown the interface on r1 to isolate it for r2")
        shutdown_bringup_interface(tgen, "r1", "r1-eth0", False)

        time.sleep(2)
        step("Reset the client")
        p.send_signal(signal.SIGINT)
        time.sleep(2)
        p.wait()
        p = None

        step("Kill ospfd on R1")
        kill_router_daemons(tgen, "r1", ["ospfd"])
        time.sleep(2)

        step("Bring ospfd on R1 back up")
        start_router_daemons(tgen, "r1", ["ospfd"])

        p = r1.popen(
            [
                apibin,
                "-v",
                "add,10,1.2.3.4,231,1",
                "add,10,1.2.3.4,231,1,feedaceecafebeef",
                "wait, 5",
            ]
        )

        step("Bring the interface on r1 back up for connection to r2")
        shutdown_bringup_interface(tgen, "r1", "r1-eth0", True)

        step("Verify area opaque LSA refresh")
        json_cmd = "show ip ospf da opaque-area json"
        add_detail_input_dict = {
            "areaLocalOpaqueLsa": {
                "areas": {
                    "1.2.3.4": [
                        {
                            "linkStateId": "231.0.0.1",
                            "advertisingRouter": "1.0.0.0",
                            "lsaSeqNumber": "80000005",
                            "checksum": "a87e",
                            "length": 28,
                            "opaqueDataLength": 8,
                        },
                    ],
                },
            },
        }
        assert verify_ospf_database(tgen, r1, add_detail_input_dict, json_cmd) is None
        assert verify_ospf_database(tgen, r2, add_detail_input_dict, json_cmd) is None

        step("Shutdown the interface on r1 to isolate it for r2")
        shutdown_bringup_interface(tgen, "r1", "r1-eth0", False)

        time.sleep(2)
        step("Reset the client")
        p.send_signal(signal.SIGINT)
        time.sleep(2)
        p.wait()
        p = None

        step("Kill ospfd on R1")
        kill_router_daemons(tgen, "r1", ["ospfd"])
        time.sleep(2)

        step("Bring ospfd on R1 back up")
        start_router_daemons(tgen, "r1", ["ospfd"])

        step("Bring the interface on r1 back up for connection to r2")
        shutdown_bringup_interface(tgen, "r1", "r1-eth0", True)

        step("Verify area opaque LSA Purging")
        json_cmd = "show ip ospf da opaque-area json"
        add_detail_input_dict = {
            "areaLocalOpaqueLsa": {
                "areas": {
                    "1.2.3.4": [
                        {
                            "lsaAge": 3600,
                            "linkStateId": "231.0.0.1",
                            "advertisingRouter": "1.0.0.0",
                            "lsaSeqNumber": "80000005",
                            "checksum": "a87e",
                            "length": 28,
                            "opaqueDataLength": 8,
                        },
                    ],
                },
            },
        }
        assert verify_ospf_database(tgen, r1, add_detail_input_dict, json_cmd) is None
        assert verify_ospf_database(tgen, r2, add_detail_input_dict, json_cmd) is None
        step("Verify Area Opaque LSA removal after timeout (60 seconds)")
        time.sleep(60)
        json_cmd = "show ip ospf da opaque-area json"
        timeout_detail_input_dict = {
            "areaLocalOpaqueLsa": {
                "areas": {
                    "1.2.3.4": [],
                },
            },
        }
        assert (
            verify_ospf_database(tgen, r1, timeout_detail_input_dict, json_cmd) is None
        )
        assert (
            verify_ospf_database(tgen, r2, timeout_detail_input_dict, json_cmd) is None
        )

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
def test_ospf_opaque_restart(tgen):
    apibin = os.path.join(CLIENTDIR, "ospfclient.py")
    rc, o, e = tgen.gears["r2"].net.cmd_status([apibin, "--help"])
    logging.debug("%s --help: rc: %s stdout: '%s' stderr: '%s'", apibin, rc, o, e)
    _test_opaque_add_restart_add(tgen, apibin)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
