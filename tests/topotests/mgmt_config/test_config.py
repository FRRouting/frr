# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# June 10 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"""
Test mgmtd parsing of configs.

So:

MGMTD matches zebra:

one exit file:    ONE: vty -f file
one exit redir:   ONE: vty < file
early exit file:  ONE: vty -f file
early exit redir: ONE: vty < file
early end file:   ALL: vty -f file
early end redir:  ONE: vty < file

Raw tests:

FAILED mgmt_config/test_config.py::test_mgmtd_one_exit_file - AssertionError: vtysh < didn't work after exit
FAILED mgmt_config/test_config.py::test_mgmtd_one_exit_redir - AssertionError: vtysh < didn't work after exit
FAILED mgmt_config/test_config.py::test_mgmtd_early_exit_file - AssertionError: vtysh -f didn't work after 1 exit
FAILED mgmt_config/test_config.py::test_mgmtd_early_exit_redir - AssertionError: vtysh < didn't work after 1 exits
FAILED mgmt_config/test_config.py::test_mgmtd_early_end_redir - AssertionError: vtysh < didn't work after 1 end

FAILED mgmt_config/test_config.py::test_zebra_one_exit_file - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_one_exit_redir - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_early_exit_file - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_early_exit_redir - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_early_end_redir - AssertionError: zebra second conf missing

Before fixed:

one exit file:    NONE: vty -f file
early exit file:  NONE: vty -f file

FAILED mgmt_config/test_config.py::test_mgmtd_one_exit_file - AssertionError: vtysh -f didn't work before exit
FAILED mgmt_config/test_config.py::test_mgmtd_one_exit_redir - AssertionError: vtysh < didn't work after exit
FAILED mgmt_config/test_config.py::test_mgmtd_early_exit_file - AssertionError: vtysh -f didn't work before exit
FAILED mgmt_config/test_config.py::test_mgmtd_early_exit_redir - AssertionError: vtysh < didn't work after 1 exits
FAILED mgmt_config/test_config.py::test_mgmtd_early_end_redir - AssertionError: vtysh < didn't work after 1 end

FAILED mgmt_config/test_config.py::test_zebra_one_exit_file - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_one_exit_redir - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_early_exit_file - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_early_exit_redir - AssertionError: zebra second conf missing
FAILED mgmt_config/test_config.py::test_zebra_early_end_redir - AssertionError: zebra second conf missing

"""
import ipaddress
import logging
import os
import re
from pathlib import Path

import pytest
from lib.common_config import retry, step
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@retry(retry_timeout=1, initial_wait=0.1)
def check_kernel(r1, prefix, expected=True):
    net = ipaddress.ip_network(prefix)
    if net.version == 6:
        kernel = r1.cmd_nostatus("ip -6 route show", warn=not expected)
    else:
        kernel = r1.cmd_nostatus("ip -4 route show", warn=not expected)

    logging.debug("checking kernel routing table:\n%0.1920s", kernel)
    route = f"{str(net)}(?: nhid [0-9]+)?.*proto (static|196)"
    m = re.search(route, kernel)
    if expected and not m:
        return f"Failed to find \n'{route}'\n in \n'{kernel:.1920}'"
    elif not expected and m:
        return f"Failed found \n'{route}'\n in \n'{kernel:.1920}'"
    return None


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    # configure mgmtd using current mgmtd config file
    tgen.gears["r1"].load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    tgen.gears["r1"].load_config(TopoRouter.RD_MGMTD)

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def save_log_snippet(logfile, content, savepath=None):
    os.sync()
    os.sync()
    os.sync()

    with open(logfile, encoding="utf-8") as f:
        buf = f.read()
    assert content == buf[: len(content)]
    newcontent = buf[len(content) :]

    if savepath:
        with open(savepath, "w", encoding="utf-8") as f:
            f.write(newcontent)

    return buf


def mapname(lname):
    return lname.replace(".conf", "") + "-log.txt"


logbuf = ""


@pytest.fixture(scope="module")
def r1(tgen):
    return tgen.gears["r1"].net


@pytest.fixture(scope="module")
def confdir():
    return Path(os.environ["PYTEST_TOPOTEST_SCRIPTDIR"]) / "r1"


@pytest.fixture(scope="module")
def tempdir(r1):
    return Path(r1.rundir)


@pytest.fixture(scope="module")
def logpath(tempdir):
    return tempdir / "mgmtd.log"


@pytest.fixture(autouse=True, scope="function")
def cleanup_config(r1, tempdir, logpath):
    global logbuf

    logbuf = save_log_snippet(logpath, logbuf, "/dev/null")

    yield

    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no allow-external-route-update'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no ip multicast rpf-lookup-mode urib-only'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no ip table range 2 3'")

    logbuf = save_log_snippet(logpath, logbuf, "/dev/null")


def test_staticd_startup(r1):
    r1.cmd_nostatus(
        "vtysh -c 'debug mgmt client frontend' "
        "-c 'debug mgmt client backend' "
        "-c 'debug mgmt backend frontend datastore transaction'"
    )
    step("Verifying routes are present on r1")
    result = check_kernel(r1, "12.0.0.0/24", retry_timeout=3.0)
    assert result is None


def test_mgmtd_one_exit_file(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "one-exit.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    result1 = check_kernel(r1, "20.1.0.0/24")
    result2 = check_kernel(r1, "20.2.0.0/24")

    assert result1 is None, "vtysh -f didn't work before exit"
    assert result2 is not None, "vtysh < worked after exit, unexpected"


def test_mgmtd_one_exit_redir(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "one-exit2.conf"
    step(f"Redirect {conf} file into vtysh")
    output = r1.cmd_nostatus(f"vtysh < {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    result1 = check_kernel(r1, "21.1.0.0/24")
    result2 = check_kernel(r1, "21.2.0.0/24")

    assert result1 is None, "vtysh < didn't work before exit"
    assert result2 is not None, "vtysh < worked after exit, unexpected"


def test_mgmtd_early_exit_file(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-exit.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    result1 = check_kernel(r1, "13.1.0.0/24")
    result2 = check_kernel(r1, "13.2.0.0/24")
    result3 = check_kernel(r1, "13.3.0.0/24")

    assert result1 is None, "vtysh -f didn't work before exit"
    assert result2 is not None, "vtysh -f worked after 1 exit, unexpected"
    assert result3 is not None, "vtysh -f worked after 2 exit, unexpected"


def test_mgmtd_early_exit_redir(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-exit2.conf"
    step(f"Redirect {conf} file into vtysh")
    output = r1.cmd_nostatus(f"vtysh < {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    result1 = check_kernel(r1, "14.1.0.0/24")
    result2 = check_kernel(r1, "14.2.0.0/24")
    result3 = check_kernel(r1, "14.3.0.0/24")

    assert result1 is None, "vtysh < didn't work before exit"
    assert result2 is not None, "vtysh < worked after 1 exits, unexpected"
    assert result3 is not None, "vtysh < worked after 2 exits, unexpected"


def test_mgmtd_early_end_file(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-end.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    result1 = check_kernel(r1, "15.1.0.0/24")
    result2 = check_kernel(r1, "15.2.0.0/24")
    result3 = check_kernel(r1, "15.3.0.0/24")

    assert result1 is None, "vtysh -f didn't work before end"
    assert result2 is None, "vtysh -f didn't work after 1 end"
    assert result3 is None, "vtysh -f didn't work after 2 ends"


def test_mgmtd_early_end_redir(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-end2.conf"
    step(f"Redirect {conf} file into vtysh")
    output = r1.cmd_nostatus(f"vtysh < {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    result1 = check_kernel(r1, "16.1.0.0/24")
    result2 = check_kernel(r1, "16.2.0.0/24")
    result3 = check_kernel(r1, "16.3.0.0/24")

    assert result1 is None, "vtysh < didn't work before end"
    assert result2 is not None, "vtysh < worked after 1 end, unexpected"
    assert result3 is not None, "vtysh < worked after 2 end, unexpected"


#
# Zebra
#


def test_zebra_one_exit_file(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "one-exit-zebra.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    showrun = r1.cmd_nostatus("vtysh -c 'show running'")
    assert "allow-external-route-update" in showrun, "zebra conf missing"
    assert (
        "ip multicast rpf-lookup-mode urib-only" not in showrun
    ), "zebra second conf present, unexpected"


def test_zebra_one_exit_redir(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "one-exit2-zebra.conf"
    step(f"Redirect {conf} file into vtysh")
    output = r1.cmd_nostatus(f"vtysh < {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    showrun = r1.cmd_nostatus("vtysh -c 'show running'")

    assert "allow-external-route-update" in showrun, "zebra conf missing"
    assert (
        "ip multicast rpf-lookup-mode urib-only" not in showrun
    ), "zebra second conf present, unexpected"


def test_zebra_early_exit_file(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-exit-zebra.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    showrun = r1.cmd_nostatus("vtysh -c 'show running'")

    assert "allow-external-route-update" in showrun, "zebra conf missing"
    assert (
        "ip multicast rpf-lookup-mode urib-only" not in showrun
    ), "zebra second conf present, unexpected"
    assert "ip table range 2 3" not in showrun, "zebra third conf present, unexpected"


def test_zebra_early_exit_redir(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-exit2-zebra.conf"
    step(f"Redirect {conf} file into vtysh")
    output = r1.cmd_nostatus(f"vtysh < {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    showrun = r1.cmd_nostatus("vtysh -c 'show running'")

    assert "allow-external-route-update" in showrun, "zebra conf missing"
    assert (
        "ip multicast rpf-lookup-mode urib-only" not in showrun
    ), "zebra second conf present, unexpected"
    assert "ip table range 2 3" not in showrun, "zebra third conf present, unexpected"


def test_zebra_early_end_file(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-end-zebra.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    showrun = r1.cmd_nostatus("vtysh -c 'show running'")

    assert "allow-external-route-update" in showrun, "zebra conf missing"
    assert (
        "ip multicast rpf-lookup-mode urib-only" in showrun
    ), "zebra second conf missing"
    assert "ip table range 2 3" in showrun, "zebra third missing"


def test_zebra_early_end_redir(r1, confdir, tempdir, logpath):
    global logbuf

    conf = "early-end2-zebra.conf"
    step(f"Redirect {conf} file into vtysh")
    output = r1.cmd_nostatus(f"vtysh < {confdir / conf}")
    logbuf = save_log_snippet(logpath, logbuf, tempdir / mapname(conf))
    print(output)

    showrun = r1.cmd_nostatus("vtysh -c 'show running'")

    assert "allow-external-route-update" in showrun, "zebra conf missing"
    assert (
        "ip multicast rpf-lookup-mode urib-only" not in showrun
    ), "zebra second conf present, unexpected"
    assert "ip table range 2 3" not in showrun, "zebra third conf present, unexpected"
