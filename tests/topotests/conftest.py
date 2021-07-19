"""
Topotest conftest.py file.
"""

import glob
import os
import pdb
import re
import pytest

from lib.micronet_compat import Mininet
from lib.topogen import get_topogen, diagnose_env
from lib.topotest import json_cmp_result
from lib.topotest import g_extra_config as topotest_extra_config
from lib.topolog import logger


try:
    from _pytest._code.code import ExceptionInfo
    leak_check_ok = True
except ImportError:
    leak_check_ok = False


def pytest_addoption(parser):
    """
    Add topology-only option to the topology tester. This option makes pytest
    only run the setup_module() to setup the topology without running any tests.
    """
    parser.addoption(
        "--asan-abort",
        action="store_true",
        help="Configure address sanitizer to abort process on error",
    )

    parser.addoption(
        "--gdb-breakpoints",
        metavar="SYMBOL[,SYMBOL...]",
        help="Comma-separated list of functions to set gdb breakpoints on",
    )

    parser.addoption(
        "--gdb-daemons",
        metavar="DAEMON[,DAEMON...]",
        help="Comma-separated list of daemons to spawn gdb on, or 'all'",
    )

    parser.addoption(
        "--gdb-routers",
        metavar="ROUTER[,ROUTER...]",
        help="Comma-separated list of routers to spawn gdb on, or 'all'",
    )

    parser.addoption(
        "--mininet-on-error",
        action="store_true",
        help="Mininet cli on test failure",
    )

    parser.addoption(
        "--pause-after",
        action="store_true",
        help="Pause after each test",
    )

    parser.addoption(
        "--shell",
        metavar="ROUTER[,ROUTER...]",
        help="Comma-separated list of routers to spawn shell on, or 'all'",
    )

    parser.addoption(
        "--shell-on-error",
        action="store_true",
        help="Spawn shell on all routers on test failure",
    )

    parser.addoption(
        "--strace-daemons",
        metavar="DAEMON[,DAEMON...]",
        help="Comma-separated list of daemons to strace, or 'all'",
    )

    parser.addoption(
        "--topology-only",
        action="store_true",
        default=False,
        help="Only set up this topology, don't run tests",
    )

    parser.addoption(
        "--valgrind-extra",
        action="store_true",
        help="Generate suppression file, and enable more precise (slower) valgrind checks",
    )

    parser.addoption(
        "--valgrind-memleaks",
        action="store_true",
        help="Run all daemons under valgrind for memleak detection",
    )

    parser.addoption(
        "--vtysh",
        metavar="ROUTER[,ROUTER...]",
        help="Comma-separated list of routers to spawn vtysh on, or 'all'",
    )

    parser.addoption(
        "--vtysh-on-error",
        action="store_true",
        help="Spawn vtysh on all routers on test failure",
    )


def check_for_memleaks():
    if not topotest_extra_config["valgrind_memleaks"]:
        return

    leaks = []
    tgen = get_topogen()
    latest = []
    existing = []
    if tgen is not None:
        logdir = "/tmp/topotests/{}".format(tgen.modname)
        if hasattr(tgen, "valgrind_existing_files"):
            existing = tgen.valgrind_existing_files
        latest = glob.glob(os.path.join(logdir, "*.valgrind.*"))

    for vfile in latest:
        if vfile in existing:
            continue
        with open(vfile) as vf:
            vfcontent = vf.read()
            match = re.search(r"ERROR SUMMARY: (\d+) errors", vfcontent)
            if match and match.group(1) != "0":
                emsg = '{} in {}'.format(match.group(1), vfile)
                leaks.append(emsg)

    if leaks:
        if leak_check_ok:
            pytest.fail("Memleaks found:\n\t" + "\n\t".join(leaks))
        else:
            logger.error("Memleaks found:\n\t" + "\n\t".join(leaks))


def pytest_runtest_call():
    """
    This function must be run after setup_module(), it does standarized post
    setup routines. It is only being used for the 'topology-only' option.
    """
    if topotest_extra_config["topology_only"]:
        tgen = get_topogen()
        if tgen is not None:
            # Allow user to play with the setup.
            tgen.mininet_cli()

        pytest.exit("the topology executed successfully")


def pytest_assertrepr_compare(op, left, right):
    """
    Show proper assertion error message for json_cmp results.
    """
    del op

    json_result = left
    if not isinstance(json_result, json_cmp_result):
        json_result = right
        if not isinstance(json_result, json_cmp_result):
            return None

    return json_result.gen_report()


def pytest_configure(config):
    """
    Assert that the environment is correctly configured, and get extra config.
    """

    if not diagnose_env():
        pytest.exit("environment has errors, please read the logs")

    asan_abort = config.getoption("--asan-abort")
    topotest_extra_config["asan_abort"] = asan_abort

    gdb_routers = config.getoption("--gdb-routers")
    gdb_routers = gdb_routers.split(",") if gdb_routers else []
    topotest_extra_config["gdb_routers"] = gdb_routers

    gdb_daemons = config.getoption("--gdb-daemons")
    gdb_daemons = gdb_daemons.split(",") if gdb_daemons else []
    topotest_extra_config["gdb_daemons"] = gdb_daemons

    gdb_breakpoints = config.getoption("--gdb-breakpoints")
    gdb_breakpoints = gdb_breakpoints.split(",") if gdb_breakpoints else []
    topotest_extra_config["gdb_breakpoints"] = gdb_breakpoints

    mincli_on_error = config.getoption("--mininet-on-error")
    topotest_extra_config["mininet_on_error"] = mincli_on_error

    shell = config.getoption("--shell")
    topotest_extra_config["shell"] = shell.split(",") if shell else []

    strace = config.getoption("--strace-daemons")
    topotest_extra_config["strace_daemons"] = strace.split(",") if strace else []

    pause_after = config.getoption("--pause-after")

    shell_on_error = config.getoption("--shell-on-error")
    topotest_extra_config["shell_on_error"] = shell_on_error

    topotest_extra_config["valgrind_extra"] = config.getoption("--valgrind-extra")
    topotest_extra_config["valgrind_memleaks"] = config.getoption("--valgrind-memleaks")

    vtysh = config.getoption("--vtysh")
    topotest_extra_config["vtysh"] = vtysh.split(",") if vtysh else []

    vtysh_on_error = config.getoption("--vtysh-on-error")
    topotest_extra_config["vtysh_on_error"] = vtysh_on_error

    topotest_extra_config["pause_after"] = pause_after or shell or vtysh

    topotest_extra_config["topology_only"] = config.getoption("--topology-only")


def pytest_runtest_makereport(item, call):
    "Log all assert messages to default logger with error level"

    # Nothing happened
    if call.when == "call":
        pause = topotest_extra_config["pause_after"]
    else:
        pause = False

    if call.excinfo is None and call.when == "call":
        try:
            check_for_memleaks()
        except:
            call.excinfo = ExceptionInfo()

    if call.excinfo is None:
        error = False
    else:
        parent = item.parent
        modname = parent.module.__name__

        # Treat skips as non errors, don't pause after
        if call.excinfo.typename != "AssertionError":
            pause = False
            error = False
            logger.info(
                'assert skipped at "{}/{}": {}'.format(
                    modname, item.name, call.excinfo.value
                )
            )
        else:
            error = True
            # Handle assert failures
            parent._previousfailed = item  # pylint: disable=W0212
            logger.error(
                'assert failed at "{}/{}": {}'.format(
                    modname, item.name, call.excinfo.value
                )
            )

            # We want to pause, if requested, on any error not just test cases
            # (e.g., call.when == "setup")
            if not pause:
                pause = topotest_extra_config["pause_after"]

            # (topogen) Set topology error to avoid advancing in the test.
            tgen = get_topogen()
            if tgen is not None:
                # This will cause topogen to report error on `routers_have_failure`.
                tgen.set_error("{}/{}".format(modname, item.name))

    if error and topotest_extra_config["shell_on_error"]:
        # Really would like something better than using this global here.
        # Not all tests use topogen though so get_topogen() won't work.
        for node in Mininet.g_mnet_inst.hosts.values():
            pause = True
            node.runInWindow(os.getenv("SHELL", "bash"))

    if error and topotest_extra_config["vtysh_on_error"]:
        # Really would like something better than using this global here.
        # Not all tests use topogen though so get_topogen() won't work.
        for node in Mininet.g_mnet_inst.hosts.values():
            pause = True
            node.runInWindow("vtysh")

    if error and topotest_extra_config["mininet_on_error"]:
        # Really would like something better than using this global here.
        # Not all tests use topogen though so get_topogen() won't work.
        Mininet.g_mnet_inst.cli()

    if pause:
        try:
            user = raw_input('Testing paused, "pdb" to debug, "Enter" to continue: ')
        except NameError:
            user = input('Testing paused, "pdb" to debug, "Enter" to continue: ')
        if user.strip() == "pdb":
            pdb.set_trace()
