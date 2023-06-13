# -*- coding: utf-8 eval: (blacken-mode 1) -*-
"""
Topotest conftest.py file.
"""
# pylint: disable=consider-using-f-string

import contextlib
import glob
import logging
import os
import re
import resource
import subprocess
import sys
import time
from pathlib import Path

import lib.fixtures
import pytest
from lib.micronet_compat import Mininet
from lib.topogen import diagnose_env, get_topogen
from lib.topolog import get_test_logdir, logger
from lib.topotest import json_cmp_result
from munet import cli
from munet.base import Commander, proc_error
from munet.cleanup import cleanup_current, cleanup_previous
from munet.config import ConfigOptionsProxy
from munet.testing.util import pause_test

from lib import topolog, topotest

try:
    # Used by munet native tests
    from munet.testing.fixtures import event_loop, unet  # pylint: disable=all # noqa

    @pytest.fixture(scope="module")
    def rundir_module(pytestconfig):
        d = os.path.join(pytestconfig.option.rundir, get_test_logdir())
        logging.debug("rundir_module: test module rundir %s", d)
        return d

except (AttributeError, ImportError):
    pass


# Remove this and use munet version when we move to pytest_asyncio
@contextlib.contextmanager
def chdir(ndir, desc=""):
    odir = os.getcwd()
    os.chdir(ndir)
    if desc:
        logging.debug("%s: chdir from %s to %s", desc, odir, ndir)
    try:
        yield
    finally:
        if desc:
            logging.debug("%s: chdir back from %s to %s", desc, ndir, odir)
        os.chdir(odir)


@contextlib.contextmanager
def log_handler(basename, logpath):
    topolog.logstart(basename, logpath)
    try:
        yield
    finally:
        topolog.logfinish(basename, logpath)


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
        "--cli-on-error",
        action="store_true",
        help="Mininet cli on test failure",
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
        "--logd",
        action="append",
        metavar="DAEMON[,ROUTER[,...]",
        help=(
            "Tail-F the DAEMON log file on all or a subset of ROUTERs."
            " Option can be given multiple times."
        ),
    )

    parser.addoption(
        "--memleaks",
        action="store_true",
        help="Report memstat results as errors",
    )

    parser.addoption(
        "--pause",
        action="store_true",
        help="Pause after each test",
    )

    parser.addoption(
        "--pause-at-end",
        action="store_true",
        help="Pause before taking munet down",
    )

    parser.addoption(
        "--pause-on-error",
        action="store_true",
        help="Do not pause after (disables default when --shell or -vtysh given)",
    )

    parser.addoption(
        "--no-pause-on-error",
        dest="pause_on_error",
        action="store_false",
        help="Do not pause after (disables default when --shell or -vtysh given)",
    )

    parser.addoption(
        "--pcap",
        default="",
        metavar="NET[,NET...]",
        help="Comma-separated list of networks to capture packets on, or 'all'",
    )

    parser.addoption(
        "--perf",
        action="append",
        metavar="DAEMON[,ROUTER[,...]",
        help=(
            "Collect performance data from given DAEMON on all or a subset of ROUTERs."
            " Option can be given multiple times."
        ),
    )

    parser.addoption(
        "--perf-options",
        metavar="OPTS",
        default="-g",
        help="Options to pass to `perf record`.",
    )

    rundir_help = "directory for running in and log files"
    parser.addini("rundir", rundir_help, default="/tmp/topotests")
    parser.addoption("--rundir", metavar="DIR", help=rundir_help)

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


def check_for_valgrind_memleaks():
    assert topotest.g_pytest_config.option.valgrind_memleaks

    leaks = []
    tgen = get_topogen()  # pylint: disable=redefined-outer-name
    latest = []
    existing = []
    if tgen is not None:
        logdir = tgen.logdir
        if hasattr(tgen, "valgrind_existing_files"):
            existing = tgen.valgrind_existing_files
        latest = glob.glob(os.path.join(logdir, "*.valgrind.*"))
        latest = [x for x in latest if "core" not in x]

    daemons = set()
    for vfile in latest:
        if vfile in existing:
            continue
        # do not consider memleaks from parent fork (i.e., owned by root)
        if os.stat(vfile).st_uid == 0:
            existing.append(vfile)  # do not check again
            logger.debug("Skipping valgrind file %s owned by root", vfile)
            continue
        logger.debug("Checking valgrind file %s not owned by root", vfile)
        with open(vfile, encoding="ascii") as vf:
            vfcontent = vf.read()
            match = re.search(r"ERROR SUMMARY: (\d+) errors", vfcontent)
            if match:
                existing.append(vfile)  # have summary don't check again
            if match and match.group(1) != "0":
                emsg = "{} in {}".format(match.group(1), vfile)
                leaks.append(emsg)
                daemon = re.match(r".*\.valgrind\.(.*)\.\d+", vfile).group(1)
                daemons.add("{}({})".format(daemon, match.group(1)))

    if tgen is not None:
        tgen.valgrind_existing_files = existing

    if leaks:
        logger.error("valgrind memleaks found:\n\t%s", "\n\t".join(leaks))
        pytest.fail("valgrind memleaks found for daemons: " + " ".join(daemons))


def check_for_memleaks():
    leaks = []
    tgen = get_topogen()  # pylint: disable=redefined-outer-name
    latest = []
    existing = []
    if tgen is not None:
        logdir = tgen.logdir
        if hasattr(tgen, "memstat_existing_files"):
            existing = tgen.memstat_existing_files
        latest = glob.glob(os.path.join(logdir, "*/*.err"))

    daemons = []
    for vfile in latest:
        if vfile in existing:
            continue
        with open(vfile, encoding="ascii") as vf:
            vfcontent = vf.read()
            num = vfcontent.count("memstats:")
            if num:
                existing.append(vfile)  # have summary don't check again
                emsg = "{} types in {}".format(num, vfile)
                leaks.append(emsg)
                daemon = re.match(r".*test[a-z_A-Z0-9\+]*/(.*)\.err", vfile).group(1)
                daemons.append("{}({})".format(daemon, num))

    if tgen is not None:
        tgen.memstat_existing_files = existing

    if leaks:
        logger.error("memleaks found:\n\t%s", "\n\t".join(leaks))
        pytest.fail("memleaks found for daemons: " + " ".join(daemons))


@pytest.fixture(autouse=True, scope="module")
def module_autouse(request):
    basename = get_test_logdir(request.node.nodeid, True)
    logdir = Path(topotest.g_pytest_config.option.rundir) / basename
    logpath = logdir / "exec.log"

    subprocess.check_call("mkdir -p -m 1777 {}".format(logdir), shell=True)

    with log_handler(basename, logpath):
        sdir = os.path.dirname(os.path.realpath(request.fspath))
        with chdir(sdir, "module autouse fixture"):
            yield


@pytest.fixture(autouse=True, scope="module")
def module_check_memtest(request):
    yield
    if request.config.option.valgrind_memleaks:
        if get_topogen() is not None:
            check_for_valgrind_memleaks()
    if request.config.option.memleaks:
        if get_topogen() is not None:
            check_for_memleaks()


#
# Disable per test function logging as FRR CI system can't handle it.
#
# @pytest.fixture(autouse=True, scope="function")
# def function_autouse(request):
#     # For tests we actually use the logdir name as the logfile base
#     logbase = get_test_logdir(nodeid=request.node.nodeid, module=False)
#     logbase = os.path.join(topotest.g_pytest_config.option.rundir, logbase)
#     logpath = Path(logbase)
#     path = Path(f"{logpath.parent}/exec-{logpath.name}.log")
#     subprocess.check_call("mkdir -p -m 1777 {}".format(logpath.parent), shell=True)
#     with log_handler(request.node.nodeid, path):
#         yield


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> None:
    "Hook the function that is called to execute the test."

    # For topology only run the CLI then exit
    if item.config.option.topology_only:
        get_topogen().cli()
        pytest.exit("exiting after --topology-only")

    # Let the default pytest_runtest_call execute the test function
    yield

    # Check for leaks if requested
    if item.config.option.valgrind_memleaks:
        check_for_valgrind_memleaks()
    if item.config.option.memleaks:
        check_for_memleaks()


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
    topotest.g_pytest_config = ConfigOptionsProxy(config)

    if config.getoption("--collect-only"):
        return

    if "PYTEST_XDIST_WORKER" not in os.environ:
        os.environ["PYTEST_XDIST_MODE"] = config.getoption("dist", "no")
        os.environ["PYTEST_TOPOTEST_WORKER"] = ""
        is_xdist = os.environ["PYTEST_XDIST_MODE"] != "no"
        is_worker = False
        wname = ""
    else:
        wname = os.environ["PYTEST_XDIST_WORKER"]
        os.environ["PYTEST_TOPOTEST_WORKER"] = wname
        is_xdist = True
        is_worker = True

    resource.setrlimit(
        resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    )
    # -----------------------------------------------------
    # Set some defaults for the pytest.ini [pytest] section
    # ---------------------------------------------------

    rundir = config.option.rundir
    if not rundir:
        rundir = config.getini("rundir")
    if not rundir:
        rundir = "/tmp/topotests"
    config.option.rundir = rundir

    if not config.getoption("--junitxml"):
        config.option.xmlpath = os.path.join(rundir, "topotests.xml")
    xmlpath = config.option.xmlpath

    # Save an existing topotest.xml
    if os.path.exists(xmlpath):
        fmtime = time.localtime(os.path.getmtime(xmlpath))
        suffix = "-" + time.strftime("%Y%m%d%H%M%S", fmtime)
        commander = Commander("pytest")
        mv_path = commander.get_exec_path("mv")
        commander.cmd_status([mv_path, xmlpath, xmlpath + suffix])

    # Set the log_file (exec) to inside the rundir if not specified
    if not config.getoption("--log-file") and not config.getini("log_file"):
        config.option.log_file = os.path.join(rundir, "exec.log")

    # Handle pytest-xdist each worker get's it's own top level log file
    # `exec-worker-N.log`
    if wname:
        wname = wname.replace("gw", "worker-")
        cpath = Path(config.option.log_file).absolute()
        config.option.log_file = f"{cpath.parent}/{cpath.stem}-{wname}{cpath.suffix}"
    elif is_xdist:
        cpath = Path(config.option.log_file).absolute()
        config.option.log_file = f"{cpath.parent}/{cpath.stem}-xdist{cpath.suffix}"

    # Turn on live logging if user specified verbose and the config has a CLI level set
    if config.getoption("--verbose") and not is_xdist and not config.getini("log_cli"):
        if config.getoption("--log-cli-level", None) is None:
            # By setting the CLI option to the ini value it enables log_cli=1
            cli_level = config.getini("log_cli_level")
            if cli_level is not None:
                config.option.log_cli_level = cli_level

    have_tmux = bool(os.getenv("TMUX", ""))
    have_screen = not have_tmux and bool(os.getenv("STY", ""))
    have_xterm = not have_tmux and not have_screen and bool(os.getenv("DISPLAY", ""))
    have_windows = have_tmux or have_screen or have_xterm
    have_windows_pause = have_tmux or have_xterm
    xdist_no_windows = is_xdist and not is_worker and not have_windows_pause

    def assert_feature_windows(b, feature):
        if b and xdist_no_windows:
            pytest.exit(
                "{} use requires byobu/TMUX/XTerm under dist {}".format(
                    feature, os.environ["PYTEST_XDIST_MODE"]
                )
            )
        elif b and not is_xdist and not have_windows:
            pytest.exit("{} use requires byobu/TMUX/SCREEN/XTerm".format(feature))

    #
    # Check for window capability if given options that require window
    #
    assert_feature_windows(config.option.gdb_routers, "GDB")
    assert_feature_windows(config.option.gdb_daemons, "GDB")
    assert_feature_windows(config.option.cli_on_error, "--cli-on-error")
    assert_feature_windows(config.option.shell, "--shell")
    assert_feature_windows(config.option.shell_on_error, "--shell-on-error")
    assert_feature_windows(config.option.vtysh, "--vtysh")
    assert_feature_windows(config.option.vtysh_on_error, "--vtysh-on-error")

    if config.option.topology_only and is_xdist:
        pytest.exit("Cannot use --topology-only with distributed test mode")

        pytest.exit("Cannot use --topology-only with distributed test mode")

    # Check environment now that we have config
    if not diagnose_env(rundir):
        pytest.exit("environment has errors, please read the logs in %s" % rundir)

    # slave TOPOTESTS_CHECK_MEMLEAK to memleaks flag
    if config.option.memleaks:
        if "TOPOTESTS_CHECK_MEMLEAK" not in os.environ:
            os.environ["TOPOTESTS_CHECK_MEMLEAK"] = "/dev/null"
    else:
        if "TOPOTESTS_CHECK_MEMLEAK" in os.environ:
            del os.environ["TOPOTESTS_CHECK_MEMLEAK"]
        if "TOPOTESTS_CHECK_STDERR" in os.environ:
            del os.environ["TOPOTESTS_CHECK_STDERR"]


@pytest.fixture(autouse=True, scope="session")
def setup_session_auto():
    # Aligns logs nicely
    logging.addLevelName(logging.WARNING, " WARN")
    logging.addLevelName(logging.INFO, " INFO")

    if "PYTEST_TOPOTEST_WORKER" not in os.environ:
        is_worker = False
    elif not os.environ["PYTEST_TOPOTEST_WORKER"]:
        is_worker = False
    else:
        is_worker = True

    logger.debug("Before the run (is_worker: %s)", is_worker)
    if not is_worker:
        cleanup_previous()
    yield
    if not is_worker:
        cleanup_current()
    logger.debug("After the run (is_worker: %s)", is_worker)


def pytest_runtest_setup(item):
    module = item.parent.module
    script_dir = os.path.abspath(os.path.dirname(module.__file__))
    os.environ["PYTEST_TOPOTEST_SCRIPTDIR"] = script_dir


def pytest_runtest_makereport(item, call):
    "Log all assert messages to default logger with error level"

    pause = bool(item.config.getoption("--pause"))
    title = "unset"

    if call.excinfo is None:
        error = False
    else:
        parent = item.parent
        modname = parent.module.__name__

        # Treat skips as non errors, don't pause after
        if call.excinfo.typename == "Skipped":
            pause = False
            error = False
            logger.info(
                'test skipped at "{}/{}": {}'.format(
                    modname, item.name, call.excinfo.value
                )
            )
        else:
            error = True
            # Handle assert failures
            parent._previousfailed = item  # pylint: disable=W0212
            logger.error(
                'test failed at "{}/{}": {}'.format(
                    modname, item.name, call.excinfo.value
                )
            )
            title = "{}/{}".format(modname, item.name)

            # We want to pause, if requested, on any error not just test cases
            # (e.g., call.when == "setup")
            if not pause:
                pause = item.config.option.pause_on_error or item.config.option.pause

            # (topogen) Set topology error to avoid advancing in the test.
            tgen = get_topogen()  # pylint: disable=redefined-outer-name
            if tgen is not None:
                # This will cause topogen to report error on `routers_have_failure`.
                tgen.set_error("{}/{}".format(modname, item.name))

    commander = Commander("pytest")
    isatty = sys.stdout.isatty()
    error_cmd = None

    if error and item.config.option.vtysh_on_error:
        error_cmd = commander.get_exec_path(["vtysh"])
    elif error and item.config.option.shell_on_error:
        error_cmd = os.getenv("SHELL", commander.get_exec_path(["bash"]))

    if error_cmd:
        is_tmux = bool(os.getenv("TMUX", ""))
        is_screen = not is_tmux and bool(os.getenv("STY", ""))
        is_xterm = not is_tmux and not is_screen and bool(os.getenv("DISPLAY", ""))

        channel = None
        win_info = None
        wait_for_channels = []
        wait_for_procs = []
        # Really would like something better than using this global here.
        # Not all tests use topogen though so get_topogen() won't work.
        for node in Mininet.g_mnet_inst.hosts.values():
            pause = True

            if is_tmux:
                channel = (
                    "{}-{}".format(os.getpid(), Commander.tmux_wait_gen)
                    if not isatty
                    else None
                )
                Commander.tmux_wait_gen += 1
                wait_for_channels.append(channel)

            pane_info = node.run_in_window(
                error_cmd,
                new_window=win_info is None,
                background=True,
                title="{} ({})".format(title, node.name),
                name=title,
                tmux_target=win_info,
                wait_for=channel,
            )
            if is_tmux:
                if win_info is None:
                    win_info = pane_info
            elif is_xterm:
                assert isinstance(pane_info, subprocess.Popen)
                wait_for_procs.append(pane_info)

        # Now wait on any channels
        for channel in wait_for_channels:
            logger.debug("Waiting on TMUX channel %s", channel)
            commander.cmd_raises([commander.get_exec_path("tmux"), "wait", channel])
        for p in wait_for_procs:
            logger.debug("Waiting on TMUX xterm process %s", p)
            o, e = p.communicate()
            if p.wait():
                logger.warning("xterm proc failed: %s:", proc_error(p, o, e))

    if error and item.config.option.cli_on_error:
        # Really would like something better than using this global here.
        # Not all tests use topogen though so get_topogen() won't work.
        if Mininet.g_mnet_inst:
            cli.cli(Mininet.g_mnet_inst, title=title, background=False)
        else:
            logger.error("Could not launch CLI b/c no mininet exists yet")

    if pause and isatty:
        pause_test()


#
# Add common fixtures available to all tests as parameters
#

tgen = pytest.fixture(lib.fixtures.tgen)
topo = pytest.fixture(lib.fixtures.topo)
