# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# April 22 2022, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2022, LabN Consulting, L.L.C
#
"""A module that implements pytest fixtures.

To use in your project, in your conftest.py add:

  from munet.testing.fixtures import *
"""
import contextlib
import logging
import os

from pathlib import Path
from typing import Union

import pytest
import pytest_asyncio

from ..base import BaseMunet
from ..base import Bridge
from ..base import get_event_loop
from ..cleanup import cleanup_current
from ..cleanup import cleanup_previous
from ..native import L3NodeMixin
from ..parser import async_build_topology
from ..parser import get_config
from .util import async_pause_test
from .util import pause_test


@contextlib.asynccontextmanager
async def achdir(ndir: Union[str, Path], desc=""):
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
def chdir(ndir: Union[str, Path], desc=""):
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


def get_test_logdir(nodeid=None, module=False):
    """Get log directory relative pathname."""
    xdist_worker = os.getenv("PYTEST_XDIST_WORKER", "")
    mode = os.getenv("PYTEST_XDIST_MODE", "no")

    # nodeid: all_protocol_startup/test_all_protocol_startup.py::test_router_running
    # may be missing "::testname" if module is True
    if not nodeid:
        nodeid = os.environ["PYTEST_CURRENT_TEST"].split(" ")[0]

    cur_test = nodeid.replace("[", "_").replace("]", "_")
    if module:
        idx = cur_test.rfind("::")
        path = cur_test if idx == -1 else cur_test[:idx]
        testname = ""
    else:
        path, testname = cur_test.split("::")
        testname = testname.replace("/", ".")
    path = path[:-3].replace("/", ".")

    # We use different logdir paths based on how xdist is running.
    if mode == "each":
        if module:
            return os.path.join(path, "worker-logs", xdist_worker)
        return os.path.join(path, testname, xdist_worker)
    assert mode in ("no", "load", "loadfile", "loadscope"), f"Unknown dist mode {mode}"
    return path if module else os.path.join(path, testname)


def _push_log_handler(desc, logpath):
    logpath = os.path.abspath(logpath)
    logging.debug("conftest: adding %s logging at %s", desc, logpath)
    root_logger = logging.getLogger()
    handler = logging.FileHandler(logpath, mode="w")
    fmt = logging.Formatter("%(asctime)s %(levelname)5s: %(name)s: %(message)s")
    handler.setFormatter(fmt)
    root_logger.addHandler(handler)
    return handler


def _pop_log_handler(handler):
    root_logger = logging.getLogger()
    logging.debug("conftest: removing logging handler %s", handler)
    root_logger.removeHandler(handler)


@contextlib.contextmanager
def log_handler(desc, logpath):
    handler = _push_log_handler(desc, logpath)
    try:
        yield
    finally:
        _pop_log_handler(handler)


# =================
# Sessions Fixtures
# =================


@pytest.fixture(autouse=True, scope="session")
def session_autouse():
    if "PYTEST_TOPOTEST_WORKER" not in os.environ:
        is_worker = False
    elif not os.environ["PYTEST_TOPOTEST_WORKER"]:
        is_worker = False
    else:
        is_worker = True

    if not is_worker:
        # This is unfriendly to multi-instance
        cleanup_previous()

    # We never pop as we want to keep logging
    _push_log_handler("session", "/tmp/unet-test/pytest-session.log")

    yield

    if not is_worker:
        cleanup_current()


# ===============
# Module Fixtures
# ===============


@pytest.fixture(autouse=True, scope="module")
def module_autouse(request):
    logpath = get_test_logdir(request.node.name, True)
    logpath = os.path.join("/tmp/unet-test", logpath, "pytest-exec.log")
    with log_handler("module", logpath):
        sdir = os.path.dirname(os.path.realpath(request.fspath))
        with chdir(sdir, "module autouse fixture"):
            yield

        if BaseMunet.g_unet:
            raise Exception("Base Munet was not cleaned up/deleted")


@pytest.fixture(scope="module")
def event_loop():
    """Create an instance of the default event loop for the session."""
    loop = get_event_loop()
    try:
        logging.info("event_loop_fixture: yielding with new event loop watcher")
        yield loop
    finally:
        loop.close()


@pytest.fixture(scope="module")
def rundir_module():
    d = os.path.join("/tmp/unet-test", get_test_logdir(module=True))
    logging.debug("conftest: test module rundir %s", d)
    return d


async def _unet_impl(
    _rundir, _pytestconfig, unshare=None, top_level_pidns=None, param=None
):
    try:
        # Default is not to unshare inline if not specified otherwise
        unshare_default = False
        pidns_default = True
        if isinstance(param, (tuple, list)):
            pidns_default = bool(param[2]) if len(param) > 2 else True
            unshare_default = bool(param[1]) if len(param) > 1 else False
            param = str(param[0])
        elif isinstance(param, bool):
            unshare_default = param
            param = None
        if unshare is None:
            unshare = unshare_default
        if top_level_pidns is None:
            top_level_pidns = pidns_default

        logging.info("unet fixture: basename=%s unshare_inline=%s", param, unshare)
        _unet = await async_build_topology(
            config=get_config(basename=param) if param else None,
            rundir=_rundir,
            unshare_inline=unshare,
            top_level_pidns=top_level_pidns,
            pytestconfig=_pytestconfig,
        )
    except Exception as error:
        logging.debug(
            "unet fixture: unet build failed: %s\nparam: %s",
            error,
            param,
            exc_info=True,
        )
        pytest.skip(
            f"unet fixture: unet build failed: {error}", allow_module_level=True
        )
        raise

    try:
        tasks = await _unet.run()
    except Exception as error:
        logging.debug("unet fixture: unet run failed: %s", error, exc_info=True)
        await _unet.async_delete()
        pytest.skip(f"unet fixture: unet run failed: {error}", allow_module_level=True)
        raise

    logging.debug("unet fixture: containers running")

    # Pytest is supposed to always return even if exceptions
    try:
        yield _unet
    except Exception as error:
        logging.error("unet fixture: yield unet unexpected exception: %s", error)

    logging.debug("unet fixture: module done, deleting unet")
    await _unet.async_delete()

    # No one ever awaits these so cancel them
    logging.debug("unet fixture: cleanup")
    for task in tasks:
        task.cancel()

    # Reset the class variables so auto number is predictable
    logging.debug("unet fixture: resetting ords to 1")
    L3NodeMixin.next_ord = 1
    Bridge.next_ord = 1


@pytest.fixture(scope="module")
async def unet(request, rundir_module, pytestconfig):  # pylint: disable=W0621
    """A unet creating fixutre.

    The request param is either the basename of the config file or a tuple of the form:
    (basename, unshare, top_level_pidns), with the second and third elements boolean and
    optional, defaulting to False, True.
    """
    param = request.param if hasattr(request, "param") else None
    sdir = os.path.dirname(os.path.realpath(request.fspath))
    async with achdir(sdir, "unet fixture"):
        async for x in _unet_impl(rundir_module, pytestconfig, param=param):
            yield x


@pytest.fixture(scope="module")
async def unet_share(request, rundir_module, pytestconfig):  # pylint: disable=W0621
    """A unet creating fixutre.

    This share variant keeps munet from unsharing the process to a new namespace so that
    root level commands and actions are execute on the host, normally they are executed
    in the munet namespace which allowing things like scapy inline in tests to work.

    The request param is either the basename of the config file or a tuple of the form:
    (basename, top_level_pidns), the second value is a boolean.
    """
    param = request.param if hasattr(request, "param") else None
    if isinstance(param, (tuple, list)):
        param = (param[0], False, param[1])
    sdir = os.path.dirname(os.path.realpath(request.fspath))
    async with achdir(sdir, "unet_share fixture"):
        async for x in _unet_impl(
            rundir_module, pytestconfig, unshare=False, param=param
        ):
            yield x


@pytest.fixture(scope="module")
async def unet_unshare(request, rundir_module, pytestconfig):  # pylint: disable=W0621
    """A unet creating fixutre.

    This unshare variant has the top level munet unshare the process inline so that
    root level commands and actions are execute in a new namespace. This allows things
    like scapy inline in tests to work.

    The request param is either the basename of the config file or a tuple of the form:
    (basename, top_level_pidns), the second value is a boolean.
    """
    param = request.param if hasattr(request, "param") else None
    if isinstance(param, (tuple, list)):
        param = (param[0], True, param[1])
    sdir = os.path.dirname(os.path.realpath(request.fspath))
    async with achdir(sdir, "unet_unshare fixture"):
        async for x in _unet_impl(
            rundir_module, pytestconfig, unshare=True, param=param
        ):
            yield x


# =================
# Function Fixtures
# =================


@pytest.fixture(autouse=True, scope="function")
async def function_autouse(request):
    async with achdir(
        os.path.dirname(os.path.realpath(request.fspath)), "func.fixture"
    ):
        yield


@pytest.fixture(autouse=True)
async def check_for_pause(request, pytestconfig):
    # When we unshare inline we can't pause in the pytest_runtest_makereport hook
    # so do it here.
    if BaseMunet.g_unet and BaseMunet.g_unet.unshare_inline:
        pause = bool(pytestconfig.getoption("--pause"))
        if pause:
            await async_pause_test(f"XXX before test '{request.node.name}'")
    yield


@pytest.fixture(scope="function")
def stepf(pytestconfig):
    class Stepnum:
        """Track the stepnum in closure."""

        num = 0

        def inc(self):
            self.num += 1

    pause = pytestconfig.getoption("pause")
    stepnum = Stepnum()

    def stepfunction(desc=""):
        desc = f": {desc}" if desc else ""
        if pause:
            pause_test(f"before step {stepnum.num}{desc}")
        logging.info("STEP %s%s", stepnum.num, desc)
        stepnum.inc()

    return stepfunction


@pytest_asyncio.fixture(scope="function")
async def astepf(pytestconfig):
    class Stepnum:
        """Track the stepnum in closure."""

        num = 0

        def inc(self):
            self.num += 1

    pause = pytestconfig.getoption("pause")
    stepnum = Stepnum()

    async def stepfunction(desc=""):
        desc = f": {desc}" if desc else ""
        if pause:
            await async_pause_test(f"before step {stepnum.num}{desc}")
        logging.info("STEP %s%s", stepnum.num, desc)
        stepnum.inc()

    return stepfunction


@pytest.fixture(scope="function")
def rundir():
    d = os.path.join("/tmp/unet-test", get_test_logdir(module=False))
    logging.debug("conftest: test function rundir %s", d)
    return d


# Configure logging
@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    d = os.path.join(
        "/tmp/unet-test", get_test_logdir(nodeid=item.nodeid, module=False)
    )
    config = item.config
    logging_plugin = config.pluginmanager.get_plugin("logging-plugin")
    filename = Path(d, "pytest-exec.log")
    logging_plugin.set_log_path(str(filename))
    logging.debug("conftest: test function setup: rundir %s", d)
    yield


@pytest.fixture
async def unet_perfunc(request, rundir, pytestconfig):  # pylint: disable=W0621
    param = request.param if hasattr(request, "param") else None
    async for x in _unet_impl(rundir, pytestconfig, param=param):
        yield x


@pytest.fixture
async def unet_perfunc_unshare(request, rundir, pytestconfig):  # pylint: disable=W0621
    """Build unet per test function with an optional topology basename parameter.

    The fixture can be parameterized to choose different config files.
    For example, use as follows to run the test with unet_perfunc configured
    first with a config file named `cfg1.yaml` then with config file `cfg2.yaml`
    (where the actual files could end with `json` or `toml` rather than `yaml`).

        @pytest.mark.parametrize(
            "unet_perfunc", ["cfg1", "cfg2]", indirect=["unet_perfunc"]
        )
        def test_example(unet_perfunc)
    """
    param = request.param if hasattr(request, "param") else None
    async for x in _unet_impl(rundir, pytestconfig, unshare=True, param=param):
        yield x


@pytest.fixture
async def unet_perfunc_share(request, rundir, pytestconfig):  # pylint: disable=W0621
    """Build unet per test function with an optional topology basename parameter.

    This share variant keeps munet from unsharing the process to a new namespace so that
    root level commands and actions are execute on the host, normally they are executed
    in the munet namespace which allowing things like scapy inline in tests to work.

    The fixture can be parameterized to choose different config files.  For example, use
    as follows to run the test with unet_perfunc configured first with a config file
    named `cfg1.yaml` then with config file `cfg2.yaml` (where the actual files could
    end with `json` or `toml` rather than `yaml`).

        @pytest.mark.parametrize(
            "unet_perfunc", ["cfg1", "cfg2]", indirect=["unet_perfunc"]
        )
        def test_example(unet_perfunc)
    """
    param = request.param if hasattr(request, "param") else None
    async for x in _unet_impl(rundir, pytestconfig, unshare=False, param=param):
        yield x
