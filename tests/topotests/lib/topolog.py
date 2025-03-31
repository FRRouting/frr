# SPDX-License-Identifier: ISC
#
# topolog.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
Logging utilities for topology tests.

This file defines our logging abstraction.
"""

import logging
import os

try:
    from xdist import is_xdist_controller
except ImportError:

    def is_xdist_controller():
        return False


# Helper dictionary to convert Topogen logging levels to Python's logging.
DEBUG_TOPO2LOGGING = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "output": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}
FORMAT = "%(asctime)s %(levelname)s: %(name)s: %(message)s"

handlers = {}
logger = logging.getLogger("topo")


# Remove this and use munet version when we move to pytest_asyncio
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


def set_handler(lg, target=None):
    if target is None:
        h = logging.NullHandler()
    else:
        if isinstance(target, str):
            h = logging.FileHandler(filename=target, mode="w")
        else:
            h = logging.StreamHandler(stream=target)
        h.setFormatter(logging.Formatter(fmt=FORMAT))
    # Don't filter anything at the handler level
    h.setLevel(logging.DEBUG)
    lg.addHandler(h)
    return h


def set_log_level(lg, level):
    "Set the logging level."
    # Messages sent to this logger only are created if this level or above.
    log_level = DEBUG_TOPO2LOGGING.get(level, level)
    lg.setLevel(log_level)


def reset_logger(lg):
    while lg.handlers:
        x = lg.handlers.pop()
        x.close()
        lg.removeHandler(x)


def get_logger(name, log_level=None, target=None, reset=True):
    lg = logging.getLogger(name)

    if reset:
        reset_logger(lg)

    if log_level is not None:
        set_log_level(lg, log_level)

    if target is not None:
        set_handler(lg, target)

    return lg


def logstart(nodeid, logpath):
    """Called from pytest before module setup."""
    worker = os.getenv("PYTEST_TOPOTEST_WORKER", "")
    wstr = f" on worker {worker}" if worker else ""
    handler_id = nodeid + worker
    logpath = logpath.absolute()

    logging.debug("logstart: adding logging for %s%s at %s", nodeid, wstr, logpath)
    root_logger = logging.getLogger()
    handler = logging.FileHandler(logpath, mode="w")
    handler.setFormatter(logging.Formatter(FORMAT))

    root_logger.addHandler(handler)
    handlers[handler_id] = handler

    logging.debug("logstart: added logging for %s%s at %s", nodeid, wstr, logpath)
    return handler


def logfinish(nodeid, logpath):
    """Called from pytest after module teardown."""
    worker = os.getenv("PYTEST_TOPOTEST_WORKER", "")
    wstr = f" on worker {worker}" if worker else ""

    root_logger = logging.getLogger()

    handler_id = nodeid + worker

    if handler_id not in handlers:
        logging.critical("can't find log handler to remove")
    else:
        logging.debug(
            "logfinish: removing logging for %s%s at %s", nodeid, wstr, logpath
        )
        h = handlers[handler_id]
        root_logger.removeHandler(h)
        h.flush()
        h.close()
        del handlers[handler_id]
        logging.debug(
            "logfinish: removed logging for %s%s at %s", nodeid, wstr, logpath
        )


console_handler = set_handler(logger, None)
set_log_level(logger, "debug")
