#
# topolog.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Logging utilities for topology tests.

This file defines our logging abstraction.
"""

import logging
import os
import subprocess
import sys

if sys.version_info[0] > 2:
    pass
else:
    pass

try:
    from xdist import is_xdist_controller
except ImportError:

    def is_xdist_controller():
        return False


BASENAME = "topolog"

# Helper dictionary to convert Topogen logging levels to Python's logging.
DEBUG_TOPO2LOGGING = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "output": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}
FORMAT = "%(asctime)s.%(msecs)03d %(levelname)s: %(name)s: %(message)s"

handlers = {}
logger = logging.getLogger("topolog")


def set_handler(l, target=None):
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
    l.addHandler(h)
    return h


def set_log_level(l, level):
    "Set the logging level."
    # Messages sent to this logger only are created if this level or above.
    log_level = DEBUG_TOPO2LOGGING.get(level, level)
    l.setLevel(log_level)


def get_logger(name, log_level=None, target=None):
    l = logging.getLogger("{}.{}".format(BASENAME, name))

    if log_level is not None:
        set_log_level(l, log_level)

    if target is not None:
        set_handler(l, target)

    return l


# nodeid: all_protocol_startup/test_all_protocol_startup.py::test_router_running


def get_test_logdir(nodeid=None):
    """Get log directory relative pathname."""
    xdist_worker = os.getenv("PYTEST_XDIST_WORKER", "")
    mode = os.getenv("PYTEST_XDIST_MODE", "no")

    if not nodeid:
        nodeid = os.environ["PYTEST_CURRENT_TEST"].split(" ")[0]

    cur_test = nodeid.replace("[", "_").replace("]", "_")
    path, testname = cur_test.split("::")
    path = path[:-3].replace("/", ".")

    # We use different logdir paths based on how xdist is running.
    if mode == "each":
        return os.path.join(path, testname, xdist_worker)
    elif mode == "load":
        return os.path.join(path, testname)
    else:
        assert (
            mode == "no" or mode == "loadfile" or mode == "loadscope"
        ), "Unknown dist mode {}".format(mode)

        return path


def logstart(nodeid, location, rundir):
    """Called from pytest before module setup."""

    mode = os.getenv("PYTEST_XDIST_MODE", "no")
    worker = os.getenv("PYTEST_TOPOTEST_WORKER", "")

    # We only per-test log in the workers (or non-dist)
    if not worker and mode != "no":
        return

    handler_id = nodeid + worker
    assert handler_id not in handlers

    rel_log_dir = get_test_logdir(nodeid)
    exec_log_dir = os.path.join(rundir, rel_log_dir)
    subprocess.check_call(
        "mkdir -p {0} && chmod 1777 {0}".format(exec_log_dir), shell=True
    )
    exec_log_path = os.path.join(exec_log_dir, "exec.log")

    # Add test based exec log handler
    h = set_handler(logger, exec_log_path)
    handlers[handler_id] = h

    if worker:
        logger.info(
            "Logging on worker %s for %s into %s", worker, handler_id, exec_log_path
        )
    else:
        logger.info("Logging for %s into %s", handler_id, exec_log_path)


def logfinish(nodeid, location):
    """Called from pytest after module teardown."""
    # This function may not be called if pytest is interrupted.

    worker = os.getenv("PYTEST_TOPOTEST_WORKER", "")
    handler_id = nodeid + worker

    if handler_id in handlers:
        # Remove test based exec log handler
        if worker:
            logger.info("Closing logs for %s", handler_id)

        h = handlers[handler_id]
        logger.removeHandler(handlers[handler_id])
        h.flush()
        h.close()
        del handlers[handler_id]


console_handler = set_handler(logger, None)
set_log_level(logger, "debug")
