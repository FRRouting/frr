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


set_handler(logger, None)
set_log_level(logger, "debug")
