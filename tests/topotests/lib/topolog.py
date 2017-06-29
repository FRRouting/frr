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

# Helper dictionary to convert Topogen logging levels to Python's logging.
DEBUG_TOPO2LOGGING = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'output': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
}

#
# Logger class definition
#

class Logger(object):
    """
    Logger class that encapsulates logging functions, internaly it uses Python
    logging module with a separated instance instead of global.

    Default logging level is 'info'.
    """

    def __init__(self):
        self.logger = logging.Logger('topolog', level=logging.INFO)
        self.handler = logging.StreamHandler()
        self.handler.setFormatter(
            logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s')
        )
        self.logger.addHandler(self.handler)

    def set_log_level(self, level):
        "Set the logging level"
        self.logger.setLevel(DEBUG_TOPO2LOGGING.get(level))

#
# Global variables
#

logger_config = Logger()
logger = logger_config.logger
