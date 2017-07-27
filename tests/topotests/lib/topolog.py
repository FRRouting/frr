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

import sys
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

class InfoFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno in (logging.DEBUG, logging.INFO)

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
        # Create default global logger
        self.log_level = logging.INFO
        self.logger = logging.Logger('topolog', level=self.log_level)

        handler_stdout = logging.StreamHandler(sys.stdout)
        handler_stdout.setLevel(logging.DEBUG)
        handler_stdout.addFilter(InfoFilter())
        handler_stdout.setFormatter(
            logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s')
        )
        handler_stderr = logging.StreamHandler()
        handler_stderr.setLevel(logging.WARNING)
        handler_stderr.setFormatter(
            logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s')
        )

        self.logger.addHandler(handler_stdout)
        self.logger.addHandler(handler_stderr)

        # Handle more loggers
        self.loggers = {'topolog': self.logger}

    def set_log_level(self, level):
        "Set the logging level"
        self.log_level = DEBUG_TOPO2LOGGING.get(level)
        self.logger.setLevel(self.log_level)

    def get_logger(self, name='topolog', log_level=None, target=sys.stdout):
        """
        Get a new logger entry. Allows creating different loggers for formating,
        filtering or handling (file, stream or stdout/stderr).
        """
        if log_level is None:
            log_level = self.log_level
        if self.loggers.has_key(name):
            return self.loggers[name]

        nlogger = logging.Logger(name, level=log_level)
        if isinstance(target, str):
            handler = logging.FileHandler(filename=target)
        else:
            handler = logging.StreamHandler(stream=target)

        handler.setFormatter(
            logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s')
        )
        nlogger.addHandler(handler)
        self.loggers[name] = nlogger
        return nlogger

#
# Global variables
#

logger_config = Logger()
logger = logger_config.logger
