# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# December 4 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
#
"""Utilities for logging in munet."""

import logging

from pathlib import Path


do_color = True


class MultiFileHandler(logging.FileHandler):
    """A logging handler that logs to new files based on the logger name.

    The MultiFileHandler operates as a FileHandler with additional functionality. In
    addition to logging to the specified logging file MultiFileHandler also creates new
    FileHandlers for child loggers based on a root logging name path.

    The ``root_path`` determines when to create a new FileHandler. For each received log
    record, ``root_path`` is removed from the logger name of the record if present, and
    the resulting channel path (if any) determines the directory for a new log file to
    also emit the record to. The new file path is constructed by starting with the
    directory ``filename`` resides in, then joining the path determined above after
    converting "." to "/" and finally by adding back the basename of ``filename``.

      record logger path => mutest.output.testingfoo
      root_path => mutest.output
      base filename => /tmp/mutest/mutest-exec.log
      new logfile => /tmp/mutest/testingfoo/mutest-exec.log

    All messages are also emitted to the common FileLogger for ``filename``.

    If a log record is from a logger that does not start with ``root_path`` no file is
    created and the normal emit occurs.

    Args:
        root_path: the logging path of the root level for this handler.
        new_handler_level: logging level for newly created handlers
        log_dir: the log directory to put log files in.
        filename: the base log file.
    """

    def __init__(self, root_path, filename=None, **kwargs):
        self.__root_path = root_path
        self.__basename = Path(filename).name
        if root_path[-1] != ".":
            self.__root_path += "."
        self.__root_pathlen = len(self.__root_path)
        self.__kwargs = kwargs
        self.__log_dir = Path(filename).absolute().parent
        self.__log_dir.mkdir(parents=True, exist_ok=True)
        self.__filenames = {}
        self.__added = set()

        if "new_handler_level" not in kwargs:
            self.__new_handler_level = logging.NOTSET
        else:
            new_handler_level = kwargs["new_handler_level"]
            del kwargs["new_handler_level"]
            self.__new_handler_level = new_handler_level

        super().__init__(filename=filename, **kwargs)

        if self.__new_handler_level is None:
            self.__new_handler_level = self.level

    def __log_filename(self, name):
        if name in self.__filenames:
            return self.__filenames[name]

        if not name.startswith(self.__root_path):
            newname = None
        else:
            newname = name[self.__root_pathlen :]
            newname = Path(newname.replace(".", "/"))
            newname = self.__log_dir.joinpath(newname)
            newname = newname.joinpath(self.__basename)
            self.__filenames[name] = newname

        self.__filenames[name] = newname
        return newname

    def emit(self, record):
        newname = self.__log_filename(record.name)
        if newname:
            if newname not in self.__added:
                self.__added.add(newname)
                h = logging.FileHandler(filename=newname, **self.__kwargs)
                h.setLevel(self.__new_handler_level)
                h.setFormatter(self.formatter)
                logging.getLogger(record.name).addHandler(h)
                h.emit(record)
        super().emit(record)


class ColorFormatter(logging.Formatter):
    """A formatter that adds color sequences based on level."""

    def __init__(self, fmt=None, datefmt=None, style="%", **kwargs):
        grey = "\x1b[90m"
        yellow = "\x1b[33m"
        red = "\x1b[31m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        # basefmt = " ------| %(message)s "

        self.formatters = {
            logging.DEBUG: logging.Formatter(grey + fmt + reset),
            logging.INFO: logging.Formatter(grey + fmt + reset),
            logging.WARNING: logging.Formatter(yellow + fmt + reset),
            logging.ERROR: logging.Formatter(red + fmt + reset),
            logging.CRITICAL: logging.Formatter(bold_red + fmt + reset),
        }
        # Why are we even bothering?
        super().__init__(fmt, datefmt, style, **kwargs)

    def format(self, record):
        if not do_color:
            return super().format(record)
        formatter = self.formatters.get(record.levelno)
        return formatter.format(record)


class ResultColorFormatter(logging.Formatter):
    """A formatter that colorizes PASS/FAIL strings based on level."""

    green = "\x1b[32m"
    red = "\x1b[31m"
    reset = "\x1b[0m"

    def format(self, record):
        s = super().format(record)
        if not do_color:
            return s
        idx = s.find("FAIL")
        if idx >= 0 and record.levelno > logging.INFO:
            s = s[:idx] + self.red + "FAIL" + self.reset + s[idx + 4 :]
        elif record.levelno == logging.INFO:
            idx = s.find("PASS")
            if idx >= 0:
                s = s[:idx] + self.green + "PASS" + self.reset + s[idx + 4 :]
        return s
