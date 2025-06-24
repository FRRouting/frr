# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# April 22 2022, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2022, LabN Consulting, L.L.C
#
"""Utility functions useful when using munet testing functionailty in pytest."""
import asyncio
import datetime
import fcntl
import functools
import logging
import os
import re
import select
import sys
import time

from ..base import BaseMunet
from ..base import Timeout
from ..cli import async_cli


# =================
# Utility Functions
# =================


async def async_pause_test(desc=""):
    """Pause the running of a test offering options for CLI or PDB."""
    isatty = sys.stdout.isatty()
    if not isatty:
        desc = f" for {desc}" if desc else ""
        logging.info("NO PAUSE on non-tty terminal%s", desc)
        return

    while True:
        if desc:
            print(f"\n== PAUSING: {desc} ==")
        try:
            user = input('PAUSED, "cli" for CLI, "pdb" to debug, "Enter" to continue: ')
        except EOFError:
            print("^D...continuing")
            break
        user = user.strip()
        if user == "cli":
            await async_cli(BaseMunet.g_unet)
        elif user == "pdb":
            breakpoint()  # pylint: disable=W1515
        elif user:
            print(f'Unrecognized input: "{user}"')
        else:
            break


def pause_test(desc=""):
    """Pause the running of a test offering options for CLI or PDB."""
    asyncio.run(async_pause_test(desc))


def retry(
    retry_timeout, initial_wait=0, retry_sleep=2, expected=True, assert_is_except=True
):
    """Retry decorated function until it returns None, raises an exception, or timeout.

    * `retry_timeout`: Retry for at least this many seconds; after waiting
                       initial_wait seconds
    * `initial_wait`: Sleeps for this many seconds before first executing function
    * `retry_sleep`: The time to sleep between retries.
    * `expected`: if False then the return logic is inverted, except for exceptions,
                  (i.e., a non None ends the retry loop, and returns that value)
    * `assert_is_except`: If True (the default) then an AssertionError raised by the
                         wrapped function will be treated as an excpetion. If False then
                         an assertion raised by the wrapped fucntion is treated as
                         non-None result it is treated as an exception. This is
                         important for handling the expected=False case. Exceptions are
                         always treated as failures even when expected is False.
    """

    def _retry(func):
        @functools.wraps(func)
        def func_retry(*args, **kwargs):
            # Allow the wrapped function's args to override the fixtures
            _assert_is_except = kwargs.pop("assert_is_except", assert_is_except)
            _retry_sleep = float(kwargs.pop("retry_sleep", retry_sleep))
            _retry_timeout = kwargs.pop("retry_timeout", retry_timeout)
            _expected = kwargs.pop("expected", expected)
            _initial_wait = kwargs.pop("initial_wait", initial_wait)
            retry_until = datetime.datetime.now() + datetime.timedelta(
                seconds=_retry_timeout + _initial_wait
            )

            if initial_wait > 0:
                logging.info("Waiting for [%s]s as initial delay", initial_wait)
                time.sleep(initial_wait)

            while True:
                seconds_left = (retry_until - datetime.datetime.now()).total_seconds()
                try:
                    try:
                        try:
                            ret = func(*args, seconds_left=seconds_left, **kwargs)
                        except TypeError as error:
                            if "seconds_left" not in str(error):
                                raise
                            ret = func(*args, **kwargs)
                    except AssertionError as error:
                        if _assert_is_except:
                            raise
                        logging.info('Function returned assertion: "%s"', error)
                        ret = error
                    else:
                        logging.debug("Function returned %s", ret)

                    positive_result = ret is None
                    if _expected == positive_result:
                        logging.debug("Function succeeds")
                        return ret
                except Exception as error:
                    logging.info('Function raised exception: "%s"', error)
                    ret = error

                if seconds_left < 0:
                    logging.info("Retry timeout of %ds reached", _retry_timeout)
                    if isinstance(ret, Exception):
                        raise ret
                    return ret

                logging.info(
                    "Sleeping %ds until next retry with %.1f retry time left",
                    _retry_sleep,
                    seconds_left,
                )
                time.sleep(_retry_sleep)

        func_retry._original = func  # pylint: disable=W0212
        return func_retry

    return _retry


def readline(f, timeout=None):
    """Read a line or timeout.

    This function will take over the file object, the file object should not be used
    outside of calling this function once you begin.

    Return: A line, remaining buffer if EOF (subsequent calls will return ""), or None
    for timeout.
    """
    fd = f.fileno()
    if not hasattr(f, "munet_non_block_set"):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        f.munet_non_block_set = True
        f.munet_lines = []
        f.munet_buf = ""

    if f.munet_lines:
        return f.munet_lines.pop(0)

    timeout = Timeout(timeout)
    remaining = timeout.remaining()
    while remaining > 0:
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return None

        c = f.read()
        if c is None:
            logging.error("munet readline: unexpected None during read")
            return None

        if not c:
            logging.debug("munet readline: got eof")
            c = f.munet_buf
            f.munet_buf = ""
            return c

        f.munet_buf += c
        while "\n" in f.munet_buf:
            a, f.munet_buf = f.munet_buf.split("\n", 1)
            f.munet_lines.append(a + "\n")

        if f.munet_lines:
            return f.munet_lines.pop(0)

        remaining = timeout.remaining()
    return None


def waitline(f, regex, timeout=120):
    """Match a regex within lines from a file with a timeout.

    This function will take over the file object (by calling `readline` above), the file
    object should not be used outside of calling these functions once you begin.

    Return: the match object or None.
    """
    timeo = Timeout(timeout)
    while not timeo.is_expired():
        line = readline(f, timeo.remaining())
        if line is None:
            break

        if line == "":
            logging.warning("waitline: got eof while matching '%s'", regex)
            return None

        assert line[-1] == "\n"
        line = line[:-1]
        if not line:
            continue

        logging.debug("waitline: searching: '%s' for '%s'", line, regex)
        m = re.search(regex, line)
        if m:
            logging.debug("waitline: matched '%s'", m.group(0))
            return m

    logging.warning(
        "Timeout while getting output matching '%s' within %ss (actual %ss)",
        regex,
        timeout,
        timeo.elapsed(),
    )
    return None
