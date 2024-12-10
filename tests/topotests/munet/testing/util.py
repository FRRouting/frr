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
import functools
import logging
import sys
import time

from ..base import BaseMunet
from ..cli import async_cli


# =================
# Utility Functions
# =================


async def async_pause_test(desc=""):
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
    asyncio.run(async_pause_test(desc))


<<<<<<< HEAD
def retry(retry_timeout, initial_wait=0, expected=True):
=======
def retry(retry_timeout, initial_wait=0, retry_sleep=2, expected=True):
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    """decorator: retry while functions return is not None or raises an exception.

    * `retry_timeout`: Retry for at least this many seconds; after waiting
                       initial_wait seconds
    * `initial_wait`: Sleeps for this many seconds before first executing function
<<<<<<< HEAD
=======
    * `retry_sleep`: The time to sleep between retries.
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    * `expected`: if False then the return logic is inverted, except for exceptions,
                  (i.e., a non None ends the retry loop, and returns that value)
    """

    def _retry(func):
        @functools.wraps(func)
        def func_retry(*args, **kwargs):
<<<<<<< HEAD
            retry_sleep = 2

            # Allow the wrapped function's args to override the fixtures
=======
            # Allow the wrapped function's args to override the fixtures
            _retry_sleep = float(kwargs.pop("retry_sleep", retry_sleep))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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
<<<<<<< HEAD
                    ret = func(*args, **kwargs)
                    if _expected and ret is None:
                        logging.debug("Function succeeds")
                        return ret
                    logging.debug("Function returned %s", ret)
                except Exception as error:
                    logging.info("Function raised exception: %s", str(error))
=======
                    try:
                        ret = func(*args, seconds_left=seconds_left, **kwargs)
                    except TypeError as error:
                        if "seconds_left" not in str(error):
                            raise
                        ret = func(*args, **kwargs)

                    logging.debug("Function returned %s", ret)

                    positive_result = ret is None
                    if _expected == positive_result:
                        logging.debug("Function succeeds")
                        return ret
                except Exception as error:
                    logging.info('Function raised exception: "%s"', error)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
                    ret = error

                if seconds_left < 0:
                    logging.info("Retry timeout of %ds reached", _retry_timeout)
                    if isinstance(ret, Exception):
                        raise ret
                    return ret

                logging.info(
                    "Sleeping %ds until next retry with %.1f retry time left",
<<<<<<< HEAD
                    retry_sleep,
                    seconds_left,
                )
                time.sleep(retry_sleep)
=======
                    _retry_sleep,
                    seconds_left,
                )
                time.sleep(_retry_sleep)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

        func_retry._original = func  # pylint: disable=W0212
        return func_retry

    return _retry
