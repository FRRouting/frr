#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Exceptions for use in topotato pytest integration
"""

from _pytest.outcomes import Exit, Failed, Skipped


# actual test failures


class TopotatoFail(Failed):
    """
    Actual failures from topotato tests that stem from a check coded in the
    real test.
    """


class TopotatoCLICompareFail(TopotatoFail):
    """
    CLI output is not what we expected.
    """


class TopotatoCLIUnsuccessfulFail(TopotatoFail):
    """
    CLI command returned nonzero return code (VTY_WARNING & co.)
    """


class TopotatoRouteCompareFail(TopotatoFail):
    """
    Routes in the kernel are not what they should be.
    """


class TopotatoPacketFail(TopotatoFail):
    """
    Expected packet not seen.
    """


class TopotatoLogFail(TopotatoFail):
    """
    Expected log message not seen.
    """


class TopotatoDaemonCrash(TopotatoFail):
    """
    Daemon exited/crashed unexpectedly.
    """


# hard testrun aborts


class TopotatoExit(Exit):
    """
    System errors that aren't test failures and should abort the testrun
    """


class TopotatoEnvProblem(TopotatoExit):
    """
    Something's not quite set up correctly
    """


# skip reasons


class TopotatoSkipped(Skipped):
    """
    Decided not to run test for some reason
    """


class TopotatoNoOSSupport(TopotatoSkipped):
    """
    OS does not support necessary feature
    """


class TopotatoEarlierFailSkip(TopotatoSkipped):
    """
    Earlier test failed & caused skip of remaining tests
    """
