#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Exceptions for use in topotato pytest integration
"""

import attr
from typing import Optional

from _pytest.outcomes import Exit, Failed, Skipped

from _pytest._code import ExceptionInfo
from _pytest._code.code import TerminalRepr
from _pytest._io import TerminalWriter


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

    def __init__(self, daemon: str, router: str, cmdline: Optional[str] = None):
        self.daemon = daemon
        self.router = router
        self.cmdline = cmdline
        super().__init__()

    def __str__(self):
        if self.cmdline:
            return f"{self.router}/{self.daemon}: {self.cmdline}"
        return f"{self.router}/{self.daemon}"

    @attr.s(eq=False, auto_attribs=True)
    class TopotatoRepr(TerminalRepr):
        excinfo: "TopotatoDaemonCrash"

        def toterminal(self, tw: TerminalWriter) -> None:
            exc = self.excinfo.value
            tw.line("")
            tw.sep(" ", f"{exc.daemon} crashed on {exc.router}", red=True, bold=True)
            if exc.cmdline:
                tw.line("")
                tw.line(f"started as: {exc.cmdline}")
            if exc.__cause__ is not None:
                tw.line("")
                tw.line(f"cause: {exc.__cause__!r}")


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


# test coding errors


class TopotatoUnhandledArgs(TypeError):
    """
    Unexpected arguments in "yield from AssertXyz.make()"
    """
