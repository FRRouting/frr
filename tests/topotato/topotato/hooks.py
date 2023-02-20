#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Hooks defined and used by topotato.
"""
# pylint: disable=unused-argument,unused-import

from typing import Callable
import typing

from pytest import hookspec, hookimpl

from .utils import EnvcheckResult

if typing.TYPE_CHECKING:
    from .base import TopotatoItem


@hookspec()
def pytest_topotato_envcheck(session, result: EnvcheckResult):
    pass


@hookspec()
def pytest_topotato_run(item: "TopotatoItem", testfunc: Callable):
    pass


@hookspec()
def pytest_topotato_failure(item: "TopotatoItem", excinfo, excrepr, codeloc):
    pass
