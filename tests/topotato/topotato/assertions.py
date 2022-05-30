#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Assertions (and Modifiers) to use in topotato tests:
"""
# pylint: disable=too-many-ancestors

import os
import sys
import time
import json
import logging
import tempfile
import re
from collections import OrderedDict

from typing import (
    Any,
    ClassVar,
    List,
    Optional,
    Tuple,
    Union,
)

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore

import pytest

from .utils import json_cmp, text_rich_cmp
from .base import TopotatoItem, TopotatoInstance, skiptrace
from .livelog import LogMessage
from .pdmlpacket import PDMLPacket
from .exceptions import (
    TopotatoCLICompareFail,
    TopotatoCLIUnsuccessfulFail,
    TopotatoLogFail,
    TopotatoPacketFail,
    TopotatoRouteCompareFail,
)

__all__ = [
    "AssertKernelRoutesV4",
    "AssertKernelRoutesV6",
    "AssertVtysh",
    "AssertPacket",
    "AssertLog",
    "DaemonRestart",
    "ModifyLinkStatus",
    "BackgroundCommand",
]

logger = logging.getLogger("topotato")
logger.setLevel(logging.DEBUG)


class TopotatoAssertion(TopotatoItem):
    """
    Common base for assertions (test items that do NOT modify state)
    """


class TopotatoModifier(TopotatoItem):
    """
    Common base for modifiers (test items that DO modify state)

    The intention here is to allow the framework to distinguish whether some
    item is a dependency for future assertions.  If an assertion fails, the
    test continues.  If a modifier fails, the remainder of the test is skipped.
    """


class TimedMixin:
    """
    Documentation helper for timing configuration.

    :param float delay: interval to retry test at, in seconds.
    :param Optional[float] maxwait: deadline until which to retry.  At least
       one attempt is made even if this deadline has already passed.

    .. caution::

       The ``maxwait`` parameter is a deadline anchored at **starting up the
       test network for this test class**, not the particular test (which is
       what topotests did.)

       This is generally what's needed for tests:  something is supposed to
       have converted by X time after the test environment was started up.

       The distinction is particularly important when a test is indeed failing:
       two consecutive tests with the same deadline will *not* make topotato
       wait twice that amount, the wait on the first test will have depleted
       the maxwait for the second and only one attempt will be made that.
    """

    _delay: float
    _maxwait: Optional[float]


class AssertKernelRoutes(TopotatoAssertion, TimedMixin):
    """
    Common code for v4/v6 kernel routing table check.
    """

    af: ClassVar[Union[Literal[4], Literal[6]]]

    # pylint does not understand that from_parent is our __init__
    _rtr: str
    _routes: dict
    _local: bool

    # pylint: disable=arguments-differ,too-many-arguments,protected-access
    @classmethod
    def from_parent(
        cls, parent, name, rtr, routes, *, local=False, delay=0.1, maxwait=None
    ):
        name = "%s:%s/routes-v%d" % (name, rtr, cls.af)
        self = super().from_parent(parent, name=name)

        self._rtr = rtr
        self._routes = routes
        self._local = local
        self._delay = delay
        self._maxwait = maxwait
        return self

    def __call__(self):
        router = self.instance.routers[self._rtr]
        start = time.time()

        while True:
            routes = router.routes(self.af, self._local)
            diff = json_cmp(routes, self._routes)
            if diff is None:
                break

            if self._maxwait is None or time.time() - start > self._maxwait:
                raise TopotatoRouteCompareFail(diff)

            self.sleep(step=self._delay, until=self._maxwait)


class AssertKernelRoutesV4(AssertKernelRoutes):
    """
    Retrieve IPv4 routing table from kernel and compare against reference.

    .. py:method:: make(rtr, routes, *, local=False, delay=0.1, maxwait=None)
       :classmethod:

       Generate a test item to verify the kernel IPv4 routing table matches
       some expectation.

       :param Union[str, .toponom.Router] rtr: Router to retrieve routes from.
          Either a string router name or a :py:class:`toponom.Router` object is
          acceptable.
       :param Dict[str, Any] routes: Expected routes.  Dictionary may include
          JSONCompare flags like :py:class:`.utils.JSONCompareIgnoreContent`.
       :param local: include ``local`` table / system routes.
    """

    # mypy issue 8796 workaround - repeat the type
    af: ClassVar[Union[Literal[4], Literal[6]]]
    af = 4


class AssertKernelRoutesV6(AssertKernelRoutes):
    """
    Same as :py:class:`AssertKernelRoutesV4`, but for IPv6.
    """

    # mypy issue 8796 workaround - repeat the type
    af: ClassVar[Union[Literal[4], Literal[6]]]
    af = 6


class AssertVtysh(TopotatoAssertion, TimedMixin):
    commands: OrderedDict

    # pylint does not understand that from_parent is our __init__
    _rtr: str
    _daemon: str
    _command: str
    _compare: Optional[str]

    # pylint: disable=arguments-differ,too-many-arguments,protected-access
    @classmethod
    def from_parent(
        cls,
        parent,
        name,
        rtr,
        daemon,
        command,
        compare=None,
        *,
        delay=0.1,
        maxwait=None
    ):
        name = '%s:%s/%s/vtysh "%s"' % (
            name,
            rtr.name,
            daemon,
            command.replace("\n", "; "),
        )
        self = super().from_parent(parent, name=name)

        self._rtr = rtr
        self._daemon = daemon
        self._command = command
        self._compare = compare
        self._delay = delay
        self._maxwait = maxwait
        self.commands = OrderedDict()
        return self

    def __call__(self):
        router = self.instance.routers[self._rtr.name]
        start = time.time()

        while True:
            cmdtime = time.time()
            out, rc = router.vtysh_fast(self._daemon, self._command)
            if rc != 0:
                result = TopotatoCLIUnsuccessfulFail("vtysh return value %d" % rc)
            else:
                result = None
                if isinstance(self._compare, type(None)):
                    pass
                elif isinstance(self._compare, str):
                    result = text_rich_cmp(
                        self.instance.configs,
                        self._rtr.name,
                        out,
                        self._compare,
                        "output from %s" % (self._command),
                    )
                elif isinstance(self._compare, dict):
                    diff = json_cmp(json.loads(out), self._compare)
                    if diff is not None:
                        result = TopotatoCLICompareFail(diff)

            self.commands.setdefault((self._rtr.name, self._daemon), []).append(
                (cmdtime, self._command, out, rc, result)
            )

            if result is None:
                return

            if self._maxwait is None or time.time() - start > self._maxwait:
                print("# %s" % self._command)
                print(out)
                print("-----")
                raise result
            self.sleep(
                step=self._delay - ((time.time() - start) % self._delay),
                until=self._maxwait,
            )

    @property
    def command(self):
        return self._command

    @property
    def compare(self):
        return self._compare


class AssertPacket(TopotatoAssertion):
    # pylint does not understand that from_parent is our __init__
    _link: str
    _pkt: Any
    _maxwait: Optional[float]

    matched: Optional[Any]

    # pylint: disable=arguments-differ,protected-access
    @classmethod
    def from_parent(cls, parent, name, link, pkt, *, maxwait=None):
        name = "%s:%s/packet" % (name, link)
        self: AssertPacket = super().from_parent(parent, name=name)

        self._link = link
        self._pkt = pkt
        self._maxwait = maxwait
        self.matched = None
        return self

    def __call__(self):
        netinst = self.getparent(TopotatoInstance).netinst

        for _, pkt in netinst.poller.run_iter(time.time() + self._maxwait):
            if not isinstance(pkt, PDMLPacket):
                continue
            if pkt["frame/.interface_id/frame.interface_name"].val != self._link:
                continue
            try:
                if self._pkt(pkt):
                    self.matched = pkt
                    pkt.match_for.append(self)
                    break
            except KeyError:
                pass
        else:
            raise TopotatoPacketFail("no pkt")


class AssertLog(TopotatoAssertion):
    # pylint does not understand that from_parent is our __init__
    _rtr: str
    _daemon: str
    _pkt: Any
    _maxwait: Optional[float]
    _msg = Union[re.Pattern, str]

    matched: Optional[Any]

    # pylint: disable=arguments-differ,protected-access,too-many-arguments
    @classmethod
    def from_parent(cls, parent, name, rtr, daemon, msg, *, maxwait=None):
        name = "%s:%s/%s/log" % (name, rtr.name, daemon)
        self: AssertLog = super().from_parent(parent, name=name)

        self._rtr = rtr
        self._daemon = daemon
        self._msg = msg
        self._maxwait = maxwait
        self.matched = None
        return self

    @skiptrace
    def __call__(self):
        # inst = self.getparent(TopotatoInstance)
        deadline = time.time() + self._maxwait

        for _, msg in self.instance.poller.run_iter(deadline):
            if not isinstance(msg, LogMessage):
                continue

            text = msg.text
            if isinstance(self._msg, re.Pattern):
                m = self._msg.match(text)
                if not m:
                    continue
            else:
                if text.find(self._msg) == -1:
                    continue

            self.matched = msg
            msg.match_for.append(self)
            break
        else:
            raise TopotatoLogFail(self._msg)


class DaemonRestart(TopotatoModifier):
    # pylint does not understand that from_parent is our __init__
    _rtr: str
    _daemon: str

    # pylint: disable=arguments-differ,protected-access
    @classmethod
    def from_parent(cls, parent, name, rtr, daemon):
        self: DaemonRestart = super().from_parent(
            parent, name="%s:%s.%s/restart" % (name, rtr.name, daemon)
        )
        self._rtr = rtr
        self._daemon = daemon
        return self

    def runtest(self):
        if self.skipall:
            pytest.skip(self.skipall)

        router = self.instance.routers[self._rtr.name]
        router.restart(self._daemon)


class ModifyLinkStatus(TopotatoModifier):
    _rtr: Any
    _iface: str
    _state: bool

    # pylint: disable=arguments-differ,protected-access,too-many-arguments
    @classmethod
    def from_parent(cls, parent, name, rtr, iface, state):
        name = "%s:%s/link %s (%s) -> %s" % (
            name,
            rtr.name,
            iface.ifname,
            iface.other.endpoint.name,
            "UP" if state else "DOWN",
        )
        self = super().from_parent(parent, name=name)

        self._rtr = rtr
        self._iface = iface
        self._state = state
        return self

    def __call__(self):
        router = self.instance.routers[self._rtr.name]
        router.link_set(self._iface, self._state)


class BackgroundCommand:
    """
    run sth in bg
    """

    def __init__(self, rtr, cmd):
        self._rtr = rtr
        self._cmd = cmd

    class Action(TopotatoModifier):
        _rtr: str
        _cmdobj: "BackgroundCommand"

        # pylint: disable=arguments-differ,protected-access
        @classmethod
        def from_parent(cls, parent, name, cmdobj):
            name = '%s:%s/exec "%s" (%s)' % (
                name,
                cmdobj._rtr.name,
                cmdobj._cmd,
                cls.__name__,
            )
            self = super().from_parent(parent, name=name)

            self._rtr = cmdobj._rtr
            self._cmdobj = cmdobj
            return self

    class Start(Action):
        # pylint: disable=consider-using-with
        def __call__(self):
            router = self.instance.routers[self._rtr.name]

            ifd = open("/dev/null", "rb")
            self._cmdobj.tmpfile = tmpfile = tempfile.TemporaryFile()

            self._cmdobj.proc = router.popen(
                ["/bin/sh", "-c", self._cmdobj._cmd],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                stdin=ifd,
                stdout=tmpfile,
                stderr=tmpfile,
            )

    class Wait(Action):
        def __call__(self):
            ret = self._cmdobj.proc.wait()
            self._cmdobj.tmpfile.seek(0)
            output = self._cmdobj.tmpfile.read().decode("UTF-8")
            del self._cmdobj.tmpfile
            sys.stdout.write(output)

            if ret != 0:
                raise ValueError("nonzero exit: %s!" % ret)

    @skiptrace
    def start(self):
        yield from self.Start.make(self)

    @skiptrace
    def wait(self):
        yield from self.Wait.make(self)
