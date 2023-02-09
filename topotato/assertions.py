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
import inspect
from collections import OrderedDict

from typing import (
    Any,
    ClassVar,
    List,
    Optional,
    Type,
    Union,
)

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore

from scapy.packet import Packet  # type: ignore
import pytest

from .utils import json_cmp, text_rich_cmp, deindent
from .base import TopotatoItem, TopotatoFunction, skiptrace
from .livescapy import TimedScapy
from .livelog import LogMessage
from .timeline import TimingParams
from .exceptions import (
    TopotatoCLICompareFail,
    TopotatoCLIUnsuccessfulFail,
    TopotatoLogFail,
    TopotatoPacketFail,
    TopotatoRouteCompareFail,
    TopotatoUnhandledArgs,
)

__all__ = [
    "AssertKernelRoutesV4",
    "AssertKernelRoutesV6",
    "AssertVtysh",
    "AssertPacket",
    "AssertLog",
    "DaemonRestart",
    "Delay",
    "ModifyLinkStatus",
    "BackgroundCommand",
    "ReconfigureFRR",
]

logger = logging.getLogger("topotato")


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
    Helper for (retry-)timing configuration.

    :param float delay: interval to retry test at, in seconds.
    :param Optional[float] maxwait: deadline until which to retry.  At least
       one attempt is made even if this deadline has already passed.

    For simplicity, the same mixin is used for active and passive timing.
    Active timing uses the delay parameter to repeat active attempts whie
    passive timing listens on received events and therefore does not use the
    delay parameter.

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

    _timing: TimingParams

    default_delay: ClassVar[Optional[float]] = None
    """
    Delay between active attempts.

    Only used for assertions that actively perform checks rather than
    listening for events.  If None, the delay parameter will not be accepted.
    """
    default_maxwait: ClassVar[Optional[float]] = None
    """
    Maximum time to wait on this assertions.
    """

    @classmethod
    def consume_kwargs(cls, kwargs):
        if cls.default_delay is None:
            if "delay" in kwargs:
                raise TopotatoUnhandledArgs(
                    "%s does not accept a delay parameter" % cls.__name__
                )

        delay = kwargs.pop("delay", cls.default_delay)
        maxwait = kwargs.pop("maxwait", cls.default_maxwait)

        timing = TimingParams(delay, maxwait)

        def finalize(self):
            # pylint: disable=protected-access
            self._timing = timing.anchor(self.relative_start)

            fn = self.getparent(TopotatoFunction)
            if fn.include_startup:
                self._timing.full_history = True

        return [finalize]

    def relative_start(self):
        fn = self.getparent(TopotatoFunction)
        return fn.started_ts


class AssertKernelRoutes(TopotatoAssertion, TimedMixin):
    """
    Common code for v4/v6 kernel routing table check.
    """

    af: ClassVar[Union[Literal[4], Literal[6]]]
    default_delay = 0.1

    # pylint does not understand that from_parent is our __init__
    _rtr: str
    _routes: dict
    _local: bool

    # pylint: disable=arguments-differ,too-many-arguments,protected-access
    @classmethod
    def from_parent(cls, parent, name, rtr, routes, *, local=False, **kwargs):
        name = "%s:%s/routes-v%d" % (name, rtr, cls.af)
        self = super().from_parent(parent, name=name, **kwargs)

        self._rtr = rtr
        self._routes = routes
        self._local = local
        return self

    def __call__(self):
        router = self.instance.routers[self._rtr]

        for _ in self.timeline.run_tick(self._timing):
            routes = router.routes(self.af, self._local)
            diff = json_cmp(routes, self._routes)
            if diff is None:
                break
        else:
            raise TopotatoRouteCompareFail(str(diff))


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

    default_delay = 0.1

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
        **kwargs,
    ):
        name = "%s:%s/%s/vtysh[%s]" % (
            name,
            rtr.name,
            daemon,
            command.replace("\n", "; "),
        )
        self = super().from_parent(parent, name=name, **kwargs)

        self._rtr = rtr
        self._daemon = daemon
        self._command = command
        self._compare = compare
        self.commands = OrderedDict()
        return self

    def __call__(self):
        router = self.instance.routers[self._rtr.name]

        for _ in self.timeline.run_tick(self._timing):
            cmdtime = time.time()
            out, rc = router.vtysh_polled(self.timeline, self._daemon, self._command)
            if rc != 0:
                result = TopotatoCLIUnsuccessfulFail("vtysh return value %d" % rc)
            else:
                result = None
                if isinstance(self._compare, type(None)):
                    pass
                elif isinstance(self._compare, str):
                    out = deindent(out, trim=True)
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
                        result = TopotatoCLICompareFail(str(diff))

            self.commands.setdefault((self._rtr.name, self._daemon), []).append(
                (cmdtime, self._command, out, rc, result)
            )

            if result is None:
                break
        else:
            raise result

    @property
    def command(self):
        return self._command

    @property
    def compare(self):
        return self._compare


class ReconfigureFRR(AssertVtysh):
    # pylint: disable=arguments-differ,too-many-arguments,protected-access
    @classmethod
    def from_parent(
        cls,
        parent,
        name,
        rtr,
        daemon,
        command,
        compare="",
        **kwargs,
    ):
        command_with_shell_enabled = "enable\nconfigure\n" + command
        name = "%s:%s/%s/vtysh[%s]" % (
            name,
            rtr.name,
            daemon,
            command_with_shell_enabled.replace("\n", "; "),
        )
        self = super().from_parent(
            parent,
            name,
            rtr,
            daemon,
            command_with_shell_enabled,
            compare,
            **kwargs,
        )
        return self


class AssertPacket(TopotatoAssertion, TimedMixin):
    # pylint does not understand that from_parent is our __init__
    _link: str
    _pkt: Any
    _argtypes: List[Type[Packet]]

    matched: Optional[Any]

    # pylint: disable=arguments-differ,protected-access
    @classmethod
    def from_parent(cls, parent, name, link, pkt, **kwargs):
        name = "%s:%s/packet" % (name, link)
        self: AssertPacket = super().from_parent(parent, name=name, **kwargs)

        self._link = link
        self._pkt = pkt
        self.matched = None

        self._argtypes = []
        argspec = inspect.getfullargspec(self._pkt)
        for arg in argspec.args:
            if arg not in argspec.annotations:
                raise TypeError(
                    "%r needs a type annotation for parameter %r" % (self._pkt, arg)
                )
            argtype = argspec.annotations[arg]
            if not issubclass(argtype, Packet):
                raise TypeError(
                    "%r argument %r (%r) is not a scapy.Packet subtype"
                    % (self._pkt, arg, argtype)
                )
            self._argtypes.append(argtype)

        return self

    def __call__(self):
        for element in self.timeline.run_timing(self._timing):
            if not isinstance(element, TimedScapy):
                continue
            pkt = element.pkt
            if pkt.sniffed_on != self._link:
                continue

            args = []
            cur_layer = pkt

            for argtype in self._argtypes:
                cur_layer = cur_layer.getlayer(argtype)
                if cur_layer is None:
                    break
                args.append(cur_layer)

            if cur_layer is None:
                continue

            if self._pkt(*args):
                self.matched = pkt
                element.match_for.append(self)
                break
        else:
            raise TopotatoPacketFail(
                "did not receive a matching packet for:\n%s"
                % inspect.getsource(self._pkt)
            )


class AssertLog(TopotatoAssertion, TimedMixin):
    # pylint does not understand that from_parent is our __init__
    _rtr: str
    _daemon: str
    _pkt: Any
    _msg = Union[re.Pattern, str]

    matched: Optional[Any]

    # pylint: disable=arguments-differ,protected-access,too-many-arguments
    @classmethod
    def from_parent(cls, parent, name, rtr, daemon, msg, **kwargs):
        name = "%s:%s/%s/log" % (name, rtr.name, daemon)
        self: AssertLog = super().from_parent(parent, name=name, **kwargs)

        self._rtr = rtr
        self._daemon = daemon
        self._msg = msg
        self.matched = None
        return self

    @skiptrace
    def __call__(self):
        for msg in self.timeline.run_timing(self._timing):
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
            detail = self._msg
            if isinstance(detail, re.Pattern):
                detail = detail.pattern
            raise TopotatoLogFail(detail)


class Delay(TopotatoAssertion, TimedMixin):
    # pylint: disable=arguments-differ,protected-access,too-many-arguments
    @classmethod
    def from_parent(cls, parent, name, **kwargs):
        name = "%s" % (name,)
        self: AssertLog = super().from_parent(parent, name=name, **kwargs)

        return self

    @skiptrace
    def __call__(self):
        for _ in self.timeline.run_timing(self._timing):
            pass


class DaemonRestart(TopotatoModifier):
    # pylint does not understand that from_parent is our __init__
    _rtr: str
    _daemon: str

    # pylint: disable=arguments-differ,protected-access
    @classmethod
    def from_parent(cls, parent, name, rtr, daemon, **kwargs):
        self: DaemonRestart = super().from_parent(
            parent, name="%s:%s/%s/restart" % (name, rtr.name, daemon), **kwargs
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
    def from_parent(cls, parent, name, rtr, iface, state, **kwargs):
        name = "%s:%s/link[%s (%s) -> %s]" % (
            name,
            rtr.name,
            iface.ifname,
            iface.other.endpoint.name,
            "UP" if state else "DOWN",
        )
        self = super().from_parent(parent, name=name, **kwargs)

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
        def from_parent(cls, parent, name, cmdobj, **kwargs):
            name = '%s:%s/exec["%s" (%s)]' % (
                name,
                cmdobj._rtr.name,
                cmdobj._cmd,
                cls.__name__,
            )
            self = super().from_parent(parent, name=name, **kwargs)

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
