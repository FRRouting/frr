#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Base classes for topotato tests and test items, as well as startup/shutdown
"""

import os
import inspect
from collections import OrderedDict
import time
import subprocess
import signal
import logging
from abc import ABC, abstractmethod

import typing
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
)

# from typing_extensions import Literal

import pytest
import _pytest
from _pytest import nodes

# from _pytest.mark.structures import Mark

from .exceptions import TopotatoFail
from .liveshark import LiveShark

if typing.TYPE_CHECKING:
    from topotato.frr import FRRNetworkInstance

logger = logging.getLogger("topotato")
logger.setLevel(logging.DEBUG)


class _SkipTrace(set):
    """
    get calling code location while skipping over specific functions

    create an instance (skiptrace = _SkipTrace()) below, then use that
    instance as decorator (without braces at the end!).

    get_caller will return the calling stack frame while skipping over
    functions annotated with the decorator
    """

    def __call__(self, origfn):
        fn = origfn
        while not hasattr(fn, "__code__") and hasattr(fn, "__func__"):
            fn = getattr(fn, "__func__")
        self.add(fn.__code__)
        return origfn

    def get_caller(self) -> Optional[inspect.FrameInfo]:
        stack = inspect.stack()
        for s in stack[1:]:
            if s.frame.f_code not in self:
                caller = s
                break
        else:
            del stack
            raise IndexError("cannot locate caller")

        del stack
        return caller


skiptrace = _SkipTrace()


class TimedElement(ABC):
    @abstractmethod
    def ts(self):
        raise NotImplementedError()

    @abstractmethod
    def html(self, ts_start):
        raise NotImplementedError()

    def __lt__(self, other):
        return self.ts() < other.ts()


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class TopotatoItem(nodes.Item):
    """
    base class for test "items" - asserts, route checks, etc.

    this is heavily pytest-specific machinery.  dragons may be involved.
    """

    plaintext_arg: ClassVar[Optional[str]] = None

    # location in test source this is created from
    _codeloc: Optional[inspect.FrameInfo]

    _request: _pytest.fixtures.FixtureRequest
    _fixtureinfo: _pytest.fixtures.FuncFixtureInfo
    fixturenames: Any
    funcargs: Dict[str, Any]

    _obj: "TestBase"
    instance: "FRRNetworkInstance"

    # TBD: replace/rework skipping functionality
    skipall = None

    # pylint: disable=protected-access
    @classmethod
    def from_parent(
        cls: Type["TopotatoItem"], parent: nodes.Node, *args, **kw
    ) -> "TopotatoItem":
        if args:
            raise ValueError("leftover arguments: %r" % args)
        self: TopotatoItem = cast("TopotatoItem", super().from_parent(parent, **kw))

        tparent = self.getparent(TopotatoClass)
        assert tparent is not None

        self._obj = tparent.obj

        self._fixtureinfo = self.session._fixturemanager.getfixtureinfo(
            self, self._obj, cls, funcargs=False
        )
        self.fixturenames = self._fixtureinfo.names_closure
        self.funcargs = {}
        self._request = _pytest.fixtures.FixtureRequest(self, _ispytest=True) # type: ignore

        self.add_marker(pytest.mark.usefixtures(self._obj.instancefn.__name__))
        return self

    @skiptrace
    @classmethod
    def make(
        cls: Type["TopotatoItem"], *args, **kwargs
    ) -> Generator[Optional["TopotatoItem"], Tuple["TopotatoClass", str], None]:
        caller = skiptrace.get_caller()
        assert caller is not None
        yield from cls._make("#%d" % (caller.lineno), caller, *args, **kwargs)

    @skiptrace
    @classmethod
    def _make(
        cls: Type["TopotatoItem"], namesuffix, codeloc, *args, **kwargs
    ) -> Generator[Optional["TopotatoItem"], Tuple["TopotatoClass", str], None]:

        parent, name = yield None
        self = cls.from_parent(parent, name + namesuffix, *args, **kwargs)
        self._codeloc = codeloc
        yield self

    def setup(self):
        super().setup()

        self._request._fillfixtures()
        self.instance = self.funcargs[self._obj.instancefn.__name__]

    def runtest(self):
        if self.skipall:
            pytest.skip(self.skipall)
        self()  # pylint: disable=not-callable

    def sleep(self, step, until):
        abs_until = time.time() + until  # XXX TODO
        for _ in self.parent.liveshark.run(step, abs_until):
            pass

    def reportinfo(self):  # -> Tuple[Union[py.path.local, str], int, str]:
        fspath = self._codeloc.filename
        lineno = self._codeloc.lineno
        return fspath, lineno, self.name

    def repr_failure(self, excinfo, style=None):
        if not hasattr(self, "_codeloc"):
            return super().repr_failure(excinfo)

        if isinstance(excinfo.value, _pytest.fixtures.FixtureLookupError):
            return excinfo.value.formatrepr()

        class FakeTraceback:
            def __init__(self, codeloc, nexttb):
                self.tb_frame = codeloc.frame
                self.tb_lineno = codeloc.lineno
                self.tb_next = nexttb

        ftb = FakeTraceback(self._codeloc, excinfo.traceback[0]._rawentry)
        excinfo.traceback.insert(0, _pytest._code.code.TracebackEntry(ftb))

        if self.config.getoption("fulltrace", False):
            style = "long"
        elif isinstance(excinfo.value, TopotatoFail):
            excinfo.traceback = _pytest._code.Traceback([excinfo.traceback[0]])
            style = "long"
        else:
            tb = _pytest._code.Traceback([excinfo.traceback[-1]])
            excinfo.traceback = excinfo.traceback.filter(_pytest._code.filter_traceback)
            if len(excinfo.traceback) == 0:
                excinfo.traceback = tb
            if style in ["auto", None]:
                style = "long"

        # see comment in pytest
        Path = _pytest.pathlib.Path
        try:
            abspath = Path(os.getcwd()) != Path(str(self.config.invocation_dir))
        except OSError:
            abspath = True

        return excinfo.getrepr(
            funcargs=True,
            abspath=abspath,
            showlocals=self.config.getoption("showlocals", False),
            style=style,
            tbfilter=False,
            truncate_locals=True,
        )


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class InstanceStartup(TopotatoItem):
    commands: OrderedDict

    # pylint: disable=arguments-differ
    @classmethod
    def from_parent(cls, parent):
        self = super().from_parent(parent, name="startup")
        return self

    def reportinfo(self):
        fspath, _, _ = self.parent.parent.reportinfo()
        return fspath, float("-inf"), "startup"

    def runtest(self):
        if self.skipall:
            pytest.skip(self.skipall)

        self.parent.starting_ts = time.time()

        self.instance.start()
        time.sleep(0.2)
        # self.instance.status()

        self.commands = OrderedDict()

        failed = []
        for rtr in self.instance.network.routers.keys():
            router = self.instance.routers[rtr]

            for daemon in self.instance.configs.daemons:
                if not self.instance.configs.want_daemon(rtr, daemon):
                    continue

                out, rc = router.vtysh_fast(daemon, "show version")
                self.commands.setdefault((rtr, daemon), []).append(
                    ("show version", out, rc, None)
                )
                if rc != 0:
                    failed.append((rtr, daemon))

        if len(failed) > 0:
            raise ValueError("daemons failed to start: %r" % failed)

        # let tshark decode in the background (otherwise it adds a few seconds
        # during shutdown to dump everything)
        self.parent.pcap_tail_f = None
        self.parent.tshark_proc = None
        pdml_rd = None

        # pylint: disable=consider-using-with
        if getattr(self.instance, "pcapfile", None):
            for _ in range(0, 10):
                if os.path.exists(self.instance.pcapfile):
                    break
                time.sleep(0.025)

            pcap_rd, pcap_wr = os.pipe()
            pdml_rd, pdml_wr = os.pipe()

            self.parent.pcap_tail_f = subprocess.Popen(
                ["tail", "-f", "-c", "+0", self.instance.pcapfile],
                stdout=pcap_wr,
            )
            self.parent.tshark_proc = subprocess.Popen(
                ["tshark", "-r", "-", "-q", "-l", "-T", "pdml"],
                stdout=pdml_wr,
                stdin=pcap_rd,
            )

            os.close(pcap_rd)
            os.close(pcap_wr)
            os.close(pdml_wr)

        self.parent.started_ts = time.time()
        self.parent.liveshark = LiveShark(pdml_rd, self.parent.started_ts)


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class InstanceShutdown(TopotatoItem):
    # pylint: disable=arguments-differ
    @classmethod
    def from_parent(cls, parent):
        self = super().from_parent(parent, name="shutdown")
        return self

    def reportinfo(self):
        fspath, _, _ = self.parent.parent.reportinfo()
        return fspath, float("inf"), "shutdown"

    def runtest(self):
        if self.skipall:
            pytest.skip(self.skipall)

        self.instance.stop()

        if self.parent.pcap_tail_f:
            self.parent.pcap_tail_f.send_signal(signal.SIGINT)
            self.parent.pcap_tail_f.wait()

            assert self.parent.tshark_proc

            for _ in self.parent.liveshark.run(15.0, expect_eof=True):
                pass

            if self.parent.tshark_proc.wait() != 0:
                logger.error("tshark nonzero exit")
            self.parent.liveshark.close()


class TestBase:
    instancefn: ClassVar[Callable[..., "FRRNetworkInstance"]]

    @classmethod
    def _topotato_makeitem(cls, collector, name, obj):
        if cls is TestBase:
            return []
        return [TopotatoClass.from_hook(obj, collector, name=name)]

class TopotatoWrapped:
    def __wrapped__(self):
        pass

    def __init__(self, wrap, call = None):
        assert inspect.isgeneratorfunction(wrap)

        self._wrap = wrap
        self._call = call or wrap

    def __get__(self, obj, objtype=None):
        return self.__class__(self._wrap, self._call.__get__(obj, objtype))

    def __call__(self, *args, **kwargs):
        return self._call(*args, **kwargs)

    def _topotato_makeitem(self, collector, name, obj):
        return list(collector._topotato_child(name, obj))


def topotatofunc(fn):
    """
    decorator to mark methods as item-yielding test generators

    (TBD: just use @TopotatoWrapped directly?)
    """
    return TopotatoWrapped(fn)


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class TopotatoInstance(_pytest.python.Instance):
    obj: TestBase
    parent: "TopotatoClass"

    def collect(self):
        yield InstanceStartup.from_parent(self)
        yield from super().collect()
        yield InstanceShutdown.from_parent(self)

    # pytest 6.0.x => _makeitem()
    # pytest 6.2.x => _genfunctions()

    @skiptrace
    def _topotato_child(
        self, name: str, obj: object
    ) -> Union[
        None, nodes.Item, nodes.Collector, List[Union[nodes.Item, nodes.Collector]]
    ]:
        assert isinstance(obj, TopotatoWrapped)

        # obj contains unbound methods; get bound instead
        method = getattr(self.obj, name)
        assert callable(method)

        topo = self.parent.obj.instancefn.net

        argspec = inspect.getfullargspec(method._call).args[2:]
        args = []
        for argname in argspec:
            args.append(topo.routers[argname])

        iterator = method(topo, *args)

        tests = []
        sendval = None
        try:
            while True:
                value = iterator.send(sendval)
                if value is not None:
                    logger.debug("collect on: %r test: %r", self, value)
                    tests.append(value)
                sendval = (self, name)
        except StopIteration:
            pass

        return tests


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class TopotatoClass(_pytest.python.Class):
    _instance: TopotatoInstance
    _obj: Type[TestBase]

    # pylint: disable=protected-access
    @classmethod
    def from_hook(cls, obj, collector, name):
        self = super().from_parent(collector, name=name)
        self._obj = obj

        for fixture in getattr(self._obj, "use", []):
            self.add_marker(pytest.mark.usefixtures(fixture))

        self.add_marker(pytest.mark.usefixtures(self._obj.instancefn.__name__))
        return self

    def collect(self) -> Iterable[Union[nodes.Item, nodes.Collector]]:
        self._inject_setup_class_fixture()
        self._inject_setup_method_fixture()
        self._instance = TopotatoInstance.from_parent(self, name="()")
        return [self._instance]
