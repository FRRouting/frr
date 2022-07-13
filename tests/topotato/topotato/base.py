#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
topotato is designed as a heavily custom extension to pytest.  The core
aspects of this are defined in this module (:py:mod:`topotato.base`).
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

import pytest
import _pytest
from _pytest import nodes

# from _pytest.mark.structures import Mark

from .exceptions import (
    TopotatoFail,
    TopotatoEarlierFailSkip,
    TopotatoDaemonCrash,
)
from .liveshark import LiveShark, LiveScapy
from .utils import ClassHooks

if typing.TYPE_CHECKING:
    from topotato.frr import FRRNetworkInstance

logger = logging.getLogger("topotato")
logger.setLevel(logging.DEBUG)


class _SkipTrace(set):
    """
    Get calling code location while skipping over specific functions.

    Create an instance (cf. :py:data:`skiptrace`), then use that instance as
    decorator (without braces at the end!).
    """

    def __call__(self, origfn):
        fn = origfn
        while not hasattr(fn, "__code__") and hasattr(fn, "__func__"):
            fn = getattr(fn, "__func__")
        self.add(fn.__code__)
        return origfn

    def __repr__(self):
        # this is pretty much just for sphinx/autodoc
        return "<%s.%s>" % (self.__class__.__module__, self.__class__.__name__)

    def get_callers(self) -> List[inspect.FrameInfo]:
        """
        :return: the calling stack frames left after skipping over functions
           annotated with this decorator.
        """
        stack = inspect.stack()
        stack.pop(0)

        while stack and stack[0].frame.f_code in self:
            stack.pop(0)

        if not stack:
            raise IndexError("cannot locate caller")
        return stack


skiptrace = _SkipTrace()
"""
Decorator for use in topotato logic to make tracebacks more useful.

Functions/methods annotated with this decorator will be left out when printing
backtraces.  Most :py:mod:`topotato.assertions` code should use this since the
inner details of how a topotato assertion works are not normally what you want
to debug when a test fails.

.. todo::

   Add a testrun/pytest option that disables this, for bug hunting in topotato
   itself.
"""


class TimedElement(ABC):
    """
    Abstract base for test report items.

    Sortable by timestamp, and possibly with a HTML conversion function.
    """

    def __init__(self):
        super().__init__()
        self.match_for = []

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
class TopotatoItem(nodes.Item, ClassHooks):
    """
    pytest base class for test "items" - asserts, route checks, etc.

    This is heavily pytest-specific machinery.  Dragons may be involved.  You
    should NOT ever see this class directly in a topotato test source file.
    The various assertions are subclasses of this, and instances are handed
    to pytest to do its thing.
    """

    _codeloc: Optional[inspect.FrameInfo]
    """
    Test source code location that resulted in the creation of this item.
    Filtered heavily to condense down useful information.
    """

    # pytest dragons -- before touching, check what these mean to pytest!
    _request: _pytest.fixtures.FixtureRequest
    _fixtureinfo: _pytest.fixtures.FuncFixtureInfo
    fixturenames: Any
    funcargs: Dict[str, Any]

    _obj: "TestBase"
    """
    The test source instance which this item has resulted from, i.e. an
    instance of WhateverTestClass defined in test_something.py
    """

    instance: "FRRNetworkInstance"
    """
    Running network instance this item belongs to.
    """

    # TBD: replace/rework skipping functionality
    skipall = None

    # pylint: disable=protected-access
    @classmethod
    def from_parent(
        cls: Type["TopotatoItem"], parent: nodes.Node, *args, **kw
    ) -> "TopotatoItem":
        """
        pytest's replacement for the constructor.  Supposedly less fragile.

        Do not call this directly, use :py:meth:`make`.
        """

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

        _kwargs = {}
        if (
            "_ispytest"
            in inspect.getfullargspec(_pytest.fixtures.FixtureRequest).kwonlyargs
        ):
            # work around warning - TBD: find a better way to do this?
            _kwargs["_ispytest"] = True
        self._request = _pytest.fixtures.FixtureRequest(self, **_kwargs)  # type: ignore

        self.add_marker(pytest.mark.usefixtures(self._obj.instancefn.__name__))
        return self

    @skiptrace
    @classmethod
    def make(
        cls: Type["TopotatoItem"], *args, **kwargs
    ) -> Generator[Optional["TopotatoItem"], Tuple["TopotatoClass", str], None]:
        """
        Core plumbing to create an actual test item.

        All topotato tests should be the result of the main test source file
        invoking a whole bunch of::

           yield from SomeSubclass.make(...)

        Note that this is a generator and calling it without a yield from won't
        do anything useful.  args/kwargs are passed along to the actual test.
        """

        callers = skiptrace.get_callers()
        assert callers

        location = ""
        while callers:
            module = inspect.getmodule(callers[0].frame)
            if not module or module.__name__.startswith("topotato."):
                break
            caller = callers.pop(0)
            location = "#%d%s" % (caller.lineno, location)
        del callers

        # ordering of test items is based on caller here, so we need to go
        # with the topmost or we end up reordering things in a weird way.
        yield from cls._make(location, caller, *args, **kwargs)

    @skiptrace
    @classmethod
    def _make(
        cls: Type["TopotatoItem"], namesuffix, codeloc, *args, **kwargs
    ) -> Generator[Optional["TopotatoItem"], Tuple["TopotatoClass", str], None]:

        parent, _ = yield None
        self = cls.from_parent(parent, namesuffix, *args, **kwargs)
        self._codeloc = codeloc
        yield self

    def setup(self):
        """
        Called by pytest in the "setup" stage (pytest_runtest_setup)
        """
        super().setup()

        self._request._fillfixtures()
        self.instance = self.funcargs[self._obj.instancefn.__name__]

    @skiptrace
    def runtest(self):
        """
        Called by pytest in the "call" stage (pytest_runtest_call)
        """
        testinst = self.getparent(TopotatoInstance)
        if testinst.skipall:
            raise TopotatoEarlierFailSkip() from testinst.skipall
        # pylint: disable=not-callable
        self()

    def sleep(self, step=None, until=None):
        obj = self
        while getattr(obj, "started_ts", None) is None:
            obj = obj.parent

        abs_until = obj.started_ts + (until or float("inf"))
        abs_delay = time.time() + (step or float("inf"))
        deadline = min(abs_until, abs_delay)

        tinst = self.getparent(TopotatoInstance)
        tinst.netinst.poller.sleep(deadline - time.time())

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
    """
    Test pseudo-item to start up topology.

    Includes starting tshark and checking all daemons are running.
    """

    commands: OrderedDict

    # pylint: disable=arguments-differ
    @classmethod
    def from_parent(cls, parent):
        assert isinstance(parent, TopotatoInstance)

        self = super().from_parent(parent, name="startup")
        return self

    def reportinfo(self):
        fspath, _, _ = self.getparent(TopotatoClass).reportinfo()
        return fspath, float("-inf"), "startup"

    def runtest(self):
        try:
            self.parent.do_start(self)
        except TopotatoFail as e:
            self.parent.skipall = e
            raise


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class InstanceShutdown(TopotatoItem):
    """
    Test pseudo-item to shut down topology.

    As part of shut down, tshark is stopped / the pcap file is closed in an
    orderly fashion (otherwise you get truncated pcap files.)
    """

    # pylint: disable=arguments-differ
    @classmethod
    def from_parent(cls, parent):
        assert isinstance(parent, TopotatoInstance)

        self = super().from_parent(parent, name="shutdown")
        return self

    def reportinfo(self):
        fspath, _, _ = self.getparent(TopotatoClass).reportinfo()
        return fspath, float("inf"), "shutdown"

    def runtest(self):
        self.parent.do_stop(self)


class TestBase:
    """
    Base class for all topotato tests.

    Everything implementing a topotato test must derive from this base.  It
    doesn't need to be direct, i.e. further subclassing is possible.
    """

    instancefn: ClassVar[Callable[..., "FRRNetworkInstance"]]
    """
    Network instance/topology fixture (required.)

    This must be set to the :py:func:`topotato.fixtures.instance_fixture`
    decorated network instance setup function for this test.  This normally
    looks something like this::

       @instance_fixture()
       def testenv(configs):
           return FRRNetworkInstance(configs.topology, configs).prepare()

       class MyTest(TestBase):
           instancefn = testenv

    With ``configs`` again referring to a configuration fixture and so on.
    """

    @classmethod
    def _topotato_makeitem(cls, collector, name, obj):
        """
        Primary topotato pytest integration.

        topotato's pytest collection hook
        (:py:func:`topotato.pytestintegration.pytest_pycollect_makeitem`)
        checks for the existence of this method;  its existence is the initial
        entry point to the topotato pytest integration machinery.  Everything
        else happens as a result of this, because we return
        :py:class:`TopotatoClass` here, rather than the
        :py:class:`_pytest.python.Class` you would normally get from pytest.
        """
        if cls is TestBase:
            return []
        return [TopotatoClass.from_hook(obj, collector, name=name)]


class TopotatoWrapped:
    """
    Marker-type method wrapper to signal a method as topotato test.

    .. note::

       Understanding what this does is not particularly important/helpful for
       comprehending topotato as a whole, this is just necessary low-level
       Python plumbing without huge consequences.

    This is a bit more complicated than would be immediately apparent because
    we're wrapping a *method*, not a *function*.  Thing is, methods are
    initially defined as unbound functions, and then become bound methods when
    dereferenced by accessing them through an instance.

    The way Python handles this is that the method actually gets a descriptor
    object in the class, with a __get__ on it that does the method binding
    mentioned above.  So when you do ``obj.foobar``, there's an intermediate
    step through ``obj.foobar.__get__(obj, objtype)``.

    This class basically replicates that, but keeps returning instances of
    itself until you actually call the method.  The starting point is a
    decorated class definition along the lines of::

       class A:
           @TopotatoWrapped
           def something(self, args):
               pass

    After this, ``A.someting`` is an instance of TopotatoWrapped with
    :py:attr:`_wrap` set to the original (unbound) definition of ``something``
    and :py:attr:`_call` the same.

    When you start working with instances, e.g.::

       a = A()
       a.something(args)

    First, nothing happens on creating the instance.  But ``a.something`` (note
    the missing ``()``, so the function call isn't happening yet) results in
    :py:meth:`__get__` being called.  That returns a new instance of
    TopotatoWrapped with the same :py:attr:`_wrap`, but :py:attr:`_call` is
    updated to now point to the *bound* method (which we get transitively from
    the original ``__get__``.)  Finally, the function call is routed through
    :py:meth:`__call__` and passed onto the bound method.

    Ultimately, this gives us a properly working *method* wrapper that we
    can stick other things on - like :py:meth:`_topotato_makeitem`, which sets
    up topotato test items for functions annotated this way.
    """

    def __init__(self, wrap, call=None):
        assert inspect.isgeneratorfunction(wrap)

        self._wrap = wrap
        self._call = call or wrap
        self.__wrapped__ = call or wrap

    def __get__(self, obj, objtype=None):
        return self.__class__(self._wrap, self._call.__get__(obj, objtype))

    def __call__(self, *args, **kwargs):
        return self._call(*args, **kwargs)

    # pylint: disable=protected-access,no-self-use
    def _topotato_makeitem(self, collector, name, obj):
        """
        topotato pytest integration.

        Refer to :py:meth:`TestBase._topotato_makeitem`, this is the method
        level equivalent of that.
        """
        return [TopotatoFunction.from_hook(obj, collector, name)]


def topotatofunc(fn):
    """
    Decorator to mark methods as item-yielding test generators.

    .. todo::

       Just decorate with :py:class:`TopotatoWrapped` directly?  A class as
       decorator does look a bit weird though...
    """
    return TopotatoWrapped(fn)


class TopotatoFunction(nodes.Collector, _pytest.python.PyobjMixin):
    # pylint: disable=protected-access
    @classmethod
    def from_hook(cls, obj, collector, name):
        self = super().from_parent(collector, name=name)
        self._obj = obj._call
        self._obj_raw = obj

        return self

    @skiptrace
    def collect(
        self,
    ) -> Union[
        None, nodes.Item, nodes.Collector, List[Union[nodes.Item, nodes.Collector]]
    ]:
        assert isinstance(self.parent, TopotatoInstance)

        # obj contains unbound methods; get bound instead
        method = getattr(self.parent.obj, self.name)
        assert callable(method)

        tcls = self.getparent(TopotatoClass)
        assert tcls is not None
        topo = tcls.obj.instancefn.net

        # pylint: disable=protected-access
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
                sendval = (self, self.name)
        except StopIteration:
            pass

        return tests


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class TopotatoInstance(_pytest.python.Instance):
    """
    pytest representation/handle to an instance of a test class.

    This is created (somewhat implicitly) by pytest to get a handle on an
    instance of a test-defining class.
    """

    obj: TestBase
    """
    The actual instance of our test class.
    """
    parent: "TopotatoClass"
    """
    Parent in the pytest sense, in this case the class definition.
    """

    skipall: Optional[Exception]

    starting_ts: float
    started_ts: float
    liveshark: LiveShark
    netinst: "FRRNetworkInstance"
    pcap_tail_f: Optional[subprocess.Popen]
    tshark_proc: Optional[subprocess.Popen]

    # pylint: disable=protected-access
    @classmethod
    def from_parent(
        cls: Type["TopotatoInstance"], parent: nodes.Node, *args, **kw
    ) -> "TopotatoInstance":
        self = super().from_parent(parent, *args, **kw)

        self.skipall = None

        self.pcap_tail_f = None
        self.tshark_proc = None
        return self

    def collect(self):
        """
        Tell pytest our test items, in this case adding startup/shutdown.

        Note that the various methods in the class are still collected using
        standard pytest logic.  However, the :py:func:`topotatofunc` decorator
        will cause methods to have a ``_topotato_makeitem`` attribute, which
        then replaces the :py:class:`_pytest.python.Function` with the
        topotato assertions defined for the test.
        """
        yield InstanceStartup.from_parent(self)
        yield from super().collect()
        yield InstanceShutdown.from_parent(self)

    def do_start(self, startitem):
        if self.skipall:
            pytest.skip(self.skipall)

        self.starting_ts = time.time()

        self.netinst = netinst = startitem.instance

        netinst.start()
        netinst.poller.sleep(0.2)
        # netinst.status()

        startitem.commands = OrderedDict()

        failed = []
        for rtr in netinst.network.routers.keys():
            router = netinst.routers[rtr]

            for daemon in netinst.configs.daemons:
                if not netinst.configs.want_daemon(rtr, daemon):
                    continue

                try:
                    out, rc = router.vtysh_fast(daemon, "show version")
                except ConnectionRefusedError:
                    failed.append((rtr, daemon))
                startitem.commands.setdefault((rtr, daemon), []).append(
                    ("show version", out, rc, None)
                )
                if rc != 0:
                    failed.append((rtr, daemon))

        if len(failed) > 0:
            netinst.poller.sleep(0)
            raise TopotatoDaemonCrash("daemons failed to start: %r" % failed)

        # let tshark decode in the background (otherwise it adds a few seconds
        # during shutdown to dump everything)
        pdml_rd = None

        # pylint: disable=consider-using-with
        if getattr(netinst, "pcapfile", None):
            for _ in range(0, 10):
                if os.path.exists(netinst.pcapfile):
                    break
                time.sleep(0.025)

            pcap_rd, pcap_wr = os.pipe()
            pdml_rd, pdml_wr = os.pipe()

            self.pcap_tail_f = subprocess.Popen(
                ["tail", "-f", "-c", "+0", netinst.pcapfile],
                stdout=pcap_wr,
            )
            self.tshark_proc = subprocess.Popen(
                ["tshark", "-r", "-", "-q", "-l", "-T", "pdml"],
                stdout=pdml_wr,
                stdin=pcap_rd,
            )

            os.close(pcap_rd)
            os.close(pcap_wr)
            os.close(pdml_wr)

        self.started_ts = time.time()
        self.liveshark = LiveShark(pdml_rd, self.started_ts)
        netinst.poller.append(self.liveshark)

        self.livescapy = LiveScapy(netinst, self.started_ts)
        netinst.poller.append(self.livescapy)

    def do_stop(self, stopitem):
        netinst = stopitem.instance

        netinst.stop()

        if self.pcap_tail_f:
            self.pcap_tail_f.send_signal(signal.SIGINT)
            self.pcap_tail_f.wait()

            self.liveshark.expect_eof = True

        for router in netinst.routers.values():
            for daemonlog in router.livelogs.values():
                daemonlog.close_prep()

        netinst.poller.sleep(2, final=True)  # FIXME

        if self.tshark_proc:
            if self.tshark_proc.wait(timeout=2.0) != 0:
                logger.error("tshark nonzero exit")
            self.liveshark.close()


# false warning on get_closest_marker()
# pylint: disable=abstract-method
class TopotatoClass(_pytest.python.Class):
    """
    Representation of a test class definition.

    :py:meth:`TestBase._topotato_makeitem` results in topotato tests getting
    one of this here rather than the regular :py:class:`_pytest.python.Class`.
    This allows us to customize behavior.
    """

    _instance: TopotatoInstance
    _obj: Type[TestBase]

    # pylint: disable=protected-access
    @classmethod
    def from_hook(cls, obj, collector, name):
        self = super().from_parent(collector, name=name)
        self._obj = obj

        # TODO: automatically add a bunch of markers for test requirements.
        for fixture in getattr(self._obj, "use", []):
            self.add_marker(pytest.mark.usefixtures(fixture))

        self.add_marker(pytest.mark.usefixtures(self._obj.instancefn.__name__))
        return self

    def collect(self) -> Iterable[Union[nodes.Item, nodes.Collector]]:
        """
        Tell pytest our test items, in this case making a
        :py:class:`TopotatoInstance`.
        """
        # invoke some pytest fixture magic that we'd lose here otherwise.
        self._inject_setup_class_fixture()
        self._inject_setup_method_fixture()
        self._instance = TopotatoInstance.from_parent(self, name="()")
        return [self._instance]
