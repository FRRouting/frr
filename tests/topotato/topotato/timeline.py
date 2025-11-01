#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
test timeline related utilities
"""

from abc import ABC, abstractmethod
import bisect
import time
from dataclasses import dataclass

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
    Union,
)

from .defer import select
from .pcapng import Context, Block, Sink

if typing.TYPE_CHECKING:
    from .base import TopotatoItem


@dataclass
class TimingParams:
    delay: Optional[float]
    maxwait: Optional[float]
    full_history: bool = False

    _start: Callable[[], float] = time.time

    def anchor(self, anchor: Callable[[], float]):
        self._start = anchor
        return self

    def ticks(self):
        now = time.time()

        # immediate tick
        yield float("-inf")

        start = self._start()
        nexttick = start + self.delay
        deadline = start + (self.maxwait or 0.0)

        while nexttick < deadline:
            if nexttick >= now:
                yield nexttick
            nexttick += self.delay

    def evaluate(self):
        start = self._start()
        return (start, start + (self.maxwait or 0.0))


class MiniPollee(ABC):
    """
    Event receiver for topotato event loop

    Can be added on :py:class:`MiniPoller` to receive fd poll events.
    """

    @abstractmethod
    def readable(self) -> Generator["TimedElement", None, None]:
        """
        Event handler, called when file descriptor is readable.

        Should yield :py:class:`TimedElement` instances describing events that
        are happening live.
        """
        yield from []
        raise NotImplementedError()

    @abstractmethod
    def fileno(self) -> Optional[int]:
        """
        Return file descriptor to poll in event loop.

        Can return None if nothing to poll currently.
        """
        raise NotImplementedError()

    # pylint: disable=unused-argument, no-self-use
    def serialize(
        self, context: Context
    ) -> Generator[Tuple[Optional[Dict[str, Any]], Optional[Block]], None, None]:
        """
        Generate possible header blocks for this event source.

        Only pcap-ng is currently handled, dicts for JSON are thrown away.
        """
        yield from []


class MiniPoller:
    """
    Event loop for topotato.  Used when sleeping or doing I/O in tests.
    """

    pollees: List[MiniPollee]
    """
    Poll items, e.g. Log message readers and Packet receivers.
    """

    def __init__(self):
        super().__init__()
        self.pollees = []

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, self.pollees)

    def sleep(self, duration: float, final: Union[bool, Iterable[MiniPollee]] = False):
        """
        Delay for some time while processing events.

        :param final: drain events until all MiniPollees report None as fd.
        """
        for _ in self.run_iter(time.time() + duration, final=final):
            pass

    def run_tick(self, timing: TimingParams) -> Generator[int, None, None]:
        """
        Process events while generating retry "ticks" for an active check.

        Yields the retry iteration count as an integer.
        """

        for i, deadline in enumerate(timing.ticks()):
            # do polling pass first, to avoid building up backlog
            # on first iteration of this loop, nexttick = now, so no delay
            for _ in self.run_iter(deadline):
                pass

            yield i
            # caller will use break when check was sucessful

    def record(self, element: "TimedElement"):
        pass

    def run_iter(
        self, deadline=float("inf"), final: Union[bool, Iterable[MiniPollee]] = False
    ) -> Generator["TimedElement", None, None]:
        """
        Process events and yield :py:class:`TimedElement` items as they happen.

        :param deadline: maximum time to wait until, as unix timestamp.
        :param final: drain events until all MiniPollees report None as fd.
        """

        if isinstance(final, Iterable):
            _final = set(final)
        elif final is True:
            _final = set(self.pollees)
        else:
            _final = set()

        # always run at least one iteration
        first = True

        while True:
            fdmap: Dict[int, MiniPollee] = {}

            for target in self.pollees:
                fileno = target.fileno()
                if fileno is None:
                    continue
                fdmap[fileno] = target

            if final is not False and not set(fdmap.values()) & _final:
                break

            fds = list(fdmap.keys())

            timeout = max(deadline - time.time(), 0)
            if timeout == 0 and not first:
                return
            if timeout == float("inf"):
                timeout = None

            ready, _, _ = select.select(fds, [], [], timeout)
            if not ready:
                break

            for fd in ready:
                assert fd in fdmap
                for i in fdmap[fd].readable():
                    self.record(i)
                    yield i

            first = False


class TimedElement(ABC):
    """
    Abstract base for test report items.

    Sortable by timestamp, and tracks if it fulfilled some test condition.
    """

    match_for: List["TopotatoItem"]
    """
    If this object satisfied some test condition, the test item is recorded here.
    """

    def __init__(self):
        super().__init__()
        self.match_for = []

    @property
    @abstractmethod
    def ts(self) -> Tuple[float, int]:
        """
        Timestamp for this item.

        First tuple item is an absolute unix timestamp.  Second is an integer
        sequence number for relative ordering (some log messages used to have
        only second precision, so the sequence number was necessary.
        """
        raise NotImplementedError()

    @abstractmethod
    def serialize(
        self, context: Context
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Block]]:
        """
        Serialize this item for report generation.

        Result tuple is a dict for JSON plus a Block for pcap-ng output.
        """
        raise NotImplementedError()

    def __lt__(self, other):
        return self.ts < other.ts


class FrameworkEvent(TimedElement):
    typ: ClassVar[str]

    def __init__(self):
        super().__init__()
        self._ts = time.time()
        self._data = {"type": self.typ}

    @property
    def ts(self):
        return (self._ts, 0)

    def serialize(self, context: Context):
        return (self._data, None)


class _Dummy(TimedElement):
    def __init__(self, ts: float):
        super().__init__()
        self._ts = ts

    @property
    def ts(self):
        return (self._ts, 0)

    def serialize(self, context: Context):
        return (None, None)


class Timeline(MiniPoller, List[TimedElement]):
    """
    Sorted list of TimedElement|s
    """

    def record(self, element: TimedElement):
        bisect.insort(self, element)

    def serialize(self, sink: Sink) -> Tuple[List, Dict[str, Any]]:
        ret = []
        toplevel: Dict[str, Any] = {}

        for poller in self.pollees:
            for jsdata, block in poller.serialize(sink):
                if block:
                    sink.write(block)
                if jsdata:
                    for k, v in jsdata.items():
                        toplevel.setdefault(k, {}).update(v)

        for item in self:
            jsdata, block = item.serialize(sink)
            if jsdata:
                ret.append({"ts": item.ts[0], "data": jsdata})
            if block:
                sink.write(block)
        return ret, toplevel

    def iter_since(
        self, start: float = float("-inf")
    ) -> Generator[TimedElement, None, None]:
        if start == float("-inf"):
            startidx = 0
        else:
            startidx = bisect.bisect_left(self, _Dummy(start))

        yield from self[startidx:]

    def run_timing(self, timing: TimingParams) -> Generator[TimedElement, None, None]:
        start, end = timing.evaluate()

        if timing.full_history:
            yield from self.iter_since()
        else:
            yield from self.iter_since(start)
        yield from self.run_iter(end)

    def install(self, pollee: MiniPollee):
        self.pollees.append(pollee)

    def uninstall(self, pollee: MiniPollee):
        self.pollees.remove(pollee)

    class WithPollee:
        def __init__(self, poller: "Timeline", pollee: MiniPollee):
            self._poller = poller
            self._pollee = pollee

        def __enter__(self):
            self._poller.install(self._pollee)
            return self._poller

        def __exit__(self, exc_type, exc_value, tb):
            self._poller.uninstall(self._pollee)

    def with_pollee(self, pollee: MiniPollee):
        return self.WithPollee(self, pollee)
