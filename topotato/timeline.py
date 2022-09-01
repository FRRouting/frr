#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
test timeline related utilities
"""

from abc import ABC, abstractmethod, abstractproperty
import bisect
import time
import select

import typing
from typing import List, Iterable, Tuple, Callable, Generator, Optional, Dict, Any
from .pcapng import Context, Block, Sink

if typing.TYPE_CHECKING:
    from .base import TopotatoItem

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

    def serialize(self, context: Context) -> Generator[Tuple[Optional[Dict[str, Any]], Optional[Block]], None, None]:
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

    def sleep(self, duration: float, final=False):
        """
        Delay for some time while processing events.

        :param final: drain events until all MiniPollees report None as fd.
        """
        for _ in self.run_iter(time.time() + duration, final=final):
            pass

    def run_iter(self, deadline=float("inf"), final=False) -> Generator["TimedElement", None, None]:
        """
        Process events and yield :py:class:`TimedElement` items as they happen.

        :param deadline: maximum time to wait until, as unix timestamp.
        :param final: drain events until all MiniPollees report None as fd.
        """

        # always run at least one iteration
        first = True

        while True:
            fdmap: Dict[int, MiniPollee] = {}
            for target in self.pollees:
                fileno = target.fileno()
                if fileno is None:
                    continue
                fdmap[fileno] = target

            if final and not fdmap:
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
                yield from fdmap[fd].readable()

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

    @abstractproperty
    def ts(self) -> Tuple[float, int]:
        """
        Timestamp for this item.

        First tuple item is an absolute unix timestamp.  Second is an integer
        sequence number for relative ordering (some log messages used to have
        only second precision, so the sequence number was necessary.
        """
        raise NotImplementedError()

    @abstractmethod
    def serialize(self, context: Context) -> Tuple[Optional[Dict[str, Any]], Optional[Block]]:
        """
        Serialize this item for report generation.

        Result tuple is a dict for JSON plus a Block for pcap-ng output.
        """
        raise NotImplementedError()

    def __lt__(self, other):
        return self.ts < other.ts


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

    def __init__(self):
        super().__init__()

    def record(self, element: TimedElement):
        bisect.insort(self, element)

    def serialize(self, sink: Sink):
        ret = []

        for poller in self.pollees:
            for _, block in poller.serialize(sink):
                if block:
                    sink.write(block)

        for item in self:
            jsdata, block = item.serialize(sink)
            if jsdata:
                ret.append({'ts': item.ts[0], 'data': jsdata})
            if block:
                sink.write(block)
        return ret

    def iter_since(self, start: float = float('-inf')) -> Generator[TimedElement, None, None]:
        if start == float('-inf'):
            startidx = 0
        else:
            startidx = bisect.bisect_left(self, _Dummy(start))

        yield from self[startidx:]

    def run_iter(self, deadline=float("inf"), final=False, check_after: Optional[float] = None) -> Generator[TimedElement, None, None]:
        if check_after is not None:
            yield from self.iter_since(check_after)

        for item in super().run_iter(deadline, final):
            self.record(item)
            yield item

    def install(self, pollee: MiniPollee):
        self.pollees.append(pollee)

    def uninstall(self, pollee: MiniPollee):
        self.pollees.remove(pollee)
