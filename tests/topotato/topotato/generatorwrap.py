#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023  David Lamparter for NetDEF, Inc.
"""
Wrap generator functions & raise exceptions if a generator is never used.
"""

import sys
import functools
import traceback
import inspect
import gc
from types import TracebackType
from typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    List,
    Optional,
    TypeVar,
    Type,
)


class GeneratorDeletedUnused(Exception):
    """
    Exception raised from :py:meth:`GeneratorWrapper.__del__` if the generator
    never actually ran.

    Note that exceptions raised from __del__ are handled through
    sys.unraisablehook since __del__ is called asynchronously and exceptions
    are normally printed but ignored there.
    """

    origin: Iterable[str]
    """
    Formatted string traceback for the generator's call location.

    Not saving FrameInfo/related here since the frame continues executing
    after the call site and these objects would change due to that.
    """

    def __init__(self, origin: Iterable[str]):
        self.origin = origin


class GeneratorsUnused(Exception):
    """
    Accumulation of :py:class:`GeneratorDeletedUnused` when caught inside of
    :py:class:`GeneratorChecks` ``with`` context.
    """

    exceptions: List[GeneratorDeletedUnused]

    def __init__(self, exceptions: List[GeneratorDeletedUnused]):
        super().__init__()
        self.exceptions = exceptions

    def __str__(self):
        items = "\n===\n".join(
            e.origin[-1].rstrip("\n ") for e in self.exceptions
        ).replace("\n", "\n  ")
        return f'{len(self.exceptions)} generators were invoked but never executed (forgotten "yield from"?):\n  {items}'


class GeneratorChecks:
    """
    Context manager to collect raised :py:class:`GeneratorDeletedUnused`.

    Since __del__ goes to sys.unraisablehook, this context manager places
    itself into that hook for the duration of its ``with`` block.  All
    GeneratorDeletedUnused exceptions are collected and then raised at the
    end of the context.
    """

    _prev_hook: Optional[Callable[[Any], Any]] = None
    """
    Original sys.unraisablehook to restore after.
    """
    _errs: List[GeneratorDeletedUnused]
    """
    Accumulated exceptions, if any.
    """

    def __init__(self):
        self._errs = []

    def _unraisable(self, args) -> None:
        """
        Handler to be installed into sys.unraisablehook.
        """
        assert self._prev_hook

        if isinstance(args.exc_value, GeneratorDeletedUnused):
            self._errs.append(args.exc_value)
            return

        self._prev_hook(args)

    def __enter__(self):
        self._prev_hook = sys.unraisablehook
        sys.unraisablehook = self._unraisable
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        tb: Optional[TracebackType],
    ):
        assert self._prev_hook

        gc.collect()
        sys.unraisablehook = self._prev_hook
        self._prev_hook = None

        if exc_type is not None:
            return

        if not self._errs:
            return

        raise GeneratorsUnused(self._errs)


TG = TypeVar("TG")


class GeneratorWrapper(Generic[TG]):
    """
    Decorator / wrapper for generators to raise exception if it never ran.

    Use like::
        @GeneratorWrapper.apply
        def my_generator(foo):
            yield foo + 1
            yield foo - 1

    When the generator is later _called_ but not actually iterated over, it
    will raise :py:class:`GeneratorDeletedUnused` from its __del__ method.
    These should be collected like this::

        with GeneratorChecks():
            # this will result in an exception at the end of the with block
            my_generator(234)

            # this will execute normally
            for i in my_generator(123):
                print (i)
    """

    _wraps: TG
    """
    Original generator object to forward __iter__ to.
    """
    _run: bool
    """
    Has this generator actually been iterated over?  (Not necessarily to completion.)
    """
    _loc: Iterable[str]
    """
    Location of call to pass to :py:class:`GeneratorDeletedUnused`, see there.
    """

    def __init__(self, wraps: TG, loc: Iterable[str]):
        self._wraps = wraps
        self._loc = loc
        self._run = False

    def __iter__(self):
        self._run = True
        del self._loc
        return self._wraps.__iter__()

    def __del__(self):
        if self._run:
            return
        if isinstance(self._wraps, GeneratorWrapper):
            self._wraps._run = True
        raise GeneratorDeletedUnused(self._loc)

    @classmethod
    def apply(cls, function: Callable[..., TG]) -> Callable[..., TG]:
        """
        Decorator to be used on generator functions.
        """
        if isinstance(function, (classmethod, staticmethod)):
            raise RuntimeError(
                "@GeneratorWrapper.apply must come after @classmethod/@staticmethod"
            )
        if not inspect.isgeneratorfunction(function):
            raise RuntimeError("@GeneratorWrapper.apply must be used on a generator")

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            loc = traceback.format_stack(inspect.currentframe().f_back)
            return cls(function(*args, **kwargs), loc)

        return wrapper
