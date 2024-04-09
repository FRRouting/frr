# SPDX-License-Identifier: MIT
#
# Copyright (c) 2010-2017 Benjamin Peterson
#

#
# This code is taken from the six python2 to python3 compatibility module
#

import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3


def add_metaclass(metaclass):
    """Class decorator for creating a class with a metaclass."""

    def wrapper(cls):
        orig_vars = cls.__dict__.copy()
        slots = orig_vars.get("__slots__")
        if slots is not None:
            if isinstance(slots, str):
                slots = [slots]
            for slots_var in slots:
                orig_vars.pop(slots_var)
        orig_vars.pop("__dict__", None)
        orig_vars.pop("__weakref__", None)
        return metaclass(cls.__name__, cls.__bases__, orig_vars)

    return wrapper


if PY3:
    import builtins

    exec_ = getattr(builtins, "exec")

    def reraise(tp, value, tb=None):
        try:
            if value is None:
                value = tp()
            if value.__traceback__ is not tb:
                raise value.with_traceback(tb)
            raise value
        finally:
            value = None
            tb = None


else:

    def exec_(_code_, _globs_=None, _locs_=None):
        """Execute code in a namespace."""
        if _globs_ is None:
            frame = sys._getframe(1)
            _globs_ = frame.f_globals
            if _locs_ is None:
                _locs_ = frame.f_locals
            del frame
        elif _locs_ is None:
            _locs_ = _globs_
        exec("""exec _code_ in _globs_, _locs_""")

    exec_(
        """def reraise(tp, value, tb=None):
    try:
        raise tp, value, tb
    finally:
        tb = None
"""
    )
