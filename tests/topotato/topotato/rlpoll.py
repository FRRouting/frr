#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
readline polled/async "bindings"

The functions necessary for using readline in a poll loop aren't exposed by
Python's readline module :(

Now you would think one could just put this in a separate thread, but... no.
The place that breaks is when you want to erase the prompt / current input
in order to process some events / write log messages, and then redisplay the
prompt.
"""
# pylint: disable=global-statement

import sys
import ctypes
from ctypes.util import find_library
import readline  # pylint: disable=unused-import

from typing import Callable, Optional

_rl_callback_fn = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
_rl_command_fn = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int)

_rl_lib = find_library("readline")
if _rl_lib is None:
    _rl_lib = find_library("edit")
if _rl_lib is None:
    raise ImportError("failed to load libreadline/libedit")

_libreadline = ctypes.cdll.LoadLibrary(_rl_lib)
_libreadline.rl_callback_handler_install.argtypes = [ctypes.c_char_p, _rl_callback_fn]
_libreadline.rl_bind_key.argtypes = [ctypes.c_char, _rl_command_fn]
_libreadline.rl_set_prompt.argtypes = [ctypes.c_char_p]

_c_lib = find_library("c")
if _c_lib is None:
    raise ImportError("failed to load libc")

_libc = ctypes.cdll.LoadLibrary(_c_lib)
_libc.fflush.argtypes = [ctypes.c_void_p]
_libc_stdout = ctypes.c_void_p.in_dll(_libc, "stdout")

# keep a reference to the callback function.  This is absolutely crucial
# because we're giving a pointer to rl_callback_handler_install, but that
# does NOT hold a reference - so Python may deallocate the object!
_cb_handler = None


def callback_handler_install(prompt: str, callback: Callable[[Optional[str]], None]):
    global _cb_handler

    fn_wrap = _rl_callback_fn(callback)
    promptb = prompt.encode(sys.stdout.encoding)
    _libreadline.rl_callback_handler_install(promptb, fn_wrap)
    _cb_handler = fn_wrap


def callback_handler_remove():
    global _cb_handler

    _libreadline.rl_callback_handler_remove()
    _cb_handler = None


def callback_read_char():
    _libreadline.rl_callback_read_char()


def set_prompt(prompt: str):
    promptb = prompt.encode(sys.stdout.encoding)
    _libreadline.rl_set_prompt(promptb)


def on_new_line():
    _libreadline.rl_on_new_line()


def clear_visible_line():
    if hasattr(_libreadline, "rl_clear_visible_line"):
        _libreadline.rl_clear_visible_line()
        _libc.fflush(_libc_stdout)
    else:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


def forced_update_display():
    _libreadline.rl_forced_update_display()


def redisplay():
    _libreadline.rl_redisplay()
