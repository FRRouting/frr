#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
potatool - externally interact with topotato sessions.
"""

import os
import select
import sys
import ctypes
from ctypes.util import find_library
import shlex
import traceback
import logging
import argparse
import cmd
import atexit
import readline
import termios

from typing import (
    ClassVar,
    Optional,
)

import pyinotify  # type: ignore

from .watch import WatchedSession

# _logger = logging.getLogger("potatool" if __name__ == "__main__" else __name__)


class PotatoolSession(WatchedSession):
    """
    Potatool add-ons to WatchedSession.

    Allows the user to select a session and router by name.
    """

    want_sess: ClassVar[Optional[str]] = None
    want_rtr: ClassVar[Optional[str]] = None
    sel_sess: ClassVar[Optional["PotatoolSession"]] = None
    sel_rtr: ClassVar[Optional["PotatoolSession.Router"]] = None

    @classmethod
    def reselect(cls):
        cls.sel_ses, cls.sel_rtr = None, None

        if cls.want_sess is None:
            if len(cls.running) == 1:
                # if there is only 1 running session, it is selected by default
                cls.sel_sess = list(cls.running.values())[0]
        elif cls.want_sess in cls.running:
            cls.sel_sess = cls.running[cls.want_sess]

        if cls.sel_sess is not None:
            if cls.want_rtr in cls.sel_sess.routers:
                cls.sel_rtr = cls.sel_sess.routers[cls.want_rtr]
                if cls.sel_rtr.pid is None:
                    # never select dead router
                    cls.sel_rtr = None

    @classmethod
    def session_started(cls, inst):
        super().session_started(inst)
        cls.reselect()

    @classmethod
    def session_stopped(cls, inst):
        super().session_stopped(inst)
        cls.reselect()

    def _router_setup(self, filename):
        super()._router_setup(filename)
        self.reselect()

    def _router_teardown(self, filename):
        super()._router_teardown(filename)
        self.reselect()


# pylint: disable=no-self-use
class PotatoolShell(cmd.Cmd):
    def do_session(self, arg):
        args = shlex.split(arg)

        if len(args) == 0:
            print(f"selected session: {PotatoolSession.want_sess}")
            print(f"active session:   {PotatoolSession.sel_sess}")
            print(f"selected router:  {PotatoolSession.want_rtr}")
            print(f"active router:    {PotatoolSession.sel_rtr}")
        elif len(args) == 1:
            if args[0] in {"None", ""}:
                args[0] = None
            PotatoolSession.want_sess = args[0]
            PotatoolSession.reselect()
            if PotatoolSession.sel_sess is None:
                print(f"session {args[0]} selected, but not currently running")
        else:
            print("usage:  session [NAME]")

    def do_router(self, arg):
        args = shlex.split(arg)

        if len(args) == 0:
            print(f"selected session: {PotatoolSession.want_sess}")
            print(f"active session:   {PotatoolSession.sel_sess}")
            print(f"selected router:  {PotatoolSession.want_rtr}")
            print(f"active router:    {PotatoolSession.sel_rtr}")
            if PotatoolSession.sel_sess:
                print("routers:")
                for rtr in PotatoolSession.sel_sess.routers.keys():
                    print(f"  - {rtr}")

        elif len(args) == 1:
            if args[0] in {"None", ""}:
                args[0] = None
            PotatoolSession.want_rtr = args[0]
            PotatoolSession.reselect()

            if PotatoolSession.sel_sess is None:
                print(f"router {args[0]} selected, but no session running")
            elif PotatoolSession.sel_rtr is None:
                print(f"router {args[0]} selected, but not currently running")
        else:
            print("usage:  router [NAME]")

    def do_shell(self, arg):
        args = shlex.split(arg)

        if PotatoolSession.want_rtr is None:
            print("please select a router first.")
            return
        if PotatoolSession.sel_rtr is None:
            print("selected router {PotatoolSession.want_rtr} not currently running")
            return

        if len(args) == 0:
            args = [os.environ.get("SHELL", "/bin/sh")]

        PotatoolSession.sel_rtr.run(args)


#
# VERY HACKY CODE / WIP BEYOND THIS POINT!
#

rl_callback_fn = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
rl_command_fn = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int)

rl_name = find_library("readline")
assert rl_name is not None
libreadline = ctypes.cdll.LoadLibrary(rl_name)
libreadline.rl_callback_handler_install.argtypes = [ctypes.c_char_p, rl_callback_fn]
libreadline.rl_bind_key.argtypes = [ctypes.c_char, rl_command_fn]


def main():
    logging.basicConfig(
        format="%(asctime)s.%(msecs)03d %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        level=logging.WARNING,
    )

    argp = argparse.ArgumentParser(description="🔝🥔 interactive utility")
    argp.add_argument("-s", "--session", type=str, help="select session by name")
    argp.add_argument("-r", "--router", type=str, help="select router")
    argp.add_argument("CMD", nargs="*", help="execute potatool shell command")
    args = argp.parse_args()

    shell = PotatoolShell()

    PotatoolSession.want_sess = args.session
    PotatoolSession.want_rtr = args.router

    if args.CMD:
        # non-interactive mode
        PotatoolSession.load()
        shell.onecmd(shlex.join(args.CMD))
        sys.exit(0)

    logging.getLogger().setLevel(logging.DEBUG)

    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm)

    PotatoolSession.start_watch(wm)

    #
    # readline integration
    #

    histfile = os.path.join(os.path.expanduser("~"), ".potatool_history")

    try:
        readline.read_history_file(histfile)
        hist_len = readline.get_current_history_length()
    except FileNotFoundError:
        open(histfile, "wb").close()
        hist_len = 0

    save_termios = termios.tcgetattr(0)

    def save():
        nonlocal hist_len

        termios.tcsetattr(0, termios.TCSANOW, save_termios)

        new_hist_len = readline.get_current_history_length()
        readline.set_history_length(1000)
        readline.append_history_file(new_hist_len - hist_len, histfile)
        hist_len = new_hist_len

    atexit.register(save)

    #
    # async readline shenanigans
    #

    # libreadline.rl_initialize()
    readline.parse_and_bind("set enable-bracketed-paste off")

    running = True
    rl_input = None

    def rl_cb(textb):
        nonlocal running, rl_input

        libreadline.rl_callback_handler_remove()

        if textb is None:
            running = False
            return

        rl_input = textb.decode("UTF-8")

    rl_cbfn = rl_callback_fn(rl_cb)

    def rl_questionmark(a, ch):
        sys.stdout.write("\n")

        curline = readline.get_line_buffer()
        sys.stderr.write("autocomplete TBD, sorry :)\n")
        sys.stdout.flush()
        libreadline.rl_on_new_line()
        return 0

    rl_questionmarkfn = rl_command_fn(rl_questionmark)
    # libreadline.rl_bind_key(ord("?"), rl_questionmarkfn)

    def rl_prompt():
        if PotatoolSession.sel_sess is not None:
            state = (
                "\033[38;5;147m(\033[1;38;5;117m%s\033[0;38;5;147m)"
                % PotatoolSession.sel_sess.name
            )
            if PotatoolSession.sel_rtr is not None:
                state += (
                    " \033[38;5;118m%s \033[38;5;246m(\033[38;5;252m%d\033[38;5;246m)"
                    % (PotatoolSession.sel_rtr.name, PotatoolSession.sel_rtr.pid)
                )
            elif PotatoolSession.want_rtr is not None:
                state += " \033[1;38;5;196m%s (n/a)" % PotatoolSession.want_rtr
            else:
                state += " \033[38;5;249m..."
        else:
            state = "\033[1;38;5;208m(?)"

        p = "\033[38;5;108mtopotato\033[38;5;148m:%s\033[1;38;5;214m # \033[m" % (state)
        return p.encode("UTF-8")

    poller = select.poll()
    poller.register(0, select.POLLIN)
    poller.register(wm.get_fd(), select.POLLIN)

    _rl_prompt = rl_prompt()
    libreadline.rl_callback_handler_install(_rl_prompt, rl_cbfn)

    while running:
        ready = poller.poll()

        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        do_rl = False

        for fd, event in ready:
            if fd == wm.get_fd():
                notifier.read_events()
                notifier.process_events()
            if fd == 0:
                do_rl = True

        libreadline.rl_forced_update_display()
        if do_rl:
            libreadline.rl_callback_read_char()

        if rl_input is not None:
            if rl_input.strip() != "":
                readline.add_history(rl_input)

            try:
                shell.onecmd(rl_input)
            except:
                sys.stderr.write("while executing %r:\n" % rl_input)
                traceback.print_exc()

            _rl_prompt = rl_prompt()
            libreadline.rl_callback_handler_install(_rl_prompt, rl_cbfn)
            rl_input = None

        prev_prompt = _rl_prompt
        _rl_prompt = rl_prompt()
        if _rl_prompt != prev_prompt:
            libreadline.rl_callback_handler_remove()
            libreadline.rl_callback_handler_install(_rl_prompt, rl_cbfn)

    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
