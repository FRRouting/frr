#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
potatool - externally interact with topotato sessions.
"""

import os
import select
import sys
import inspect
import shlex
import re
import traceback
import logging
import argparse
import subprocess
import atexit
import readline
import termios
import pickle
import binascii

import typing
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Union,
    Optional,
)

import pyinotify  # type: ignore

from .watch import WatchedSession
from .interactive import Interactive
from .utils import deindent
from . import rlpoll


def typing_is_optional(hint):
    if typing.get_origin(hint) is not Union:
        return hint, False

    uargs = typing.get_args(hint)
    optional = type(None) in uargs
    if optional:
        uargs = tuple(i for i in uargs if i is not type(None))
    return Union[uargs], optional


class CLIError(Exception):
    def __init__(self, text):
        super().__init__(text)
        self.text = text


def cli_cmd(name: Optional[str] = None):
    def decorate(func):
        _name = name
        if _name is None:
            while getattr(func, "__func__", None):
                func = func.__func__
            assert func.__name__.startswith("do_")
            _name = func.__name__[3:]
        func.potatool_cli = {
            "name": _name,
        }
        return func

    return decorate


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
        cls.sel_sess, cls.sel_rtr = None, None

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

    #
    # CLI glue
    #

    cli: Dict[str, Callable[..., Any]] = {}
    remap = {
        "?": "help",
        "!": "shell",
    }

    @classmethod
    def clisetup(cls):
        for item in cls.__dict__.values():
            cliopts = getattr(item, "potatool_cli", None)
            if cliopts is None:
                continue
            cls.cli[cliopts["name"]] = item

    @classmethod
    def do(cls, command: str):
        words = shlex.split(command)

        if not words:
            return None
        cmdname = words.pop(0)
        cmdname = cls.remap.get(cmdname, cmdname)

        if cmdname in cls.cli:
            return cls.apply(cmdname, cls.cli[cmdname], words)

        candidates = [item for item in cls.cli.items() if item[0].startswith(cmdname)]
        if len(candidates) == 1:
            cmdname, cmd = candidates[0]
        elif not candidates:
            raise CLIError(f"no such command: {cmdname!r}")
        else:
            m = "".join([f"\n\t{ item[0] }" for item in candidates])
            raise CLIError(f"ambiguous command: {cmdname!r}\npossible matches:{m}")

        return cls.apply(cmdname, cmd, words)

    @classmethod
    def _fillkwargs(cls, cmdname, argspec, hints):
        kwargs = {}
        for kwname in argspec.kwonlyargs:
            hint = hints.get(kwname)
            hint, optional = typing_is_optional(hint)

            if isinstance(hint, type) and issubclass(hint, cls.Router):
                if optional and cls.sel_rtr is None:
                    kwargs[kwname] = None
                    continue
                if PotatoolSession.sel_rtr is None:
                    raise CLIError(f"{cmdname!r} needs a router selected and active.")
                kwargs[kwname] = cls.sel_rtr

        return kwargs

    @classmethod
    def _fillargs(cls, cmdname, argspec, hints, args):
        argv = []
        todo = argspec.args
        while todo:
            arg = todo.pop(0)
            hint = hints.get(arg)
            hint, optional = typing_is_optional(hint)
            origin = typing.get_origin(hint)

            if optional and not args:
                break
            if origin in [List, list]:
                argv.append(args)
                args = []
                break
            if origin in [str, None]:
                if not args:
                    raise CLIError(f"missing {arg!r} parameter")
                argv.append(args.pop(0))
                continue

            raise CLIError(f"unknown arg type for {arg!r}")

        if args:
            raise CLIError(f"too many arguments for {cmdname!r}: {args!r}")

        return argv

    # pylint: disable=unnecessary-dunder-call
    @classmethod
    def apply(cls, cmdname, cmd, args):
        if isinstance(cmd, (classmethod, staticmethod)):
            cmd = cmd.__get__(None, cls)
        elif cls.sel_sess is None:
            raise CLIError(f"{cmdname} needs a session selected and active.")
        else:
            cmd = cmd.__get__(cls.sel_sess, cls)

        argspec = inspect.getfullargspec(cmd)
        if inspect.ismethod(cmd):
            argspec.args.pop(0)
        hints = typing.get_type_hints(cmd)

        kwargs = cls._fillkwargs(cmdname, argspec, hints)
        argv = cls._fillargs(cmdname, argspec, hints, args)

        return cmd(*argv, **kwargs)

    #
    # CLI functions
    #

    @cli_cmd()
    @classmethod
    def do_help(cls):
        """
        This help text.
        """
        sys.stdout.write("available commands:\n\n")
        for name, cmd in sorted(cls.cli.items()):
            helptext = cmd.__doc__ or "(no help available)"
            helptext = deindent(helptext).strip().replace("\n", "\n" + 20 * " ")
            sys.stdout.write("%-19s %s\n" % (name, helptext))
        sys.stdout.write("\n")

    @cli_cmd()
    @classmethod
    def do_session(cls, name: Optional[str] = None):
        """
        Select a topotato session.
        Not necessary if only one topotato session is running.
        """

        if name is None:
            print(f"selected session: {PotatoolSession.want_sess}")
            print(f"active session:   {PotatoolSession.sel_sess}")
            print(f"selected router:  {PotatoolSession.want_rtr}")
            print(f"active router:    {PotatoolSession.sel_rtr}")
            return

        if name in {"None", ""}:
            name = None
        PotatoolSession.want_sess = name
        PotatoolSession.reselect()

        if name is None:
            return
        if PotatoolSession.sel_sess is None:
            print(f"session {name} selected, but not currently running")

    # pylint: disable=no-self-use
    @cli_cmd()
    def do_router(self, name: Optional[str] = None):
        """
        Select a router in the current session.
        Most commands require a router be selected.
        """
        if name is None:
            print(f"selected session: {PotatoolSession.want_sess}")
            print(f"active session:   {PotatoolSession.sel_sess}")
            print(f"selected router:  {PotatoolSession.want_rtr}")
            print(f"active router:    {PotatoolSession.sel_rtr}")
            if PotatoolSession.sel_sess:
                print("routers:")
                for rtr in PotatoolSession.sel_sess.routers.keys():
                    print(f"  - {rtr}")
            return

        if name in {"None", ""}:
            name = None
        PotatoolSession.want_rtr = name
        PotatoolSession.reselect()

        if name is None:
            return
        if PotatoolSession.sel_sess is None:
            print(f"router {name} selected, but no session running")
        elif PotatoolSession.sel_rtr is None:
            print(f"router {name} selected, but not currently running")

    def _run(self, router, command):
        try:
            router.run(command)
            return 0
        except subprocess.CalledProcessError as e:
            sys.stderr.write(
                f"{shlex.join(command)}: exited with status {e.returncode}\n"
            )
            return e.returncode

    @cli_cmd()
    def do_shell(self, command: List[str], *, router: "PotatoolSession.Router"):
        """
        Run a command in currently selected router.
        If no command is specified, start user's shell (SHELL env var).
        """
        if not command:
            command = [os.environ.get("SHELL", "/bin/sh")]

        return self._run(router, command)

    @cli_cmd()
    def do_topo(self):
        """
        Show currently running topology.
        """
        if "nom" not in self.state:
            raise CLIError("session topology unavailable")

        nom = pickle.loads(binascii.a2b_base64(self.state["nom"]))
        Interactive.show_diagram(nom, sys.stdout)

    @cli_cmd()
    def do_addrs(self):
        """
        Show interfaces/addresses in currently running topology.
        """
        if "nom" not in self.state:
            raise CLIError("session topology unavailable")

        nom = pickle.loads(binascii.a2b_base64(self.state["nom"]))
        Interactive.show_network(nom, sys.stdout)

    @cli_cmd()
    def do_ps(self, *, router: "PotatoolSession.Router"):
        """
        Show processes.
        """
        self._run(router, ["ps", "uf", "-N", "-C", "ps"])

    @cli_cmd()
    def do_ip(self, args: List[str], *, router: "PotatoolSession.Router"):
        """
        Run `ip` in router.
        """
        return self._run(router, ["ip"] + args)

    def _vtysh(self, router, args):
        frrpath = self.state.get("frrpath")
        if not frrpath:
            raise CLIError("session not fully initialized")
        rundirs = self.state.get("rundirs", {})
        if router.name not in rundirs:
            raise CLIError(f"no vtysh directory for router {router.name}")

        return self._run(
            router,
            [
                os.path.join(frrpath, "vtysh/vtysh"),
                "--vty_socket",
                rundirs[router.name],
            ]
            + args,
        )

    @cli_cmd()
    def do_vtysh(self, args: List[str], *, router: "PotatoolSession.Router"):
        """
        Run `vtysh` in router.
        """
        if args and not args[0].startswith("-"):
            args = ["-c", shlex.join(args)]
        return self._vtysh(router, args)

    @cli_cmd()
    def do_show(self, args: List[str], *, router: "PotatoolSession.Router"):
        """
        Pass through "show" command into vtysh.
        """
        args = ["-c", shlex.join(["show"] + args)]
        return self._vtysh(router, args)

    @cli_cmd()
    @staticmethod
    def do_exit():
        sys.exit(0)


PotatoolSession.clisetup()

#
# VERY HACKY CODE / WIP BEYOND THIS POINT!
#

# pylint: disable=too-many-statements,too-many-locals
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

    PotatoolSession.want_sess = args.session
    PotatoolSession.want_rtr = args.router

    if args.CMD:
        # non-interactive mode
        PotatoolSession.load()
        PotatoolSession.do(shlex.join(args.CMD))
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
        with open(histfile, "wb") as fd:
            pass
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

    readline.parse_and_bind("set enable-bracketed-paste off")

    running = True
    rl_input = None

    def rl_cb(textb):
        nonlocal running, rl_input

        rlpoll.callback_handler_remove()

        if textb is None:
            running = False
            return

        rl_input = textb.decode("UTF-8")

    rl_escape = re.compile(r"(\033\[[0-9;]*m)")

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
        return rl_escape.sub("\001\\1\002", p)

    poller = select.poll()
    poller.register(0, select.POLLIN)
    poller.register(wm.get_fd(), select.POLLIN)

    _rl_prompt = rl_prompt()
    rlpoll.callback_handler_install(_rl_prompt, rl_cb)

    while running:
        ready = poller.poll()

        do_rl = False

        for fd, _ in ready:
            if fd == wm.get_fd():
                rlpoll.clear_visible_line()
                notifier.read_events()
                notifier.process_events()
                rlpoll.forced_update_display()
            if fd == 0:
                do_rl = True

        if do_rl:
            rlpoll.callback_read_char()

        if rl_input is not None:
            if rl_input.strip() != "":
                readline.add_history(rl_input)

            # pylint: disable=broad-except
            try:
                PotatoolSession.do(rl_input)
            except CLIError as e:
                sys.stderr.write(e.text + "\n")
            except Exception:
                sys.stderr.write("while executing %r:\n" % rl_input)
                traceback.print_exc()

            _rl_prompt = rl_prompt()
            rlpoll.callback_handler_install(_rl_prompt, rl_cb)
            rl_input = None

        prev_prompt = _rl_prompt
        _rl_prompt = rl_prompt()
        if _rl_prompt != prev_prompt:
            rlpoll.set_prompt(_rl_prompt)
            rlpoll.redisplay()

    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
