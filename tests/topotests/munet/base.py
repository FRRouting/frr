# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# July 9 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021, LabN Consulting, L.L.C.
#
"""A module that implements core functionality for library or standalone use."""
import asyncio
import datetime
import errno
import ipaddress
import logging
import os
import platform
import re
import readline
import shlex
import signal
import subprocess
import sys
import tempfile
import time as time_mod

from collections import defaultdict
from pathlib import Path
from typing import Union

from . import config as munet_config
from . import linux


try:
    import pexpect

    from pexpect.fdpexpect import fdspawn
    from pexpect.popen_spawn import PopenSpawn

    have_pexpect = True
except ImportError:
    have_pexpect = False

PEXPECT_PROMPT = "PEXPECT_PROMPT>"
PEXPECT_CONTINUATION_PROMPT = "PEXPECT_PROMPT+"

root_hostname = subprocess.check_output("hostname")
our_pid = os.getpid()


detailed_cmd_logging = False


class MunetError(Exception):
    """A generic munet error."""


class CalledProcessError(subprocess.CalledProcessError):
    """Improved logging subclass of subprocess.CalledProcessError."""

    def __str__(self):
        o = self.output.strip() if self.output else ""
        e = self.stderr.strip() if self.stderr else ""
        s = f"returncode: {self.returncode} command: {self.cmd}"
        o = "\n\tstdout: " + o if o else ""
        e = "\n\tstderr: " + e if e else ""
        return s + o + e

    def __repr__(self):
        o = self.output.strip() if self.output else ""
        e = self.stderr.strip() if self.stderr else ""
        return f"munet.base.CalledProcessError({self.returncode}, {self.cmd}, {o}, {e})"


class Timeout:
    """An object to passively monitor for timeouts."""

    def __init__(self, delta):
        self.delta = datetime.timedelta(seconds=delta)
        self.started_on = datetime.datetime.now()
        self.expires_on = self.started_on + self.delta

    def elapsed(self):
        elapsed = datetime.datetime.now() - self.started_on
        return elapsed.total_seconds()

    def is_expired(self):
        return datetime.datetime.now() > self.expires_on

    def remaining(self):
        remaining = self.expires_on - datetime.datetime.now()
        return remaining.total_seconds()

    def __iter__(self):
        return self

    def __next__(self):
        remaining = self.remaining()
        if remaining <= 0:
            raise StopIteration()
        return remaining


def fsafe_name(name):
    return "".join(x if x.isalnum() else "_" for x in name)


def indent(s):
    return "\t" + s.replace("\n", "\n\t")


def shell_quote(command):
    """Return command wrapped in single quotes."""
    if sys.version_info[0] >= 3:
        return shlex.quote(command)
    return "'" + command.replace("'", "'\"'\"'") + "'"


def cmd_error(rc, o, e):
    s = f"rc {rc}"
    o = "\n\tstdout: " + o.strip() if o and o.strip() else ""
    e = "\n\tstderr: " + e.strip() if e and e.strip() else ""
    return s + o + e


def shorten(s):
    s = s.strip()
    i = s.find("\n")
    if i > 0:
        s = s[: i - 1]
        if not s.endswith("..."):
            s += "..."
    if len(s) > 72:
        s = s[:69]
        if not s.endswith("..."):
            s += "..."
    return s


def comm_result(rc, o, e):
    s = f"\n\treturncode {rc}" if rc else ""
    o = "\n\tstdout: " + shorten(o) if o and o.strip() else ""
    e = "\n\tstderr: " + shorten(e) if e and e.strip() else ""
    return s + o + e


def proc_str(p):
    if hasattr(p, "args"):
        args = p.args if isinstance(p.args, str) else " ".join(p.args)
    else:
        args = ""
    return f"proc pid: {p.pid} args: {args}"


def proc_error(p, o, e):
    if hasattr(p, "args"):
        args = p.args if isinstance(p.args, str) else " ".join(p.args)
    else:
        args = ""

    s = f"rc {p.returncode} pid {p.pid}"
    a = "\n\targs: " + args if args else ""
    o = "\n\tstdout: " + (o.strip() if o and o.strip() else "*empty*")
    e = "\n\tstderr: " + (e.strip() if e and e.strip() else "*empty*")
    return s + a + o + e


def comm_error(p):
    rc = p.poll()
    assert rc is not None
    if not hasattr(p, "saved_output"):
        p.saved_output = p.communicate()
    return proc_error(p, *p.saved_output)


async def acomm_error(p):
    rc = p.returncode
    assert rc is not None
    if not hasattr(p, "saved_output"):
        p.saved_output = await p.communicate()
    return proc_error(p, *p.saved_output)


def get_kernel_version():
    kvs = (
        subprocess.check_output("uname -r", shell=True, text=True).strip().split("-", 1)
    )
    kv = kvs[0].split(".")
    kv = [int(x) for x in kv]
    return kv


def convert_number(value) -> int:
    """Convert a number value with a possible suffix to an integer.

    >>> convert_number("100k") == 100 * 1024
    True
    >>> convert_number("100M") == 100 * 1000 * 1000
    True
    >>> convert_number("100Gi") == 100 * 1024 * 1024 * 1024
    True
    >>> convert_number("55") == 55
    True
    """
    if value is None:
        raise ValueError("Invalid value None for convert_number")
    rate = str(value)
    base = 1000
    if rate[-1] == "i":
        base = 1024
        rate = rate[:-1]
    suffix = "KMGTPEZY"
    index = suffix.find(rate[-1])
    if index == -1:
        base = 1024
        index = suffix.lower().find(rate[-1])
    if index != -1:
        rate = rate[:-1]
    return int(rate) * base ** (index + 1)


def is_file_like(fo):
    return isinstance(fo, int) or hasattr(fo, "fileno")


def get_tc_bits_value(user_value):
    value = convert_number(user_value) / 1000
    return f"{value:03f}kbit"


def get_tc_bytes_value(user_value):
    # Raw numbers are bytes in tc
    return convert_number(user_value)


def get_tmp_dir(uniq):
    return os.path.join(tempfile.mkdtemp(), uniq)


async def _async_get_exec_path(binary, cmdf, cache):
    if isinstance(binary, str):
        bins = [binary]
    else:
        bins = binary
    for b in bins:
        if b in cache:
            return cache[b]

        rc, output, _ = await cmdf("which " + b, warn=False)
        if not rc:
            cache[b] = os.path.abspath(output.strip())
            return cache[b]
    return None


def _get_exec_path(binary, cmdf, cache):
    if isinstance(binary, str):
        bins = [binary]
    else:
        bins = binary
    for b in bins:
        if b in cache:
            return cache[b]

        rc, output, _ = cmdf("which " + b, warn=False)
        if not rc:
            cache[b] = os.path.abspath(output.strip())
            return cache[b]
    return None


def get_event_loop():
    """Configure and return our non-thread using event loop.

    This function configures a new child watcher to not use threads.
    Threads cannot be used when we inline unshare a PID namespace.
    """
    policy = asyncio.get_event_loop_policy()
    loop = policy.get_event_loop()
    if not hasattr(os, "pidfd_open"):
        return loop

    owatcher = policy.get_child_watcher()
    logging.debug(
        "event_loop_fixture: global policy %s, current loop %s, current watcher %s",
        policy,
        loop,
        owatcher,
    )

    policy.set_child_watcher(None)
    owatcher.close()

    try:
        watcher = asyncio.PidfdChildWatcher()  # pylint: disable=no-member
    except Exception:
        watcher = asyncio.SafeChildWatcher()
    loop = policy.get_event_loop()

    logging.debug(
        "event_loop_fixture: attaching new watcher %s to loop and setting in policy",
        watcher,
    )
    watcher.attach_loop(loop)
    policy.set_child_watcher(watcher)
    policy.set_event_loop(loop)
    assert asyncio.get_event_loop_policy().get_child_watcher() is watcher

    return loop


class Commander:  # pylint: disable=R0904
    """An object that can execute commands."""

    tmux_wait_gen = 0

    def __init__(self, name, logger=None, unet=None, **kwargs):
        """Create a Commander.

        Args:
            name: name of the commander object
            logger: logger to use for logging commands a defualt is supplied if this
                is None
            unet: unet that owns this object, only used by Commander in run_in_window,
                otherwise can be None.
        """
        # del kwargs  # deal with lint warning
        # logging.warning("Commander: name %s kwargs %s", name, kwargs)

        self.name = name
        self.unet = unet
        self.deleting = False
        self.last = None
        self.exec_paths = {}

        # For running commands one time only (deals with asyncio)
        self.cmd_once_done = {}
        self.cmd_once_locks = {}

        if not logger:
            logname = f"munet.{self.__class__.__name__.lower()}.{name}"
            self.logger = logging.getLogger(logname)
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger = logger

        super().__init__(**kwargs)

    @property
    def is_vm(self):
        return False

    @property
    def is_container(self):
        return False

    def set_logger(self, logfile):
        self.logger = logging.getLogger(__name__ + ".commander." + self.name)
        self.logger.setLevel(logging.DEBUG)
        if isinstance(logfile, str):
            handler = logging.FileHandler(logfile, mode="w")
        else:
            handler = logging.StreamHandler(logfile)

        fmtstr = "%(asctime)s.%(msecs)03d %(levelname)s: {}({}): %(message)s".format(
            self.__class__.__name__, self.name
        )
        handler.setFormatter(logging.Formatter(fmt=fmtstr))
        self.logger.addHandler(handler)

    def _get_pre_cmd(self, use_str, use_pty, **kwargs):
        """Get the pre-user-command values.

        The values returned here should be what is required to cause the user's command
        to execute in the correct context (e.g., namespace, container, sshremote).
        """
        del kwargs
        del use_pty
        return "" if use_str else []

    def __str__(self):
        return f"{self.__class__.__name__}({self.name})"

    async def async_get_exec_path(self, binary):
        """Return the full path to the binary executable.

        `binary` :: binary name or list of binary names
        """
        return await _async_get_exec_path(
            binary, self.async_cmd_status_nsonly, self.exec_paths
        )

    def get_exec_path(self, binary):
        """Return the full path to the binary executable.

        `binary` :: binary name or list of binary names
        """
        return _get_exec_path(binary, self.cmd_status_nsonly, self.exec_paths)

    def get_exec_path_host(self, binary):
        """Return the full path to the binary executable.

        If the object is actually a derived class (e.g., a container) this method will
        return the exec path for the native namespace rather than the container. The
        path is the one which the other xxx_host methods will use.

        `binary` :: binary name or list of binary names
        """
        return get_exec_path_host(binary)

    def test(self, flags, arg):
        """Run test binary, with flags and arg."""
        test_path = self.get_exec_path(["test"])
        rc, _, _ = self.cmd_status([test_path, flags, arg], warn=False)
        return not rc

    def test_nsonly(self, flags, arg):
        """Run test binary, with flags and arg."""
        test_path = self.get_exec_path(["test"])
        rc, _, _ = self.cmd_status_nsonly([test_path, flags, arg], warn=False)
        return not rc

    def path_exists(self, path):
        """Check if path exists."""
        return self.test("-e", path)

    async def cleanup_pid(self, pid, kill_pid=None):
        """Signal a pid to exit with escalating forcefulness."""
        if kill_pid is None:
            kill_pid = pid

        for sn in (signal.SIGHUP, signal.SIGKILL):
            self.logger.debug(
                "%s: %s %s (wait %s)", self, signal.Signals(sn).name, kill_pid, pid
            )

            os.kill(kill_pid, sn)

            # No need to wait after this.
            if sn == signal.SIGKILL:
                return

            # try each signal, waiting 15 seconds for exit before advancing
            wait_sec = 30
            self.logger.debug("%s: waiting %ss for pid to exit", self, wait_sec)
            for _ in Timeout(wait_sec):
                try:
                    status = os.waitpid(pid, os.WNOHANG)
                    if status == (0, 0):
                        await asyncio.sleep(0.1)
                    else:
                        self.logger.debug("pid %s exited status %s", pid, status)
                        return
                except OSError as error:
                    if error.errno == errno.ECHILD:
                        self.logger.debug("%s: pid %s was reaped", self, pid)
                    else:
                        self.logger.warning(
                            "%s: error waiting on pid %s: %s", self, pid, error
                        )
                    return
            self.logger.debug("%s: timeout waiting on pid %s to exit", self, pid)

    def _get_sub_args(self, cmd_list, defaults, use_pty=False, ns_only=False, **kwargs):
        """Returns pre-command, cmd, and default keyword args."""
        assert not isinstance(cmd_list, str)

        defaults["shell"] = False
        pre_cmd_list = self._get_pre_cmd(False, use_pty, ns_only=ns_only, **kwargs)
        cmd_list = [str(x) for x in cmd_list]

        # os_env = {k: v for k, v in os.environ.items() if k.startswith("MUNET")}
        # env = {**os_env, **(kwargs["env"] if "env" in kwargs else {})}
        env = {**(kwargs["env"] if "env" in kwargs else os.environ)}
        if "MUNET_NODENAME" not in env:
            env["MUNET_NODENAME"] = self.name
        if "MUNET_PID" not in env and "MUNET_PID" in os.environ:
            env["MUNET_PID"] = os.environ["MUNET_PID"]
        kwargs["env"] = env

        defaults.update(kwargs)

        return pre_cmd_list, cmd_list, defaults

    def _common_prologue(self, async_exec, method, cmd, skip_pre_cmd=False, **kwargs):
        cmd_list = self._get_cmd_as_list(cmd)
        if method == "_spawn":
            defaults = {
                "encoding": "utf-8",
                "codec_errors": "ignore",
            }
        else:
            defaults = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
            if not async_exec:
                defaults["encoding"] = "utf-8"

        pre_cmd_list, cmd_list, defaults = self._get_sub_args(
            cmd_list, defaults, **kwargs
        )

        use_pty = kwargs.get("use_pty", False)
        if method == "_spawn":
            # spawn doesn't take "shell" keyword arg
            if "shell" in defaults:
                del defaults["shell"]
            # this is required to avoid receiving a STOPPED signal on expect!
            if not use_pty:
                defaults["preexec_fn"] = os.setsid
            defaults["env"]["PS1"] = "$ "

        if not detailed_cmd_logging:
            pre_cmd_str = shlex.join(pre_cmd_list) if not skip_pre_cmd else ""
            if "nsenter" in pre_cmd_str:
                self.logger.debug('%s("%s")', method, shlex.join(cmd_list))
            elif pre_cmd_str:
                self.logger.debug(
                    '%s("%s") [precmd: %s]', method, shlex.join(cmd_list), pre_cmd_str
                )
            else:
                self.logger.debug('%s("%s") [no precmd]', method, shlex.join(cmd_list))
        else:
            self.logger.debug(
                '%s: %s("%s", pre_cmd: "%s" use_pty: %s kwargs: %.120s)',
                self,
                method,
                cmd_list,
                pre_cmd_list if not skip_pre_cmd else "",
                use_pty,
                defaults,
            )

        actual_cmd_list = cmd_list if skip_pre_cmd else pre_cmd_list + cmd_list
        return actual_cmd_list, defaults

    async def _async_popen(self, method, cmd, **kwargs):
        """Create a new asynchronous subprocess."""
        acmd, kwargs = self._common_prologue(True, method, cmd, **kwargs)
        p = await asyncio.create_subprocess_exec(*acmd, **kwargs)
        return p, acmd

    def _popen(self, method, cmd, **kwargs):
        """Create a subprocess."""
        acmd, kwargs = self._common_prologue(False, method, cmd, **kwargs)
        p = subprocess.Popen(acmd, **kwargs)
        return p, acmd

    def _fdspawn(self, fo, **kwargs):
        defaults = {}
        defaults.update(kwargs)

        if "echo" in defaults:
            del defaults["echo"]

        if "encoding" not in defaults:
            defaults["encoding"] = "utf-8"
            if "codec_errors" not in defaults:
                defaults["codec_errors"] = "ignore"
        encoding = defaults["encoding"]

        self.logger.debug("%s: _fdspawn(%s, kwargs: %s)", self, fo, defaults)

        p = fdspawn(fo, **defaults)

        # We don't have TTY like conversions of LF to CRLF
        p.crlf = os.linesep.encode(encoding)

        # we own the socket now detach the file descriptor to keep it from closing
        if hasattr(fo, "detach"):
            fo.detach()

        return p

    def _spawn(self, cmd, skip_pre_cmd=False, use_pty=False, echo=False, **kwargs):
        logging.debug(
            '%s: _spawn: cmd "%s" skip_pre_cmd %s use_pty %s echo %s kwargs %s',
            self,
            cmd,
            skip_pre_cmd,
            use_pty,
            echo,
            kwargs,
        )
        actual_cmd, defaults = self._common_prologue(
            False, "_spawn", cmd, skip_pre_cmd=skip_pre_cmd, use_pty=use_pty, **kwargs
        )

        self.logger.debug(
            '%s: %s("%s", use_pty %s echo %s defaults: %s)',
            self,
            "PopenSpawn" if not use_pty else "pexpect.spawn",
            actual_cmd,
            use_pty,
            echo,
            defaults,
        )

        # We don't specify a timeout it defaults to 30s is that OK?
        if not use_pty:
            p = PopenSpawn(actual_cmd, **defaults)
        else:
            p = pexpect.spawn(actual_cmd[0], actual_cmd[1:], echo=echo, **defaults)
        return p, actual_cmd

    def spawn(
        self,
        cmd,
        spawned_re,
        expects=(),
        sends=(),
        use_pty=False,
        logfile=None,
        logfile_read=None,
        logfile_send=None,
        trace=None,
        **kwargs,
    ):
        """Create a spawned send/expect process.

        Args:
            cmd: list of args to exec/popen with, or an already open socket
            spawned_re: what to look for to know when done, `spawn` returns when seen
            expects: a list of regex other than `spawned_re` to look for. Commonly,
                "ogin:" or "[Pp]assword:"r.
            sends: what to send when an element of `expects` matches. So e.g., the
                username or password if thats what corresponding expect matched. Can
                be the empty string to send nothing.
            use_pty: true for pty based expect, otherwise uses popen (pipes/files)
            trace: if true then log send/expects
            **kwargs - kwargs passed on the _spawn.

        Returns:
            A pexpect process.

        Raises:
            pexpect.TIMEOUT, pexpect.EOF as documented in `pexpect`
            CalledProcessError if EOF is seen and `cmd` exited then
                raises a CalledProcessError to indicate the failure.
        """
        if is_file_like(cmd):
            assert not use_pty
            ac = "*socket*"
            p = self._fdspawn(cmd, **kwargs)
        else:
            p, ac = self._spawn(cmd, use_pty=use_pty, **kwargs)

        if logfile:
            p.logfile = logfile
        if logfile_read:
            p.logfile_read = logfile_read
        if logfile_send:
            p.logfile_send = logfile_send

        # for spawned shells (i.e., a direct command an not a console)
        # this is wrong and will cause 2 prompts
        if not use_pty:
            # This isn't very nice looking
            p.echo = False
            if not is_file_like(cmd):
                p.isalive = lambda: p.proc.poll() is None
            if not hasattr(p, "close"):
                p.close = p.wait

        # Do a quick check to see if we got the prompt right away, otherwise we may be
        # at a console so we send a \n to re-issue the prompt
        index = p.expect([spawned_re, pexpect.TIMEOUT, pexpect.EOF], timeout=0.1)
        if index == 0:
            assert p.match is not None
            self.logger.debug(
                "%s: got spawned_re quick: '%s' matching '%s'",
                self,
                p.match.group(0),
                spawned_re,
            )
            return p

        # Now send a CRLF to cause the prompt (or whatever else) to re-issue
        p.send("\n")
        try:
            patterns = [spawned_re, *expects]

            self.logger.debug("%s: expecting: %s", self, patterns)

            while index := p.expect(patterns):
                if trace:
                    assert p.match is not None
                    self.logger.debug(
                        "%s: got expect: '%s' matching %d '%s', sending '%s'",
                        self,
                        p.match.group(0),
                        index,
                        patterns[index],
                        sends[index - 1],
                    )
                if sends[index - 1]:
                    p.send(sends[index - 1])

                self.logger.debug("%s: expecting again: %s", self, patterns)
            self.logger.debug(
                "%s: got spawned_re: '%s' matching '%s'",
                self,
                p.match.group(0),
                spawned_re,
            )
            return p
        except pexpect.TIMEOUT:
            self.logger.error(
                "%s: TIMEOUT looking for spawned_re '%s' expect buffer so far:\n%s",
                self,
                spawned_re,
                indent(p.buffer),
            )
            raise
        except pexpect.EOF as eoferr:
            if p.isalive():
                raise
            rc = p.status
            before = indent(p.before)
            error = CalledProcessError(rc, ac, output=before)
            self.logger.error(
                "%s: EOF looking for spawned_re '%s' before EOF:\n%s",
                self,
                spawned_re,
                before,
            )
            p.close()
            raise error from eoferr

    async def shell_spawn(
        self,
        cmd,
        prompt,
        expects=(),
        sends=(),
        use_pty=False,
        will_echo=False,
        is_bourne=True,
        init_newline=False,
        **kwargs,
    ):
        """Create a shell REPL (read-eval-print-loop).

        Args:
            cmd: shell and list of args to popen with, or an already open socket
            prompt: the REPL prompt to look for, the function returns when seen
            expects: a list of regex other than `spawned_re` to look for. Commonly,
                "ogin:" or "[Pp]assword:"r.
            sends: what to send when an element of `expects` matches. So e.g., the
                username or password if thats what corresponding expect matched. Can
                be the empty string to send nothing.
            is_bourne: if False then do not modify shell prompt for internal
                parser friently format, and do not expect continuation prompts.
            init_newline: send an initial newline for non-bourne shell spawns, otherwise
                expect the prompt simply from running the command
            use_pty: true for pty based expect, otherwise uses popen (pipes/files)
            will_echo: bash is buggy in that it echo's to non-tty unlike any other
                sh/ksh, set this value to true if running back
            **kwargs - kwargs passed on the _spawn.
        """
        combined_prompt = r"({}|{})".format(re.escape(PEXPECT_PROMPT), prompt)

        assert not is_file_like(cmd) or not use_pty
        p = self.spawn(
            cmd,
            combined_prompt,
            expects=expects,
            sends=sends,
            use_pty=use_pty,
            echo=False,
            **kwargs,
        )
        assert not p.echo

        if not is_bourne:
            if init_newline:
                p.send("\n")
            return ShellWrapper(p, prompt, will_echo=will_echo)

        ps1 = PEXPECT_PROMPT
        ps2 = PEXPECT_CONTINUATION_PROMPT

        # Avoid problems when =/usr/bin/env= prints the values
        ps1p = ps1[:5] + "${UNSET_V}" + ps1[5:]
        ps2p = ps2[:5] + "${UNSET_V}" + ps2[5:]

        ps1 = re.escape(ps1)
        ps2 = re.escape(ps2)
        extra = [
            "TERM=dumb",
            "set +o emacs",
            "set +o vi",
            "unset HISTFILE",
            "PAGER=cat",
            "export PAGER",
        ]
        pchg = "PS1='{0}' PS2='{1}' PROMPT_COMMAND=''\n".format(ps1p, ps2p)
        p.send(pchg)
        return ShellWrapper(p, ps1, ps2, extra_init_cmd=extra, will_echo=will_echo)

    def popen(self, cmd, **kwargs):
        """Creates a pipe with the given `command`.

        Args:
            cmd: `str` or `list` of command to open a pipe with.
            **kwargs: kwargs is eventually passed on to Popen. If `command` is a string
                then will be invoked with `bash -c`, otherwise `command` is a list and
                will be invoked without a shell.

        Returns:
            a subprocess.Popen object.
        """
        return self._popen("popen", cmd, **kwargs)[0]

    def popen_nsonly(self, cmd, **kwargs):
        """Creates a pipe with the given `command`.

        Args:
            cmd: `str` or `list` of command to open a pipe with.
            **kwargs: kwargs is eventually passed on to Popen. If `command` is a string
                then will be invoked with `bash -c`, otherwise `command` is a list and
                will be invoked without a shell.

        Returns:
            a subprocess.Popen object.
        """
        return self._popen("popen_nsonly", cmd, ns_only=True, **kwargs)[0]

    async def async_popen(self, cmd, **kwargs):
        """Creates a pipe with the given `command`.

        Args:
            cmd: `str` or `list` of command to open a pipe with.
            **kwargs: kwargs is eventually passed on to create_subprocess_exec. If
                `command` is a string then will be invoked with `bash -c`, otherwise
                `command` is a list and will be invoked without a shell.

        Returns:
            a asyncio.subprocess.Process object.
        """
        p, _ = await self._async_popen("async_popen", cmd, **kwargs)
        return p

    async def async_popen_nsonly(self, cmd, **kwargs):
        """Creates a pipe with the given `command`.

        Args:
            cmd: `str` or `list` of command to open a pipe with.
            **kwargs: kwargs is eventually passed on to create_subprocess_exec. If
                `command` is a string then will be invoked with `bash -c`, otherwise
                `command` is a list and will be invoked without a shell.

        Returns:
            a asyncio.subprocess.Process object.
        """
        p, _ = await self._async_popen(
            "async_popen_nsonly", cmd, ns_only=True, **kwargs
        )
        return p

    async def async_cleanup_proc(self, p, pid=None):
        """Terminate a process started with a popen call.

        Args:
            p: return value from :py:`async_popen`, :py:`popen`, et al.
            pid: pid to signal instead of p.pid, typically a child of
                cmd_p == nsenter.

        Returns:
            None on success, the ``p`` if multiple timeouts occur even
            after a SIGKILL sent.
        """
        if not p:
            return None

        if p.returncode is not None:
            if isinstance(p, subprocess.Popen):
                o, e = p.communicate()
            else:
                o, e = await p.communicate()
            self.logger.debug(
                "%s: [cleanup_proc] proc already exited status: %s",
                self,
                proc_error(p, o, e),
            )
            return None

        if pid is None:
            pid = p.pid

        self.logger.debug(
            "%s: [cleanup_proc] terminate process: %s (pid %s)", self, proc_str(p), pid
        )
        try:
            # This will SIGHUP and wait a while then SIGKILL and return immediately
            await self.cleanup_pid(p.pid, pid)

            # Wait another 2 seconds after the possible SIGKILL above for the
            # parent nsenter to cleanup and exit
            wait_secs = 2
            if isinstance(p, subprocess.Popen):
                o, e = p.communicate(timeout=wait_secs)
            else:
                o, e = await asyncio.wait_for(p.communicate(), timeout=wait_secs)
            self.logger.debug(
                "%s: [cleanup_proc] exited after kill, status: %s",
                self,
                proc_error(p, o, e),
            )
        except (asyncio.TimeoutError, subprocess.TimeoutExpired):
            self.logger.warning("%s: [cleanup_proc] SIGKILL timeout", self)
            return p
        except Exception as error:
            self.logger.warning(
                "%s: [cleanup_proc] kill unexpected exception: %s",
                self,
                error,
                exc_info=True,
            )
            return p
        return None

    @staticmethod
    def _cmd_status_input(stdin):
        pinput = None
        if isinstance(stdin, (bytes, str)):
            pinput = stdin
            stdin = subprocess.PIPE
        return pinput, stdin

    def _cmd_status_finish(self, p, c, ac, o, e, raises, warn):
        rc = p.returncode
        self.last = (rc, ac, c, o, e)
        if not rc:
            resstr = comm_result(rc, o, e)
            if resstr:
                self.logger.debug("%s", resstr)
        else:
            if warn:
                self.logger.warning("%s: proc failed: %s", self, proc_error(p, o, e))
            if raises:
                # error = Exception("stderr: {}".format(stderr))
                # This annoyingly doesnt' show stderr when printed normally
                raise CalledProcessError(rc, ac, o, e)
        return rc, o, e

    def _cmd_status(self, cmds, raises=False, warn=True, stdin=None, **kwargs):
        """Execute a command."""
        timeout = None
        if "timeout" in kwargs:
            timeout = kwargs["timeout"]
            del kwargs["timeout"]

        pinput, stdin = Commander._cmd_status_input(stdin)
        p, actual_cmd = self._popen("cmd_status", cmds, stdin=stdin, **kwargs)
        o, e = p.communicate(pinput, timeout=timeout)
        return self._cmd_status_finish(p, cmds, actual_cmd, o, e, raises, warn)

    async def _async_cmd_status(
        self, cmds, raises=False, warn=True, stdin=None, text=None, **kwargs
    ):
        """Execute a command."""
        timeout = None
        if "timeout" in kwargs:
            timeout = kwargs["timeout"]
            del kwargs["timeout"]

        pinput, stdin = Commander._cmd_status_input(stdin)
        p, actual_cmd = await self._async_popen(
            "async_cmd_status", cmds, stdin=stdin, **kwargs
        )

        if text is False:
            encoding = None
        else:
            encoding = kwargs.get("encoding", "utf-8")

        if encoding is not None and isinstance(pinput, str):
            pinput = pinput.encode(encoding)
        try:
            o, e = await asyncio.wait_for(p.communicate(), timeout=timeout)
        except (TimeoutError, asyncio.TimeoutError) as error:
            raise subprocess.TimeoutExpired(
                cmd=actual_cmd, timeout=timeout, output=None, stderr=None
            ) from error
        if encoding is not None:
            o = o.decode(encoding) if o is not None else o
            e = e.decode(encoding) if e is not None else e
        return self._cmd_status_finish(p, cmds, actual_cmd, o, e, raises, warn)

    def _get_cmd_as_list(self, cmd):
        """Given a list or string return a list form for execution.

        If `cmd` is a string then the returned list uses bash and looks
        like this: ["/bin/bash", "-c", cmd]. Some node types override
        this function if they utilize a different shell as to return
        a different list of values.

        Args:
            cmd: list or string representing the command to execute.

        Returns:
            list of commands to execute.
        """
        if not isinstance(cmd, str):
            cmds = cmd
        else:
            # Make sure the code doesn't think `cd` will work.
            assert not re.match(r"cd(\s*|\s+(\S+))$", cmd)
            cmds = ["/bin/bash", "-c", cmd]
        return cmds

    def cmd_nostatus(self, cmd, **kwargs):
        """Run given command returning output[s].

        Args:
            cmd: `str` or `list` of the command to execute.  If a string is given
                it is run using a shell, otherwise the list is executed directly
                as the binary and arguments.
            **kwargs: kwargs is eventually passed on to Popen. If `command` is a string
                then will be invoked with `bash -c`, otherwise `command` is a list and
                will be invoked without a shell.

        Returns:
            if "stderr" is in kwargs and not equal to subprocess.STDOUT, then
            both stdout and stderr are returned, otherwise stderr is combined
            with stdout and only stdout is returned.
        """
        #
        # This method serves as the basis for all derived sync cmd variations, so to
        # override sync cmd behavior simply override this function and *not* the other
        # variations, unless you are changing only that variation's behavior
        #

        # XXX change this back to _cmd_status instead of cmd_status when we
        # consolidate and cleanup the container overrides of *cmd_* functions

        cmds = cmd
        if "stderr" in kwargs and kwargs["stderr"] != subprocess.STDOUT:
            _, o, e = self.cmd_status(cmds, **kwargs)
            return o, e
        if "stderr" in kwargs:
            del kwargs["stderr"]
        _, o, _ = self.cmd_status(cmds, stderr=subprocess.STDOUT, **kwargs)
        return o

    def cmd_status(self, cmd, **kwargs):
        """Run given command returning status and outputs.

        Args:
            cmd: `str` or `list` of the command to execute.  If a string is given
                it is run using a shell, otherwise the list is executed directly
                as the binary and arguments.
            **kwargs: kwargs is eventually passed on to Popen. If `command` is a string
                then will be invoked with `bash -c`, otherwise `command` is a list and
                will be invoked without a shell.

        Returns:
            (status, output, error) are returned
            status: the returncode of the command.
            output: stdout as a string from the command.
            error: stderr as a string from the command.
        """
        #
        # This method serves as the basis for all derived sync cmd variations, so to
        # override sync cmd behavior simply override this function and *not* the other
        # variations, unless you are changing only that variation's behavior
        #
        return self._cmd_status(cmd, **kwargs)

    def cmd_raises(self, cmd, **kwargs):
        """Execute a command. Raise an exception on errors.

        Args:
            cmd: `str` or `list` of the command to execute.  If a string is given
                it is run using a shell, otherwise the list is executed directly
                as the binary and arguments.
            **kwargs: kwargs is eventually passed on to Popen. If `command` is a string
                then will be invoked with `bash -c`, otherwise `command` is a list and
                will be invoked without a shell.

        Returns:
            output: stdout as a string from the command.

        Raises:
            CalledProcessError: on non-zero exit status
        """
        _, stdout, _ = self._cmd_status(cmd, raises=True, **kwargs)
        return stdout

    def cmd_nostatus_nsonly(self, cmd, **kwargs):
        # Make sure the command runs on the host and not in any container.
        return self.cmd_nostatus(cmd, ns_only=True, **kwargs)

    def cmd_status_nsonly(self, cmd, **kwargs):
        # Make sure the command runs on the host and not in any container.
        return self._cmd_status(cmd, ns_only=True, **kwargs)

    def cmd_raises_nsonly(self, cmd, **kwargs):
        # Make sure the command runs on the host and not in any container.
        _, stdout, _ = self._cmd_status(cmd, raises=True, ns_only=True, **kwargs)
        return stdout

    async def async_cmd_status(self, cmd, **kwargs):
        """Run given command returning status and outputs.

        Args:
            cmd: `str` or `list` of the command to execute.  If a string is given
                it is run using a shell, otherwise the list is executed directly
                as the binary and arguments.
            **kwargs: kwargs is eventually passed on to create_subprocess_exec. If
                `cmd` is a string then will be invoked with `bash -c`, otherwise
                `cmd` is a list and will be invoked without a shell.

        Returns:
            (status, output, error) are returned
            status: the returncode of the command.
            output: stdout as a string from the command.
            error: stderr as a string from the command.
        """
        #
        # This method serves as the basis for all derived async cmd variations, so to
        # override async cmd behavior simply override this function and *not* the other
        # variations, unless you are changing only that variation's behavior
        #
        return await self._async_cmd_status(cmd, **kwargs)

    async def async_cmd_nostatus(self, cmd, **kwargs):
        """Run given command returning output[s].

        Args:
            cmd: `str` or `list` of the command to execute.  If a string is given
                it is run using a shell, otherwise the list is executed directly
                as the binary and arguments.
            **kwargs: kwargs is eventually passed on to create_subprocess_exec. If
                `cmd` is a string then will be invoked with `bash -c`, otherwise
                `cmd` is a list and will be invoked without a shell.

        Returns:
            if "stderr" is in kwargs and not equal to subprocess.STDOUT, then
            both stdout and stderr are returned, otherwise stderr is combined
            with stdout and only stdout is returned.

        """
        # XXX change this back to _async_cmd_status instead of cmd_status when we
        # consolidate and cleanup the container overrides of *cmd_* functions

        cmds = cmd
        if "stderr" in kwargs and kwargs["stderr"] != subprocess.STDOUT:
            _, o, e = await self._async_cmd_status(cmds, **kwargs)
            return o, e
        if "stderr" in kwargs:
            del kwargs["stderr"]
        _, o, _ = await self._async_cmd_status(cmds, stderr=subprocess.STDOUT, **kwargs)
        return o

    async def async_cmd_raises(self, cmd, **kwargs):
        """Execute a command. Raise an exception on errors.

        Args:
            cmd: `str` or `list` of the command to execute.  If a string is given
                it is run using a shell, otherwise the list is executed directly
                as the binary and arguments.
            **kwargs: kwargs is eventually passed on to create_subprocess_exec. If
                `cmd` is a string then will be invoked with `bash -c`, otherwise
                `cmd` is a list and will be invoked without a shell.

        Returns:
            output: stdout as a string from the command.

        Raises:
            CalledProcessError: on non-zero exit status
        """
        _, stdout, _ = await self._async_cmd_status(cmd, raises=True, **kwargs)
        return stdout

    async def async_cmd_status_nsonly(self, cmd, **kwargs):
        # Make sure the command runs on the host and not in any container.
        return await self._async_cmd_status(cmd, ns_only=True, **kwargs)

    async def async_cmd_raises_nsonly(self, cmd, **kwargs):
        # Make sure the command runs on the host and not in any container.
        _, stdout, _ = await self._async_cmd_status(
            cmd, raises=True, ns_only=True, **kwargs
        )
        return stdout

    def cmd_legacy(self, cmd, **kwargs):
        """Execute a command with stdout and stderr joined, *IGNORES ERROR*."""
        defaults = {"stderr": subprocess.STDOUT}
        defaults.update(kwargs)
        _, stdout, _ = self._cmd_status(cmd, raises=False, **defaults)
        return stdout

    # Run a command in a new window (gnome-terminal, screen, tmux, xterm)
    def run_in_window(  # pylint: disable=too-many-positional-arguments
        self,
        cmd,
        wait_for=False,
        background=False,
        name=None,
        title=None,
        forcex=False,
        new_window=False,
        tmux_target=None,
        ns_only=False,
    ):
        """Run a command in a new window (TMUX, Screen or XTerm).

        Args:
            cmd: string to execute.
            wait_for: True to wait for exit from command or `str` as channel name to
                signal on exit, otherwise False
            background: Do not change focus to new window.
            title: Title for new pane (tmux) or window (xterm).
            name: Name of the new window (tmux)
            forcex: Force use of X11.
            new_window: Open new window (instead of pane) in TMUX
            tmux_target: Target for tmux pane.

        Returns:
            the pane/window identifier from TMUX (depends on `new_window`)
        """
        channel = None
        if isinstance(wait_for, str):
            channel = wait_for
        elif wait_for is True:
            channel = "{}-wait-{}".format(our_pid, Commander.tmux_wait_gen)
            Commander.tmux_wait_gen += 1

        if forcex or ("TMUX" not in os.environ and "STY" not in os.environ):
            root_level = False
        else:
            root_level = True

        # SUDO: The important thing to note is that with all these methods we are
        # executing on the users windowing system, so even though we are normally
        # running as root, we will not be when the command is dispatched. Also
        # in the case of SCREEN and X11 we need to sudo *back* to the user as well
        # This is also done by SSHRemote by defualt so we should *not* sudo back
        # if we are SSHRemote.

        # XXX need to test ssh in screen
        # XXX need to test ssh in Xterm
        sudo_path = get_exec_path_host(["sudo"])
        # This first test case seems same as last but using list instead of string?
        if self.is_vm and self.use_ssh and not ns_only:  # pylint: disable=E1101
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
            cmd = [
                "/usr/bin/env",
                f"MUNET_NODENAME={self.name}",
            ]
            if "MUNET_PID" in os.environ:
                cmd.append(f"MUNET_PID={os.environ.get('MUNET_PID')}")
            cmd += cmd

            # get the ssh cmd
            cmd = self._get_pre_cmd(False, True, ns_only=ns_only) + [shlex.join(cmd)]
            unet = self.unet  # pylint: disable=E1101
            uns_cmd = unet._get_pre_cmd(  # pylint: disable=W0212
                False, True, ns_only=True, root_level=root_level
            )
            # get the nsenter for munet
            nscmd = [
                sudo_path,
                *uns_cmd,
                *cmd,
            ]
        else:
            # This is the command to execute to be inside the namespace.
            # We are getting into trouble with quoting.
            envvars = f"MUNET_NODENAME={self.name} NODENAME={self.name}"
            if hasattr(self, "rundir"):
                envvars += f" RUNDIR={self.rundir}"
            if "MUNET_PID" in os.environ:
                envvars += f" MUNET_PID={os.environ.get('MUNET_PID')}"
            if hasattr(self.unet, "config_dirname") and self.unet.config_dirname:
                envvars += f" CONFIGDIR={self.unet.config_dirname}"
            elif "CONFIGDIR" in os.environ:
                envvars += f" CONFIGDIR={os.environ['CONFIGDIR']}"
            cmd = f"/usr/bin/env {envvars} {cmd}"
            # We need sudo b/c we are executing as the user inside the window system.
            sudo_path = get_exec_path_host(["sudo"])
            nscmd = (
                sudo_path
                + " "
                + self._get_pre_cmd(True, True, ns_only=ns_only, root_level=root_level)
                + " "
                + cmd
            )

        if "TMUX" in os.environ and not forcex:
            cmd = [get_exec_path_host("tmux")]
            if new_window:
                cmd.append("new-window")
                cmd.append("-P")
                if name:
                    cmd.append("-n")
                    cmd.append(name)
                if tmux_target:
                    cmd.append("-t")
                    cmd.append(tmux_target)
            else:
                cmd.append("split-window")
                cmd.append("-P")
                cmd.append("-h")
                if not tmux_target:
                    tmux_target = os.getenv("TMUX_PANE", "")
            if background:
                cmd.append("-d")
            if tmux_target:
                cmd.append("-t")
                cmd.append(tmux_target)

            # nscmd is always added as single string argument
            if not isinstance(nscmd, str):
                nscmd = shlex.join(nscmd)
            if title:
                nscmd = f"printf '\033]2;{title}\033\\'; {nscmd}"
            if channel:
                nscmd = f'trap "tmux wait -S {channel}; exit 0" EXIT; {nscmd}'
            cmd.append(nscmd)

        elif "STY" in os.environ and not forcex:
            # wait for not supported in screen for now
            channel = None
            cmd = [get_exec_path_host("screen")]
            if not os.path.exists(
                "/run/screen/S-{}/{}".format(os.environ["USER"], os.environ["STY"])
            ):
                # XXX not appropriate for ssh
                cmd = ["sudo", "-Eu", os.environ["SUDO_USER"]] + cmd

            if title:
                cmd.append("-t")
                cmd.append(title)

            if isinstance(nscmd, str):
                nscmd = shlex.split(nscmd)
            cmd.extend(nscmd)
        elif "DISPLAY" in os.environ:
            cmd = [get_exec_path_host("xterm")]
            if "SUDO_USER" in os.environ:
                # Do this b/c making things work as root with xauth seems hard
                cmd = [
                    get_exec_path_host("sudo"),
                    "-Eu",
                    os.environ["SUDO_USER"],
                ] + cmd
            if title:
                cmd.append("-T")
                cmd.append(title)

            cmd.append("-e")
            if isinstance(nscmd, str):
                cmd.extend(shlex.split(nscmd))
            else:
                cmd.extend(nscmd)

            # if channel:
            #    return self.cmd_raises(cmd, skip_pre_cmd=True)
            # else:
            p = commander.popen(
                cmd,
                # skip_pre_cmd=True,
                stdin=None,
                shell=False,
            )
            # We should reap the child and report the error then.
            time_mod.sleep(2)
            if p.poll() is not None:
                self.logger.error("%s: Failed to launch xterm: %s", self, comm_error(p))
            return p
        else:
            self.logger.error(
                "DISPLAY, STY, and TMUX not in environment, can't open window"
            )
            raise Exception("Window requestd but TMUX, Screen and X11 not available")

        # pane_info = self.cmd_raises(cmd, skip_pre_cmd=True, ns_only=True).strip()
        # We are prepending the nsenter command, so use unet.rootcmd
        pane_info = commander.cmd_raises(cmd).strip()

        # Re-adjust the layout
        if "TMUX" in os.environ:
            cmd = [
                get_exec_path_host("tmux"),
                "select-layout",
                "-t",
                pane_info if not tmux_target else tmux_target,
                "even-horizontal",
            ]
            commander.cmd_status(cmd)
            cmd = [
                get_exec_path_host("tmux"),
                "select-layout",
                "-t",
                pane_info if not tmux_target else tmux_target,
                "tiled",
            ]
            commander.cmd_status(cmd)

        # Wait here if we weren't handed the channel to wait for
        if channel and wait_for is True:
            cmd = [get_exec_path_host("tmux"), "wait", channel]
            # commander.cmd_status(cmd, skip_pre_cmd=True)
            commander.cmd_status(cmd)

        return pane_info

    async def async_cmd_raises_once(self, cmd, **kwargs):
        if cmd in self.cmd_once_done:
            return self.cmd_once_done[cmd]

        if cmd not in self.cmd_once_locks:
            self.cmd_once_locks[cmd] = asyncio.Lock()

        async with self.cmd_once_locks[cmd]:
            if cmd not in self.cmd_once_done:
                self.logger.info("Running command once: %s", cmd)
                self.cmd_once_done[cmd] = await commander.async_cmd_raises(
                    cmd, **kwargs
                )
        return self.cmd_once_done[cmd]

    def cmd_raises_once(self, cmd, **kwargs):
        if cmd not in self.cmd_once_done:
            self.cmd_once_done[cmd] = commander.cmd_raises(cmd, **kwargs)
        return self.cmd_once_done[cmd]

    def delete(self):
        """Calls self.async_delete within an exec loop."""
        asyncio.run(self.async_delete())

    async def _async_delete(self):
        """Delete this objects resources.

        This is the actual implementation of the resource cleanup, each class
        should cleanup it's own resources, generally catching and reporting,
        but not reraising any exceptions for it's own cleanup, then it should
        invoke `super()._async_delete() without catching any exceptions raised
        therein. See other examples in `base.py` or `native.py`
        """
        self.logger.info("%s: deleted", self)

    async def async_delete(self):
        """Delete the Commander (or derived object).

        The actual implementation for any class should be in `_async_delete`
        new derived classes should look at the documentation for that function.
        """
        try:
            self.deleting = True
            await self._async_delete()
        except Exception as error:
            self.logger.error("%s: error while deleting: %s", self, error)


class InterfaceMixin:
    """A mixin class to support interface functionality."""

    def __init__(self, *args, **kwargs):
        # del kwargs  # get rid of lint
        # logging.warning("InterfaceMixin: args: %s kwargs: %s", args, kwargs)

        self._intf_addrs = defaultdict(lambda: [None, None])
        self.net_intfs = {}
        self.next_intf_index = 0
        self.basename = "eth"
        # self.basename = name + "-eth"
        super().__init__(*args, **kwargs)

    @property
    def intfs(self):
        return sorted(self._intf_addrs.keys())

    @property
    def networks(self):
        return sorted(self.net_intfs.keys())

    def get_intf_addr(self, ifname, ipv6=False):
        if ifname not in self._intf_addrs:
            return None
        return self._intf_addrs[ifname][bool(ipv6)]

    def set_intf_addr(self, ifname, ifaddr):
        ifaddr = ipaddress.ip_interface(ifaddr)
        self._intf_addrs[ifname][ifaddr.version == 6] = ifaddr

    def net_addr(self, netname, ipv6=False):
        if netname not in self.net_intfs:
            return None
        return self.get_intf_addr(self.net_intfs[netname], ipv6=ipv6)

    def set_intf_basename(self, basename):
        self.basename = basename

    def get_next_intf_name(self):
        while True:
            ifname = self.basename + str(self.next_intf_index)
            self.next_intf_index += 1
            if ifname not in self._intf_addrs:
                break
        return ifname

    def get_ns_ifname(self, ifname):
        """Return a namespace unique interface name.

        This function is primarily overriden by L3QemuVM, IOW by any class
        that doesn't create it's own network namespace and will share that
        with the root (unet) namespace.

        Args:
            ifname: the interface name.

        Returns:
            A name unique to the namespace of this object. By defualt the assumption
            is the ifname is namespace unique.
        """
        return ifname

    def register_interface(self, ifname):
        if ifname not in self._intf_addrs:
            self._intf_addrs[ifname] = [None, None]

    def register_network(self, netname, ifname):
        if netname in self.net_intfs:
            assert self.net_intfs[netname] == ifname
        else:
            self.net_intfs[netname] = ifname

    def get_linux_tc_args(self, ifname, config):
        """Get interface constraints (jitter, delay, rate) for linux TC.

        The keys and their values are as follows:

        delay (int): number of microseconds
        jitter (int): number of microseconds
        jitter-correlation (float): % correlation to previous (default 10%)
        loss (float): % of loss
        loss-correlation (float): % correlation to previous (default 0%)
        rate  (int or str): bits per second, string allows for use of
            {KMGTKiMiGiTi} prefixes "i" means K == 1024 otherwise K == 1000
        """
        del ifname  # unused

        netem_args = ""

        def get_number(c, v, d=None):
            if v not in c or c[v] is None:
                return d
            return convert_number(c[v])

        delay = get_number(config, "delay")
        if delay is not None:
            netem_args += f" delay {delay}usec"

        jitter = get_number(config, "jitter")
        if jitter is not None:
            if not delay:
                raise ValueError("jitter but no delay specified")
            jitter_correlation = get_number(config, "jitter-correlation", 10)
            netem_args += f" {jitter}usec {jitter_correlation}%"

        loss = get_number(config, "loss")
        if loss is not None:
            loss_correlation = get_number(config, "loss-correlation", 0)
            if loss_correlation:
                netem_args += f" loss {loss}% {loss_correlation}%"
            else:
                netem_args += f" loss {loss}%"

        if (o_rate := config.get("rate")) is None:
            return netem_args, ""

        #
        # This comment is not correct, but is trying to talk through/learn the
        # machinery.
        #
        # tokens arrive at `rate` into token buffer.
        # limit - number of bytes that can be queued waiting for tokens
        #   -or-
        # latency - maximum amount of time a packet may sit in TBF queue
        #
        # So this just allows receiving faster than rate for latency amount of
        # time, before dropping.
        #
        # latency = sizeofbucket(limit) / rate (peakrate?)
        #
        #   32kbit
        # -------- = latency = 320ms
        #  100kbps
        #
        #  -but then-
        # burst ([token] buffer) the largest number of instantaneous
        # tokens available (i.e, bucket size).

        tbf_args = ""
        DEFLIMIT = 1518 * 1
        DEFBURST = 1518 * 2
        try:
            tc_rate = o_rate["rate"]
            tc_rate = convert_number(tc_rate)
            limit = convert_number(o_rate.get("limit", DEFLIMIT))
            burst = convert_number(o_rate.get("burst", DEFBURST))
        except (KeyError, TypeError):
            tc_rate = convert_number(o_rate)
            limit = convert_number(DEFLIMIT)
            burst = convert_number(DEFBURST)
        tbf_args += f" rate {tc_rate/1000}kbit"
        if delay:
            # give an extra 1/10 of buffer space to handle delay
            tbf_args += f" limit {limit} burst {burst}"
        else:
            tbf_args += f" limit {limit} burst {burst}"

        return netem_args, tbf_args

    def set_intf_constraints(self, ifname, **constraints):
        """Set interface outbound constraints.

        Set outbound constraints (jitter, delay, rate) for an interface. All arguments
        may also be passed as a string and will be converted to numerical format. All
        arguments are also optional. If not specified then that existing constraint will
        be cleared.

        Args:
            ifname: the name of the interface
            delay (int): number of microseconds.
            jitter (int): number of microseconds.
            jitter-correlation (float): Percent correlation to previous (default 10%).
            loss (float): Percent of loss.
            loss-correlation (float): Percent correlation to previous (default 25%).
            rate (int): bits per second, string allows for use of
                {KMGTKiMiGiTi} prefixes "i" means K == 1024 otherwise K == 1000.
        """
        nsifname = self.get_ns_ifname(ifname)
        netem_args, tbf_args = self.get_linux_tc_args(nsifname, constraints)
        count = 1
        selector = f"root handle {count}:"
        if netem_args:
            self.cmd_raises(
                f"tc qdisc add dev {nsifname} {selector} netem {netem_args}"
            )
            count += 1
            selector = f"parent {count-1}: handle {count}"
        # Place rate limit after delay otherwise limit/burst too complex
        if tbf_args:
            self.cmd_raises(f"tc qdisc add dev {nsifname} {selector} tbf {tbf_args}")

        self.cmd_raises(f"tc qdisc show dev {nsifname}")


class LinuxNamespace(Commander, InterfaceMixin):
    """A linux Namespace.

    An object that creates and executes commands in a linux namespace
    """

    def __init__(
        self,
        name,
        net=True,
        mount=True,
        uts=True,
        cgroup=False,
        ipc=False,
        pid=False,
        time=False,
        user=False,
        unshare_inline=False,
        set_hostname=True,
        private_mounts=None,
        **kwargs,
    ):
        """Create a new linux namespace.

        Args:
            name: Internal name for the namespace.
            net: Create network namespace.
            mount: Create network namespace.
            uts: Create UTS (hostname) namespace.
            cgroup: Create cgroup namespace.
            ipc: Create IPC namespace.
            pid: Create PID namespace, also mounts new /proc.
            time: Create time namespace.
            user: Create user namespace, also keeps capabilities.
            set_hostname: Set the hostname to `name`, uts must also be True.
            private_mounts: List of strings of the form
                "[/external/path:]/internal/path. If no external path is specified a
                tmpfs is mounted on the internal path. Any paths specified are first
                passed to `mkdir -p`.
            unshare_inline: Unshare the process itself rather than using a proxy.
            logger: Passed to superclass.
        """
        # logging.warning("LinuxNamespace: name %s kwargs %s", name, kwargs)

        super().__init__(name, **kwargs)

        unet = self.unet

        self.logger.debug("%s: creating", self)

        self.cwd = os.path.abspath(os.getcwd())

        self.nsflags = []
        self.ifnetns = {}
        self.uflags = 0
        self.p_ns_fds = None
        self.p_ns_fnames = None
        self.pid_ns = False
        self.init_pid = None
        self.unshare_inline = unshare_inline
        self.nsenter_fork = True

        #
        # Collect the namespaces to unshare
        #
        if hasattr(self, "proc_path") and self.proc_path:  # pylint: disable=no-member
            pp = Path(self.proc_path)  # pylint: disable=no-member
        else:
            pp = unet.proc_path if unet else Path("/proc")
        pp = pp.joinpath("%P%", "ns")

        flags = ""
        uflags = 0
        nslist = []
        nsflags = []
        if cgroup:
            nselm = "cgroup"
            nslist.append(nselm)
            nsflags.append(f"--{nselm}={pp / nselm}")
            flags += "C"
            uflags |= linux.CLONE_NEWCGROUP
        if ipc:
            nselm = "ipc"
            nslist.append(nselm)
            nsflags.append(f"--{nselm}={pp / nselm}")
            flags += "i"
            uflags |= linux.CLONE_NEWIPC
        if mount or pid:
            # We need a new mount namespace for pid
            nselm = "mnt"
            nslist.append(nselm)
            nsflags.append(f"--mount={pp / nselm}")
            mount = True
            flags += "m"
            uflags |= linux.CLONE_NEWNS
        if net:
            nselm = "net"
            nslist.append(nselm)
            nsflags.append(f"--{nselm}={pp / nselm}")
            # if pid:
            #     os.system(f"touch /tmp/netns-{name}")
            #     cmd.append(f"--net=/tmp/netns-{name}")
            # else:
            flags += "n"
            uflags |= linux.CLONE_NEWNET
        if pid:
            self.pid_ns = True
            # We look for this b/c the unshare pid will share with /sibn/init
            nselm = "pid_for_children"
            nslist.append(nselm)
            nsflags.append(f"--pid={pp / nselm}")
            flags += "p"
            uflags |= linux.CLONE_NEWPID
        if time:
            nselm = "time"
            # XXX time_for_children?
            nslist.append(nselm)
            nsflags.append(f"--{nselm}={pp / nselm}")
            flags += "T"
            uflags |= linux.CLONE_NEWTIME
        if user:
            nselm = "user"
            nslist.append(nselm)
            nsflags.append(f"--{nselm}={pp / nselm}")
            flags += "U"
            uflags |= linux.CLONE_NEWUSER
        if uts:
            nselm = "uts"
            nslist.append(nselm)
            nsflags.append(f"--{nselm}={pp / nselm}")
            flags += "u"
            uflags |= linux.CLONE_NEWUTS

        assert flags, "LinuxNamespace with no namespaces requested"

        # Should look path up using resources maybe...
        mutini_path = get_our_script_path("mutini")
        if not mutini_path:
            mutini_path = get_our_script_path("mutini.py")
        assert mutini_path
        cmd = [mutini_path, f"--unshare-flags={flags}", "-v"]
        fname = fsafe_name(self.name) + "-mutini.log"
        fname = (unet or self).rundir.joinpath(fname)
        stdout = open(fname, "w", encoding="utf-8")
        stderr = subprocess.STDOUT

        #
        # Save the current namespace info to compare against later
        #

        if not unet:
            nsdict = {x: os.readlink(f"/proc/self/ns/{x}") for x in nslist}
        else:
            nsdict = {
                x: os.readlink(f"{unet.proc_path}/{unet.pid}/ns/{x}") for x in nslist
            }

        #
        # (A) Basically we need to save the pid of the unshare call for nsenter.
        #
        # For `unet is not None` (node case) the level this exists at is based on wether
        # unet is using a forking nsenter or not. So if unet.nsenter_fork == True then
        # we need the child pid of the p.pid (child of pid returned to us), otherwise
        # unet.nsenter_fork == False and we just use p.pid as it will be unshare after
        # nsenter exec's it.
        #
        # For the `unet is None` (unet case) the unshare is at the top level or
        # non-existent so we always save the returned p.pid. If we are unshare_inline we
        # won't have a __pre_cmd but we can save our child_pid to kill later, otherwise
        # we set unet.pid to None b/c there's literally nothing to do.
        #
        # ---------------------------------------------------------------------------
        # Breakdown for nested (non-unet) namespace creation, and what PID
        # to use for __pre_cmd nsenter use.
        # ---------------------------------------------------------------------------
        #
        # tl;dr
        #   - for non-inline unshare: Use BBB with pid_for_children, unless none/none
        #     #then (AAA) returned
        #   - for inline unshare: use returned pid (AAA) with pid_for_children
        #
        # All commands use unet.popen to launch the unshare of mutini or cat.
        # mutini for PID unshare, otherwise cat. AAA is the returned pid BBB is the
        # child of the returned.
        #
        # Unshare Variant
        # ---------------
        #
        # Here we are running mutini if we are creating new pid namespace workspace,
        # cat otherwise.
        #
        # [PID+PID] pid tree looks like this:
        #
        # PID  NSPID PPID PGID
        # uuu    -   N/A  uuu  main unet process
        # AAA    -   uuu  AAA  nsenter (forking, from unet) (in unet namespaces -pid)
        # BBB    -   AAA  AAA  unshare --fork --kill-child (forking)
        # CCC    1   BBB  CCC  mutini (non-forking since it is pid 1 in new namespace)
        #
        # Use BBB if we use pid_for_children, CCC for all
        #
        # [PID+none] For non-pid workspace creation (but unet pid) we use cat and pid
        # tree looks like this:
        #
        # PID  PPID PGID
        # uuu  N/A  uuu  main unet process
        # AAA  uuu  AAA  nsenter (forking) (in unet namespaces -pid)
        # BBB  AAA  AAA  unshare -> cat (from unshare non-forking)
        #
        # Use BBB for all
        #
        # [none+PID] For pid workspace creation (but NOT unet pid) we use mutini and pid
        # tree looks like this:
        #
        # PID  NSPID PPID PGID
        # uuu    -   N/A  uuu  main unet process
        # AAA    -   uuu  AAA  nsenter -> unshare --fork --kill-child
        # BBB    1   AAA  AAA  mutini (non-forking since it is pid 1 in new namespace)
        #
        # Use AAA if we use pid_for_children, BBB for all
        #
        # [none+none] For non-pid workspace and non-pid unet we use cat and pid tree
        # looks like this:
        #
        # PID  PPID PGID
        # uuu  N/A  uuu  main unet process
        # AAA  uuu  AAA  nsenter -> unshare -> cat
        #
        # Use AAA for all, there's no BBB
        #
        # Inline-Unshare Variant
        # ----------------------
        #
        # For unshare_inline and new PID namespace we have unshared all but our PID
        # namespace, but our children end up in the new namespace so the fork popen
        # does is good enough.
        #
        # [PID+PID] pid tree looks like this:
        #
        # PID  NSPID PPID PGID
        # uuu    -   N/A  uuu  main unet process
        # AAA    -   uuu  AAA  unshare --fork --kill-child (forking)
        # BBB    1   AAA  BBB  mutini
        #
        # Use AAA if we use pid_for_children, BBB for all
        #
        # [PID+none] For non-pid workspace creation (but unet pid) we use cat and pid
        # tree looks like this:
        #
        # PID  PPID PGID
        # uuu  N/A  uuu  main unet process
        # AAA  uuu  AAA  unshare -> cat
        #
        # Use AAA for all
        #
        # [none+PID] For pid workspace creation (but NOT unet pid) we use mutini and pid
        # tree looks like this:
        #
        # PID  NSPID PPID PGID
        # uuu    -   N/A  uuu  main unet process
        # AAA    -   uuu  AAA  unshare --fork --kill-child
        # BBB    1   AAA  BBB  mutini
        #
        # Use AAA if we use pid_for_children, BBB for all
        #
        # [none+none] For non-pid workspace and non-pid unet we use cat and pid tree
        # looks like this:
        #
        # PID  PPID PGID
        # uuu  N/A  uuu  main unet process
        # AAA  uuu  AAA  unshare -> cat
        #
        # Use AAA for all.
        #
        #
        # ---------------------------------------------------------------------------
        # Breakdown for unet namespace creation, and what PID to use for __pre_cmd
        # ---------------------------------------------------------------------------
        #
        # tl;dr: save returned PID or nothing.
        #   - for non-inline unshare: Use AAA with pid_for_children (returned pid)
        #   - for inline unshare: no __precmd as the fork in popen is enough.
        #
        # Use commander to launch the unshare mutini/cat (for PID/none
        # workspace PID) for non-inline case. AAA is the returned pid BBB is the child
        # of the returned.
        #
        # Unshare Variant
        # ---------------
        #
        # Here we are running mutini if we are creating new pid namespace workspace,
        # cat otherwise.
        #
        # [PID] for unet pid creation pid tree looks like this:
        #
        # PID  NSPID PPID PGID
        # uuu    -   N/A  uuu  main unet process
        # AAA    -   uuu  AAA  unshare --fork --kill-child (forking)
        # BBB    1   AAA  BBB  mutini
        #
        # Use AAA if we use pid_for_children, BBB for all
        #
        # [none] for unet non-pid, pid tree looks like this:
        #
        # PID  PPID PGID
        # uuu  N/A  uuu  main unet process
        # AAA  uuu  AAA  unshare -> cat
        #
        # Use AAA for all
        #
        # Inline-Unshare Variant
        # -----------------------
        #
        # For unshare_inline and new PID namespace we have unshared all but our PID
        # namespace, but our children end up in the new namespace so the fork in popen
        # does is good enough.
        #
        # [PID] for unet pid creation pid tree looks like this:
        #
        # PID  NSPID PPID PGID
        # uuu    -   N/A  uuu  main unet process
        # AAA    1   uuu  AAA  mutini
        #
        # Save p / p.pid, but don't configure any nsenter, uneeded.
        #
        # Use nothing as the fork when doing a popen is enough to be in all the right
        # namepsaces.
        #
        # [none] for unet non-pid, pid tree looks like this:
        #
        # PID  PPID PGID
        # uuu  N/A  uuu  main unet process
        #
        # Nothing, no __pre_cmd.
        #
        #

        self.ppid = os.getppid()
        self.unshare_inline = unshare_inline
        if unshare_inline:
            assert unet is None
            self.uflags = uflags
            #
            # Open file descriptors for current namespaces for later restoration.
            #
            try:
                # pidfd_open is actually present in 5.4, is this 5.8 check for another
                # aspect of what the pidfd_open code is relying on, something in the
                # namespace code? If not we can simply check for os.pidfd_open() being
                # present as our compat module linux.py runtime patches it in if
                # supported by the kernel.
                kversion = [int(x) for x in platform.release().split("-")[0].split(".")]
                kvok = kversion[0] > 5 or (kversion[0] == 5 and kversion[1] >= 8)
            except ValueError:
                kvok = False
            if not kvok:
                # get list of namespace file descriptors before we unshare
                self.p_ns_fds = []
                self.p_ns_fnames = []
                tmpflags = uflags
                for i in range(0, 64):
                    v = 1 << i
                    if (tmpflags & v) == 0:
                        continue
                    tmpflags &= ~v
                    if v in linux.namespace_files:
                        path = os.path.join("/proc/self", linux.namespace_files[v])
                        if os.path.exists(path):
                            self.p_ns_fds.append(os.open(path, 0))
                            self.p_ns_fnames.append(f"{path} -> {os.readlink(path)}")
                            self.logger.debug(
                                "%s: saving old namespace fd %s (%s)",
                                self,
                                self.p_ns_fnames[-1],
                                self.p_ns_fds[-1],
                            )
                    if not tmpflags:
                        break
            else:
                self.p_ns_fds = None
                self.p_ns_fnames = None
                self.ppid_fd = linux.pidfd_open(self.ppid)

            self.logger.debug(
                "%s: unshare to new namespaces %s",
                self,
                linux.clone_flag_string(uflags),
            )

            linux.unshare(uflags)

            if not pid:
                p = None
                self.pid = None
                self.nsenter_fork = False
            else:
                # Need to fork to create the PID namespace, but we need to continue
                # running from the parent so that things like pytest work. We'll execute
                # a mutini process to manage the child init 1 duties.
                #
                # We (the parent pid) can no longer create threads, due to that being
                # restricted by the kernel. See EINVAL in clone(2).
                #
                p = commander.popen(
                    [mutini_path, "-v"],
                    stdin=subprocess.PIPE,
                    stdout=stdout,
                    stderr=stderr,
                    text=True,
                    # new session/pgid so signals don't propagate
                    start_new_session=True,
                    shell=False,
                )
                self.pid = p.pid
                self.nsenter_fork = False
        else:
            # Using cat and a stdin PIPE is nice as it will exit when we do. However,
            # we also detach it from the pgid so that signals do not propagate to it.
            # This is b/c it would exit early (e.g., ^C) then, at least the main munet
            # proc which has no other processes like frr daemons running, will take the
            # main network namespace with it, which will remove the bridges and the
            # veth pair (because the bridge side veth is deleted).
            self.logger.debug("%s: creating namespace process: %s", self, cmd)

            # Use the parent unet process if we have one this will cause us to inherit
            # the namespaces correctly even in the non-inline case.
            parent = self.unet if self.unet else commander

            p = parent.popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                text=True,
                shell=False,
                # start_new_session=not unet
                # preexec_fn=os.setsid if not unet else None,
                preexec_fn=os.setsid,
            )

            # The pid number returned is in the global pid namespace. For unshare_inline
            # this can be unfortunate b/c our /proc has been remounted in our new pid
            # namespace and won't contain global pid namespace pids. To solve for this
            # we get all the pid values for the process below.

            # See (A) above for when we need the child pid.
            self.logger.debug("%s: namespace process: %s", self, proc_str(p))
            self.pid = p.pid
            if unet and unet.nsenter_fork:
                assert not unet.unshare_inline
                # Need child pid of p.pid
                pgrep = unet.rootcmd.get_exec_path("pgrep")
                # a sing fork was done
                child_pid = unet.rootcmd.cmd_raises([pgrep, "-o", "-P", str(p.pid)])
                self.pid = int(child_pid.strip())
                self.logger.debug("%s: child of namespace process: %s", self, pid)

        self.p = p

        # Let's always have a valid value.
        if self.pid is None:
            self.pid = our_pid

        #
        # Let's find all our pids in the nested PID namespaces
        #
        if unet:
            proc_path = unet.proc_path
        else:
            proc_path = self.proc_path if hasattr(self, "proc_path") else "/proc"
        proc_path = f"{proc_path}/{self.pid}"

        pid_status = open(f"{proc_path}/status", "r", encoding="ascii").read()
        m = re.search(r"\nNSpid:((?:\t[0-9]+)+)\n", pid_status)
        self.pids = [int(x) for x in m.group(1).strip().split("\t")]
        assert self.pids[0] == self.pid

        self.logger.debug("%s: namespace scoped pids: %s", self, self.pids)

        # -----------------------------------------------
        # Now let's wait until unshare completes it's job
        # -----------------------------------------------
        timeout = Timeout(30)
        if self.pid is not None and self.pid != our_pid:
            while (not p or not p.poll()) and not timeout.is_expired():
                # check new namespace values against old (nsdict), unshare
                # can actually take a bit to complete.
                for fname in tuple(nslist):
                    # self.pid will be the global pid b/c we didn't unshare_inline
                    nspath = f"{proc_path}/ns/{fname}"
                    try:
                        nsf = os.readlink(nspath)
                    except OSError as error:
                        self.logger.debug(
                            "unswitched: error (ok) checking %s: %s", nspath, error
                        )
                        continue
                    if nsdict[fname] != nsf:
                        self.logger.debug(
                            "switched: original %s current %s", nsdict[fname], nsf
                        )
                        nslist.remove(fname)
                    elif unshare_inline:
                        logging.warning(
                            "unshare_inline not unshared %s == %s", nsdict[fname], nsf
                        )
                    else:
                        self.logger.debug(
                            "unswitched: current %s elapsed: %s", nsf, timeout.elapsed()
                        )
                if not nslist:
                    self.logger.debug(
                        "all done waiting for unshare after %s", timeout.elapsed()
                    )
                    break

                elapsed = int(timeout.elapsed())
                if elapsed <= 3:
                    time_mod.sleep(0.1)
                else:
                    self.logger.info(
                        "%s: unshare taking more than %ss: %s", self, elapsed, nslist
                    )
                    time_mod.sleep(1)

        if p is not None and p.poll():
            self.logger.error("%s: namespace process failed: %s", self, comm_error(p))
            assert p.poll() is None, "unshare failed"

        #
        # Setup the pre-command to enter the target namespace from the running munet
        # process using self.pid
        #

        if pid:
            nsenter_fork = True
        elif unet and unet.nsenter_fork:
            # if unet created a pid namespace we need to enter it since we aren't
            # entering a child pid namespace we created for the node. Otherwise
            # we have a /proc remounted under unet, but our process is running in
            # the root pid namepsace
            nselm = "pid_for_children"
            nsflags.append(f"--pid={pp / nselm}")
            nsenter_fork = True
        else:
            # We dont need a fork.
            nsflags.append("-F")
            nsenter_fork = False

        # Save nsenter values if running from root namespace
        # we need this for the unshare_inline case when run externally (e.g., from
        # within tmux server).
        root_nsflags = [x.replace("%P%", str(self.pid)) for x in nsflags]
        self.__root_base_pre_cmd = ["/usr/bin/nsenter", *root_nsflags]
        self.__root_pre_cmd = list(self.__root_base_pre_cmd)

        if unshare_inline:
            assert unet is None
            # We have nothing to do here since our process is now in the correct
            # namespaces and children will inherit from us, even the PID namespace will
            # be corrent b/c commands are run by first forking.
            self.nsenter_fork = False
            self.nsflags = []
            self.__base_pre_cmd = []
        else:
            # We will use nsenter
            self.nsenter_fork = nsenter_fork
            self.nsflags = nsflags
            self.__base_pre_cmd = list(self.__root_base_pre_cmd)

        self.__pre_cmd = list(self.__base_pre_cmd)

        # Always mark new mount namespaces as recursive private
        if mount:
            # if self.p is None and not pid:
            self.cmd_raises_nsonly("mount --make-rprivate /")

        # We need to remount the procfs for the new PID namespace, since we aren't using
        # unshare(1) which does that for us.
        if pid and unshare_inline:
            assert mount
            self.cmd_raises_nsonly("mount -t proc proc /proc")

        # We do not want cmd_status in child classes (e.g., container) for
        # the remaining setup calls in this __init__ function.

        if net:
            # Remount /sys to pickup any changes in the network, but keep root
            # /sys/fs/cgroup. This pattern could be made generic and supported for any
            # overlapping mounts
            if mount:
                tmpmnt = f"/tmp/cgm-{self.pid}"
                self.cmd_status_nsonly(
                    f"mkdir {tmpmnt} && mount --rbind /sys/fs/cgroup {tmpmnt}"
                )
                rc = o = e = None
                for i in range(0, 10):
                    rc, o, e = self.cmd_status_nsonly(
                        "mount -t sysfs sysfs /sys", warn=False
                    )
                    if not rc:
                        break
                    self.logger.debug(
                        "got error mounting new sysfs will retry: %s",
                        cmd_error(rc, o, e),
                    )
                    time_mod.sleep(1)
                else:
                    raise Exception(cmd_error(rc, o, e))

                self.cmd_status_nsonly(
                    f"mount --move {tmpmnt} /sys/fs/cgroup && rmdir {tmpmnt}"
                )

            # Original micronet code
            # self.cmd_raises_nsonly("mount -t sysfs sysfs /sys")
            # self.cmd_raises_nsonly(
            #     "mount -o rw,nosuid,nodev,noexec,relatime "
            #     "-t cgroup2 cgroup /sys/fs/cgroup"
            # )

        # Set the hostname to the namespace name
        if uts and set_hostname:
            self.cmd_status_nsonly("hostname " + self.name)
            nroot = subprocess.check_output("hostname")
            if unshare_inline or (unet and unet.unshare_inline):
                assert (
                    root_hostname != nroot
                ), f'hostname unchanged from "{nroot}" wanted "{self.name}"'
            else:
                # Assert that we didn't just change the host hostname
                assert (
                    root_hostname == nroot
                ), f'root hostname "{root_hostname}" changed to "{nroot}"!'

        if private_mounts:
            if isinstance(private_mounts, str):
                private_mounts = [private_mounts]
            for m in private_mounts:
                s = m.split(":", 1)
                if len(s) == 1:
                    self.tmpfs_mount(s[0])
                else:
                    self.bind_mount(s[0], s[1])

        # this will fail if running inside the namespace with PID
        if pid:
            o = self.cmd_nostatus_nsonly("ls -l /proc/1/ns")
        else:
            o = self.cmd_nostatus_nsonly("ls -l /proc/self/ns")

        self.logger.debug("namespaces:\n %s", o)

        # will cache the path, which is important in delete to avoid running a shell
        # which can hang during cleanup
        self.ip_path = get_exec_path_host("ip")
        if net:
            self.cmd_status_nsonly([self.ip_path, "link", "set", "lo", "up"])

        self.logger.info("%s: created", self)

    def _get_pre_cmd(self, use_str, use_pty, ns_only=False, root_level=False, **kwargs):
        """Get the pre-user-command values.

        The values returned here should be what is required to cause the user's command
        to execute in the correct context (e.g., namespace, container, sshremote).
        """
        del kwargs
        del ns_only
        del use_pty
        pre_cmd = self.__root_pre_cmd if root_level else self.__pre_cmd
        return shlex.join(pre_cmd) if use_str else list(pre_cmd)

    def tmpfs_mount(self, inner):
        self.logger.debug("Mounting tmpfs on %s", inner)
        self.cmd_raises("mkdir -p " + inner)
        self.cmd_raises("mount -n -t tmpfs tmpfs " + inner)

    def bind_mount(self, outer, inner):
        self.logger.debug("Bind mounting %s on %s", outer, inner)
        if commander.test("-f", outer):
            self.cmd_raises(f"mkdir -p {os.path.dirname(inner)} && touch {inner}")
        else:
            if not commander.test("-e", outer):
                commander.cmd_raises_nsonly(f"mkdir -p {outer}")
            self.cmd_raises(f"mkdir -p {inner}")
        self.cmd_raises("mount --rbind {} {} ".format(outer, inner))

    def add_netns(self, ns):
        self.logger.debug("Adding network namespace %s", ns)

        if os.path.exists("/run/netns/{}".format(ns)):
            self.logger.warning("%s: Removing existing nsspace %s", self, ns)
            try:
                self.delete_netns(ns)
            except Exception as ex:
                self.logger.warning(
                    "%s: Couldn't remove existing nsspace %s: %s",
                    self,
                    ns,
                    str(ex),
                    exc_info=True,
                )
        self.cmd_raises_nsonly([self.ip_path, "netns", "add", ns])

    def delete_netns(self, ns):
        self.logger.debug("Deleting network namespace %s", ns)
        self.cmd_raises_nsonly([self.ip_path, "netns", "delete", ns])

    def set_intf_netns(self, intf, ns, up=False):
        # In case a user hard-codes 1 thinking it "resets"
        ns = str(ns)
        if ns == "1":
            ns = str(self.pid)

        self.logger.debug("Moving interface %s to namespace %s", intf, ns)

        cmd = [self.ip_path, "link", "set", intf, "netns", ns]
        if up:
            cmd.append("up")
        self.intf_ip_cmd(intf, cmd)
        if ns == str(self.pid):
            # If we are returning then remove from dict
            if intf in self.ifnetns:
                del self.ifnetns[intf]
        else:
            self.ifnetns[intf] = ns

    def reset_intf_netns(self, intf):
        self.logger.debug("Moving interface %s to default namespace", intf)
        self.set_intf_netns(intf, str(self.pid))

    def intf_ip_cmd(self, intf, cmd):
        """Run an ip command, considering an interface's possible namespace."""
        if intf in self.ifnetns:
            if isinstance(cmd, list):
                assert cmd[0].endswith("ip")
                cmd[1:1] = ["-n", self.ifnetns[intf]]
            else:
                assert cmd.startswith("ip ")
                cmd = "ip -n " + self.ifnetns[intf] + cmd[2:]
        self.cmd_raises_nsonly(cmd)

    def intf_tc_cmd(self, intf, cmd):
        """Run a tc command, considering an interface's possible namespace."""
        if intf in self.ifnetns:
            if isinstance(cmd, list):
                assert cmd[0].endswith("tc")
                cmd[1:1] = ["-n", self.ifnetns[intf]]
            else:
                assert cmd.startswith("tc ")
                cmd = "tc -n " + self.ifnetns[intf] + cmd[2:]
        self.cmd_raises_nsonly(cmd)

    def set_ns_cwd(self, cwd: Union[str, Path]):
        """Common code for changing pre_cmd and pre_nscmd."""
        self.logger.debug("%s: new CWD %s", self, cwd)
        self.__root_pre_cmd = self.__root_base_pre_cmd + ["--wd=" + str(cwd)]
        if self.__pre_cmd:
            self.__pre_cmd = self.__base_pre_cmd + ["--wd=" + str(cwd)]
        elif self.unshare_inline:
            os.chdir(cwd)

    async def _async_delete(self):
        if type(self) == LinuxNamespace:  # pylint: disable=C0123
            self.logger.info("%s: deleting", self)
        else:
            self.logger.debug("%s: LinuxNamespace sub-class deleting", self)

        # Signal pid namespace proc to exit
        if (
            (self.p is None or self.p.pid != self.pid)
            and self.pid
            and self.pid != our_pid
        ):
            self.logger.debug(
                "cleanup separate pid %s from namespace proc pid %s",
                self.pid,
                self.p.pid if self.p else None,
            )
            await self.cleanup_pid(self.pid)

        if self.p is not None:
            self.logger.debug("cleanup namespace proc pid %s", self.p.pid)
            await self.async_cleanup_proc(self.p)

        # return to the previous namespace, need to do this in case anothe munet
        # is being created, especially when it plans to inherit the parent's (host)
        # namespace.
        if self.uflags:
            logging.info("restoring from inline unshare: cwd: %s", os.getcwd())
            # This only works in linux>=5.8
            if self.p_ns_fds is None:
                self.logger.debug(
                    "%s: restoring namespaces %s",
                    self,
                    linux.clone_flag_string(self.uflags),
                )
                # fd = linux.pidfd_open(self.ppid)
                fd = self.ppid_fd
                retry = 3
                for i in range(0, retry):
                    try:
                        linux.setns(fd, self.uflags)
                    except OSError as error:
                        self.logger.warning(
                            "%s: could not reset to old namespace fd %s: %s",
                            self,
                            fd,
                            error,
                        )
                        if i == retry - 1:
                            raise
                        time_mod.sleep(1)
                os.close(fd)
            else:
                while self.p_ns_fds:
                    fd = self.p_ns_fds.pop()
                    fname = self.p_ns_fnames.pop()
                    self.logger.debug(
                        "%s: restoring namespace from fd %s (%s)", self, fname, fd
                    )
                    retry = 3
                    for i in range(0, retry):
                        try:
                            linux.setns(fd, 0)
                            break
                        except OSError as error:
                            self.logger.warning(
                                "%s: could not reset to old namespace fd %s (%s): %s",
                                self,
                                fname,
                                fd,
                                error,
                            )
                            if i == retry - 1:
                                raise
                        time_mod.sleep(1)
                    os.close(fd)
                self.p_ns_fds = None
                self.p_ns_fnames = None
            logging.info("restored from unshare: cwd: %s", os.getcwd())

        self.__root_base_pre_cmd = ["/bin/false"]
        self.__base_pre_cmd = ["/bin/false"]
        self.__root_pre_cmd = ["/bin/false"]
        self.__pre_cmd = ["/bin/false"]

        await super()._async_delete()


class SharedNamespace(Commander):
    """Share another namespace.

    An object that executes commands in an existing pid's linux namespace
    """

    def __init__(self, name, pid=None, nsflags=None, **kwargs):
        """Share a linux namespace.

        Args:
            name: Internal name for the namespace.
            pid: PID of the process to share with.
            nsflags: nsenter flags to pass to inherit namespaces from
        """
        super().__init__(name, **kwargs)

        self.logger.debug("%s: Creating", self)

        self.cwd = os.path.abspath(os.getcwd())
        self.pid = pid if pid is not None else our_pid

        nsflags = (x.replace("%P%", str(self.pid)) for x in nsflags) if nsflags else []
        self.__base_pre_cmd = ["/usr/bin/nsenter", *nsflags] if nsflags else []
        self.__pre_cmd = self.__base_pre_cmd
        self.ip_path = self.get_exec_path("ip")

    def _get_pre_cmd(self, use_str, use_pty, ns_only=False, root_level=False, **kwargs):
        """Get the pre-user-command values.

        The values returned here should be what is required to cause the user's command
        to execute in the correct context (e.g., namespace, container, sshremote).
        """
        del kwargs
        del ns_only
        del use_pty
        assert not root_level
        return shlex.join(self.__pre_cmd) if use_str else list(self.__pre_cmd)

    def set_ns_cwd(self, cwd: Union[str, Path]):
        """Common code for changing pre_cmd and pre_nscmd."""
        self.logger.debug("%s: new CWD %s", self, cwd)
        self.__pre_cmd = self.__base_pre_cmd + ["--wd=" + str(cwd)]


class Bridge(SharedNamespace, InterfaceMixin):
    """A linux bridge."""

    next_ord = 1

    @classmethod
    def _get_next_id(cls):
        # Do not use `cls` here b/c that makes the variable class specific
        n = Bridge.next_ord
        Bridge.next_ord = n + 1
        return n

    def __init__(self, name=None, mtu=None, unet=None, **kwargs):
        """Create a linux Bridge."""
        self.id = self._get_next_id()
        if not name:
            name = "br{}".format(self.id)

        unet_pid = our_pid if unet.pid is None else unet.pid

        super().__init__(name, pid=unet_pid, nsflags=unet.nsflags, unet=unet, **kwargs)

        self.set_intf_basename(self.name + "-e")

        self.mtu = mtu

        self.logger.debug("Bridge: Creating")

        # assert len(self.name) <= 16  # Make sure fits in IFNAMSIZE
        self.cmd_raises(f"ip link delete {name} || true")
        self.cmd_raises(f"ip link add {name} type bridge")
        if self.mtu:
            self.cmd_raises(f"ip link set {name} mtu {self.mtu}")
        self.cmd_raises(f"ip link set {name} up")

        self.logger.debug("%s: Created, Running", self)

    def get_ifname(self, netname):
        return self.net_intfs[netname] if netname in self.net_intfs else None

    async def _async_delete(self):
        """Stop the bridge (i.e., delete the linux resources)."""
        if type(self) == Bridge:  # pylint: disable=C0123
            self.logger.info("%s: deleting", self)
        else:
            self.logger.debug("%s: Bridge sub-class deleting", self)

        rc, o, e = await self.async_cmd_status(
            [self.ip_path, "link", "show", self.name],
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            warn=False,
        )
        if not rc:
            rc, o, e = await self.async_cmd_status(
                [self.ip_path, "link", "delete", self.name],
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                warn=False,
            )
        if rc:
            self.logger.error(
                "%s: error deleting bridge %s: %s",
                self,
                self.name,
                cmd_error(rc, o, e),
            )
        await super()._async_delete()


class BaseMunet(LinuxNamespace):
    """Munet."""

    def __init__(
        self,
        name="munet",
        isolated=True,
        pid=True,
        rundir=None,
        pytestconfig=None,
        **kwargs,
    ):
        """Create a Munet."""
        # logging.warning("BaseMunet: %s", name)

        self.hosts = {}
        self.switches = {}
        self.links = {}
        self.macs = {}
        self.rmacs = {}
        self.isolated = isolated

        self.cli_server = None
        self.cli_sockpath = None
        self.cli_histfile = None
        self.cli_in_window_cmds = {}
        self.cli_run_cmds = {}

        #
        # We need a directory for various files
        #
        if not rundir:
            rundir = "/tmp/munet"
        self.rundir = Path(rundir)

        #
        # Always having a global /proc is required to keep things from exploding
        # complexity with nested new pid namespaces..
        #
        if pid:
            self.proc_path = Path(tempfile.mkdtemp(suffix="-proc", prefix="mu-"))
            logging.debug("%s: mounting /proc on proc_path %s", name, self.proc_path)
            linux.mount("proc", str(self.proc_path), "proc")
        else:
            self.proc_path = Path("/proc")

        #
        # Now create a root level commander that works regardless of whether we inline
        # unshare or not. Save it in the global variable as well
        #

        if not self.isolated:
            self.rootcmd = commander
        elif not pid:
            nsflags = (
                f"--mount={self.proc_path / '1/ns/mnt'}",
                f"--net={self.proc_path / '1/ns/net'}",
                f"--uts={self.proc_path / '1/ns/uts'}",
                # f"--ipc={self.proc_path / '1/ns/ipc'}",
                # f"--time={self.proc_path / '1/ns/time'}",
                # f"--cgroup={self.proc_path / '1/ns/cgroup'}",
            )
            self.rootcmd = SharedNamespace("root", pid=1, nsflags=nsflags)
        else:
            # XXX user
            nsflags = (
                # XXX Backing up PID namespace just doesn't work.
                # f"--pid={self.proc_path / '1/ns/pid_for_children'}",
                f"--mount={self.proc_path / '1/ns/mnt'}",
                f"--net={self.proc_path / '1/ns/net'}",
                f"--uts={self.proc_path / '1/ns/uts'}",
                # f"--ipc={self.proc_path / '1/ns/ipc'}",
                # f"--time={self.proc_path / '1/ns/time'}",
                # f"--cgroup={self.proc_path / '1/ns/cgroup'}",
            )
            self.rootcmd = SharedNamespace("root", pid=1, nsflags=nsflags)
        global roothost  # pylint: disable=global-statement

        roothost = self.rootcmd

        self.cfgopt = munet_config.ConfigOptionsProxy(pytestconfig)

        # This allows us to cleanup any leftover running munet's
        if "MUNET_PID" in os.environ:
            if os.environ["MUNET_PID"] != str(our_pid):
                logging.error(
                    "Found env MUNET_PID != our pid %s, instead its %s, changing",
                    our_pid,
                    os.environ["MUNET_PID"],
                )
        os.environ["MUNET_PID"] = str(our_pid)

        super().__init__(
            name, mount=True, net=isolated, uts=isolated, pid=pid, unet=None, **kwargs
        )

        # this is for testing purposes do not use
        if not BaseMunet.g_unet:
            BaseMunet.g_unet = self

        self.logger.debug("%s: Creating", self)

    def __getitem__(self, key):
        if key in self.switches:
            return self.switches[key]
        return self.hosts[key]

    def add_host(self, name, cls=LinuxNamespace, **kwargs):
        """Add a host to munet."""
        self.logger.debug("%s: add_host %s(%s)", self, cls.__name__, name)

        self.hosts[name] = cls(name, unet=self, **kwargs)

        return self.hosts[name]

    def add_link(self, node1, node2, if1, if2, mtu=None, **intf_constraints):
        """Add a link between switch and node or 2 nodes.

        If constraints are given they are applied to each endpoint. See
        `InterfaceMixin::set_intf_constraints()` for more info.
        """
        isp2p = False

        try:
            name1 = node1.name
        except AttributeError:
            if node1 in self.switches:
                node1 = self.switches[node1]
            else:
                node1 = self.hosts[node1]
            name1 = node1.name

        try:
            name2 = node2.name
        except AttributeError:
            if node2 in self.switches:
                node2 = self.switches[node2]
            else:
                node2 = self.hosts[node2]
            name2 = node2.name

        if name1 in self.switches:
            assert name2 in self.hosts
        elif name2 in self.switches:
            assert name1 in self.hosts
            name1, name2 = name2, name1
            if1, if2 = if2, if1
        else:
            # p2p link
            assert name1 in self.hosts
            assert name2 in self.hosts
            isp2p = True

        lname = "{}:{}-{}:{}".format(name1, if1, name2, if2)
        self.logger.debug("%s: add_link %s%s", self, lname, " p2p" if isp2p else "")
        self.links[lname] = (name1, if1, name2, if2)

        # And create the veth now.
        if isp2p:
            lhost, rhost = self.hosts[name1], self.hosts[name2]
            lifname = "i1{:x}".format(lhost.pid)

            # Done at root level
            nsif1 = lhost.get_ns_ifname(if1)
            nsif2 = rhost.get_ns_ifname(if2)

            # Use pids[-1] to get the unet scoped pid for hosts
            self.cmd_raises_nsonly(
                f"ip link add {lifname} type veth peer name {nsif2}"
                f" netns {rhost.pids[-1]}"
            )
            self.cmd_raises_nsonly(f"ip link set {lifname} netns {lhost.pids[-1]}")

            lhost.cmd_raises_nsonly("ip link set {} name {}".format(lifname, nsif1))
            if mtu:
                lhost.cmd_raises_nsonly("ip link set {} mtu {}".format(nsif1, mtu))
            lhost.cmd_raises_nsonly("ip link set {} up".format(nsif1))
            lhost.register_interface(if1)

            if mtu:
                rhost.cmd_raises_nsonly("ip link set {} mtu {}".format(nsif2, mtu))
            rhost.cmd_raises_nsonly("ip link set {} up".format(nsif2))
            rhost.register_interface(if2)
        else:
            switch = self.switches[name1]
            rhost = self.hosts[name2]

            nsif1 = switch.get_ns_ifname(if1)
            nsif2 = rhost.get_ns_ifname(if2)

            if mtu is None:
                mtu = switch.mtu

            if len(nsif1) > 16:
                self.logger.error('"%s" len %s > 16', nsif1, len(nsif1))
            elif len(nsif2) > 16:
                self.logger.error('"%s" len %s > 16', nsif2, len(nsif2))
            assert len(nsif1) < 16 and len(nsif2) < 16  # Make sure fits in IFNAMSIZE

            self.logger.debug("%s: Creating veth pair for link %s", self, lname)

            # Use pids[-1] to get the unet scoped pid for hosts
            # switch is already in our namespace so nothing to convert.
            self.cmd_raises_nsonly(
                f"ip link add {nsif1} type veth peer name {nsif2}"
                f" netns {rhost.pids[-1]}"
            )

            if mtu:
                # if switch.mtu:
                #     # the switch interface should match the switch config
                #     switch.cmd_raises_nsonly(
                #         "ip link set {} mtu {}".format(if1, switch.mtu)
                #     )
                switch.cmd_raises_nsonly("ip link set {} mtu {}".format(nsif1, mtu))
                rhost.cmd_raises_nsonly("ip link set {} mtu {}".format(nsif2, mtu))

            switch.register_interface(if1)
            rhost.register_interface(if2)
            rhost.register_network(switch.name, if2)

            switch.cmd_raises_nsonly(f"ip link set {nsif1} master {switch.name}")

            switch.cmd_raises_nsonly(f"ip link set {nsif1} up")
            rhost.cmd_raises_nsonly(f"ip link set {nsif2} up")

        # Cache the MAC values, and reverse mapping
        self.get_mac(name1, nsif1)
        self.get_mac(name2, nsif2)

        # Setup interface constraints if provided
        if intf_constraints:
            node1.set_intf_constraints(if1, **intf_constraints)
            node2.set_intf_constraints(if2, **intf_constraints)

    def add_switch(self, name, cls=Bridge, **kwargs):
        """Add a switch to munet."""
        self.logger.debug("%s: add_switch %s(%s)", self, cls.__name__, name)
        self.switches[name] = cls(name, unet=self, **kwargs)
        return self.switches[name]

    def get_mac(self, name, ifname):
        if name in self.hosts:
            dev = self.hosts[name]
        else:
            dev = self.switches[name]

        nsifname = self.get_ns_ifname(ifname)

        if (name, ifname) not in self.macs:
            _, output, _ = dev.cmd_status_nsonly("ip -o link show " + nsifname)
            m = re.match(".*link/(loopback|ether) ([0-9a-fA-F:]+) .*", output)
            mac = m.group(2)
            self.macs[(name, ifname)] = mac
            self.rmacs[mac] = (name, ifname)

        return self.macs[(name, ifname)]

    async def _delete_link(self, lname):
        rname, rif = self.links[lname][2:4]
        host = self.hosts[rname]
        nsrif = host.get_ns_ifname(rif)

        self.logger.debug("%s: Deleting veth pair for link %s", self, lname)
        rc, o, e = await host.async_cmd_status_nsonly(
            [self.ip_path, "link", "delete", nsrif],
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            warn=False,
        )
        if rc:
            self.logger.error("Err del veth pair %s: %s", lname, cmd_error(rc, o, e))

    async def _delete_links(self):
        # for x in self.links:
        #     await self._delete_link(x)
        return await asyncio.gather(*[self._delete_link(x) for x in self.links])

    async def _async_delete(self):
        """Delete the munet topology."""
        # logger = self.logger if False else logging
        logger = self.logger
        if type(self) == BaseMunet:  # pylint: disable=C0123
            logger.info("%s: deleting.", self)
        else:
            logger.debug("%s: BaseMunet sub-class deleting.", self)

        logger.debug("Deleting links")
        try:
            await self._delete_links()
        except Exception as error:
            logger.error("%s: error deleting links: %s", self, error, exc_info=True)

        logger.debug("Deleting hosts and bridges")
        try:
            # Delete hosts and switches, wait for them all to complete
            # even if there is an exception.
            htask = [x.async_delete() for x in self.hosts.values()]
            stask = [x.async_delete() for x in self.switches.values()]
            await asyncio.gather(*htask, *stask, return_exceptions=True)
        except Exception as error:
            logger.error(
                "%s: error deleting hosts and switches: %s", self, error, exc_info=True
            )

        self.links = {}
        self.hosts = {}
        self.switches = {}

        try:
            if self.cli_server:
                self.cli_server.cancel()
                self.cli_server = None
            if self.cli_sockpath:
                await self.async_cmd_status(
                    "rm -rf " + os.path.dirname(self.cli_sockpath)
                )
                self.cli_sockpath = None
        except Exception as error:
            logger.error(
                "%s: error cli server or sockpaths: %s", self, error, exc_info=True
            )

        try:
            if self.cli_histfile:
                readline.write_history_file(self.cli_histfile)
                self.cli_histfile = None
        except Exception as error:
            logger.error(
                "%s: error saving history file: %s", self, error, exc_info=True
            )

        # XXX for some reason setns during the delete is changing our dir to /.
        cwd = os.getcwd()

        try:
            await super()._async_delete()
        except Exception as error:
            logger.error(
                "%s: error deleting parent classes: %s", self, error, exc_info=True
            )
        os.chdir(cwd)

        try:
            if self.proc_path and str(self.proc_path) != "/proc":
                logger.debug("%s: umount, remove proc_path %s", self, self.proc_path)
                linux.umount(str(self.proc_path), 0)
                os.rmdir(self.proc_path)
        except Exception as error:
            logger.warning(
                "%s: error umount and removing proc_path %s: %s",
                self,
                self.proc_path,
                error,
                exc_info=True,
            )
            try:
                linux.umount(str(self.proc_path), linux.MNT_DETACH)
            except Exception as error2:
                logger.error(
                    "%s: error umount with detach proc_path %s: %s",
                    self,
                    self.proc_path,
                    error2,
                    exc_info=True,
                )

        if BaseMunet.g_unet == self:
            BaseMunet.g_unet = None


BaseMunet.g_unet = None

if True:  # pylint: disable=using-constant-test

    class ShellWrapper:
        """A Read-Execute-Print-Loop (REPL) interface.

        A newline or prompt changing command should be sent to the
        spawned child prior to creation as the `prompt` will be `expect`ed
        """

        def __init__(
            self,
            spawn,
            prompt,
            continuation_prompt=None,
            extra_init_cmd=None,
            will_echo=False,
            escape_ansi=False,
        ):
            self.echo = will_echo
            self.escape = (
                re.compile(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]") if escape_ansi else None
            )

            logging.debug(
                'ShellWraper: prompt "%s" will_echo %s child.echo %s',
                prompt,
                will_echo,
                spawn.echo,
            )

            self.child = spawn
            if self.child.echo:
                logging.info("Setting child to echo")
                self.child.setecho(False)
                self.child.waitnoecho()
                assert not self.child.echo

            self.prompt = prompt
            self.cont_prompt = continuation_prompt

            # Use expect_exact if we can as it should be faster
            self.expects = [prompt]
            if re.escape(prompt) == prompt and hasattr(self.child, "expect_exact"):
                self._expectf = self.child.expect_exact
            else:
                self._expectf = self.child.expect
            if continuation_prompt:
                self.expects.append(continuation_prompt)
                if re.escape(continuation_prompt) != continuation_prompt:
                    self._expectf = self.child.expect

            if extra_init_cmd:
                if isinstance(extra_init_cmd, str):
                    extra_init_cmd = [extra_init_cmd]
                for ecmd in extra_init_cmd:
                    self.expect_prompt()
                    self.child.sendline(ecmd)
            self.expect_prompt()

        def expect_prompt(self, timeout=-1):
            return self._expectf(self.expects, timeout=timeout)

        def run_command(self, command, timeout=-1):
            """Pexpect REPLWrapper compatible run_command.

            This will split `command` into lines and feed each one to the shell.

            Args:
                command: string of commands separated by newlines, a trailing
                    newline will cause and empty line to be sent.
                timeout: pexpect timeout value.
            """
            lines = command.splitlines()
            if command[-1] == "\n":
                lines.append("")
            output = ""
            index = 0
            for line in lines:
                self.child.sendline(line)
                index = self.expect_prompt(timeout=timeout)
                output += self.child.before

            if index:
                if hasattr(self.child, "kill"):
                    self.child.kill(signal.SIGINT)
                else:
                    self.child.send("\x03")
                self.expect_prompt(timeout=30 if self.child.timeout is None else -1)
                raise ValueError("Continuation prompt found at end of commands")

            if self.escape:
                output = self.escape.sub("", output)

            return output

        def cmd_nostatus(self, cmd, timeout=-1):
            r"""Execute a shell command.

            Returns:
                (strip/cleaned \r) output
            """
            output = self.run_command(cmd, timeout)
            output = output.replace("\r\n", "\n")
            if self.echo:
                # remove the command
                idx = output.find(cmd)
                if idx == -1:
                    logging.warning(
                        "Didn't find command ('%s') in expected output ('%s')",
                        cmd,
                        output,
                    )
                else:
                    # Remove up to and including the command from the output stream
                    output = output[idx + len(cmd) :]

            return output.replace("\r", "").strip()

        def cmd_status(self, cmd, timeout=-1):
            r"""Execute a shell command.

            Returns:
                status and (strip/cleaned \r) output
            """
            # Run the command getting the output
            output = self.cmd_nostatus(cmd, timeout)

            # Now get the status
            scmd = "echo $?"
            rcstr = self.run_command(scmd)
            rcstr = rcstr.replace("\r\n", "\n")
            if self.echo:
                # remove the command
                idx = rcstr.find(scmd)
                if idx == -1:
                    if self.echo:
                        logging.warning(
                            "Didn't find status ('%s') in expected output ('%s')",
                            scmd,
                            rcstr,
                        )
                    try:
                        rc = int(rcstr)
                    except Exception:
                        rc = 255
                else:
                    rcstr = rcstr[idx + len(scmd) :].strip()
            try:
                rc = int(rcstr)
            except ValueError as error:
                logging.error(
                    "%s: error with expected status output: %s: %s",
                    self,
                    error,
                    rcstr,
                    exc_info=True,
                )
                rc = 255
            return rc, output

        def cmd_raises(self, cmd, timeout=-1):
            r"""Execute a shell command.

            Returns:
                (strip/cleaned \r) ouptut

            Raises:
               CalledProcessError: on non-zero exit status
            """
            rc, output = self.cmd_status(cmd, timeout)
            if rc:
                raise CalledProcessError(rc, cmd, output)
            return output


# ---------------------------
# Root level utility function
# ---------------------------


def get_exec_path(binary):
    return commander.get_exec_path(binary)


def get_exec_path_host(binary):
    return commander.get_exec_path(binary)


def get_our_script_path(script):
    # would be nice to find this w/o using a path lookup
    sdir = os.path.dirname(os.path.abspath(__file__))
    spath = os.path.join(sdir, script)
    if os.path.exists(spath):
        return spath
    return get_exec_path(script)


commander = Commander("munet")
roothost = None
