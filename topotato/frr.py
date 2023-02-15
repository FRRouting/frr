#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
FRR handling - turns a toponom router into an FRR router
"""

import importlib
import json
import logging
import os
import pwd
import re
import shlex
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
import typing
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Generator,
    List,
    Literal,
    Mapping,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)

import pytest
import jinja2

from .utils import deindent, get_dir, EnvcheckResult
from .timeline import Timeline, MiniPollee, TimedElement
from .livelog import LiveLog
from .exceptions import TopotatoDaemonCrash
from .pcapng import Context
from .osdep import NetworkInstance

if typing.TYPE_CHECKING:
    from . import toponom


logger = logging.getLogger("topotato")

# TBD: might be more accessible to just put these in a templates/ dir
_templates = {
    "boilerplate.conf": """
        log record-priority
        log timestamp precision 6
        !
        hostname {{ router.name }}
        service advanced-vty
        !
        #% block main
        #% endblock
        !
        line vty
        !
        """.replace(
        "\n        ", "\n"
    ).lstrip(
        "\n"
    ),
}


def load_template(name):
    return _templates.get(name)


# the 'X'+'X' is to not break the extended syntax hilighting
jenv = jinja2.Environment(
    line_comment_prefix="#" + "#",
    line_statement_prefix="#" + "%",
    autoescape=False,
    loader=jinja2.FunctionLoader(load_template),
)


class FRRSetupError(EnvironmentError):
    pass


class FRRConfigs(dict):
    """
    set of config files for an FRR setup

    this is a subclass of dict, keyed by router name, and has another level
    of dicts for the daemons, i.e.  frrconfig['r1']['zebra']
    """

    daemons: ClassVar[List[str]]
    binmap: ClassVar[Dict[str, str]]
    makevars: ClassVar[Mapping[str, str]]
    frrcred: ClassVar[Any]
    xrefs: ClassVar[Optional[Dict[Any, Any]]] = None

    frrpath: ClassVar[str]
    srcpath: ClassVar[str]
    confpath = "/etc/frr"

    # will be overridden by init, but necessary when running separate tests
    # directly outside of pytest, e.g. to just dump the configs
    daemons = []
    daemons.extend("zebra staticd".split())
    daemons.extend("bgpd ripd ripngd ospfd ospf6d isisd fabricd babeld eigrpd".split())
    daemons.extend("pimd pim6d ldpd nhrpd sharpd pathd pbrd bfdd vrrpd".split())

    daemons_integrated_only = frozenset("pim6d".split())

    @staticmethod
    @pytest.hookimpl()
    def pytest_addoption(parser):
        parser.addoption(
            "--frr-builddir",
            type=str,
            default=None,
            help="FRR build directory (overrides frr_builddir pytest.ini option)",
        )

        parser.addini(
            "frr_builddir",
            "FRR build directory (normally same as source, but out-of-tree is supported)",
            default="../frr",
        )

    # pylint: disable=too-many-locals,too-many-statements,too-many-branches
    @classmethod
    @pytest.hookimpl()
    def pytest_topotato_envcheck(cls, session, result: EnvcheckResult):
        """
        grab some setup information about a FRR build from frrpath

        among other things, this figures out which daemons are even available
        """
        frrpath = get_dir(session, "--frr-builddir", "frr_builddir")
        cls.frrpath = frrpath = os.path.abspath(frrpath)

        logger.debug("FRR build directory: %r", frrpath)
        try:
            with open(os.path.join(frrpath, "Makefile"), encoding="utf-8") as fd:
                makefile = fd.read()
        except FileNotFoundError as exc:
            raise FRRSetupError(
                "%r does not seem to be a FRR build directory, did you run ./configure && make?"
                % frrpath
            ) from exc

        srcdirm = re.search(r"^top_srcdir\s*=\s*(.*)$", makefile, re.M)
        if srcdirm is None:
            raise FRRSetupError("cannot identify source directory for %r")

        cls.srcpath = srcdir = os.path.abspath(os.path.join(frrpath, srcdirm.group(1)))
        logger.debug("FRR source directory: %r", srcdir)

        oldpath = sys.path[:]
        sys.path.append(os.path.join(srcdir, "python"))
        makevarmod = importlib.import_module("makevars")
        sys.path = oldpath

        cls.makevars = makevarmod.MakeReVars(makefile)  # type: ignore

        try:
            cls.frrcred = pwd.getpwnam(cls.makevars["enable_user"])
        except KeyError as e:
            result.error("FRR configured to use a non-existing user (%r)" % e)

        if cls.makevars["sysconfdir"] != cls.confpath:
            result.error(
                "FRR configured with --sysconfdir=%r, must be %r for topotato"
                % (cls.makevars["sysconfdir"], cls.confpath)
            )
        if not os.path.isdir(cls.confpath):
            result.error(
                "FRR config directory %r does not exist or is not a directory"
                % cls.confpath
            )

        in_topotato = set(cls.daemons)
        cls.daemons = list(sorted(cls.makevars["vtysh_daemons"].split()))
        missing = set(cls.daemons) - in_topotato
        for daemon in missing:
            logger.warning(
                "daemon %s missing from FRRConfigs.daemons, please add!", daemon
            )

        # this determines startup order
        cls.daemons.remove("zebra")
        cls.daemons.remove("staticd")
        cls.daemons.insert(0, "zebra")
        cls.daemons.insert(1, "staticd")

        logger.info("FRR daemons: %s", ", ".join(cls.daemons))

        notbuilt = set()
        cls.binmap = {}
        buildprogs = []
        buildprogs.extend(cls.makevars["sbin_PROGRAMS"].split())
        buildprogs.extend(cls.makevars["noinst_PROGRAMS"].split())
        for name in buildprogs:
            _, daemon = name.rsplit("/", 1)
            if daemon not in cls.daemons:
                logger.debug("ignoring target %r", name)
            else:
                logger.debug("%s => %s", daemon, name)
                if not os.path.exists(os.path.join(frrpath, name)):
                    result.warning("daemon %r enabled but not built?" % daemon)
                    notbuilt.add(daemon)
                else:
                    cls.binmap[daemon] = name

        disabled = set(cls.daemons) - set(cls.binmap.keys()) - notbuilt
        for daemon in sorted(disabled):
            result.warning("daemon %r not enabled in configure, skipping" % daemon)

        xrefpath = os.path.join(frrpath, "frr.xref")
        if os.path.exists(xrefpath):
            with open(xrefpath, "r", encoding="utf-8") as fd:
                cls.xrefs = json.load(fd)

    def __init__(self, topology: "toponom.Network"):
        super().__init__()
        self.topology = topology

    @dataclass
    class TemplateUtils:
        configs: "FRRConfigs"
        router: "toponom.Router"
        daemon: str

        def static_route_for(
            self,
            dst: "toponom.AnyNetwork",
            *,
            rtr_filter: Callable[["toponom.Router"], bool] = lambda nbr: True,
        ):
            """
            Calculate and output a staticd route for given destination.

            Current router is used as starting point.  Uses a simple
            breath-first search, only one route will be output (no ECMP.)
            If the destination is directly connected, output is a comment.
            """
            visited: Set["toponom.Router"] = set()
            queue: List[
                Tuple[
                    "toponom.Router",
                    List[Tuple["toponom.LinkIface", "toponom.LinkIface"]],
                ]
            ] = [(self.router, [])]

            assert dst.version in [4, 6]
            ipv = cast(Union[Literal[4], Literal[6]], dst.version)

            while queue:
                rtr, path = queue.pop(0)
                if rtr in visited:
                    continue
                visited.add(rtr)
                for addr in rtr.addrs(ipv):
                    if dst == addr.network:
                        if not path:
                            return f"! {dst!s} is directly connected"
                        if_self, if_other = path[0]
                        if dst.version == 6:
                            return (
                                f"ipv6 route {dst!s} {if_other.ll6!s} {if_self.ifname}"
                            )
                        return (
                            f"ip route {dst!s} {if_other.ip4[0].ip!s} {if_self.ifname}"
                        )
                for iface, nbr_iface, nbr in rtr.neighbors(rtr_filter=rtr_filter):
                    nbr_path = path + [(iface, nbr_iface)]
                    queue.append((nbr, nbr_path))

            raise RuntimeError(f"no route for {dst!r} on {self.router!r}")

    def generate(self):
        """
        Render and fill in the actual templates.
        """
        topo = self.topology

        routers = getattr(self, "routers", list(topo.routers.keys()))
        rtrmap = {rname: topo.router(rname) for rname in routers}

        for rname in routers:
            router = topo.router(rname)
            ritem = self.setdefault(router.name, {})

            for daemon, template in self.templates.items():
                if (
                    self.daemon_rtrs[daemon] is None
                    or rname in self.daemon_rtrs[daemon]
                ):
                    ritem[daemon] = template.render(
                        daemon=daemon,
                        router=router,
                        routers=rtrmap,
                        topo=topo,
                        frr=self.TemplateUtils(self, router, daemon),
                    )
        return self

    def want_daemon(self, rtr: str, daemon: str) -> bool:
        if rtr not in self:
            return False
        return daemon in self[rtr]

    def eval(self, rtr: str, text: str):
        """
        Helper used for the "compare" text for vtysh to fill in bits

        TBD: Replace with straight-up jinja2?
        """
        expr = jenv.compile_expression(text)
        return expr(router=self.topology.routers[rtr])

    @classmethod
    def prepare(cls):
        """
        Prepare / parse the templates

        (Modifies the class itself, not much point in doing anything else)
        """
        cls.templates = {}
        cls.daemon_rtrs = {}

        for daemon in cls.daemons:
            if not hasattr(cls, daemon):
                continue
            text = deindent(getattr(cls, daemon))

            cls.templates[daemon] = jenv.from_string(text)
            cls.daemon_rtrs[daemon] = getattr(cls, "%s_routers" % daemon, None)

        return cls


class TimedVtysh(TimedElement):
    """
    Record output from an FRR vtysh invocation.

    This creates the appropriate wrapping for vtysh output to go into the
    :py:class:`Timeline`.

    One instance of this class represents only one vtysh command, if executing
    multiple commands in one go they each receive their own object.
    """

    rtrname: str
    daemon: str

    cmd: str
    """vtysh command that was executed.  Whitespace is stripped."""

    retcode: int
    """
    vtysh return code.

    .. todo::

       wrap ``CMD_*`` enum values from ``command.h``.
    """

    text: str
    """command output.  Whitespace is NOT stripped."""

    last: bool
    """
    Set if this command is the last of a multi-command batch.

    This is used to know when to stop running the Timeline event poller.
    """

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        ts: float,
        rtrname: str,
        daemon: str,
        cmd: str,
        retcode: int,
        text: str,
        last: bool,
    ):
        super().__init__()
        self._ts = ts
        self.rtrname = rtrname
        self.daemon = daemon
        self.cmd = cmd
        self.retcode = retcode
        self.text = text
        self.last = last

    @property
    def ts(self):
        return (self._ts, 0)

    def serialize(self, context: Context):
        jsdata = {
            "type": "vtysh",
            "router": self.rtrname,
            "daemon": self.daemon,
            "command": self.cmd,
            "retcode": self.retcode,
            "text": self.text,
        }
        return (jsdata, None)


class VtyshPoll(MiniPollee):
    """
    vtysh read poll event handler.

    Instances of this class are dynamically added (and removed) from the
    :py:class:`Timeline` event poll list while commands are executed.

    This also handles sending the next command when the previous one is done.
    """

    rtrname: str
    daemon: str

    _cur_cmd: Optional[str]
    _cur_out: Optional[bytes]

    def __init__(self, rtrname: str, daemon: str, sock: socket.socket, cmds: List[str]):
        self.rtrname = rtrname
        self.daemon = daemon
        self._sock = sock
        self._cmds = cmds
        self._cur_cmd = None
        self._cur_out = None

    def send_cmd(self):
        assert self._cur_cmd is None

        if not self._cmds:
            return

        self._cur_cmd = cmd = self._cmds.pop(0)
        self._cur_out = b""

        self._sock.setblocking(True)
        self._sock.sendall(cmd.strip().encode("UTF-8") + b"\0")
        self._sock.setblocking(False)

    def fileno(self) -> Optional[int]:
        return self._sock.fileno()

    def readable(self) -> Generator[TimedElement, None, None]:
        # TODO: timeout? socket close?
        assert self._cur_cmd is not None
        assert self._cur_out is not None

        self._cur_out += self._sock.recv(4096)

        if len(self._cur_out) >= 4 and self._cur_out[-4:-1] == b"\0\0\0":
            rc = self._cur_out[-1]
            raw = self._cur_out[:-4]
            text = raw.decode("UTF-8").replace("\r\n", "\n")

            # accept a few more non-error return codes?
            last = rc != 0 or not self._cmds

            yield TimedVtysh(
                time.time(), self.rtrname, self.daemon, self._cur_cmd, rc, text, last
            )

            self._cur_cmd = None
            self._cur_out = None

            if not last:
                self.send_cmd()


class FRRNetworkInstance(NetworkInstance):
    """
    Main network representation & interface, adding the FRR bits to NetworkInstance

    SwitchNS is not specialized here, nothing FRR in there.
    """

    # pylint: disable=too-many-ancestors
    class RouterNS(NetworkInstance.RouterNS):
        """
        Add a bunch of FRR daemons on top of an (OS-dependent) RouterNS
        """

        instance: "FRRNetworkInstance"
        logfiles: Dict[str, str]
        pids: Dict[str, int]
        rundir: Optional[str]
        rtrcfg: Dict[str, str]
        livelogs: Dict[str, LiveLog]

        def __init__(self, instance: "FRRNetworkInstance", name: str):
            super().__init__(instance, name)
            self.logfiles = {}
            self.livelogs = {}
            self.pids = {}
            self.rundir = None
            self.rtrcfg = {}

        def _getlogfd(self, daemon):
            if daemon not in self.livelogs:
                self.livelogs[daemon] = LiveLog(self, daemon)
                self.instance.timeline.install(self.livelogs[daemon])
            return self.livelogs[daemon].wrfd

        def xrefs(self):
            return FRRConfigs.xrefs

        def start(self):
            super().start()

            frrcred = self.instance.configs.frrcred

            self.rundir = rundir = self.tempfile("run")
            os.mkdir(rundir)
            os.chown(rundir, frrcred.pw_uid, frrcred.pw_gid)
            self.rundir = rundir
            # bit of a hack
            self.check_call(["mount", "--bind", rundir, "/var/run"])

            self.rtrcfg = self.instance.configs.get(self.name, {})

            for daemon in FRRConfigs.daemons:
                if daemon not in self.rtrcfg:
                    continue
                self.logfiles[daemon] = self.tempfile("%s.log" % daemon)
                self.start_daemon(daemon)

        def start_daemon(self, daemon: str):
            frrpath = self.instance.configs.frrpath
            binmap = self.instance.configs.binmap

            use_integrated = daemon in FRRConfigs.daemons_integrated_only

            if use_integrated:
                cfgpath = self.tempfile("integrated-" + daemon + ".conf")
            else:
                cfgpath = self.tempfile(daemon + ".conf")
            with open(cfgpath, "w", encoding="utf-8") as fd:
                fd.write(self.rtrcfg[daemon])

            assert self.rundir is not None

            logfd = self._getlogfd(daemon)

            execpath = os.path.join(frrpath, binmap[daemon])
            cmdline = []

            cmdline.extend(
                [
                    execpath,
                    "-d",
                ]
            )
            if not use_integrated:
                cmdline.extend(
                    [
                        "-f",
                        cfgpath,
                    ]
                )
            cmdline.extend(
                [
                    "--log",
                    "file:%s" % self.logfiles[daemon],
                    "--log",
                    "monitor:%d" % logfd.fileno(),
                    "--log-level",
                    "debug",
                    "--vty_socket",
                    self.rundir,
                    "-i",
                    "%s/%s.pid" % (self.rundir, daemon),
                ]
            )
            try:
                self.check_call(cmdline, pass_fds=[logfd.fileno()])
            except subprocess.CalledProcessError as e:
                raise TopotatoDaemonCrash(
                    daemon=daemon, router=self.name, cmdline=shlex.join(cmdline)
                ) from e

            # want record-priority & timestamp precision...
            pid, _, _ = self.vtysh_polled(
                self.instance.timeline,
                daemon,
                "enable\nconfigure\nlog file %s\ndebug memstats-at-exit\nend\nclear log cmdline-targets"
                % self.logfiles[daemon],
            )
            self.pids[daemon] = pid

            if use_integrated:
                self.vtysh(["-d", daemon, "-f", cfgpath])

        def restart(self, daemon: str):
            pidfile = "%s/%s.pid" % (self.rundir, daemon)
            with open(pidfile, "r", encoding="utf-8") as fd:
                pid = int(fd.read())
            self.check_call(["kill", "-TERM", str(pid)])
            for _ in range(0, 5):
                try:
                    self.check_call(["kill", "-TERM", str(pid)])
                except subprocess.CalledProcessError:
                    break
                self.instance.timeline.sleep(0.1)

            self.start_daemon(daemon)

        def end_prep(self):
            for livelog in self.livelogs.values():
                livelog.close_prep()

            for daemon, pid in list(reversed(self.pids.items())):
                try:
                    os.kill(pid, signal.SIGTERM)
                    # stagger SIGTERM signals a tiiiiny bit
                    self.instance.timeline.sleep(0.01)
                except ProcessLookupError:
                    del self.pids[daemon]
                    # FIXME: log something

            super().end_prep()

        def end(self):
            livelogs = self.livelogs.values()

            # TODO: move this to instance level
            self.instance.timeline.sleep(1.0, final=livelogs)

            for livelog in self.livelogs.values():
                livelog.close()

            super().end()

        def vtysh(self, args):
            frrpath = self.instance.configs.frrpath
            execpath = os.path.join(frrpath, "vtysh/vtysh")
            return self.popen(
                [execpath] + ["--vty_socket", self.rundir] + args,
                stdout=subprocess.PIPE,
            )

        def vtysh_polled(self, timeline: Timeline, daemon, cmds, timeout=5.0):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
            fn = self.tempfile("run/%s.vty" % (daemon))

            sock.connect(fn)
            peercred = sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3I")
            )
            pid, _, _ = struct.unpack("3I", peercred)

            cmds = [c.strip() for c in cmds.splitlines() if c.strip() != ""]

            # TODO: refactor
            vpoll = VtyshPoll(self.name, daemon, sock, cmds)

            text = []
            retcode = None

            with timeline.with_pollee(vpoll) as poller:
                vpoll.send_cmd()

                end = time.time() + timeout
                for event in poller.run_iter(end):
                    if not isinstance(event, TimedVtysh):
                        continue
                    text.append(event.text)
                    retcode = event.retcode
                    if event.last:
                        break

            return (pid, "".join(text), retcode)

    def __init__(self, network: "toponom.Network", configs: FRRConfigs):
        super().__init__(network)
        self.configs = configs
        self.timeline = Timeline()
