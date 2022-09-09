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
import select
import shlex
import socket
import subprocess
import sys
import time
import typing
from typing import List, ClassVar, Dict, Mapping, Optional, Any, Iterator, Tuple

import jinja2

from .utils import deindent, ClassHooks
from .timeline import Timeline
from .livelog import LiveLog
from .exceptions import TopotatoDaemonCrash

if typing.TYPE_CHECKING:
    from . import toponom

if sys.platform == "linux":
    from .topolinux import NetworkInstance
elif sys.platform == "freebsd12":
    from .topofreebsd import NetworkInstance
else:

    class NetworkInstance(ClassHooks):
        class RouterNS:
            pass

        def __init__(self, *args, **kwargs):
            raise NotImplementedError("no support for OS %r" % sys.platform)

        @classmethod
        def _check_env(cls, *, result, **kwargs):
            raise NotImplementedError("no support for OS %r" % sys.platform)


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


class FRRConfigs(dict, ClassHooks):
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
    daemons.extend("pimd ldpd nhrpd sharpd pathd pbrd bfdd vrrpd".split())

    # pylint: disable=too-many-locals,too-many-statements
    @classmethod
    def _check_env(cls, *, result, **kwargs):
        """
        grab some setup information about a FRR build from frrpath

        among other things, this figures out which daemons are even available
        """
        cls.frrpath = frrpath = os.path.abspath(cls.frrpath)

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

        cls.daemons = list(sorted(cls.makevars["vtysh_daemons"].split()))
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
        rundir: Optional[str]
        rtrcfg: Dict[str, str]
        livelogs: Dict[str, LiveLog]

        def __init__(self, instance: "FRRNetworkInstance", name: str):
            super().__init__(instance, name)
            self.logfiles = {}
            self.livelogs = {}
            self.rundir = None
            self.rtrcfg = {}

        def _getlogfd(self, daemon):
            if daemon not in self.livelogs:
                self.livelogs[daemon] = LiveLog(self, daemon)
                self.instance.timeline.install(self.livelogs[daemon])
            return self.livelogs[daemon].wrfd

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

            cfgpath = self.tempfile(daemon + ".conf")
            with open(cfgpath, "w", encoding="utf-8") as fd:
                fd.write(self.rtrcfg[daemon])

            assert self.rundir is not None

            logfd = self._getlogfd(daemon)

            execpath = os.path.join(frrpath, binmap[daemon])
            cmdline = [
                execpath,
                "-d",
                "-f",
                cfgpath,
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
            try:
                self.check_call(cmdline, pass_fds=[logfd.fileno()])
            except subprocess.CalledProcessError as e:
                raise TopotatoDaemonCrash(
                    daemon=daemon, router=self.name, cmdline=shlex.join(cmdline)
                ) from e

            # want record-priority & timestamp precision...
            self.vtysh_fast(
                daemon,
                "enable\nconfigure\nlog file %s\nend\nclear log cmdline-targets"
                % self.logfiles[daemon],
            )

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

        def stop(self):
            for livelog in self.livelogs.values():
                self.instance.timeline.uninstall(livelog)
                livelog.close()

            super().end()

        def vtysh(self, args):
            frrpath = self.instance.configs.frrpath
            execpath = os.path.join(frrpath, "vtysh/vtysh")
            return self.popen(
                [execpath] + ["--vty_socket", self.rundir] + args,
                stdout=subprocess.PIPE,
            )

        def vtysh_fast(self, daemon, cmds, timeout=5.0):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
            fn = self.tempfile("run/%s.vty" % (daemon))

            sock.connect(fn)
            cmds = [
                c.strip().encode("UTF-8") for c in cmds.splitlines() if c.strip != ""
            ]

            ret = b""
            for cmd in cmds:
                sock.setblocking(True)
                sock.sendall(cmd + b"\0")
                sock.setblocking(False)

                start = time.time()
                while True:
                    r = select.select([sock], [], [], start + timeout - time.time())
                    if len(r[0]) == 0:
                        raise IOError("vty connection timed out")
                    ret += sock.recv(4096)
                    if len(ret) >= 4 and ret[-4:-1] == b"\0\0\0":
                        rc = ret[-1]
                        ret = ret[:-4]
                        break

            return (ret.decode("UTF-8").replace("\r\n", "\n"), rc)

    def __init__(self, network: "toponom.Network", configs: FRRConfigs):
        super().__init__(network)
        self.configs = configs
        self.timeline = Timeline()
