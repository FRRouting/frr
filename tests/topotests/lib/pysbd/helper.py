# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Topotest helper: run `pysbd` in a router and talk to it.

    from lib.pysbd.helper import Pysbd

    sbd = Pysbd(router, ["-p", "ipv4:127.0.0.1", "-f", "ipv4:127.0.0.1"])
    sbd.start()                  # before the router daemons
    sbd.wait_connected("pim")
    sbd.command("mrt join-spt 192.168.3.10 224.100.0.1 2")
    sbd.show("routes")           # parsed `show routes json`
    sbd.stop()
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from .console import send_command

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
#: Unix socket paths can't be longer than this.
UNIX_PATH_MAX = 107

logger = logging.getLogger("topo")


def kernel_mroutes(
    router: Any, family: int = socket.AF_INET
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """
    The kernel multicast routing table `pysbd` programs, as
    {(source, group): {"iif": name, "oifs": [names], "packets": count}}.
    """
    if family == socket.AF_INET:
        vif_file, cache_file = "/proc/net/ip_mr_vif", "/proc/net/ip_mr_cache"

        def _address(text: str) -> str:
            return socket.inet_ntoa(struct.pack("<I", int(text, 16)))

    else:
        vif_file, cache_file = "/proc/net/ip6_mr_vif", "/proc/net/ip6_mr_cache"

        def _address(text: str) -> str:
            return str(ipaddress.IPv6Address(text))

    vifs = {}
    for line in router.cmd("cat {}".format(vif_file)).splitlines()[1:]:
        fields = line.split()
        vifs[fields[0]] = fields[1]

    routes = {}
    for line in router.cmd("cat {}".format(cache_file)).splitlines()[1:]:
        fields = line.split()
        routes[(_address(fields[1]), _address(fields[0]))] = {
            "iif": vifs.get(fields[2], "vif" + fields[2]),
            "packets": int(fields[3]),
            "oifs": sorted(
                vifs.get(oif.split(":")[0], "vif" + oif) for oif in fields[6:]
            ),
        }
    return routes


class PysbdError(Exception):
    pass


class Pysbd:
    """
    `router` is a topogen router (or anything with `name`, `gearlogdir`,
    `cmd` and `popen`). Extra arguments come from the `PYSBD_EXTRA_ARGS`
    environment variable (e.g. `-P` to log every packet).
    """

    def __init__(
        self, router: Any, args: List[str], logname: str = "pysbd.log"
    ) -> None:
        self.router = router
        self.args = list(args) + os.environ.get("PYSBD_EXTRA_ARGS", "").split()
        self.logfile_path = os.path.join(router.gearlogdir, logname)
        self.control = os.path.join(router.gearlogdir, "pysbd.sock")
        if len(self.control) > UNIX_PATH_MAX:
            self.control = os.path.join(
                tempfile.gettempdir(),
                "pysbd-{}-{}.sock".format(router.name, os.getpid()),
            )
        self.proc: Optional[subprocess.Popen] = None
        self._logfile: Optional[Any] = None

    def start(self, timeout: float = 30.0) -> None:
        """Start `pysbd` and wait until it accepts commands."""
        # pysbd joins several groups per interface.
        self.router.cmd("sysctl -w net.ipv4.igmp_max_memberships=1000")
        if os.path.exists(self.control):
            os.unlink(self.control)

        self._logfile = open(self.logfile_path, "w")
        command = [sys.executable, PACKAGE_DIR, "-n", "-c", self.control] + self.args
        logger.info("%s: starting %s", self.router.name, " ".join(command))
        self.proc = self.router.popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=self._logfile,
            stderr=subprocess.STDOUT,
        )

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise PysbdError(
                    "{}: pysbd exited ({}), see {}".format(
                        self.router.name, self.proc.returncode, self.logfile_path
                    )
                )
            try:
                send_command(self.control, "show debug", timeout=2)
                return
            except OSError:
                time.sleep(0.2)
        raise PysbdError("{}: pysbd does not answer commands".format(self.router.name))

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None
        if self._logfile is not None:
            self._logfile.close()
            self._logfile = None

    def command(self, line: str, check: bool = True) -> str:
        """
        Run a command and return its output. With `check` an event command
        that could not be sent raises `PysbdError`.
        """
        logger.info("%s: pysbd # %s", self.router.name, line)
        output = send_command(self.control, line)
        if output:
            logger.debug("%s: pysbd output:\n%s", self.router.name, output)
        if check and (
            "drop " in output
            or "unknown command" in output
            or "unrecognized input" in output
            or "check inputs" in output
        ):
            raise PysbdError(
                "{}: {}: {}".format(self.router.name, line, output.strip())
            )
        return output

    def show(self, what: str) -> Any:
        """Parsed `show WHAT json`."""
        return json.loads(send_command(self.control, "show {} json".format(what)))

    def wait_connected(self, name: str, timeout: float = 60.0) -> None:
        """Wait for a daemon connection (`pim`, `pim6` or `fpm`)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.show("connections").get(name, {}).get("connected"):
                return
            time.sleep(0.5)
        raise PysbdError(
            "{}: pysbd {} connection not established".format(self.router.name, name)
        )
