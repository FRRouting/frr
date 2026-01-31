#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
Live-capture log messages from FRR and feed them into topotato.
"""

import socket
import struct
import syslog
from collections import namedtuple

import typing
from typing import Dict, Generator, Optional, Set, Tuple

from ..timeline import MiniPollee, TimedElement, FrameworkEvent
from ..pcapng import JournalExport, Context

if typing.TYPE_CHECKING:
    from . import FRRRouterNS


# pylint: disable=too-many-instance-attributes
class LogMessage(TimedElement):
    """
    Parse and make accessible a binary log message from FRR.

    topotato uses FRR's live-log-to-vtysh logging backend, which crams all
    details about the log message into a binary header.  This has several
    advantages:

    - it's independent of any logging config
    - log messages are immediately available on startup as this is enabled
      with the ``--log`` cmdline option
    - all available details on the log message are included
    - no parsing regexes
    - it's a unix socket and messages are received live, no "polling" a file

    The downside is that we need to binary unpack the message header according
    to the format defined in ``lib/zlog_live.h``.  But that should change
    rarely if ever.
    """

    _prios = {
        syslog.LOG_EMERG: "emerg",
        syslog.LOG_ALERT: "alert",
        syslog.LOG_CRIT: "crit",
        syslog.LOG_ERR: "error",
        syslog.LOG_WARNING: "warn",
        syslog.LOG_NOTICE: "notif",
        syslog.LOG_INFO: "info",
        syslog.LOG_DEBUG: "debug",
    }

    _LogHdrFields = {
        "ts_sec": "Q",
        "ts_nsec": "I",
        "hdrlen": "I",
        "pid": "q",
        "tid": "q",
        "lost": "I",
        "prio": "I",
        "flags": "I",
        "textlen": "I",
        "arghdrlen": "I",
        "uid": "12s",
        "ec": "I",
        "n_argpos": "I",
    }
    """
    Ordered description of fields in binary header.  Must match
    ``struct zlog_live_hdr`` in FRR.
    """

    _LogHdr = namedtuple("LogHdr", _LogHdrFields.keys())  # type: ignore
    """
    helper structure to make decoding more readable.
    """

    header_fields: _LogHdr
    """
    raw header decoding result
    """

    arghdrlen: int
    """
    Length of the text "header" of the log messages, i.e. the
    ``[ABCDE-FGHIJ][EC 1234]`` part.  That data is available in :py:attr:`uid`
    and :py:attr:`header_fields.ec`, so it makes sense to strip it off.
    """

    args: Dict[int, Tuple[int, int]]
    """
    Positions of printf formatting arguments in the log message, start and end.
    Can be used to split up :py:attr:`rawtext` into subitems.  (Byte offsets,
    so must be used with undecoded text to be 100% correct.)
    :py:meth:`iter_args` wraps this.
    """

    rawtext: bytes
    text: str

    uid: str
    """
    log message unique identifier (xref)
    """

    _ts: float
    _prio: int

    router: "FRRRouterNS"
    daemon: str

    # mypy doesn't work with dynamic namedtuple
    @typing.no_type_check
    def __init__(self, router: "FRRRouterNS", daemon: str, rawmsg: bytes):
        super().__init__()

        # router name & daemon are not included in the message;  but we know
        # because the socket is connected to only one daemon
        self.router = router
        self.daemon = daemon

        header, rawmsg = rawmsg[:72], rawmsg[72:]

        hdata = struct.unpack("".join(self._LogHdrFields.values()), header)
        self.header_fields = fields = self._LogHdr(*hdata)

        self.uid = fields.uid.rstrip(b"\0").decode("ASCII")
        self._prio = fields.prio

        argspec, rawmsg = rawmsg[: fields.n_argpos * 8], rawmsg[fields.n_argpos * 8 :]
        self.args = {}
        for i in range(0, fields.n_argpos):
            start, end = struct.unpack("II", argspec[i * 8 : (i + 1) * 8])
            self.args[i] = (start, end)

        self.arghdrlen = fields.arghdrlen
        self.rawtext = rawmsg[: fields.textlen]
        self.text = self.rawtext.decode("UTF-8")
        self._ts = fields.ts_sec + fields.ts_nsec * 1e-9

    @property
    def ts(self) -> Tuple[float, int]:
        return (self._ts, 0)

    def serialize(self, context: Context):
        """
        Output log message to JSON and pcap-ng for test report.
        """
        _ = context.take_frame_num()

        data = self.header_fields._asdict()

        # don't need these
        del data["ts_sec"]
        del data["ts_nsec"]
        del data["hdrlen"]

        data.update(
            {
                "type": "log",
                "router": self.router.name,
                "daemon": self.daemon,
                "text": self.text,
                "uid": self.uid,
                "prio": self.prio_text,
                "args": self.args,
            }
        )

        ts_usec = self.header_fields.ts_sec * 1000000  # type: ignore
        ts_usec += self.header_fields.ts_nsec // 1000  # type: ignore

        sde = JournalExport(
            {
                "__REALTIME_TIMESTAMP": "%d" % (ts_usec,),
                "MESSAGE": self.text,
                "PRIORITY": self.header_fields.prio,  # type: ignore
                "TID": self.header_fields.tid,  # type: ignore
                "FRR_ID": self.uid,
                "FRR_EC": self.header_fields.ec,  # type: ignore
                "FRR_DAEMON": self.daemon,
                "_COMM": self.daemon,
                "_HOSTNAME": self.router.name,
                # TBD: CODE_FILE, CODE_LINE, CODE_FUNC
                # TBD: FRR_INSTANCE
                # TBD: FRR_ARG[n]
            }
        )

        # NB: wireshark currently can't decode comments on systemd journal
        # items, the pcap-ng block has no options field...
        for match in self.match_for:
            sde.options.append(sde.OptComment("match for %r" % match))

        return (data, sde)

    @property
    def prio_text(self) -> str:
        """
        Shortened textual representation of log message priority.
        """
        return self._prios.get(self._prio & 7, "???")

    def iter_args(self) -> Generator[Tuple[str, Optional[str]], None, None]:
        """
        Divvy up log message into text fragments according to printf arguments.

        Yields tuples of (text-before, format-argument), and the final
        leftover it is yielded with format-argument = None.
        """
        prev_end = self.arghdrlen
        for start, end in self.args.values():
            yield (
                self.rawtext[prev_end:start].decode("UTF-8"),
                self.rawtext[start:end].decode("UTF-8"),
            )
            prev_end = end
        yield (self.rawtext[prev_end:].decode("UTF-8"), None)

    def __str__(self):
        return self.text

    def __repr__(self):
        return "<%s @%.6f %r>" % (self.__class__.__name__, self._ts, self.text)


class LogClosed(FrameworkEvent):
    typ = "log_closed"

    def __init__(self, rtrname: str, daemon: str):
        super().__init__()
        self._data["router"] = rtrname
        self._data["daemon"] = daemon


class LiveLog(MiniPollee):
    """
    Receiver for log messages from an FRR daemon.

    Sets up an unix datagram socketpair, one end of which will be given to
    the FRR daemon to write log messages to.  One LiveLog instance is used for
    one FRR daemon, so there will be a few of these in a normal run.  Messages
    are received from the fd through the topotato event loop.
    """

    xrefs_seen: Set[str]
    """
    All FRR unique xref identifiers seen in log messages on this socket.
    """

    def __init__(self, router: "FRRRouterNS", daemon: str):
        super().__init__()

        self._router = router
        self._daemon = daemon
        self.xrefs_seen = set()

        rdfd, wrfd = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        rdfd.setblocking(False)

        bufdflt = rdfd.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        bufsz = 8388608
        while bufsz > bufdflt:
            try:
                rdfd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsz)
                break
            except OSError:
                bufsz = int(bufsz / 1.5)

        bufdflt = wrfd.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        bufsz = 8388608
        while bufsz > bufdflt:
            try:
                wrfd.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsz)
                break
            except OSError:
                bufsz = int(bufsz / 1.5)

        self._rdfd = rdfd
        self._wrfd = wrfd

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, super().__repr__())

    @property
    def wrfd(self):
        """
        Write side file descriptor number to hand to FRR.  The FD must be given
        to the daemon on fork/exec and indicated with ``--log monitor:FD`` on
        the command line.
        """
        if not self._wrfd:
            raise ValueError("trying to reuse LiveLog after it was closed")
        return self._wrfd

    def fileno(self):
        """
        Read side file descriptor to receive messages on.
        """
        return self._rdfd

    def close_prep(self):
        """
        Close FRR side file descriptor after fork/exec is done.
        """
        if self._wrfd is not None:
            self._wrfd.close()
            self._wrfd = None

    def close(self):
        assert self._wrfd is None
        if self._rdfd is not None:
            self._rdfd.close()
            self._rdfd = None

    def readable(self):
        """
        Called from event loop, receive log messages (max 100 per call).

        If there's more log messages this will be called again since the FD
        will still be readable, just give other event handlers a chance to run
        meanwhile.
        """
        for _ in range(0, 100):
            try:
                rddata = self._rdfd.recv(16384)
            except BlockingIOError:
                return

            if len(rddata) == 0:
                yield LogClosed(self._router.name, self._daemon)
                self._rdfd.close()
                self._rdfd = None
                return

            logmsg = LogMessage(self._router, self._daemon, rddata)
            self.xrefs_seen.add(logmsg.uid)
            yield logmsg

    def serialize(self, context: Context):
        """
        Output subset of xrefs data for javascript to look up on.
        """
        all_xrefs = self._router.xrefs()
        xrefs = {
            uid: data
            for uid, data in all_xrefs["refs"].items()
            if uid in self.xrefs_seen
        }

        yield ({"xrefs": xrefs}, None)
