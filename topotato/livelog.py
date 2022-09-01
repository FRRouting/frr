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
from .timeline import MiniPollee, TimedElement
from .pcapng import JournalExport, Context


# pylint: disable=too-many-instance-attributes
class LogMessage(TimedElement):
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
    _LogHdr = namedtuple("LogHdr", _LogHdrFields.keys())  # type: ignore

    def __init__(self, router, daemon, rawmsg):
        super().__init__()

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
    def ts(self):
        return (self._ts, 0)

    def serialize(self, context: Context):
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

        sde = JournalExport(
            {
                "__REALTIME_TIMESTAMP": "%d"
                % (
                    self.header_fields.ts_sec * 1000000
                    + self.header_fields.ts_nsec // 1000
                ),
                "MESSAGE": self.text,
                "PRIORITY": self.header_fields.prio,
                "TID": self.header_fields.tid,
                "FRR_ID": self.uid,
                "FRR_EC": self.header_fields.ec,
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
    def prio_text(self):
        return self._prios.get(self._prio & 7, "???")

    def iter_args(self):
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


class LiveLog(MiniPollee):
    def __init__(self, router, daemon):
        super().__init__()

        self._router = router
        self._daemon = daemon

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
        if not self._wrfd:
            raise ValueError("trying to reuse LiveLog after it was closed")
        return self._wrfd

    def fileno(self):
        return self._rdfd

    def close_prep(self):
        if self._wrfd is not None:
            self._wrfd.close()
            self._wrfd = None

    def close(self):
        assert self._wrfd is None
        if self._rdfd is not None:
            self._rdfd.close()
            self._rdfd = None

    def readable(self):
        for _ in range(0, 100):
            try:
                rddata = self._rdfd.recv(16384)
            except BlockingIOError:
                return

            if len(rddata) == 0:
                self._rdfd.close()
                self._rdfd = None
                return

            yield LogMessage(self._router, self._daemon, rddata)
