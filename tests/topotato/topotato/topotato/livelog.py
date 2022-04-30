import socket
import struct
import syslog

from .utils import MiniPollee


class LogMessage:
    _prios = {
        syslog.LOG_EMERG: 'emerg',
        syslog.LOG_ALERT: 'alert',
        syslog.LOG_CRIT: 'crit',
        syslog.LOG_ERR: 'error',
        syslog.LOG_WARNING: 'warn',
        syslog.LOG_NOTICE: 'notif',
        syslog.LOG_INFO: 'info',
        syslog.LOG_DEBUG: 'debug',
    }

    def __init__(self, router, daemon, rawmsg):
        self.router = router
        self.daemon = daemon
        self.match_for = []

        header, rawmsg = rawmsg[:72], rawmsg[72:]
        ts_sec, ts_nsec, hdrlen, pid, tid, lost, prio, flags, textlen, arghdrlen, uid, ec, n_argpos = \
                struct.unpack('QIIqqIIIII12sII', header)
        self.uid = uid.rstrip(b'\0').decode('ASCII')
        self._prio = prio

        argspec, rawmsg = rawmsg[:n_argpos * 8], rawmsg[n_argpos * 8:]
        self.args = {}
        for i in range(0, n_argpos):
            start, end = struct.unpack('II', argspec[i*8:(i+1)*8])
            self.args[i] = (start, end)

        self.arghdrlen = arghdrlen
        self.rawtext = rawmsg[:textlen]
        self.text = self.rawtext.decode('UTF-8')
        self.ts = ts_sec + ts_nsec * 1e-9

    @property
    def prio_text(self):
        return self._prios.get(self._prio & 7, '???')

    def iter_args(self):
        prev_end = self.arghdrlen
        for start, end in self.args.values():
            yield (self.rawtext[prev_end:start].decode('UTF-8'),
                    self.rawtext[start:end].decode('UTF-8'))
            prev_end = end
        yield (self.rawtext[prev_end:].decode('UTF-8'), None)

    def __str__(self):
        return self.text

    def __repr__(self):
        return '<%s @%.6f %r>' % (self.__class__.__name__, self.ts, self.text)


class LiveLog(MiniPollee, list):
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
        return '<%s %s>' % (self.__class__.__name__, super().__repr__())

    @property
    def wrfd(self):
        if not self._wrfd:
            raise ValueError("trying to reuse LiveLog after it was closed")
        return self._wrfd

    def filenos(self):
        if self._rdfd:
            yield (self._rdfd, self._read)

    def close_prep(self):
        if self._wrfd is not None:
            self._wrfd.close()
            self._wrfd = None

    def close(self):
        assert self._wrfd is None
        if self._rdfd is not None:
            self._rdfd.close()
            self._rdfd = None

    def _read(self, fd):
        for _ in range(0, 100):
            try:
                rddata = fd.recv(16384)
            except BlockingIOError:
                return False

            if len(rddata) == 0:
                self._rdfd.close()
                self._rdfd = None
                return True

            msg = LogMessage(self._router, self._daemon, rddata)
            self.append(msg)
            yield (True, msg)
