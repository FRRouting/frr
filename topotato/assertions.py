
import sys, time, functools
import pytest, _pytest.nodes, _pytest.fixtures
from .utils import *
from .exceptions import *
import logging
import inspect
import tempfile
import subprocess
import select
import signal
from collections import OrderedDict

logger = logging.getLogger('topotato')
logger.setLevel(logging.DEBUG)

TopotatoCompareFail = TopotatoCLICompareFail

from .base import TopotatoItem, topotatofunc, skiptrace

class TopotatoAssertion(TopotatoItem):
    pass

class TopotatoModifier(TopotatoItem):
    pass

class AssertKernelRoutes(TopotatoAssertion):
    @classmethod
    def from_parent(cls, parent, name, rtr, routes, local = False, delay = 0.1, maxwait = None):
        name = '%s:%s/routes-v%d' % (name, rtr, cls.af)
        self = super().from_parent(parent, name=name)

        self._rtr = rtr
        self._routes = routes
        self._local = local
        self._delay = delay
        self._maxwait = maxwait
        return self

    def __call__(self):
        router = self.instance.routers[self._rtr]
        start = time.time()

        while True:
            routes = router.routes(self.af, self._local)
            diff = json_cmp(routes, self._routes)
            if diff is None:
                break

            if self._maxwait is None or time.time() - start > self._maxwait:
                raise ValueError(diff)

            self.sleep(step=self._delay, until=self._maxwait)

class AssertKernelRoutesV4(AssertKernelRoutes):
    af = 4
class AssertKernelRoutesV6(AssertKernelRoutes):
    af = 6

class AssertVtysh(TopotatoAssertion):
    @classmethod
    def from_parent(cls, parent, name, rtr, daemon, command, compare = None, *, delay = 0.1, maxwait = None):
        name = '%s:%s/%s/vtysh "%s"' % (name, rtr.name, daemon, command.replace('\n', '; '))
        self = super().from_parent(parent, name=name)

        self._rtr = rtr
        self._daemon = daemon
        self._command = command
        self._compare = compare
        self._delay = delay
        self._maxwait = maxwait
        return self

    def __call__(self):
        from .pytestintegration import text_rich_cmp

        router = self.instance.routers[self._rtr.name]
        start = time.time()
        self.commands = OrderedDict()

        while True:
            out, rc = router.vtysh_fast(self._daemon, self._command)
            if rc != 0:
                result = ValueError('vtysh return value %d' % rc)
            else:
                result = None
                if isinstance(self._compare, type(None)):
                    pass
                elif isinstance(self._compare, str):
                    result = text_rich_cmp(self.instance.configs, self._rtr.name, out, self._compare,
                            "output from %s" % (self._command))
                elif isinstance(self._compare, dict):
                    diff = json_cmp(json.loads(out), self._compare)
                    if diff is not None:
                        result = ValueError(diff)

            self.commands.setdefault((self._rtr.name, self._daemon), []).append((time.time(), self._command, out, rc, result))

            if result is None:
                return

            if self._maxwait is None or time.time() - start > self._maxwait:
                print('# %s' % self._command)
                print(out)
                print('-----')
                raise result
            self.sleep(step=self._delay - ((time.time() - start) % self._delay),
                    until=self._maxwait)


class AssertPacket(TopotatoAssertion):
    @classmethod
    def from_parent(cls, parent, name, link, pkt, maxwait = None):
        name = '%s:%s/packet' % (name, link)
        self = super().from_parent(parent, name=name)

        self._link = link
        self._pkt = pkt
        self._maxwait = maxwait
        return self

    def __call__(self):
        liveshark = self.parent.liveshark

        for is_new, pkt in liveshark.run(self._maxwait):
            try:
                if self._pkt(pkt):
                    break
            except KeyError:
                pass
        else:
            raise ValueError('no pkt')


class DaemonRestart(TopotatoModifier):
    @classmethod
    def from_parent(cls, parent, name, rtr, daemon):
        self = super().from_parent(parent, name='%s:%s.%s/restart' % (name, rtr.name, daemon))
        self._rtr = rtr
        self._daemon = daemon
        return self

    def runtest(self):
        if self.skipall:
            pytest.skip(self.skipall)

        router = self.instance.routers[self._rtr.name]
        router.restart(self._daemon)


class ScapySend(TopotatoModifier):
    @classmethod
    def from_parent(cls, parent, name, rtr, iface, pkt):
        path = '/'.join([l.__name__ for l in pkt.layers()])
        self = super().from_parent(parent, name='%s:%s/scapy(%s/%s)' % (name,
            rtr.name, iface, path))
        self._rtr = rtr
        self._iface = iface

        from scapy.all import Ether
        if not isinstance(pkt, Ether):
            pkt = Ether()/pkt

        self._pkt = pkt
        return self

    def runtest(self):
        if self.skipall:
            pytest.skip(self.skipall)

        from topotato.scapyext import NetnsL2Socket

        router = self.instance.routers[self._rtr.name]
        with router:
            sock = NetnsL2Socket(iface=self._iface, promisc=False)
            sock.send(self._pkt)


class ModifyLinkStatus(TopotatoModifier):
    @classmethod
    def from_parent(cls, parent, name, rtr, iface, state):
        name = '%s:%s/link %s (%s) -> %s' % (name, rtr.name, iface.ifname, iface.other.endpoint.name, 'UP' if state else 'DOWN')
        self = super().from_parent(parent, name=name)

        self._rtr = rtr
        self._iface = iface
        self._state = state
        return self

    def __call__(self):
        router = self.instance.routers[self._rtr.name]
        router.link_set(self._iface, self._state)

class BackgroundCommand(object):
    def __init__(self, rtr, cmd):
        self._rtr = rtr
        self._cmd = cmd

    class Action(TopotatoModifier):
        @classmethod
        def from_parent(cls, parent, name, cmdobj):
            name = '%s:%s/exec "%s" (%s)' % (name, cmdobj._rtr.name, cmdobj._cmd, cls.__name__)
            self = super().from_parent(parent, name=name)

            self._rtr = cmdobj._rtr
            self._cmdobj = cmdobj
            return self

    class Start(Action):
        def __call__(self):
            router = self.instance.routers[self._rtr.name]

            ifd = open('/dev/null', 'r')
            self._cmdobj.tmpfile = tmpfile = tempfile.TemporaryFile()

            self._cmdobj.proc = router.popen(['/bin/sh', '-c', self._cmdobj._cmd], cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), stdin=ifd, stdout=tmpfile, stderr=tmpfile)

    class Wait(Action):
        def __call__(self):
            ret = self._cmdobj.proc.wait()
            self._cmdobj.tmpfile.seek(0)
            output = self._cmdobj.tmpfile.read().decode('UTF-8')
            del self._cmdobj.tmpfile
            sys.stdout.write(output)

            if ret != 0:
                raise ValueError('nonzero exit: %s!' % ret)

    @skiptrace
    def start(self):
        yield from self.Start.make(self)

    @skiptrace
    def wait(self):
        yield from self.Wait.make(self)
