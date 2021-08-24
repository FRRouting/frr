
import sys, re, time, os, socket, select, signal, logging, functools, inspect
import subprocess
import html
import difflib
import pytest
import datetime
import signal
from lxml import etree
from collections import OrderedDict

from .htmlmonkeypatch import ResultMonkey

ResultMonkey.apply()

from .topolinux import NetworkInstance
from .utils import deindent
from .assertions import TopotatoItem, TopotatoCompareFail
from .frr import FRRConfigs
from .protomato import ProtomatoDumper
from .fixtures import *
from .base import TestBase, TopotatoClass, TopotatoInstance, TopotatoWrapped

logger = logging.getLogger('topotato')

# pidns (or tini?) sets these to IGN by default, which isn't quite what we want
signal.signal(signal.SIGINT, signal.default_int_handler)
signal.signal(signal.SIGTERM, signal.SIG_DFL)

@pytest.hookimpl(tryfirst=True)
def pytest_pycollect_makeitem(collector, name, obj):
    if hasattr(obj, '_topotato_makeitem'):
        if inspect.ismethod(obj._topotato_makeitem):
            logger.debug('_topotato_makeitem(%r, %r, %r)' % (collector, name, obj))
            return obj._topotato_makeitem(collector, name, obj)
        else:
            logger.debug('%r._topotato_makeitem: not a method', obj)


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_report_teststatus(report):
    outcome = yield
    res = outcome.get_result()
    if res[2] == 'PASSED':
        res = (res[0], res[1], '%s (%.2f)' % (res[2], report.duration))
    outcome.force_result(res)


def pytest_addoption(parser):
    parser.addoption("--run-topology", action="store_const", const=True, default=None, help="run a test topology")
    parser.addoption("--show-configs", action="store_const", const=True, default=None, help="show configurations")
    parser.addoption("--show-config", type=str, default=None, help="show specific configuration")
    parser.addoption("--show-topology", type=str, default=None, help="show specific topology")
    parser.addoption("--frr-builddir", type=str, default=None, help="override frr_builddir pytest.ini option")

    parser.addini('frr_builddir', 'FRR build directory (normally same as source, but out-of-tree is supported)', default='../frr')

def pytest_configure(config):
    assert config.pluginmanager.getplugin('html') is not None
    #config.option.css.insert(0,
    #        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'protomato.css'))
    #config.option.css.insert(0,
    #        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'topotato.css'))

from .pretty import *

def pytest_sessionstart(session):
    path = os.environ['PATH'].split(':')
    fail = 0

    def check_tool(name):
        for p in path:
            pname = os.path.join(p, name)
            if os.access(pname, os.X_OK):
                logger.debug('%s => %s' % (name, pname))
                return pname
        else:
            logger.error('cannot find "%s" in PATH, please install it.' % name)
            return None

    if os.getuid() != 0:
        logger.error('topotato must be run as root.  skipping all tests.')
        fail += 1

    tools = ['dot', 'dumpcap', 'tshark']
    if sys.platform == 'linux':
        tools.extend(['ip', 'unshare', 'nsenter', 'tini'])
    elif sys.platform == 'freebsd12':
        tools.extend(['jail', 'jexec', 'ifconfig', 'netstat'])
    else:
        logger.error('this platform (%s) is not supported by topotato.' % (sys.platform))
        fail += 1

    for tool in tools:
        if check_tool(tool) is None:
            fail += 1

    frr_builddir = session.config.getoption('--frr-builddir')
    if frr_builddir is None:
        frr_builddir = session.config.getini('frr_builddir')

    if not os.path.isabs(frr_builddir):
        selfdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        frr_builddir = os.path.abspath(os.path.join(selfdir, frr_builddir))


    if not fail:
        if not FRRConfigs.init(frr_builddir):
            fail += 1
    if fail:
        TopotatoItem.skipall = 'topotato environment not set up correctly'

    session.pretty = PrettySession(session)

class LogFormatting(list):
    class Item:
        log_ts_re = re.compile(r'^(\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+)(?:\.(\d+))? ')

        def __init__(self, seqno, router, daemon, line):
            self._router = router
            self._daemon = daemon
            self._line = line

            m = self.log_ts_re.match(line)
            if m is not None:
                vals = list([int(i) for i in m.groups()[:6]])
                _ts = datetime.datetime(*vals).timestamp()
                if m.group(7) is not None:
                    _ts += float('0.%s' % m.group(7))
            else:
                _ts = time.time()
            self._ts = (_ts, seqno)

        def __lt__(self, other):
            return self._ts < other._ts

        def __repr__(self):
            return 'LogFormatting.Item(, %r, %r, %r)@%r' % (self._router, self._daemon, self._line, self._ts)

        def html(self):
            return '%s' % self._line

    class ProtomatoItem:
        def __init__(self, tomato):
            self._ts = (tomato.ts, 0)
            self._html = tomato

        def __lt__(self, other):
            return self._ts < other._ts

        def html(self):
            return self._html.unicode(indent=2) #todo: return directly

    def __init__(self, itr):
        super().__init__()
        for rtr, daemon, logpile in itr:
            for seqno, msg in enumerate(logpile.splitlines()):
                self.append(self.Item(seqno, rtr, daemon, msg))
        self.sort()


@pytest.mark.hookwrapper
def pytest_runtest_makereport(item, call):
    pytest_html = item.config.pluginmanager.getplugin('html')
    outcome = yield
    report = outcome.get_result()

    item.session.pretty.push(item, call, report)

    if not isinstance(item, TopotatoItem):
        return

    if getattr(item, 'instance', None) is None:
        return

    if not hasattr(item.instance, 'reports'):
        item.instance.reports = []
    extra = getattr(report, 'extra', [])

    if report.when == 'call':
        report.timestamp = time.time()
        item.instance.reports.append(report)

    report.extra = extra

@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_collection(session):
    outcome = yield

    def topologies():
        for item in session.items:
            if not isinstance(item, TopotatoItem):
                continue
            if item.name != 'startup':
                continue
            yield item

    if session.config.getoption('--show-configs'):
        sys.stdout.write('\navailable configs:\n')
        for item in topologies():
            name = item.parent.nodeid

            cfgsetup = item._obj.instancefn.configs
            cfgs = cfgsetup.cfgclass(cfgsetup.net)
            routers = cfgs.generate()

            for rtr, configs in routers.items():
                for cfg, content in configs.items():
                    sys.stdout.write('    %s/%s/%s\n' % (name, rtr, cfg))
            sys.stdout.write('\n')

        session.items = []
        return

    if session.config.getoption('--show-config'):
        which = session.config.getoption('--show-config')
        path = which.split('/')

        for item in topologies():
            name = item.parent.nodeid
            if path[0] != name:
                continue

            cfgsetup = item._obj.instancefn.configs
            cfgs = cfgsetup.cfgclass(cfgsetup.net)
            routers = cfgs.generate()

            for rtr, configs in routers.items():
                if len(path) > 1 and path[1] != rtr:
                    continue
                for cfg, content in configs.items():
                    if len(path) > 2 and path[2] != cfg:
                        continue

                    sys.stdout.write('\033[33;1m--- %s/%s/%s ---\033[m\n%s\n' % (name, rtr, cfg, content))
            sys.stdout.write('\n')

        session.items = []
        return

    if session.config.getoption('--show-topology'):
        from .toponom import LAN

        which = session.config.getoption('--show-topology')

        for item in topologies():
            name = item.parent.nodeid
            if name != which:
                continue

            net = item._obj.instancefn.net

            for rtrname, rtr in net.routers.items():
                sys.stdout.write('\033[32;1m%s\033[m\n' % (('----- ' + rtrname + ' ').ljust(60, '-')))
                sys.stdout.write('\033[36;1m  %16s   %s\033[m\n' % ('lo', ', '.join([str(i) for i in rtr.lo_ip4 + rtr.lo_ip6])))
                for iface in rtr.ifaces:
                    if isinstance(iface.other.endpoint, LAN):
                        other = '\033[35;1m%-10s\033[34;1m' % iface.other.endpoint.name
                    else:
                        other = '\033[32;1m%-10s\033[34;1m' % iface.other.endpoint.name
                    sys.stdout.write('\033[34;1m  %16s   %s %s\033[m\n' % (iface.ifname, other, ', '.join([str(i) for i in iface.ip4 + iface.ip6])))

                sys.stdout.write('\n')

            for lanname, lan in net.lans.items():
                sys.stdout.write('\033[35;1m%s\033[m\n' % (('----- ' + lanname + ' ').ljust(60, '-')))
                for iface in lan.ifaces:
                    other = '\033[32;1m%16s\033[34;1m' % iface.other.endpoint.name
                    sys.stdout.write('\033[34;1m  %s   %s\033[m\n' % (other, ', '.join([str(i) for i in iface.other.ip4 + iface.other.ip6])))

                sys.stdout.write('\n')

        session.items = []
        return

    if session.config.getoption('--run-topology'):
        starters = []
        for item in session.items:
            if not isinstance(item, TopotatoItem):
                continue
            if item.name != 'startup':
                continue
            starters.append(item)

        sys.stdout.write('\navailable topologies:\n')
        for item in starters:
            sys.stdout.write('    %s\n' % (item.nodeid))
        sys.stdout.write('\n')

        if len(starters) == 1:
            starters[0].setup()
            starters[0].runtest()

            instance = starters[0].instance
            sys.stdout.write('topology running, tempdir: %s, switch ns pid: %d\n' % (
                instance.tempdir.name, instance.switch_ns.pid))
            for n, r in instance.routers.items():
                sys.stdout.write('    %-20s pid: %d\n' % (n, r.pid))

            sys.stdout.write('\nTo enter a namespace, use:\n    nsenter -a -t <pid> /bin/bash\n\nPress Ctrl+C (or kill the pytest process) to shut down the topology.\n\n')
            signal.pause()

        session.items = []

from .frr import FRRConfigs

def get_textdiff(text1, text2, title1="", title2="", **opts):
    "Returns empty string if same or formatted diff"

    diff = '\n'.join(difflib.unified_diff(text1, text2,
           fromfile=title1, tofile=title2, **opts))
    # Clean up line endings
    diff = os.linesep.join([s for s in diff.splitlines() if s])
    return diff

def text_rich_cmp(configs, rtr, out, expect, outtitle):
    lines = []
    for line in deindent(expect).split('\n'):
        items = line.split('$$')
        lre = []
        while len(items) > 0:
            lre.append(re.escape(items.pop(0)))
            if len(items) == 0:
                break
            expr = items.pop(0)
            if expr.startswith('='):
                expr = expr[1:]
                if expr.startswith(' '):
                    lre.append('\\s+')
                lre.append(re.escape(str(configs.eval(rtr, expr))))
                if expr.endswith(' '):
                    lre.append('\\s+')
            else:
                lre.append(expr)
        lines.append((line, ''.join(lre)))

    x_got, x_exp = [], []
    fail = False

    for i, out_line in enumerate(out.split('\n')):
        if i >= len(lines):
            x_got.append(out_line)
            fail = True
            continue

        ref_line, ref_re = lines[i]
        if re.match('^' + ref_re + '$', out_line):
            x_got.append(out_line)
            x_exp.append(out_line)
        else:
            x_got.append(out_line)
            x_exp.append(ref_line)
            fail = True

    if not fail:
        return None

    return TopotatoCompareFail('\n'+get_textdiff(x_got, x_exp,
            title1=outtitle,
            title2="expected")
        )
