#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
HTML test report prettying
"""

import base64
import re
import subprocess
import datetime
import time
import os

import logging
logger = logging.getLogger('topotato')
logger.setLevel(logging.DEBUG)

from py.xml import html

from . import base
from . import assertions
from .frr import FRRConfigs
from .protomato import ProtomatoDumper
from .htmlmonkeypatch import HTMLTouchupMonkey
from .utils import ClassHooks, exec_find


def _html_final_hook(html_result):
    html_result[0].append(html.link(href="topotato/topotato.css", rel="stylesheet", type="text/css"))
    html_result[0].append(html.link(href="topotato/protomato.css", rel="stylesheet", type="text/css"))
    html_result[0].append(html.script(src='topotato/protomato.js', type='text/javascript'))
    return html_result

HTMLTouchupMonkey.html_final_hook = _html_final_hook


class fmt(html):
    """custom styling"""

    class _cssclass:
        def __init__(self, *args, **kwargs):
            if getattr(self, 'class_', None) is not None:
                kwargs.setdefault('class_', self.class_)
            super().__init__(*args, **kwargs)

    class timetable(_cssclass, html.div):
        class_ = 'timetable'
    class tstamp(_cssclass, html.span):
        class_ = 'tstamp'
    class rtrname(_cssclass, html.span):
        class_ = 'rtrname'
    class dmnname(_cssclass, html.span):
        class_ = 'dmnname'

    class logmsg(_cssclass, html.div):
        class_ = 'logmsg'
    class logtext(_cssclass, html.span):
        class_ = 'logtext'
    class logmeta(_cssclass, html.span):
        class_ = 'logmeta'
    class uid(_cssclass, html.span):
        class_ = 'uid'
    class logprio(_cssclass, html.span):
        class_ = 'logprio'

    class clicmd(_cssclass, html.div):
        class_ = 'clicmd'
    class clicmdtext(_cssclass, html.span):
        class_ = 'clicmdtext'


class TimedLog(base.TimedElement):
    log_ts_re = re.compile(r'^(\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+)(?:\.(\d+))? ')
    log_prio_re = re.compile(r'^(emerg|alert|crit|error|warn|notif|info|debug)[a-z]*: ')
    log_daemon_re = re.compile(r'^([A-Z0-9_]+): ')
    log_id_re = re.compile(r'^(?:\[(?P<uid>[A-Z0-9]{5}-[A-Z0-9]{5})\])?(?:\[EC (?P<ec>\d+)\])? ?')

    def __init__(self, seqno, router, daemon, line):
        super().__init__()
        self._router = router
        self._daemon = daemon
        self._line = line

        m = self.log_ts_re.match(line)
        if m is not None:
            vals = [int(i) for i in m.groups()[:6]]
            _ts = datetime.datetime(*vals).timestamp()
            if m.group(7) is not None:
                _ts += float('0.%s' % m.group(7))
            line = line[m.end():]
        else:
            _ts = time.time()

        m = self.log_prio_re.match(line)
        if m is not None:
            self._prio = m.group(1)
            line = line[m.end():]
        else:
            self._prio = None

        m = self.log_daemon_re.match(line)
        if m is not None:
            # don't care about this...
            line = line[m.end():]

        m = self.log_id_re.match(line)
        if m is not None:
            self._uid = m.group('uid')
            self._ec = m.group('ec')
            line = line[m.end():]
        else:
            self._uid = None
            self._ec = None

        self._ts = _ts
        self._seqno = seqno
        self._text = line

    def ts(self):
        return (self._ts, self._seqno)

    def html(self, ts_rel):
        meta = []
        if self._uid:
            xref = FRRConfigs.xrefs['refs'].get(self._uid, [])
            if len(xref) == 1:
                path = os.path.join(FRRConfigs.srcpath, xref[0]['file'])
                meta.append(html.a(self._uid, href="%s#L%d" % (path, xref[0]['line'])))
            else:
                meta.append(fmt.uid(self._uid))

        msg = fmt.logmsg([
            fmt.tstamp('%.3f' % (self._ts - ts_rel)),
            fmt.rtrname(self._router),
            fmt.dmnname(self._daemon),
            fmt.logmeta(meta),
            fmt.logprio(self._prio or '???'),
            fmt.logtext(self._text),
        ])
        if self._prio is not None:
            msg.attr.class_ += ' prio-%s' % self._prio
        return msg


class PrettySession:
    def __init__(self, session, outdir=None):
        self.session = session
        self.outdir = outdir
        self.pytest_html = session.config.pluginmanager.getplugin('html')

        if outdir and not os.path.exists(outdir):
            os.mkdir(outdir)

    def push(self, item, call, result):
        if not isinstance(item, base.TopotatoItem):
            return

        if not hasattr(item, 'pretty'):
            item.pretty = PrettyItem.make(self, item)
        item.pretty(call, result)


class PrettyInstance(list):
    def __init__(self, prettysession, instance):
        super().__init__()
        self.prettysession = prettysession
        self.instance = instance
        self.timed = []

    def append(self, item):
        super().append(item)

        for router, daemon, lines in item.instance.iter_logs():
            for seqno, line in enumerate(lines.splitlines(), len(self.timed)):
                self.timed.append(TimedLog(seqno, router, daemon, line))

    def distribute(self):
        if self.instance.protomato is None:
            return

        packets = self.instance.protomato[:]
        timed = self.timed[:]

        prettyitem = None

        for prettyitem in self:
            while packets and packets[0].ts() < (prettyitem.ts_end, 0):
                prettyitem.timed.append(packets.pop(0))

            while timed and timed[0].ts() < (prettyitem.ts_end, 0):
                prettyitem.timed.append(timed.pop(0))

            prettyitem.timed.sort()

        prettyitem.timed.extend(packets)
        prettyitem.timed.extend(timed)
        prettyitem.timed.sort()

    _filename_sub = re.compile(r'[^a-zA-Z0-9]')

    def report(self):
        topotatoinst = self[0].item.parent
        topotatocls = topotatoinst.parent
        nodeid = topotatocls.nodeid
        filename = '%s.html' % (self._filename_sub.sub('_', nodeid))
        filename = os.path.join(self.prettysession.outdir, filename)

        body = [
            html.h1(nodeid),
        ]
        if topotatocls.obj.__doc__:
            body.append(html.div(topotatocls.obj.__doc__, class_='docstring'))

        items = []
        for prettyitem in self.instance.pretty:
            item = html.div(class_="item")
            item.append(html.div(prettyitem.item.nodeid[len(nodeid):], class_="nodeid"))
            item.append(prettyitem.html)
            items.append(item)
        body.append(html.div(*items, class_="items"))

        output = html.html()
        output.append(html.head(
            html.title(nodeid),
            html.meta(charset="utf-8"),
            html.link(href="../topotato/topotato.css", rel="stylesheet", type="text/css"),
            html.link(href="../topotato/protomato.css", rel="stylesheet", type="text/css"),
            html.script(src='../topotato/protomato.js', type='text/javascript'),
        ))
        output.append(html.body(*body))

        with open(filename, 'wb') as fd:
            fd.write(output.unicode().encode('UTF-8'))


class PrettyItem(ClassHooks):
    itemclasses = {}

    @classmethod
    def make(cls, session, item):
        for itemcls in type(item).mro():
            if itemcls in PrettyItem.itemclasses:
                prettycls = PrettyItem.itemclasses[itemcls]
                break
        else:
            prettycls = PrettyItem

        return prettycls(session, item)

    @classmethod
    def __init_subclass__(cls, /, matches=None, **kwargs):
        super().__init_subclass__(**kwargs)
        if matches:
            PrettyItem.itemclasses[matches] = cls

    def __init__(self, prettysession, item):
        self.prettysession = prettysession
        self.item = item
        self.timed = []
        self.result = None

    def __call__(self, call, result):
        handler = getattr(self, 'when_%s' % result.when, None)
        if handler:
            if not hasattr(result, 'extra'):
                result.extra = []
            handler(call, result)

    def when_setup(self, call, result):
        pass

    # pylint: disable=unused-argument
    def when_call(self, call, result):
        self.result = result


class PrettyTopotato(PrettyItem, matches=base.TopotatoItem):
    def __init__(self, prettysession, item):
        super().__init__(prettysession, item)
        self.timed = []
        self.ts_end = None
        self.instance = None

    def when_call(self, call, result):
        super().when_call(call, result)

        self.ts_end = time.time()

        assert hasattr(self.item, 'instance')
        self.instance = self.item.instance

        if not hasattr(self.instance, 'pretty'):
            self.instance.pretty = PrettyInstance(self.prettysession, self.instance)
        self.instance.pretty.append(self)

    def finalize(self):
        loghtml = fmt.timetable()
        for e in self.timed:
            loghtml.append(e.html(self.instance.ts_rel))
            loghtml.append('\n')

        self.html = loghtml
        extras = self.prettysession.pytest_html.extras
        self.result.extra.append(extras.html(str(loghtml)))


class PrettyStartup(PrettyTopotato, matches=base.InstanceStartup):
    @classmethod
    def _check_env(cls, *, result, **kwargs):
        cls.exec_dot = exec_find("dot")
        if cls.exec_dot is None:
            result.warning("graphviz (dot) not found; network diagrams won't be drawn.")

    # pylint: disable=consider-using-with
    def when_call(self, call, result):
        super().when_call(call, result)

        self.instance.ts_rel = self.item.parent.starting_ts
        self.instance.protomato = None

        if call.excinfo:
            return

        extras = self.prettysession.pytest_html.extras

        if self.exec_dot:
            dot = self.instance.network.dot()
            graphviz = subprocess.Popen(['dot', '-Tsvg', '-o/dev/stdout'],
                    stdin = subprocess.PIPE, stdout = subprocess.PIPE)
            out, _ = graphviz.communicate(dot.encode('UTF-8'))
            out = base64.b64encode(out).decode('US-ASCII')

            result.extra.append(extras.svg(out, 'topology diagram'))

        self.instance.protomato = ProtomatoDumper(self.instance.network.macmap(),
                self.instance.ts_rel)
        self.item.parent.liveshark.subscribe(self.instance.protomato.submit)


class PrettyShutdown(PrettyTopotato, matches=base.InstanceShutdown):
    def when_call(self, call, result):
        super().when_call(call, result)

        extras = self.prettysession.pytest_html.extras

        if getattr(self.instance, 'pcapfile', None):
            with open(self.instance.pcapfile, 'rb') as fd:
                content = fd.read()
            result.extra.append(extras.extra(
                content=content, format_type=extras.FORMAT_BINARY,
                mime_type='application/octet-stream', name='packets',
                extension='pcapng'))

        self.instance.pretty.distribute()

        for prettyitem in self.instance.pretty:
            prettyitem.finalize()

        self.instance.pretty.report()

class PrettyVtysh(PrettyTopotato, matches=assertions.AssertVtysh):
    class Line(base.TimedElement):
        def __init__(self, ts, router, daemon, cmd, out, rc, result, same):
            super().__init__()

            #    delaytext = (' <span class="delay">(after %.2fs)</span>' % after) if after is not None else ""
            #    ver_text.append('<dt><span class="rtr">%s</span> <span class="daemon">%s</span> <span class="cmd">%s</span> <span class="status status-%d">%d</span>%s</dt><dd>%s</dd>' % (
            #        rtr, daemon, cmd, rc, rc, delaytext, out))

            self._ts = ts
            self._router = router
            self._daemon = daemon
            self._cmd = cmd
            self._out = out
            self._rc = rc
            self._result = result
            self._same = same

        def ts(self):
            return (self._ts, 0)

        def html(self, ts_rel):
            clicmd = fmt.clicmd([
                fmt.tstamp('%.3f' % (self._ts - ts_rel)),
                fmt.rtrname(self._router),
                fmt.dmnname(self._daemon),
                fmt.clicmdtext(self._cmd),
            ])
            if self._same:
                clicmd.attr.class_ += ' cli-same'
            return clicmd

    def when_call(self, call, result):
        super().when_call(call, result)

        for rtr, daemon in self.item.commands.keys():
            cmds = self.item.commands[rtr, daemon]
            prev_out = None

            for ts, cmd, out, rc, result in cmds:
                self.timed.append(self.Line(ts, rtr, daemon, cmd, out, rc, result, prev_out == out))
                prev_out = out
