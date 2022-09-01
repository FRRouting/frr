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
import urllib.parse
import json
import zlib
import tempfile
from xml.etree import ElementTree

import logging
logger = logging.getLogger('topotato')
logger.setLevel(logging.DEBUG)

import jinja2
from py.xml import html

from . import base
from . import assertions
from .frr import FRRConfigs
from .protomato import ProtomatoDumper
from .utils import ClassHooks, exec_find
from .scapy import ScapySend
from .timeline import TimedElement
from .pcapng import Sink, SectionHeader, IfDesc


jenv = jinja2.Environment(
    loader=jinja2.PackageLoader("topotato.pretty", "html"),
    autoescape=True,
)


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
    class logarg(_cssclass, html.span):
        class_ = 'logarg'
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

    class cliout(_cssclass, html.div):
        class_ = 'cliout'
    class cliouttext(_cssclass, html.pre):
        class_ = 'cliouttext'

    class assertmatchitem(_cssclass, html.div):
        class_ = 'assert-match-item'


class PrettyLog(TimedElement):
    log_id_re = re.compile(r'^(?:\[(?P<uid>[A-Z0-9]{5}-[A-Z0-9]{5})\])?(?:\[EC (?P<ec>\d+)\])? ?')

    def __init__(self, prettysession, seqno, msg):
        super().__init__()
        self._prettysession = prettysession
        self._seqno = seqno

        self._msg = msg
        self._router = msg.router.name
        self._daemon = msg.daemon
        self._ts = msg.ts
        self._prio = msg.prio_text

        self._line = line = msg.text

        m = self.log_id_re.match(line)
        if m is not None:
            self._uid = m.group('uid')
            self._ec = m.group('ec')
            line = line[m.end():]
        else:
            self._uid = None
            self._ec = None

        self._text = line

    def __repr__(self):
        return '<%s @%.6f %r>' % (self.__class__.__name__, self._ts, self._text)

    @property
    def ts(self):
        return (self._ts, self._seqno)

    def html(self, id_, ts_rel):
        meta = []
        if self._uid:
            xref = FRRConfigs.xrefs['refs'].get(self._uid, [])
            loc_set = {(loc['file'], loc['line']) for loc in xref}
            if len(loc_set) == 1:
                filename, line = loc_set.pop()
                if self._prettysession.source_url:
                    path = urllib.parse.urljoin(self._prettysession.source_url, filename)
                else:
                    path = os.path.join(FRRConfigs.srcpath, filename)
                meta.append(html.a(self._uid, href="%s#L%d" % (path, line)))
            else:
                meta.append(fmt.uid(self._uid))


        logtext = []
        for text, arg in self._msg.iter_args():
            logtext.append(text)
            if arg is not None:
                logtext.append(fmt.logarg(arg))

        msg = fmt.logmsg([
            fmt.tstamp('%.3f' % (self._ts - ts_rel)),
            fmt.rtrname(self._router),
            fmt.dmnname(self._daemon),
            fmt.logmeta(meta),
            fmt.logprio(self._prio or '???'),
            fmt.logtext(logtext),
        ])
        msg.attr.id = id_
        if self._prio is not None:
            msg.attr.class_ += ' prio-%s' % self._prio

        if self._msg.match_for:
            msg.attr.class_ += ' assert-match'
            for node in self._msg.match_for:
                msg.append(fmt.assertmatchitem(node.nodeid))
        return [msg]


class PrettyExtraFile:
    def __init__(self, owner, name, ext, mimetype, data):
        self.owner = owner
        self.name = name
        self.ext = ext
        self.mimetype = mimetype
        self.data = data
        self.filename = None

        owner.extrafiles[name] = self

    def output(self, basepath, basename):
        self.filename = '%s_%s%s' % (basename, self.name, self.ext)

        with open(os.path.join(basepath, self.filename), 'wb') as fd:
            data = self.data
            if isinstance(self.data, str):
                data = data.encode('UTF-8')
            fd.write(data)


class PrettySession:
    def __init__(self, session, outdir=None, source_url=None):
        self.session = session
        self.outdir = outdir
        self.source_url = source_url

        if outdir and not os.path.exists(outdir):
            os.mkdir(outdir)

    def push(self, item, call, result):
        if not isinstance(item, base.TopotatoItem):
            return

        if not hasattr(item, 'pretty'):
            item.pretty = PrettyItem.make(self, item)
        item.pretty(call, result)


class PrettyInstance(list):
    template = jenv.get_template('instance.html.j2')

    def __init__(self, prettysession, instance):
        super().__init__()
        self.prettysession = prettysession
        self.instance = instance
        self.timed = []

    def distribute(self):
        raise NotImplementedError()

        for router in self.instance.routers.values():
            for daemonlog in router.livelogs.values():
                for seqno, msg in enumerate(daemonlog):
                    self.timed.append(PrettyLog(self.prettysession, seqno, msg))

        packets = []
        if self.instance.protomato is not None:
            packets.extend(self.instance.protomato)
        packets.sort()

        timed = self.timed[:]
        timed.sort()

        prettyitem = None

        with open('/tmp/tdump', 'w') as fd:
            from pprint import pformat
            fd.write(pformat({
                'logs': timed,
                'packets': packets,
            }))

        for prettyitem in self:
            #if isinstance(prettyitem.item, assertions.TopotatoModifier):
            #    continue

            while packets and packets[0].ts() < (prettyitem.ts_end, 0):
                prettyitem.timed.append(packets.pop(0))

            while timed and timed[0].ts() < (prettyitem.ts_end, 0):
                prettyitem.timed.append(timed.pop(0))

            prettyitem.timed.sort()

        prettyitem.timed.extend(packets)
        prettyitem.timed.extend(timed)
        prettyitem.timed.sort()

        #def _raw(pi):
        #    return list([i._msg for i in pi.timed if isinstance(i, PrettyLog)])
        #breakpoint()

    _filename_sub = re.compile(r'[^a-zA-Z0-9]')

    def report(self):
        topotatoinst = self[0].item.getparent(base.TopotatoInstance)
        topotatocls = topotatoinst.getparent(base.TopotatoClass)
        nodeid = topotatocls.nodeid
        basename = self._filename_sub.sub('_', nodeid)
        basepath = os.path.join(self.prettysession.outdir, basename)

        items = []
        prevfunc = None

        for i, prettyitem in enumerate(self.instance.pretty):
            prettyitem.idx = i

            itemnodeid = prettyitem.item.nodeid[len(nodeid):]
            itembasename = '%s_%s' % (basename, self._filename_sub.sub('_', itemnodeid))
            for extrafile in prettyitem.files():
                extrafile.output(self.prettysession.outdir, itembasename)

            funcparent = prettyitem.item.getparent(base.TopotatoFunction)
            if funcparent is not prevfunc and funcparent is not None:
                items.append(PrettyItem.make(self.prettysession, funcparent))
            prevfunc = funcparent

            items.append(prettyitem)

        del prevfunc
        del funcparent

        # remove doctype / xml / ... decls
        ElementTree.register_namespace('', "http://www.w3.org/2000/svg")
        toposvg = ElementTree.fromstring(self[0].toposvg)
        toposvg = ElementTree.tostring(toposvg).decode('UTF-8')

        data = {
            'timed': items[-1]._jsdata, # topotatoinst.netinst.timeline.serialize(),
        }
        if items[-1]._pdml:
            data['pdml'] = items[-1]._pdml
        data_json = json.dumps(data, ensure_ascii=True).encode('ASCII')
        data_bz = base64.b64encode(zlib.compress(data_json, level=6)).decode('ASCII')

        #pdml = ''
        #if hasattr(topotatoinst, 'liveshark'):
        #    if not hasattr(topotatoinst.liveshark, 'xml'):
        #        breakpoint()
        #    pdml = topotatoinst.liveshark.xml
        #    if pdml is not None:
        #    # pdml.attrib['xmlns'] = 'https://xmlns.frrouting.org/topotato/pdml/'
        #        pdml = ElementTree.tostring(pdml).decode('UTF-8')

        #pdml_json = json.dumps(pdml)

        extrafiles = {}
        for item in self:
            extrafiles.update(item.extrafiles)

        output = self.template.render(locals())

        with open('%s.html' % basepath, 'wb') as fd:
            fd.write(output.encode('UTF-8'))


class PrettyItem(ClassHooks):
    itemclasses = {}
    template = jenv.get_template('item.html.j2')

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
        self.extrafiles = {}

    def __call__(self, call, result):
        handler = getattr(self, 'when_%s' % result.when, None)
        if handler:
            handler(call, result)

    def files(self):
        if False:
            yield PrettyExtraFile(self, '', '', '', '')

    def when_setup(self, call, result):
        pass

    # pylint: disable=unused-argument
    def when_call(self, call, result):
        self.result = result

    # properties for HTML rendering

    @property
    def nodeid_rel(self):
        parentid = self.item.getparent(base.TopotatoInstance).nodeid
        selfid = self.item.nodeid
        return selfid[len(parentid):]


class PrettyTopotatoFunc(PrettyItem, matches=base.TopotatoFunction):
    template = jenv.get_template('item_func.html.j2')

    @property
    def doc(self):
        return self.item.obj.__doc__

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

    def finalize(self, idx):
        loghtml = fmt.timetable()
        for subidx, e in enumerate(self.timed):
            loghtml.extend(e.html('i%di%d' % (idx, subidx), self.instance.ts_rel))
            loghtml.append('\n')

        self.html = loghtml


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
        #self.instance.protomato = None

        if call.excinfo:
            return

        #self.instance.protomato = ProtomatoDumper(self.instance.network.macmap(),
        #        self.instance.ts_rel)
        #self.item.parent.liveshark.subscribe(self.instance.protomato.submit)

    def files(self):
        dot = self.instance.network.dot()
        yield PrettyExtraFile(self, 'dotfile', '.dot', 'text/plain; charset=utf-8', dot)

        if self.exec_dot:
            graphviz = subprocess.Popen(['dot', '-Tsvg', '-o/dev/stdout'],
                    stdin = subprocess.PIPE, stdout = subprocess.PIPE)
            self.toposvg, _ = graphviz.communicate(dot.encode('UTF-8'))
            # sigh.
            self.toposvg = self.toposvg.replace(b"\"Inconsolata Semi-Condensed\"", b"\"Inconsolata Semi Condensed\"")

            yield PrettyExtraFile(self, 'dotfilesvg', '.svg', 'image/svg+xml', self.toposvg)
        else:
            self.toposvg = None


class PrettyShutdown(PrettyTopotato, matches=base.InstanceShutdown):
    def when_call(self, call, result):
        super().when_call(call, result)

        for idx, prettyitem in enumerate(self.instance.pretty):
            prettyitem.finalize(idx)

        # FIXME: flush scapy sockets / timeline(final=True)!

        # TODO: move this to TopotatoInstance?
        with tempfile.NamedTemporaryFile(prefix='topotato', suffix='.pcapng') as fd:
            pcapng = Sink(fd, '=')

            shdr = SectionHeader()
            pcapng.write(shdr)

            jsdata = self.instance.timeline.serialize(pcapng)
            pcapng.flush()

            fd.seek(0)
            self._pcap = fd.read()

            tshark = subprocess.Popen(["tshark", "-q", "-r", fd.name, "-T", "pdml"],
                    stdout=subprocess.PIPE)
            pdml, _ = tshark.communicate()
            self._pdml = pdml.decode('UTF-8')
            self._jsdata = jsdata

        self.instance.pretty.report()

    def files(self):
        if self._pcap:
            yield PrettyExtraFile(self, 'packets', '.pcapng', 'application/octet-stream', self._pcap)


class PrettyVtysh(PrettyTopotato, matches=assertions.AssertVtysh):
    template = jenv.get_template('item_vtysh.html.j2')

    class Line(TimedElement):
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

        @property
        def ts(self):
            return (self._ts, 0)

        def serialize(self):
            return {}

        def html(self, id_, ts_rel):
            clicmd = fmt.clicmd([
                fmt.tstamp('%.3f' % (self._ts - ts_rel)),
                fmt.rtrname(self._router),
                fmt.dmnname(self._daemon),
                fmt.clicmdtext(self._cmd),
            ])
            clicmd.attr.id = id_
            if self._same:
                clicmd.attr.class_ += ' cli-same'

            ret = [clicmd]
            if self._out.strip() != '':
                clicmd.attr.onclick = 'onclickclicmd(event);'
                clicmd.attr.class_ += ' cli-has-out'
                ret.append(fmt.cliout([fmt.cliouttext(self._out)]))
            return ret

    def when_call(self, call, result):
        super().when_call(call, result)

        for rtr, daemon in self.item.commands.keys():
            cmds = self.item.commands[rtr, daemon]
            prev_out = None

            for ts, cmd, out, rc, result in cmds:
                self.timed.append(self.Line(ts, rtr, daemon, cmd, out, rc, result, prev_out == out))
                prev_out = out


class PrettyScapy(PrettyTopotato, matches=ScapySend):
    template = jenv.get_template('item_scapy.html.j2')
