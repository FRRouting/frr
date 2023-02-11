#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
HTML test report prettying
"""

import base64
import re
import subprocess
import time
import os
import json
import zlib
import tempfile
import logging
from xml.etree import ElementTree

from typing import Dict, List, Type, Optional

import docutils.core
import jinja2
import markupsafe

from . import base, assertions
from .utils import ClassHooks, exec_find, deindent
from .scapy import ScapySend
from .timeline import TimedElement
from .pcapng import Sink, SectionHeader


logger = logging.getLogger("topotato")


def _docrender(item):
    obj = item.obj

    if obj.__doc__ is None:
        return ""
    if obj.__doc__.strip() == "":
        return ""

    docstr = deindent(obj.__doc__)
    parts = docutils.core.publish_parts(docstr, writer_name="html4")
    return markupsafe.Markup(f"<div class=\"docstring\">{parts['fragment']}</div>")


jenv = jinja2.Environment(
    loader=jinja2.PackageLoader("topotato.pretty", "html"),
    autoescape=True,
)
jenv.filters["docrender"] = _docrender


# migrate to javascript
# import urllib.parse
# from .frr import FRRConfigs
#            xref = FRRConfigs.xrefs['refs'].get(self._uid, [])
#            loc_set = {(loc['file'], loc['line']) for loc in xref}
#            if len(loc_set) == 1:
#                filename, line = loc_set.pop()
#                if self._prettysession.source_url:
#                    path = urllib.parse.urljoin(self._prettysession.source_url, filename)
#                else:
#                    path = os.path.join(FRRConfigs.srcpath, filename)
#                meta.append(html.a(self._uid, href="%s#L%d" % (path, line)))
#            else:
#                meta.append(fmt.uid(self._uid))


class PrettyExtraFile:
    # pylint: disable=too-many-arguments
    def __init__(self, owner, name, ext, mimetype, data):
        self.owner = owner
        self.name = name
        self.ext = ext
        self.mimetype = mimetype
        self.data = data
        self.filename = None

        owner.extrafiles[name] = self

    def output(self, basepath, basename):
        self.filename = "%s_%s%s" % (basename, self.name, self.ext)

        with open(os.path.join(basepath, self.filename), "wb") as fd:
            data = self.data
            if isinstance(self.data, str):
                data = data.encode("UTF-8")
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

        if not hasattr(item, "pretty"):
            item.pretty = PrettyItem.make(self, item)
        item.pretty(call, result)


class PrettyInstance(list):
    template = jenv.get_template("instance.html.j2")

    def __init__(self, prettysession, instance):
        super().__init__()
        self.prettysession = prettysession
        self.instance = instance
        self.timed = []

    _filename_sub = re.compile(r"[^a-zA-Z0-9]")

    # pylint: disable=too-many-locals,protected-access,possibly-unused-variable
    def report(self):
        topotatocls = self[0].item.getparent(base.TopotatoClass)
        nodeid = topotatocls.nodeid
        basename = self._filename_sub.sub("_", nodeid)
        basepath = os.path.join(self.prettysession.outdir, basename)

        data = {
            "ts_start": getattr(topotatocls, "started_ts", None),
            "items": [],
            "macmap": self.instance.network.macmap(),
            "configs": self.instance.configs,
        }

        items = []
        prevfunc = None

        for i, prettyitem in enumerate(self.instance.pretty):
            prettyitem.idx = i

            itemnodeid = prettyitem.item.nodeid[len(nodeid) :]
            itembasename = "%s_%s" % (basename, self._filename_sub.sub("_", itemnodeid))
            for extrafile in prettyitem.files():
                extrafile.output(self.prettysession.outdir, itembasename)

            funcparent = prettyitem.item.getparent(base.TopotatoFunction)
            if funcparent is not prevfunc and funcparent is not None:
                items.append(PrettyItem.make(self.prettysession, funcparent))
            prevfunc = funcparent

            items.append(prettyitem)

            data["items"].append(
                {
                    "nodeid": itemnodeid,
                    "idx": prettyitem.idx,
                    "ts_end": prettyitem.ts_end,
                }
            )

        del prevfunc
        del funcparent

        # remove doctype / xml / ... decls
        ElementTree.register_namespace("", "http://www.w3.org/2000/svg")
        toposvg = ElementTree.fromstring(self[0].toposvg)
        toposvg = ElementTree.tostring(toposvg).decode("UTF-8")

        data["timed"] = items[-1]._jsdata
        if items[-1]._pdml:
            data["pdml"] = items[-1]._pdml
        # ugh...
        for k, v in items[-1]._jstoplevel.items():
            data.setdefault(k, {}).update(v)
        data_json = json.dumps(data, ensure_ascii=True).encode("ASCII")
        data_bz = base64.b64encode(zlib.compress(data_json, level=6)).decode("ASCII")

        extrafiles = {}
        for item in self:
            extrafiles.update(item.extrafiles)

        output = self.template.render(locals())

        with open("%s.html" % basepath, "wb") as fd:
            fd.write(output.encode("UTF-8"))


class PrettyItem(ClassHooks):
    itemclasses: Dict[Type[base.TopotatoItem], Type["PrettyItem"]] = {}
    template = jenv.get_template("item.html.j2")

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
        handler = getattr(self, "when_%s" % result.when, None)
        if handler:
            handler(call, result)

    # pylint: disable=no-self-use
    def files(self):
        yield from []

    def when_setup(self, call, result):
        pass

    # pylint: disable=unused-argument
    def when_call(self, call, result):
        self.result = result

    # properties for HTML rendering

    @property
    def nodeid_rel(self):
        parentid = self.item.getparent(base.TopotatoClass).nodeid
        selfid = self.item.nodeid
        return selfid[len(parentid) :]


class PrettyTopotatoFunc(PrettyItem, matches=base.TopotatoFunction):
    template = jenv.get_template("item_func.html.j2")

    @property
    def obj(self):
        return self.item.obj


class PrettyTopotato(PrettyItem, matches=base.TopotatoItem):
    idx: Optional[int]

    def __init__(self, prettysession, item):
        super().__init__(prettysession, item)
        self.timed = []
        self.ts_end = None
        self.instance = None
        self.idx = None

    def when_call(self, call, result):
        super().when_call(call, result)

        self.ts_end = time.time()

        assert hasattr(self.item, "instance")
        self.instance = self.item.instance

        if not hasattr(self.instance, "pretty"):
            self.instance.pretty = PrettyInstance(self.prettysession, self.instance)
        self.instance.pretty.append(self)


class PrettyStartup(PrettyTopotato, matches=base.InstanceStartup):
    toposvg: bytes

    @classmethod
    def _check_env(cls, *, result, **kwargs):
        cls.exec_dot = exec_find("dot")
        if cls.exec_dot is None:
            result.warning("graphviz (dot) not found; network diagrams won't be drawn.")

    # pylint: disable=consider-using-with
    def when_call(self, call, result):
        super().when_call(call, result)

        self.instance.ts_rel = self.item.parent.starting_ts

        if call.excinfo:
            return

    def files(self):
        dot = self.instance.network.dot()
        yield PrettyExtraFile(self, "dotfile", ".dot", "text/plain; charset=utf-8", dot)

        if self.exec_dot:
            graphviz = subprocess.Popen(
                ["dot", "-Tsvg", "-o/dev/stdout"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            self.toposvg, _ = graphviz.communicate(dot.encode("UTF-8"))
            # sigh.
            self.toposvg = self.toposvg.replace(
                b'"Inconsolata Semi-Condensed"', b'"Inconsolata Semi Condensed"'
            )

            yield PrettyExtraFile(
                self, "dotfilesvg", ".svg", "image/svg+xml", self.toposvg
            )
        else:
            self.toposvg = None


class PrettyShutdown(PrettyTopotato, matches=base.InstanceShutdown):
    _pcap: bytes
    _pdml: str
    _jsdata: List
    _jstoplevel: Dict

    def when_call(self, call, result):
        super().when_call(call, result)

        # FIXME: flush scapy sockets / timeline(final=True)!

        # TODO: move this to TopotatoClass?
        with tempfile.NamedTemporaryFile(prefix="topotato", suffix=".pcapng") as fd:
            pcapng = Sink(fd, "=")

            shdr = SectionHeader()
            pcapng.write(shdr)

            jsdata, jstoplevel = self.instance.timeline.serialize(pcapng)
            pcapng.flush()

            fd.seek(0)
            self._pcap = fd.read()

            with subprocess.Popen(
                ["tshark", "-q", "-r", fd.name, "-T", "pdml"], stdout=subprocess.PIPE
            ) as tshark:
                pdml, _ = tshark.communicate()

            ElementTree.register_namespace("", "")
            pdmltree = ElementTree.fromstring(pdml)
            # PDML decode for log messages bloats the HTML report, but they
            # need to be included so the frame numbers are consistent.  remove
            # them here.
            i = 0
            while i < len(pdmltree):
                elem = pdmltree[i]
                if (
                    elem.find(
                        "proto[@name='frame']/field[@name='frame.protocols'][@show='systemd_journal']"
                    )
                    is not None
                ):
                    pdmltree.remove(elem)
                else:
                    i += 1
            pdml = ElementTree.tostring(pdmltree)

            self._pdml = pdml.decode("UTF-8")
            self._jsdata = jsdata
            self._jstoplevel = jstoplevel

        self.instance.pretty.report()

    def files(self):
        if self._pcap:
            yield PrettyExtraFile(
                self, "packets", ".pcapng", "application/octet-stream", self._pcap
            )


class PrettyVtysh(PrettyTopotato, matches=assertions.AssertVtysh):
    template = jenv.get_template("item_vtysh.html.j2")


class PrettyScapy(PrettyTopotato, matches=ScapySend):
    template = jenv.get_template("item_scapy.html.j2")
