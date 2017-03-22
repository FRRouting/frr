#!/usr/bin/env python

import re, glob, subprocess, os, os.path, sys, resource, time, argparse, json, shlex
from io import StringIO
from functools import reduce
import clippy

cpp_re      = re.compile(r'^\s*([a-zA-Z]+)\s*(?=$|[^\s])')
split_re    = re.compile(r'([a-zA-Z0-9_]+)')
break_re    = re.compile(r'\s*\\\n\s*')

str_re      = re.compile(r'["\\]')
look_re     = re.compile('([\\(\\)"\']|//|/\\*)')
lookc_re    = re.compile('([\\(\\)"\',]|//|/\\*)')

space_re    = re.compile('\s+')

loadincl = set([
    'zebra.h',
    'config.h',
    'route_types.h',
    'command.h',
    'vrf.h',
    'json.h',
])

class LineBuffer(object):
    def __init__(self, feeder = None, initdata = '', initpos = 0):
        self.feeder = feeder
        self.buf = StringIO()
        self.buf.write(initdata)
        self.pos = initpos

    def getch(self):
        ch = self.buf.getvalue()[self.pos]
        self.pos += 1
        return ch

    def next_re(self, rex):
        while True:
            bufstr = self.buf.getvalue()
            m = rex.search(bufstr, self.pos)
            if m is not None:
                break
            self.buf.write(self.feeder())

        data = bufstr[self.pos:m.start()]
        self.pos = m.end()
        return data, m.group(0)

def c_string(delim, buf):
    strval = StringIO()
    while True:
        data, ch = buf.next_re(str_re)

        strval.write(data)
        if ch == '\\':
            strval.write(ch + buf.getch())
        else:
            break
    return strval.getvalue()

class WhitespaceError(Exception):
    pass

def c_string_collapse(instr):
    strval = StringIO()

    while len(instr) > 0 and '"' in instr:
        space, instr = instr.split('"', 1)
        space = break_re.sub(' ', space).replace('\\', '')
        while space.lstrip().startswith('#'):
            sp, space = space.lstrip().split(' ', 1)
            strval.write(sp[1:])
        if space.strip() != '':
            raise WhitespaceError(space)

        buf = LineBuffer(None, instr, 0)
        strdata = c_string('"', buf)
        instr = buf.buf.getvalue()[buf.pos:]

        strval.write(strdata)
    if instr.strip() != '':
        raise WhitespaceError(instr)
    return strval.getvalue()

class FlexArg(object):
    def __init__(self, jsargs, defs):
        self.jsargs = jsargs
        self.defs = defs
    def __str__(self):
        return ' '.join(self.jsargs)

    def collapse(self):
        strval = StringIO()
        for js in self.jsargs:
            if js.startswith('"') or js.startswith("'"):
                strval.write(js[1:-1])
                continue
            strval.write(self.defs.resolvestr(js))
        return strval.getvalue()

initinstalls = []

class Condition(object):
    conds = {}

    def __new__(cls, cond):
        ckey = tuple(cond)
        if ckey not in cls.conds:
            cls.conds[ckey] = c = super(Condition, cls).__new__(cls)
            c.cond = cond[:]
            c.state = None
            c.defuns = []
        return cls.conds[ckey]

    def append(self, defun):
        self.defuns.append(defun)
        return self

    cpp = ['cpp']
    @classmethod
    def checkall(cls):
        conds = cls.conds
        cpp_p = subprocess.Popen(cls.cpp + ['-include', 'config.h', '-'],
                stdin = subprocess.PIPE,
                stdout = subprocess.PIPE)
        test = ''

        def hasinv(key):
            for k in key:
                if isinstance(k, tuple):
                    return True
            return False
        condkeys = sorted([k for k in conds.keys() if not hasinv(k)])

        for num, cond in enumerate(condkeys):
            thistest = 'TRUE: %d\n' % (num)
            for inner in reversed(cond):
                thistest = '%s%s#else\nFALSE: %d\n#endif\n' % (
                        inner, thistest, num)
            test = test + thistest

        rv = cpp_p.communicate(test.encode('UTF-8'))[0].decode('UTF-8').split('\n')
        for line in rv:
            line = line.strip()
            if line == '' or line.startswith('#'):
                continue
            cond = conds[condkeys[int(line.split()[1])]]
            if line.startswith('TRUE:'):
                cond.state = True
            elif line.startswith('FALSE:'):
                cond.state = False
            else:
                raise ValueError

        for k in conds.keys():
            if hasinv(k):
                cond = conds[k]
                total = True
                for num, item in enumerate(k):
                    if isinstance(item, tuple):
                        for invert in item[1]:
                            if conds[k[:num] + tuple([invert])].state:
                                total = False
                                break
                    else:
                        if not conds[item].state:
                            total = False
                            break
                cond.state = total

    @classmethod
    def dumpall(cls):
        for condkey in sorted(cls.conds.keys()):
            if condkey == tuple([]): continue
            cond = cls.conds[condkey]
            print('condition [%s]: %s' % (cond.state, ('\n\t'.join(condkey)).rstrip()))
            #for defun in cond.defuns:
            #    print '\t', repr(defun)

def normalize_def(name):
    return space_re.sub(' ', name).strip()

class DefunGroup(object):
    def __new__(cls, name, *args, **kwargs):
        if name not in cls.index:
            cls.index[name] = grp = super(DefunGroup, cls).__new__(cls)
            grp.name = name
            grp.defuns = []
            grp._init(name, *args, **kwargs)
        return cls.index[name]

    def _init(self, *args, **kwargs):
        pass

    def append(self, defun):
        self.defuns.append(defun)
        return self

    @classmethod
    def iter(cls):
        for name, grp in sorted(cls.index.items(), key = lambda x: x[1].defuns[0].cmdname):
            yield grp

class DefunDefGroup(DefunGroup):
    index = {}
    def _init(self, cmddef):
        self.cmddef = cmddef
        self._nodegroups = None

    @property
    def nodegroups(self):
        if self._nodegroups is None:
            keys = []
            for defun in self.defuns:
                nodes = set(defun.get_nodes())
                i = 0
                while i < len(keys):
                    if nodes & keys[i]:
                        keys[i] = keys[i] | nodes
                        j = i + 1
                        while j < len(keys):
                            if keys[i] & keys[j]:
                                keys[j] = keys[i] | keys[j]
                                del keys[j]
                            else:
                                j += 1
                        break
                    i += 1
                else:
                    keys.append(nodes)
            self._nodegroups = {}
            for defun in self.defuns:
                nodes = set(defun.get_nodes())
                for k in keys:
                    if nodes & k or nodes == k:
                        self._nodegroups.setdefault(tuple(sorted(k)), []).append(defun)
        return self._nodegroups

    @classmethod
    def scan(cls, args):
        def check_consistent(defuns):
            r = {}
            checks = ['ignore', 'hidden']
            if args.Wall or args.Wdiff_names: checks.append('cmdname')
            if args.Wall or args.Wdiff_help: checks.append('cmdhelp')
            for k in checks:
                r[k] = set([getattr(defun, k) for defun in defuns])
            if max([len(i) for i in r.values()]) <= 1:
                return True
            sys.stderr.write('inconsistent options (%s) across the following DEFUNs:\n' % (
                    ', '.join([k for k, v in r.items() if len(v) > 1])))
            for defun in defuns:
                if defun.ignore and defun.hidden: desc = '(ignore, hidden)'
                elif defun.ignore: desc = '(ignore)'
                elif defun.hidden: desc = '(hidden)'
                else: desc = ''
                sys.stderr.write('%-25s %5d: %s%s [%s] ("%s")\n' % (
                        defun.filename + ':', defun.lineno, defun.cmdname, desc, ', '.join(defun.get_nodes()), defun.cmddef))
                if len(r['cmdhelp']) > 1:
                    sys.stderr.write('%-25s %5d:   %s\n' % (
                            defun.filename + ':', defun.lineno, defun.cmdhelp))
            sys.stderr.write('\n')
            return False

        for group in DefunDefGroup.iter():
            ok = True
            #if tuple() in group.nodegroups:
            #    disabled = group.nodegroups[tuple()]
            #    for defun in disabled:
            #        print >>sys.stderr, '%-25s %5d: disabled: %s ("%s")' % (
            #                defun.filename + ':', defun.lineno, defun.cmdname, defun.cmddef)
            for subkey, subgroup in group.nodegroups.items():
                if len(subkey) > 0:
                    ok = ok and check_consistent(subgroup)
            if ok and (args.Wdiff_across_nodes or args.Wextra):
                check_consistent(group.defuns)

    def defsh(self):
        ret = []
        for k, v in self.nodegroups.items():
            ret.append(self._defsh(k, v))
        return ''.join([r + '\n' for r in ret if r is not None])

    def _defsh(self, nodes, active):
        assert len(active) > 0

        first = active[0]
        active = [defun for defun in active if not defun.ignore]
        if len(active) == 0:
            if args.Wextra or args.Wignored:
                sys.stderr.write('%-25s %5d: ignore: %s ("%s")\n' % (
                        first.filename + ':', first.lineno, first.cmdname, first.cmddef))
            return
        first = active[0]
        active = [defun for defun in active if defun.condition.state and not defun.ignore]
        if len(active) == 0:
            if args.Wextra or args.Wdisabled:
                sys.stderr.write('%-25s %5d: cond disabled: %s ("%s")\n' % (
                        first.filename + ':', first.lineno, first.cmdname, first.cmddef))
            return
        first = active[0]

        if len(nodes) == 0:
            if args.Wall or args.Wno_install:
                sys.stderr.write('%-25s %5d: no install: %s ("%s")\n' % (
                        first.filename + ':', first.lineno, first.cmdname, first.cmddef))
            return

        nodeswitch = set([defun.nodeswitch for defun in active])
        if len(nodeswitch) != 1:
            sys.stderr.write('%-25s %5d: inconsistent nodeswitch: %s ("%s") - %r\n' % (
                    first.filename + ':', first.lineno, first.cmdname, first.cmddef, list(nodeswitch)))
            return
        nodeswitch = list(nodeswitch)[0]

        targets = set()
        for defun in active:
            for target in defun.targets:
                targets.add(target)
        targets = sorted(list(targets))

        if len(targets) == 0:
            sys.stderr.write('%-25s %5d: no target: %s ("%s")\n' % (
                    first.filename + ':', first.lineno, first.cmdname, first.cmddef))
            return None

        defsh = '%s%s (%s,%s\n\t%s_vtysh,\n\t%s,\n\t%s)\n' % (
                'DEFUNSH' if nodeswitch else 'DEFSH',
                '_HIDDEN' if first.hidden else '',
                '|'.join(targets),
                ('\n\t%s,' % first.args[0]) if nodeswitch else '',
                first.cmdname,
                '"%s"' % first.args[2].collapse(),
                '"%s"' % first.args[3].collapse().replace('\\n', '\\n"\n\t"'))
        defsh = defsh.replace('\n\t"")', ')')
        if nodeswitch:
            defsh += '{\n  vty->node = %s;\n  return CMD_SUCCESS;\n}\n' % (nodeswitch)

        for n in nodes:
            initinstalls.append((n, first.cmdname))

        return defsh

class DefunCmdGroup(DefunGroup):
    index = {}
    def _init(self, cmdname):
        self.cmdname = cmdname
        self.unbound_installs = []

    def add_install(self, node, condstack, filename, lineno):
        cond = Condition(condstack)
        for defun in self.defuns:
            if defun.filename == filename:
                defun.add_install(node, cond, filename, lineno)
                return
        sys.stderr.write('%-25s %5d: non-local install: %s -> %s\n' % (
                filename + ':', lineno, self.cmdname, node))
        self.unbound_installs.append((node, cond, filename, lineno))

class Defun(object):
    dupstrs = []

    def __init__(self, filename, lineno, targets, deftype, hidden, args, condstack, ignore, nodeswitch):
        self.filename = filename
        self.lineno = lineno
        self.targets = reduce(lambda x,y: x+y, [[tt.strip() for tt in t.split('|')] for t in targets], [])
        self.deftype = deftype
        self.hidden = hidden
        self.args = args
        self.ignore = ignore
        self.nodeswitch = nodeswitch
        self.installs = {}

        self.cmdname = str(args[1])
        try:
            self.cmddef = normalize_def(args[2].collapse())
            self.cmdhelp = args[3].collapse()
        except WhitespaceError as e:
            sys.stderr.write('%s:%d: definition unavailable for %s\n' % (filename, lineno, e.args[0]))
            return

        self.condition = Condition(condstack).append(self)
        self.defgroup = DefunDefGroup(self.cmddef).append(self)
        self.cmdgroup = DefunCmdGroup(self.cmdname).append(self)

    def add_install(self, node, cond, filename, lineno):
        self.installs.setdefault(node, []).append((cond, filename, lineno))
    def get_nodes(self):
        return [k for k, v in self.installs.items() if
                reduce(lambda x,y: x or y[0].state, v, None)]

    def __repr__(self):
        return '<Defun: %s:%s %s%s %s>' % (
                self.filename, self.lineno,
                self.deftype,
                ' (hidden)' if self.hidden else '',
                self.args[2].replace('\n', ''))

headers = {}

class CppDefs(dict):
    def __init__(self, filename):
        super(CppDefs, self).__init__()
        self.filename = filename
        self.recurse = []
        self.bufstr = {}

    def addrecurse(self, sub):
        for k, v in sub.items():
            self[k] = v
    def resolve(self, token):
        return self.get(token, token)
    def resolvestr(self, text):
        if text not in self.bufstr:
            lasttext = None
            while text != lasttext:
                lasttext = text
                text = ''.join([self.resolve(token) for token in split_re.split(text)])
            self.bufstr[text] = c_string_collapse(text)
        return self.bufstr[text]

def getheader(fn, name, procfn):
    for i in [os.path.dirname(fn), '', 'lib']:
        tryname = os.path.join(i, name)
        try:
            os.stat(tryname)
        except OSError:
            continue
        if tryname in headers:
            return headers[tryname]
        headers[tryname], numdefuns = procfn(tryname, False)
        return headers[tryname]
    # print >>sys.stderr, 'could not find include %s (bp %s)' % (name, os.path.dirname(fn))
    return None

flexcache = {}
def getflex(fn):
    if fn not in flexcache:
        flexcache[fn] = clippy.parse(fn)['data']
    return flexcache[fn]

def process_flex(fn, defuns = True):
    condstack = []
    elsestack = []

    fndir = [f for f in fn.split('/') if not f.startswith('.')][0]
    targets = ['VTYSH_%s' % (fndir.upper())]

    defs = CppDefs(fn)
    numdefuns = 0
    nodeswitch = None

    # print >>sys.stderr, '%9.6f %s' % (time.time() - t0, fn)
    data = getflex(fn)

    while len(data) > 0:
        tok = data.pop(0)
        if tok['type'] == 'PREPROC':
            imatch = cpp_re.match(tok['line'])
            if imatch is None:
                sys.stderr.write('%s:%d: CPP unsupported: %s\n' % (fn, tok['lineno'], tok['line']))
                continue
            insn = imatch.group(1).lower()

            if insn in ['if', 'ifdef', 'ifndef']:
                condstack.append('#' + tok['line'] + '\n')
                elsestack.append(['#' + tok['line'] + '\n'])
                continue
            if insn == 'elif':
                condstack[-1] = '#' + tok['line'] + '\n'
                elsestack[-1].append(tok['line'])
                continue
            if insn == 'else':
                condstack[-1] = ('invert', tuple(elsestack[-1]))
                continue
            if insn == 'endif':
                condstack.pop(-1)
                elsestack.pop(-1)
                continue

            if insn == 'include':
                inclfile = tok['line'].split()[1].strip()
                inclfile = inclfile.strip('<>"')

                if '$clippy: required$' not in tok['line']:
                    if inclfile.split('/')[-1] not in loadincl:
                        continue
                incdefs = getheader(fn, inclfile, process_flex)
                if incdefs is not None:
                    defs.addrecurse(incdefs)
                continue

            if insn == 'define':
                args = tok['line'].split()
                if not '(' in args[1]:
                    val = ' '.join(args[2:])
                    val = break_re.sub(' ', val)
                    defs[args[1]] = val
                continue

            if insn in ['warning', 'pragma', 'undef']:
                continue

            sys.stderr.write('%s:%d: CPP unsupported: %s\n' % (fn, tok['lineno'], tok['line']))
            continue

        if not defuns: continue

        args = [FlexArg(a, defs) for a in tok['args']]
        if tok['type'] == 'install_element':
            lineno = tok['lineno']
            node = str(args[0])
            cmdname = str(args[1]).lstrip('& ')
            DefunCmdGroup(cmdname).add_install(node, condstack, fn, lineno)
            continue

        if tok['type'].startswith('DEFUN') or tok['type'] == 'DEFPY' or tok['type'].startswith('ALIAS'):
            lineno = tok['lineno']
            deftype = tok['type'].split('_')[0]
            defhidden = tok['type'].endswith('_HIDDEN')
            defnosh = tok['type'].endswith('_NOSH')

            defun = Defun(fn, lineno, targets, deftype, defhidden, args, condstack, defnosh, nodeswitch)
            if not defnosh:
                numdefuns += 1
            nodeswitch = None
            continue

        if tok['type'] == 'VTYSH_TARGETS':
            targets = [str(args[0])]
            continue

        if tok['type'] == 'VTYSH_NODESWITCH':
            nodeswitch = str(args[0])
            continue

        sys.stderr.write('???? %r\n' % (tok['type']))

    #print >>sys.stderr, 'loaded %s in %f sec' % (fn, cputime() - begin)
    return defs, numdefuns

sources = '''
pimd/pim_cmd.c

bgpd/bgp_bfd.c
bgpd/bgp_debug.c
bgpd/bgp_dump.c
bgpd/bgp_encap.c
bgpd/bgp_filter.c
bgpd/bgp_mplsvpn.c
bgpd/bgp_nexthop.c
bgpd/bgp_route.c
bgpd/bgp_routemap.c
bgpd/bgp_vty.c
bgpd/bgp_evpn_vty.c

isisd/isis_redist.c
isisd/isis_spf.c
isisd/isis_te.c
isisd/isis_vty.c
isisd/isisd.c

ospfd/ospf_bfd.c
ospfd/ospf_dump.c
ospfd/ospf_opaque.c
ospfd/ospf_ri.c
ospfd/ospf_routemap.c
ospfd/ospf_te.c
ospfd/ospf_vty.c

ospf6d/ospf6_abr.c
ospf6d/ospf6_area.c
ospf6d/ospf6_asbr.c
ospf6d/ospf6_bfd.c
ospf6d/ospf6_flood.c
ospf6d/ospf6_interface.c
ospf6d/ospf6_intra.c
ospf6d/ospf6_lsa.c
ospf6d/ospf6_message.c
ospf6d/ospf6_neighbor.c
ospf6d/ospf6_route.c
ospf6d/ospf6_spf.c
ospf6d/ospf6_top.c
ospf6d/ospf6_zebra.c
ospf6d/ospf6d.c

ldpd/ldp_vty_cmds.c

nhrpd/nhrp_vty.c

ripd/rip_debug.c
ripd/rip_interface.c
ripd/rip_offset.c
ripd/rip_zebra.c
ripd/ripd.c

ripngd/ripng_debug.c
ripngd/ripng_interface.c
ripngd/ripng_offset.c
ripngd/ripng_zebra.c
ripngd/ripngd.c

lib/keychain.c
lib/routemap.c
lib/filter.c
lib/plist.c
lib/distribute.c
lib/if_rmap.c
lib/vrf.c
lib/vty.c
zebra/debug.c
lib/ns.c
zebra/interface.c
zebra/irdp_interface.c
zebra/rtadv.c
zebra/zebra_vty.c
zebra/zserv.c
zebra/router-id.c
zebra/zebra_routemap.c
zebra/zebra_fpm.c
zebra/zebra_ptm.c
zebra/zebra_mpls_vty.c

watchfrr/watchfrr_vty.c

bgpd/rfapi/bgp_rfapi_cfg.c
bgpd/rfapi/rfapi.c
bgpd/rfapi/rfapi_vty.c
bgpd/rfapi/vnc_debug.c
bgpd/rfp-example/librfp/rfp_example.c
'''

sources = [line.strip() for line in sources.strip().split('\n') if line.strip() != '']
globbed = []
for s in sources:
    globbed.extend(glob.glob(s))

argp = argparse.ArgumentParser(description = 'Quagga DEFUN resolver')
argp.add_argument('--vtysh-cmds', type = str)
argp.add_argument('-Wdiff-names', action = 'store_const', const = True)
argp.add_argument('-Wdiff-help', action = 'store_const', const = True)
argp.add_argument('-Wno-install', action = 'store_const', const = True)
argp.add_argument('-Wall', action = 'store_const', const = True)
argp.add_argument('-Wdiff-across-nodes', action = 'store_const', const = True)
argp.add_argument('-Wdisabled', action = 'store_const', const = True)
argp.add_argument('-Wignored', action = 'store_const', const = True)
argp.add_argument('-Wextra', action = 'store_const', const = True)
argp.add_argument('--dump-conds', action = 'store_const', const = True)
argp.add_argument('--cpp', type = str, default = 'cpp')
args = argp.parse_args()

Condition.cpp = shlex.split(args.cpp)

for fn in globbed:
    defs, numdefuns = process_flex(fn)
    if numdefuns > 0:
        #print >>sys.stderr, 'loaded %s (%d DEFUNs)' % (fn, numdefuns)
        pass
    else:
        sys.stderr.write('no DEFUNs in %s\n' % (fn))

Condition.checkall()
if args.dump_conds:
    Condition.dumpall()

DefunDefGroup.scan(args)

if args.vtysh_cmds is not None:
    with open(args.vtysh_cmds, 'w') as fd:
        fd.write('''#include <zebra.h>

#include "command.h"
#include "linklist.h"

#include "vtysh.h"

''')

        for defgroup in DefunDefGroup.iter():
            defsh = defgroup.defsh()
            if defsh is not None:
                fd.write(defsh)

        fd.write('''void
vtysh_init_cmd ()
{
''')
        for node, cmd in sorted(initinstalls):
            fd.write('  install_element (%s, &%s_vtysh);\n' % (node, cmd))
        fd.write('}\n')
