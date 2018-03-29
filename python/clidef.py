# FRR CLI preprocessor (DEFPY)
#
# Copyright (C) 2017  David Lamparter for NetDEF, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import clippy, traceback, sys, os
from collections import OrderedDict
from functools import reduce
from pprint import pprint
from string import Template
from io import StringIO

# the various handlers generate output C code for a particular type of
# CLI token, choosing the most useful output C type.

class RenderHandler(object):
    def __init__(self, token):
        pass
    def combine(self, other):
        if type(self) == type(other):
            return other
        return StringHandler(None)

    deref = ''
    drop_str = False
    canfail = True

class StringHandler(RenderHandler):
    argtype = 'const char *'
    decl = Template('const char *$varname = NULL;')
    code = Template('$varname = argv[_i]->arg;')
    drop_str = True
    canfail = False

class LongHandler(RenderHandler):
    argtype = 'long'
    decl = Template('long $varname = 0;')
    code = Template('''\
char *_end;
$varname = strtol(argv[_i]->arg, &_end, 10);
_fail = (_end == argv[_i]->arg) || (*_end != '\\0');''')

# A.B.C.D/M (prefix_ipv4) and
# X:X::X:X/M (prefix_ipv6) are "compatible" and can merge into a
# struct prefix:

class PrefixBase(RenderHandler):
    def combine(self, other):
        if type(self) == type(other):
            return other
        if isinstance(other, PrefixBase):
            return PrefixGenHandler(None)
        return StringHandler(None)
    deref = '&'
class Prefix4Handler(PrefixBase):
    argtype = 'const struct prefix_ipv4 *'
    decl = Template('struct prefix_ipv4 $varname = { };')
    code = Template('_fail = !str2prefix_ipv4(argv[_i]->arg, &$varname);')
class Prefix6Handler(PrefixBase):
    argtype = 'const struct prefix_ipv6 *'
    decl = Template('struct prefix_ipv6 $varname = { };')
    code = Template('_fail = !str2prefix_ipv6(argv[_i]->arg, &$varname);')
class PrefixEthHandler(PrefixBase):
    argtype = 'struct prefix_eth *'
    decl = Template('struct prefix_eth $varname = { };')
    code = Template('_fail = !str2prefix_eth(argv[_i]->arg, &$varname);')
class PrefixGenHandler(PrefixBase):
    argtype = 'const struct prefix *'
    decl = Template('struct prefix $varname = { };')
    code = Template('_fail = !str2prefix(argv[_i]->arg, &$varname);')

# same for IP addresses.  result is union sockunion.
class IPBase(RenderHandler):
    def combine(self, other):
        if type(self) == type(other):
            return other
        if type(other) in [IP4Handler, IP6Handler, IPGenHandler]:
            return IPGenHandler(None)
        return StringHandler(None)
class IP4Handler(IPBase):
    argtype = 'struct in_addr'
    decl = Template('struct in_addr $varname = { INADDR_ANY };')
    code = Template('_fail = !inet_aton(argv[_i]->arg, &$varname);')
class IP6Handler(IPBase):
    argtype = 'struct in6_addr'
    decl = Template('struct in6_addr $varname = IN6ADDR_ANY_INIT;')
    code = Template('_fail = !inet_pton(AF_INET6, argv[_i]->arg, &$varname);')
class IPGenHandler(IPBase):
    argtype = 'const union sockunion *'
    decl = Template('''union sockunion s__$varname = { .sa.sa_family = AF_UNSPEC }, *$varname = NULL;''')
    code = Template('''\
if (argv[_i]->text[0] == 'X') {
	s__$varname.sa.sa_family = AF_INET6;
	_fail = !inet_pton(AF_INET6, argv[_i]->arg, &s__$varname.sin6.sin6_addr);
	$varname = &s__$varname;
} else {
	s__$varname.sa.sa_family = AF_INET;
	_fail = !inet_aton(argv[_i]->arg, &s__$varname.sin.sin_addr);
	$varname = &s__$varname;
}''')

def mix_handlers(handlers):
    def combine(a, b):
        if a is None:
            return b
        return a.combine(b)
    return reduce(combine, handlers, None)

handlers = {
    'WORD_TKN':         StringHandler,
    'VARIABLE_TKN':     StringHandler,
    'RANGE_TKN':        LongHandler,
    'IPV4_TKN':         IP4Handler,
    'IPV4_PREFIX_TKN':  Prefix4Handler,
    'IPV6_TKN':         IP6Handler,
    'IPV6_PREFIX_TKN':  Prefix6Handler,
    'MAC_TKN':          PrefixEthHandler,
    'MAC_PREFIX_TKN':   PrefixEthHandler,
}

# core template invoked for each occurence of DEFPY.
#
# the "#if $..." bits are there to keep this template unified into one
# common form, without requiring a more advanced template engine (e.g.
# jinja2)
templ = Template('''/* $fnname => "$cmddef" */
DEFUN_CMD_FUNC_DECL($fnname)
#define funcdecl_$fnname static int ${fnname}_magic(\\
	const struct cmd_element *self __attribute__ ((unused)),\\
	struct vty *vty __attribute__ ((unused)),\\
	int argc __attribute__ ((unused)),\\
	struct cmd_token *argv[] __attribute__ ((unused))$argdefs)
funcdecl_$fnname;
DEFUN_CMD_FUNC_TEXT($fnname)
{
#if $nonempty /* anything to parse? */
	int _i;
#if $canfail /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
$argdecls
	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if $canfail /* anything that can fail? */
		_fail = 0;
#endif
$argblocks
#if $canfail /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if $canfail /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ${fnname}_magic(self, vty, argc, argv$arglist);
}

''')

# invoked for each named parameter
argblock = Template('''
		if (!strcmp(argv[_i]->varname, \"$varname\")) {$strblock
			$code
		}''')

def process_file(fn, ofd, dumpfd, all_defun):
    filedata = clippy.parse(fn)

    for entry in filedata['data']:
        if entry['type'].startswith('DEFPY') or (all_defun and entry['type'].startswith('DEFUN')):
            cmddef = entry['args'][2]
            cmddef = ''.join([i[1:-1] for i in cmddef])

            graph = clippy.Graph(cmddef)
            args = OrderedDict()
            for token, depth in clippy.graph_iterate(graph):
                if token.type not in handlers:
                    continue
                if token.varname is None:
                    continue
                arg = args.setdefault(token.varname, [])
                arg.append(handlers[token.type](token))

            #print('-' * 76)
            #pprint(entry)
            #clippy.dump(graph)
            #pprint(args)

            params = { 'cmddef': cmddef, 'fnname': entry['args'][0][0] }
            argdefs = []
            argdecls = []
            arglist = []
            argblocks = []
            doc = []
            canfail = 0

            def do_add(handler, varname, attr = ''):
                argdefs.append(',\\\n\t%s %s%s' % (handler.argtype, varname, attr))
                argdecls.append('\t%s\n' % (handler.decl.substitute({'varname': varname}).replace('\n', '\n\t')))
                arglist.append(', %s%s' % (handler.deref, varname))
                if attr == '':
                    at = handler.argtype
                    if not at.startswith('const '):
                        at = '. . . ' + at
                    doc.append('\t%-26s %s' % (at, varname))

            for varname in args.keys():
                handler = mix_handlers(args[varname])
                #print(varname, handler)
                if handler is None: continue
                do_add(handler, varname)
                code = handler.code.substitute({'varname': varname}).replace('\n', '\n\t\t\t')
                if handler.canfail:
                    canfail = 1
                strblock = ''
                if not handler.drop_str:
                    do_add(StringHandler(None), '%s_str' % (varname), ' __attribute__ ((unused))')
                    strblock = '\n\t\t\t%s_str = argv[_i]->arg;' % (varname)
                argblocks.append(argblock.substitute({'varname': varname, 'strblock': strblock, 'code': code}))

            if dumpfd is not None:
                if len(arglist) > 0:
                    dumpfd.write('"%s":\n%s\n\n' % (cmddef, '\n'.join(doc)))
                else:
                    dumpfd.write('"%s":\n\t---- no magic arguments ----\n\n' % (cmddef))

            params['argdefs'] = ''.join(argdefs)
            params['argdecls'] = ''.join(argdecls)
            params['arglist'] = ''.join(arglist)
            params['argblocks'] = ''.join(argblocks)
            params['canfail'] = canfail
            params['nonempty'] = len(argblocks)
            ofd.write(templ.substitute(params))

if __name__ == '__main__':
    import argparse

    argp = argparse.ArgumentParser(description = 'FRR CLI preprocessor in Python')
    argp.add_argument('--all-defun', action = 'store_const', const = True,
            help = 'process DEFUN() statements in addition to DEFPY()')
    argp.add_argument('--show', action = 'store_const', const = True,
            help = 'print out list of arguments and types for each definition')
    argp.add_argument('-o', type = str, metavar = 'OUTFILE',
            help = 'output C file name')
    argp.add_argument('cfile', type = str)
    args = argp.parse_args()

    dumpfd = None
    if args.o is not None:
        ofd = StringIO()
        if args.show:
            dumpfd = sys.stdout
    else:
        ofd = sys.stdout
        if args.show:
            dumpfd = sys.stderr

    process_file(args.cfile, ofd, dumpfd, args.all_defun)

    if args.o is not None:
        clippy.wrdiff(args.o, ofd, [args.cfile, os.path.realpath(__file__)])
