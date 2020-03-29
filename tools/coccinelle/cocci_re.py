import sys
import re

fmt_re = re.compile(r'''
    %
    (?P<argnum>[0-9]+\$)?
    (?P<flags>[-+#'0 I]*)
    (?P<width>[1-9][0-9]*|(?:[0-9]+\$)?\*)?
    (?P<prec>\.[0-9]+|\.(?:[0-9]+\$)?\*)?
    (?P<modif>hh|h|l|ll|L|q|j|z|Z|t)?
    (?P<conv>[diouxXeEfFgGaAcCsSpnm%])
    ''', re.X)

def fmt_replace(fmt, idx, newconv, kill_plen = False):
    items = list(fmt_re.finditer(fmt))
    newfmt = None

    while len(items) > 0:
        item = items.pop(0)

        if item.group('conv') in ['%', 'm']:
            # no args on these
            continue

        if '$' in (item.group('width') or '') or '$' in (item.group('prec') or ''):
            sys.stderr.write('\033[31;1m"%s" - argument reordering not supported\033[m\n' % (fmt))
            break

        if '*' in (item.group('width') or ''):
            idx -= 1
        if '*' in (item.group('prec') or ''):
            idx -= 1
        if idx < 0:
            sys.stderr.write('\033[31;1m"%s" - WTF width arg?\033[m\n' % (fmt))
            break
        if idx > 0:
            idx -= 1
            continue

        if item.group('conv') != 's':
            sys.stderr.write('\033[31;1m"%s" - expected %%s conversion\033[m\n' % (fmt))
            break

        newfmt = []
        newfmt.append(fmt[:item.start()])
        newfmt.append('%')
        newfmt.append(item.group('argnum') or '')
        newfmt.append(item.group('flags'))
        newfmt.append(item.group('width') or '')
        newfmt.append(item.group('prec') or '')
        newfmt.append(newconv)
        if kill_plen:
            after = fmt[item.end():]
            if not after.startswith('/%d'):
                return None
            newfmt.append(fmt[item.end() + 3:])
        else:
            newfmt.append(fmt[item.end():])

        newfmt = ''.join(newfmt)

        sys.stderr.write('\033[32;1m%s => %s\033[m\n' % (fmt, newfmt))
        break
    else:
        sys.stderr.write('\033[31;1m"%s" - out of args?\033[m\n' % (fmt))

    return newfmt
