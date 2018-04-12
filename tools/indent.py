#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 2017 by David Lamparter, placed in public domain

import sys, re, subprocess, os

# find all DEFUNs
defun_re = re.compile(
        r'^((DEF(UN(|_ATTR|_CMD_(ELEMENT|FUNC_(DECL|TEXT))|_DEPRECATED|_NOSH|_HIDDEN|SH(|_ATTR|_DEPRECATED|_HIDDEN))?|PY|PY_ATTR|PY_HIDDEN)|ALIAS)\s*\(.*?)^(?=\s*\{)',
        re.M | re.S)
define_re = re.compile(
        r'((^#\s*define[^\n]+[^\\]\n)+)',
        re.M | re.S)
# find clang-format control that we just inserted
clean_re = re.compile(
        r'^.*/\* \$FRR indent\$ \*/\s*\n\s*/\* clang-format (on|off) \*/\s*\n',
        re.M)

def wrap_file(fn):
    with open(fn, 'r') as fd:
        text = fd.read()

        repl = r'/* $FRR indent$ */\n/* clang-format off */\n' + \
                r'\1' + \
                r'/* $FRR indent$ */\n/* clang-format on */\n'

        # around each DEFUN, insert an indent-on/off comment
        text = defun_re.sub(repl, text)
        text = define_re.sub(repl, text)

        ci = subprocess.Popen(['clang-format'], stdin = subprocess.PIPE, stdout = subprocess.PIPE)
        stdout, ign = ci.communicate(text)
        ci.wait()
        if ci.returncode != 0:
            raise IOError('clang-format returned %d' % (ci.returncode))

        # remove the bits we inserted above
        final = clean_re.sub('', stdout)

        tmpname = fn + '.indent'
        with open(tmpname, 'w') as ofd:
            ofd.write(final)
        os.rename(tmpname, fn)

if __name__ == '__main__':
    for fn in sys.argv[1:]:
        wrap_file(fn)
