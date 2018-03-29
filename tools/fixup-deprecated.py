#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Script used to replace deprecated quagga/frr mactors/types/etc.
#
# loosly based on indent.py, 2017 by David Lamparter
# 2018 by Lou Berger, placed in public domain

import sys, re, subprocess, os

class replaceEntry:
    compiled = None    #compiled regex
    repl    = None     #regex
    def __init__(self, c, r):
        self.compiled = c
        self.repl = r

rList = [
    # old #define VNL, VTYNL, VTY_NEWLINE
    replaceEntry(re.compile(r'(VNL|VTYNL|VTY_NEWLINE)'),
                 r'"\\n"'),
    # old #define VTY_GET_INTEGER(desc, v, str)
    # old #define VTY_GET_INTEGER_RANGE(desc, v, str, min, max)
    # old #define VTY_GET_ULONG(desc, v, str)
    replaceEntry(re.compile(r'(VTY_GET_INTEGER(_RANGE|)|VTY_GET_ULONG)[\s\(]*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)(\s*|)(\)|,).*?;', re.M | re.S),
                 r'(\4) = strtoul((\5), NULL, 10);\t/* \3 */'),
    # old #define VTY_GET_ULL(desc, v, str)
    replaceEntry(re.compile(r'VTY_GET_ULL[\s\(]*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)(\s*|)(\)|,).*?;', re.M | re.S),
                 r'(\2) = strtoull((\3), NULL, 10);\t/* \1 */'),
    # old #define VTY_GET_IPV4_ADDRESS(desc, v, str)
    replaceEntry(re.compile(r'VTY_GET_IPV4_ADDRESS[\s\(]*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)(\s*|)(\)|,).*?;', re.M | re.S),
                 r'inet_aton((\3), &(\2));\t/* \1 */'),
    # old #define VTY_GET_IPV4_PREFIX(desc, v, str)
    replaceEntry(re.compile(r'VTY_GET_IPV4_PREFIX[\s\(]*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)(\s*|)(\)|,).*?;', re.M | re.S),
                 r'str2prefix_ipv4((\3), &(\2));\t/* \1 */'),
    # old #define vty_outln(vty, str, ...)
    replaceEntry(re.compile(r'vty_outln[\s\(]*(.*?)\s*,\s*(".*?"|.*?)\s*(\)|,)', re.M | re.S),
                 r'vty_out(\1, \2 "\\n"\3'),
        ]

def fixup_file(fn):
    with open(fn, 'r') as fd:
        text = fd.read()

        for re in rList:
            text = re.compiled.sub(re.repl,text)

        tmpname = fn + '.fixup'
        with open(tmpname, 'w') as ofd:
            ofd.write(text)
        os.rename(tmpname, fn)

if __name__ == '__main__':
    for fn in sys.argv[1:]:
        fixup_file(fn)
