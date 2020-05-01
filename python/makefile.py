#!/usr/bin/python3
#
# FRR extended automake/Makefile functionality helper
#
# This script is executed on/after generating Makefile to add some pieces for
# clippy.

import sys
import os
import subprocess
import re
import argparse
from string import Template
from makevars import MakeReVars

argp = argparse.ArgumentParser(description = 'FRR Makefile extensions')
argp.add_argument('--dev-build', action = 'store_const', const = True,
            help = 'run additional developer checks')
args = argp.parse_args()

with open('Makefile', 'r') as fd:
    before = fd.read()

mv = MakeReVars(before)

clippy_scan = mv['clippy_scan'].strip().split()
for clippy_file in clippy_scan:
    assert clippy_file.endswith('.c')

# check for files using clippy but not listed in clippy_scan
if args.dev_build:
    basepath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(os.path.join(basepath, '.git')):
        clippy_ref = subprocess.check_output([
            'git', '-C', basepath, 'grep', '-l', '-P', '^#\s*include.*_clippy.c', '--', '**.c']).decode('US-ASCII')

        clippy_ref = set(clippy_ref.splitlines())
        missing = clippy_ref - set(clippy_scan)

        if len(missing) > 0:
            sys.stderr.write('error: files seem to be using clippy, but not listed in "clippy_scan" in subdir.am:\n\t%s\n' % ('\n\t'.join(sorted(missing))))
            sys.exit(1)

clippydep = Template('''
${clippybase}.$$(OBJEXT): ${clippybase}_clippy.c
${clippybase}.lo: ${clippybase}_clippy.c
${clippybase}_clippy.c: $$(CLIPPY_DEPS)''')

clippyauxdep = Template('''# clippy{
# auxiliary clippy target
${target}: ${clippybase}_clippy.c
# }clippy''')

lines = before.splitlines()
autoderp = '#AUTODERP# '
out_lines = []
make_rule_re = re.compile('^([^:\s]+):\s*([^:\s]+)\s*($|\n)')

while lines:
    line = lines.pop(0)
    if line.startswith(autoderp):
        line = line[len(autoderp):]

    if line == '# clippy{':
        while lines:
            line = lines.pop(0)
            if line == '# }clippy':
                break
        continue

    if line.startswith('#'):
        out_lines.append(line)
        continue

    m = make_rule_re.match(line)
    if m is None:
        out_lines.append(line)
        continue

    if m.group(2) in clippy_scan:
        out_lines.append(clippyauxdep.substitute(target=m.group(1), clippybase=m.group(2)[:-2]))

    out_lines.append(line)

out_lines.append('# clippy{\n# main clippy targets')
for clippy_file in clippy_scan:
    out_lines.append(clippydep.substitute(clippybase = clippy_file[:-2]))
out_lines.append('# }clippy')
out_lines.append('')

after = '\n'.join(out_lines)
if after == before:
    sys.exit(0)

with open('Makefile.pyout', 'w') as fd:
    fd.write(after)
os.rename('Makefile.pyout', 'Makefile')
