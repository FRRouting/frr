#
# check that the first header included in C files is either
# zebra.h or config.h
#

import sys, os, re, subprocess

include_re = re.compile('^#\s*include\s+["<]([^ ">]+)[">]', re.M)

errors = 0

files = subprocess.check_output(['git', 'ls-files']).decode('ASCII')
for fn in files.splitlines():
    if not fn.endswith('.c'):
        continue
    if fn.startswith('tools/'):
        continue
    with open(fn, 'r') as fd:
        data = fd.read()
        m = include_re.search(data)
        if m is None:
            #sys.stderr.write('no #include in %s?\n' % (fn))
            continue
        if m.group(1) in ['config.h', 'zebra.h', 'lib/zebra.h']:
            continue
        sys.stderr.write('%s: %s\n' % (fn, m.group(0)))
        errors += 1

if errors:
    sys.exit(1)
