#!/usr/bin/python3

# Parses a source file, ensuring that CLI definitions (DEFUNs, ALIASs, etc)
# have install_command called on them at some point.
import sys
import glob
import re
import os
from pprint import pprint

# patterns used to extract commands
command_patterns = [
  r'DEF.*\(.*\n\s*(.*_cmd)',
  r'ALIAS.*\(.*\n\s*(.*_cmd)',
]

# patterns that count as installing the command
install_patterns = [
    r'install_element.*\(.*{0}',
    r'INSTALL.*\(.*{0}'
]

def process(filename):
    cmds = []
    uninstalled = []
    sourcetext = ''
    headertext = ''

    # read source file and header file
    with open(filename) as cf:
        try:
            sourcetext = cf.read()
            if os.path.isfile(filename.replace('.c', '.h')):
                with open(filename) as hf:
                  headertext = hf.read()
        except:
            print('Error reading {0}, skipping'.format(filename))
            return

    # build list of defined commands that aren't mentioned in header
    for pattern in command_patterns:
        for match in re.findall(pattern, sourcetext, re.M):
            if re.search(match, headertext) is None:
                cmds.append(match)

    # build list of not installed commands
    for cmd in cmds:
        pats = [ ip.format(cmd) for ip in install_patterns ]
        if not any([ re.search(pat, sourcetext) is not None for pat in pats ]):
            uninstalled.append(cmd)

    if len(uninstalled) > 0:
        print('\033[92m', end='')
        print('{0}'.format(filename))
        print('\033[0m', end='')
        for cmd in uninstalled:
            print('  {0}'.format(cmd))
        print('')

usage = """
Usage:
    ./cmd_check.py <path> [<path>...]

    where 'path' is a C source file or directory
    containing C source files
"""

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(usage)
        exit()

    cwd = os.getcwd()
    for arg in sys.argv[1:]:
        # collect all c files
        globstr = arg
        if os.path.isdir(arg):
            os.chdir(arg)
            globstr = '*.c'
        for filename in glob.glob(globstr):
            process(filename)
        os.chdir(cwd)
