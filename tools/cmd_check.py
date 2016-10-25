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
  r'DEF.*\(.*\n\s*([0-9a-z_]*_cmd)',
  r'ALIAS.*\(.*\n\s*([0-9a-z_]*_cmd)',
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
            headerfile = filename.replace('.c', '.h')
            if os.path.isfile(headerfile):
                with open(headerfile) as hf:
                  headertext = hf.read()
        except:
            print('Error reading {0}, skipping'.format(filename))
            return

    # build list of defined commands that aren't mentioned in header
    for pattern in command_patterns:
        matches = re.findall(pattern, sourcetext, re.M)
        cmds += filter(lambda x: re.search(x, headertext) is None, matches)
 
    # build list of not installed commands
    for cmd in cmds:
        pats = [ ip.format(cmd) for ip in install_patterns ]
        if all([ re.search(pat, sourcetext) is None for pat in pats ]):
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
