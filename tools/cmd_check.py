#!/usr/bin/python3

# Parses a source file, ensuring that CLI definitions (DEFUNs, ALIASs, etc)
# have install_command called on them at some point.
import sys
import glob
import re
import os
from pprint import pprint

# searching regex
search = [
  r'DEF.*\(.*\n\s*(.*_cmd)',
  r'ALIAS.*\(.*\n\s*(.*_cmd)',
]

def process(filename):
    cmds = []
    notinstalled = []
    with open(filename) as cf:
        try:
            tf = cf.read()
        except:
            print('Error reading {0}, skipping'.format(filename))
            return
        # build list of defined commands
        for expression in search:
            for match in re.findall(expression, tf, re.M):
                cmds.append(match)
        # build list of not installed commands
        notinstalled = filter(
                lambda x: len(re.findall('install_element.*\(.*{0}'.format(x), tf, re.M)) == 0,
                cmds)
        notinstalled = list(notinstalled)

    if len(notinstalled) > 0:
        print('\033[92m', end='')
        print('{0}'.format(filename))
        print('\033[0m', end='')
        for cmd in notinstalled:
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
