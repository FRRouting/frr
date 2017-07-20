#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os
import subprocess, argparse, tempfile
import indent

def run(cmd):
    proc = subprocess.Popen(cmd, stdout = subprocess.PIPE)
    rv = proc.communicate('')[0].decode('UTF-8')
    proc.wait()
    return rv

argp = argparse.ArgumentParser(description = 'git whitespace-fixing tool')
argp.add_argument('branch', metavar='BRANCH', type = str, nargs = '?', default = 'HEAD')
args = argp.parse_args()

branch = args.branch
commit   = run(['git', 'rev-list', '-n', '1', branch, '--']).strip()
beforeid = run(['git', 'rev-list', '-n', '1', 'reindent-master-before', '--']).strip()
afterid  = run(['git', 'rev-list', '-n', '1', 'reindent-master-after', '--']).strip()

beforebase = run(['git', 'merge-base', commit, beforeid]).strip()
afterbase  = run(['git', 'merge-base', commit, afterid]).strip()

if afterbase == afterid:
    sys.stderr.write('this branch was already rebased\n')
    sys.exit(1)

if beforebase != beforeid:
    sys.stderr.write('you need to rebase your branch onto the tag "reindent-master-before"\n')
    sys.exit(1)

revs = run(['git', 'rev-list', 'reindent-master-before..%s' % commit]).strip().split('\n')

srcdir = os.getcwd()
tmpdir = tempfile.mkdtemp('frrindent')
os.chdir(tmpdir)

sys.stderr.write('using temporary directory %s; %d revisions\n' % (tmpdir, len(revs)))
run(['git', 'clone', '-s', '-b', 'reindent-master-after', srcdir, 'repo'])
os.chdir('repo')

prev = beforeid
for rev in revs:
    filestat = run(['git', 'diff', '-z', '--name-status', prev, rev]).rstrip('\0').split('\0')
    changes = zip(filestat[0::2], filestat[1::2])
    sys.stderr.write('%s: %d files\n' % (rev, len(changes)))

    for typ, name in changes:
        if typ == 'D':
            run(['git', 'rm', name])
        elif typ in ['A', 'M']:
            run(['git', 'checkout', rev, '--', name])
            if name.endswith('.c') or name.endswith('.h'):
                for d in ['babeld/', 'ldpd/', 'nhrpd/']:
                    if name.startswith(d):
                        break
                else:
                    sys.stderr.write('\t%s\n' % name)
                    indent.wrap_file(name)
            run(['git', 'add', name])

    run(['git', 'commit', '-C', rev])
    prev = rev

run(['git', 'push', 'origin', 'HEAD:refs/heads/reindented-branch'])
sys.stderr.write('\n\n"reindented-branch" should now be OK.\n')
sys.stderr.write('you could use "git reset --hard reindented-branch" to set your current branch to the reindented output\n')
sys.stderr.write('\033[31;1mplease always double-check the output\033[m\n')

