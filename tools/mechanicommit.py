#!/usr/bin/python3

import sys
import os
from subprocess import Popen, PIPE
import argparse
import re
from pathlib import Path

def git(*gitargs: tuple[str]) -> str:
    proc = Popen(["git"] + list(gitargs), stdout = PIPE, encoding="UTF-8")
    rv = proc.communicate('')[0]
    proc.wait()
    return rv.removesuffix("\n")

def main():
    argp = argparse.ArgumentParser(description = 'mechanical git commit reapplication/verification tool')
    argp.add_argument('--allow-dirty', action="store_const", const=True, help="bypass dirty tree check (DANGEROUS)")

    args = argp.parse_args()

    topdir = Path(git("rev-parse", "--show-toplevel"))
    gitdir = Path(git("rev-parse", "--git-dir"))

    r_merge = gitdir / "rebase-merge"
    r_apply = gitdir / "rebase-apply"

    topmost = git("rev-parse", "HEAD")
    use_commit = None
    base = None
    allow_dirty = False

    if r_merge.exists():
        sys.stderr.write("§ currently in rebase-merge\n")

        with open(r_merge / "done", "r") as fd:
            done = fd.readlines()

        verb = None
        while done:
            while done and done[-1].strip() == "":
                done.pop(-1)
            while done and done[-1].lstrip().startswith("#"):
                done.pop(-1)
            assert len(done)
            cmd = done[-1].split(maxsplit = 1)
            verb = cmd[0]
            if verb in ["l", "label"]:
                done.pop(-1)
                continue
            break

        if verb not in ["b", "break", "e", "edit", "p", "pick"]:
            sys.stderr.write(f"unsupported rebase verb: {verb}\n")
            sys.exit(1)

        if verb in ["b", "break", "e", "edit"]:
            sys.stderr.write("§ stopped in normal state, using topmost commit\n")
            use_commit = topmost
        else:
            use_commit = cmd[1].split()[0]
            sys.stderr.write(f"§ using commit {use_commit} from rebase pick\n")
            base = topmost
            allow_dirty = True

    else:
        use_commit = topmost

    if use_commit is None:
        sys.stderr.write("§ unknown mode, aborting\n")
        sys.exit(1)
    if base is None:
        parents = git("show", "-s", "--pretty=format:%P", use_commit).split()
        if len(parents) != 1:
            sys.stderr.write("§ cannot work with a merge commit\n")
            sys.exit(1)
        base = parents[0]

    if not allow_dirty:
        status = git("status", "--porcelain", "-u")
        if status != "":
            if args.allow_dirty:
                sys.stderr.write("§ working tree contains changes or untracked files.  continuing anyway.\n")
            else:
                sys.stderr.write("§ working tree contains changes or untracked files.  refusing work.\n")
                sys.exit(1)

    commitmsg = git("show", "-s", "--pretty=format:%B", use_commit)
    m = re.search(r"""^\$cmds:\$\n(.*?)^\$:cmds\$""", commitmsg, re.MULTILINE | re.DOTALL)
    if m is None:
        sys.stderr.write("§ commit message does not contain commands?\n")
        sys.exit(1)

    cmds = m.group(1)
    sys.stderr.write(f"§ commands:\n{cmds}")

    os.chdir(topdir)
    git("checkout", base, "--", ".")
    
    env = {}
    env.update(os.environ)
    env["BASE"] = base

    shell = Popen(["/bin/sh", "-e", "-x"], stdin=PIPE, env=env, encoding="UTF-8")
    shell.stdin.write(cmds)
    shell.stdin.close()
    shell.wait()
    assert shell.returncode == 0

    git("add", "-A")

if __name__ == "__main__":
    main()
