# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# December 5 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021, LabN Consulting, L.L.C.
#
"""A command that allows external command execution inside nodes."""
import argparse
import json
import os
import sys

from pathlib import Path


def newest_file_in(filename, paths, has_sibling=None):
    new = None
    newst = None
    items = (x for y in paths for x in Path(y).rglob(filename))
    for e in items:
        st = os.stat(e)
        if has_sibling and not e.parent.joinpath(has_sibling).exists():
            continue
        if not new or st.st_mtime_ns > newst.st_mtime_ns:
            new = e
            newst = st
            continue
    return new, newst


def main(*args):
    ap = argparse.ArgumentParser(args)
    ap.add_argument("-d", "--rundir", help="runtime directory for tempfiles, logs, etc")
    ap.add_argument("node", nargs="?", help="node to enter or run command inside")
    ap.add_argument(
        "shellcmd",
        nargs=argparse.REMAINDER,
        help="optional shell-command to execute on NODE",
    )
    args = ap.parse_args()
    if args.rundir:
        configpath = Path(args.rundir).joinpath("config.json")
    else:
        configpath, _ = newest_file_in(
            "config.json",
            ["/tmp/munet", "/tmp/mutest", "/tmp/unet-test"],
            has_sibling=args.node,
        )
        print(f'Using "{configpath}"')

    if not configpath.exists():
        print(f'"{configpath}" not found')
        return 1
    rundir = configpath.parent

    nodes = []
    config = json.load(open(configpath, encoding="utf-8"))
    nodes = list(config.get("topology", {}).get("nodes", []))
    envcfg = config.get("mucmd", {}).get("env", {})

    # If args.node is not a node it's part of shellcmd
    if args.node and args.node not in nodes:
        if args.node != ".":
            args.shellcmd[0:0] = [args.node]
        args.node = None

    if args.node:
        name = args.node
        nodedir = rundir.joinpath(name)
        if not nodedir.exists():
            print('"{name}" node doesn\'t exist in "{rundir}"')
            return 1
        rundir = nodedir
    else:
        name = "munet"
    pidpath = rundir.joinpath("nspid")
    pid = open(pidpath, encoding="ascii").read().strip()

    env = {**os.environ}
    env["MUNET_NODENAME"] = name
    env["MUNET_RUNDIR"] = str(rundir)

    for k in envcfg:
        envcfg[k] = envcfg[k].replace("%NAME%", str(name))
        envcfg[k] = envcfg[k].replace("%RUNDIR%", str(rundir))

    # Can't use -F if it's a new pid namespace
    ecmd = "/usr/bin/nsenter"
    eargs = [ecmd]

    #start mucmd same way base process is started
    eargs.append(f"--mount=/proc/{pid}/ns/mnt")
    eargs.append(f"--net=/proc/{pid}/ns/net")
    eargs.append(f"--pid=/proc/{pid}/ns/pid_for_children")
    eargs.append(f"--uts=/proc/{pid}/ns/uts")
    eargs.append(f"--wd={rundir}")
    eargs += args.shellcmd
    #print("Using ", eargs)
    return os.execvpe(ecmd, eargs, {**env, **envcfg})


if __name__ == "__main__":
    exit_status = main()
    sys.exit(exit_status)
