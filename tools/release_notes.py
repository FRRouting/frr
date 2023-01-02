#!/usr/bin/python3
#
# 2021 Jafar Al-Gharaibeh, ATCorp
#
# Generate a draft FRR release notes
#

import sys
import os
import getopt
import subprocess


def run(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    rv = proc.communicate("")[0].decode("UTF-8")
    proc.wait()
    return rv


def usage(n):
    print(os.path.basename(__file__), " [-b <branch>] [-t <tag> ]")
    print("    Generate one line logs for non merge commits")
    print("   -branch: branch name to use, default to HEAD")
    print("   -tag   : generate logs up to this tag, default to latest tag")
    sys.exit(n)


def main(argv):
    branch = tag = None
    try:
        opts, args = getopt.getopt(argv, "hb:t:", ["branch=", "tag="])
    except getopt.GetoptError:
        usage(2)
    for opt, arg in opts:
        if opt == "-h":
            usage(0)
        elif opt in ("-b", "--branch"):
            branch = arg
        elif opt in ("-t", "--tag"):
            tag = arg

    if branch is None:
        branch = "HEAD"
    if tag is None:
        tag = run(["git", "describe", "--abbrev=0"]).strip("\n")

    chnglog = run(
        ["git", "log", "--no-merges", "--pretty=format:'%s'", tag + ".." + branch]
    )
    chnglog = chnglog.split("\n")

    chnglist = []
    daemons = [
        "babel",
        "bgp",
        "eigrp",
        "nhrp",
        "ospf",
        "ospf6",
        "pbr",
        "pim",
        "rip",
        "ripng",
        "sharp",
        "vrrp",
        "zebra",
    ]

    for line in chnglog:
        line = line.strip("'")
        colon = line.partition(":")
        label = colon[0].strip().lower()
        if label in daemons:
            label = label + "d"
        comment = colon[2].strip().capitalize()
        chnglist.append(label + ":" + comment)

    chnglist.sort()
    lastlabel = ""
    for line in chnglist:
        colon = line.partition(":")
        label = colon[0]
        comment = colon[2]
        if label != lastlabel:
            print("")
            print(label)
            lastlabel = label

        print("   ", comment)


if __name__ == "__main__":
    main(sys.argv[1:])
