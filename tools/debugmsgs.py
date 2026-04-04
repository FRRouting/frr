#!/usr/bin/python3

import sys
import argparse
import fnmatch
from typing import Any

try:
    import ujson as json
except ImportError:
    import json


class DebugFlag:
    _all: dict[str, "DebugFlag"] = {}

    name: str
    users: list["DebugMsg"]

    def __init__(self, jsdata: dict[str, str]):
        self._jsdata = jsdata
        self.name = jsdata["name"]
        self.users = []
        DebugFlag._all[self.name] = self

    def record(self, debugmsg: "DebugMsg"):
        self.users.append(debugmsg)

    @classmethod
    def get(cls, name: str) -> "DebugFlag":
        return cls._all[name]


class DebugMsg:
    debugflag: str | None
    file: str
    line: int
    fmtstring: str

    _by_id: dict[str, list["DebugMsg"]] = {}

    def __init__(self, msgid: str, dataitem: dict[str, Any]):
        self.msgid = msgid
        self._dataitem = dataitem
        for k in ["binary", "debugflag", "file", "line", "fmtstring", "args"]:
            setattr(self, k, dataitem.get(k))

        DebugMsg._by_id.setdefault(msgid, []).append(self)
        if self.debugflag:
            DebugFlag.get(self.debugflag).record(self)


def main():
    argp = argparse.ArgumentParser(description="FRR debug flag info tool")
    argp.add_argument("--xref", metavar="XREFFILE", type=str, help=".xref file to load (default: frr.xref)")
    argp.add_argument("flagglob", metavar="FLAGS", type=str, nargs="*", help="flags to show (by name, * for wildcards supported)")
    #argp.add_argument("xref", metavar="XREFFILE", type=str, nargs="?", help=".xref file to load (default: frr.xref)")
    args = argp.parse_args()

    verbose = False

    xreffile = args.xref or "frr.xref"
    with open(xreffile, "r") as fd:
        xrefjson = json.load(fd)

    for name, data in xrefjson.get("debugflags", {}).items():
        DebugFlag(data)

    for msgid, dataarr in xrefjson.get("refs", {}).items():
        for dataitem in dataarr:
            DebugMsg(msgid, dataitem)

    for name, flag in sorted(DebugFlag._all.items()):
        if args.flagglob:
            for expr in args.flagglob:
                if fnmatch.fnmatch(name, expr):
                    break
            else:
                continue

        if "items" in flag._jsdata:
            print(f"{flag.name}: enabled if any of the following are enabled:")
            for item in flag._jsdata["items"]:
                print("\t" + item)
            print("")
        else:
            print(f"{flag.name}: (\"{flag._jsdata["cli_cmd"]}\": {flag._jsdata["cli_help"].rsplit("\n", 2)[-2]})")
        for user in sorted(flag.users, key=lambda user: (user.file, user.line)):
            msgargs = ""
            if user.args and verbose:
                msgargs = f" ({user.args})"
            print(f"\t{user.file}:{str(user.line)+":":5} [{user.msgid}] \"{user.fmtstring}\"{msgargs}")
        print("")

if __name__ == "__main__":
    main()
