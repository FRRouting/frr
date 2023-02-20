# SPDX-License-Identifier: GPL-2.0-or-later
# FRR DWARF structure definition extractor
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.

import sys
import os
import subprocess
import re
import argparse
import json

structs = [
    "xref",
    "xref_logmsg",
    "xref_threadsched",
    "xref_install_element",
    "xrefdata",
    "xrefdata_logmsg",
    "cmd_element",
]


def extract(filename="lib/.libs/libfrr.so"):
    """
    Convert output from "pahole" to JSON.

    Example pahole output:
    $ pahole -C xref lib/.libs/libfrr.so
    struct xref {
        struct xrefdata *          xrefdata;             /*     0     8 */
        enum xref_type             type;                 /*     8     4 */
        int                        line;                 /*    12     4 */
        const char  *              file;                 /*    16     8 */
        const char  *              func;                 /*    24     8 */

        /* size: 32, cachelines: 1, members: 5 */
        /* last cacheline: 32 bytes */
    };
    """
    pahole = subprocess.check_output(
        ["pahole", "-C", ",".join(structs), filename]
    ).decode("UTF-8")

    struct_re = re.compile(r"^struct ([^ ]+) \{([^\}]+)};", flags=re.M | re.S)
    field_re = re.compile(
        r"^\s*(?P<type>[^;\(]+)\s+(?P<name>[^;\[\]]+)(?:\[(?P<array>\d+)\])?;\s*\/\*(?P<comment>.*)\*\/\s*$"
    )
    comment_re = re.compile(r"^\s*\/\*.*\*\/\s*$")

    pastructs = struct_re.findall(pahole)
    out = {}

    for sname, data in pastructs:
        this = out.setdefault(sname, {})
        fields = this.setdefault("fields", [])

        lines = data.strip().splitlines()

        next_offs = 0

        for line in lines:
            if line.strip() == "":
                continue
            m = comment_re.match(line)
            if m is not None:
                continue

            m = field_re.match(line)
            if m is not None:
                offs, size = m.group("comment").strip().split()
                offs = int(offs)
                size = int(size)
                typ_ = m.group("type").strip()
                name = m.group("name")

                if name.startswith("(*"):
                    # function pointer
                    typ_ = typ_ + " *"
                    name = name[2:].split(")")[0]

                data = {
                    "name": name,
                    "type": typ_,
                    #   'offset': offs,
                    #   'size': size,
                }
                if m.group("array"):
                    data["array"] = int(m.group("array"))

                fields.append(data)
                if offs != next_offs:
                    raise ValueError(
                        "%d padding bytes before struct %s.%s"
                        % (offs - next_offs, sname, name)
                    )
                next_offs = offs + size
                continue

            raise ValueError("cannot process line: %s" % line)

    return out


class FieldApplicator(object):
    """
    Fill ELFDissectStruct fields list from pahole/JSON

    Uses the JSON file created by the above code to fill in the struct fields
    in subclasses of ELFDissectStruct.
    """

    # only what we really need.  add more as needed.
    packtypes = {
        "int": "i",
        "uint8_t": "B",
        "uint16_t": "H",
        "uint32_t": "I",
        "char": "s",
    }

    def __init__(self, data):
        self.data = data
        self.classes = []
        self.clsmap = {}

    def add(self, cls):
        self.classes.append(cls)
        self.clsmap[cls.struct] = cls

    def resolve(self, cls):
        out = []
        # offset = 0

        fieldrename = getattr(cls, "fieldrename", {})

        def mkname(n):
            return (fieldrename.get(n, n),)

        for field in self.data[cls.struct]["fields"]:
            typs = field["type"].split()
            typs = [i for i in typs if i not in ["const"]]

            # this will break reuse of xrefstructs.json across 32bit & 64bit
            # platforms

            # if field['offset'] != offset:
            #    assert offset < field['offset']
            #    out.append(('_pad', '%ds' % (field['offset'] - offset,)))

            # pretty hacky C types handling, but covers what we need

            ptrlevel = 0
            while typs[-1] == "*":
                typs.pop(-1)
                ptrlevel += 1

            if ptrlevel > 0:
                packtype = ("P", None)
                if ptrlevel == 1:
                    if typs[0] == "char":
                        packtype = ("P", str)
                    elif typs[0] == "struct" and typs[1] in self.clsmap:
                        packtype = ("P", self.clsmap[typs[1]])
            elif typs[0] == "enum":
                packtype = ("I",)
            elif typs[0] in self.packtypes:
                packtype = (self.packtypes[typs[0]],)
            elif typs[0] == "struct":
                if typs[1] in self.clsmap:
                    packtype = (self.clsmap[typs[1]],)
                else:
                    raise ValueError(
                        "embedded struct %s not in extracted data" % (typs[1],)
                    )
            else:
                raise ValueError(
                    "cannot decode field %s in struct %s (%s)"
                    % (cls.struct, field["name"], field["type"])
                )

            if "array" in field and typs[0] == "char":
                packtype = ("%ds" % field["array"],)
                out.append(mkname(field["name"]) + packtype)
            elif "array" in field:
                for i in range(0, field["array"]):
                    out.append(mkname("%s_%d" % (field["name"], i)) + packtype)
            else:
                out.append(mkname(field["name"]) + packtype)

            # offset = field['offset'] + field['size']

        cls.fields = out

    def __call__(self):
        for cls in self.classes:
            self.resolve(cls)


def main():
    argp = argparse.ArgumentParser(description="FRR DWARF structure extractor")
    argp.add_argument(
        "-o",
        dest="output",
        type=str,
        help="write JSON output",
        default="python/xrefstructs.json",
    )
    argp.add_argument(
        "-i",
        dest="input",
        type=str,
        help="ELF file to read",
        default="lib/.libs/libfrr.so",
    )
    args = argp.parse_args()

    out = extract(args.input)
    with open(args.output + ".tmp", "w") as fd:
        json.dump(out, fd, indent=2, sort_keys=True)
    os.rename(args.output + ".tmp", args.output)


if __name__ == "__main__":
    main()
