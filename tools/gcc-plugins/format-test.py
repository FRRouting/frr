# SPDX-License-Identifier: GPL-2.0-or-later
import subprocess
import sys
import shlex
import os
import re
import hashlib

os.environ["LC_ALL"] = "C"
os.environ["LANG"] = "C"
for k in list(os.environ.keys()):
    if k.startswith("LC_"):
        os.environ.pop(k)

if len(sys.argv) < 2:
    sys.stderr.write("start as format-test.py gcc-123.45 [-options ...]\n")
    sys.exit(1)

c_re = re.compile(r"//\s+(?P<no>NO)?WARN(?:.*(?P<retain>retain-typeinfo))?")
expect = {}
lines = {}

ver_p = subprocess.Popen(
    sys.argv[1:] + ["-xc", "-P", "-E", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding="UTF-8"
)
ver = int(ver_p.communicate("__GNUC__\n")[0])

fullver = subprocess.check_output(
    sys.argv[1:] + ["-dumpfullversion"], encoding="UTF-8"
).strip()

confwith_p = subprocess.Popen(
    sys.argv[1:] + ["-v"], stderr=subprocess.PIPE,
)
confwith_l = confwith_p.communicate(b"")[1].split(b"\n")
confwith = b"".join(l + b"\n" for l in confwith_l if l.startswith(b"Configured with:") or l.startswith(b"gcc version"))
confhash = hashlib.sha1(confwith).hexdigest()[:16]

versioned_plugin = f"frr-format-{fullver}-{confhash}.so"
if os.path.exists(versioned_plugin):
    print(f"using versioned plugin for GCC version {ver} (full: {fullver}, hash: {confhash})")
    plugin_arg = ["-fplugin=./" + versioned_plugin]
else:
    print(f"trying default plugin for GCC version {ver} (full: {fullver}, hash: {confhash}")
    plugin_arg = ["-fplugin=./frr-format.so"]

with open("format-test.c", "r") as fd:
    for lno, line in enumerate(fd.readlines(), 1):
        lines[lno] = line.strip()
        m = c_re.search(line)
        if m is None:
            continue
        if m.group("no") is None:
            expect[lno] = "warn"
        else:
            expect[lno] = "nowarn"
        if ver >= 11 and m.group("retain") is not None:
            expect[lno] = { "warn": "nowarn", "nowarn": "warn" }[expect[lno]]

cmd = []
cmd.extend(shlex.split("-Wall -Wextra -Wno-unused"))
cmd.extend(plugin_arg)
cmd.extend(shlex.split("-fno-diagnostics-show-caret -c -o format-test.o format-test.c"))

gcc = subprocess.Popen(
    sys.argv[1:] + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
sout, serr = gcc.communicate()
gcc.wait()

gcclines = serr.decode("UTF-8").splitlines()
line_re = re.compile(r"^format-test\.c:(\d+):(.*)$")
gcc_warns = {}

for line in gcclines:
    if line.find("In function") >= 0:
        continue
    m = line_re.match(line)
    if m is None:
        sys.stderr.write("cannot process GCC output: %s\n" % line)
        continue

    lno = int(m.group(1))
    gcc_warns.setdefault(lno, []).append(line)

for lno, val in expect.items():
    if val == "nowarn" and lno in gcc_warns:
        sys.stderr.write(
            "unexpected gcc warning on line %d:\n\t%s\n\t%s\n"
            % (lno, lines[lno], "\n\t".join(gcc_warns[lno]))
        )
    if val == "warn" and lno not in gcc_warns:
        sys.stderr.write(
            "expected warning on line %d but did not get one\n\t%s\n"
            % (lno, lines[lno])
        )

leftover = set(gcc_warns.keys()) - set(expect.keys())
for lno in sorted(leftover):
    sys.stderr.write(
        "unmarked gcc warning on line %d:\n\t%s\n\t%s\n"
        % (lno, lines[lno], "\n\t".join(gcc_warns[lno]))
    )
