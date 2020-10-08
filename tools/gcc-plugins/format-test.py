import subprocess
import sys
import shlex
import os
import re

os.environ["LC_ALL"] = "C"
os.environ["LANG"] = "C"
for k in list(os.environ.keys()):
    if k.startswith("LC_"):
        os.environ.pop(k)

if len(sys.argv) < 2:
    sys.stderr.write("start as format-test.py gcc-123.45 [-options ...]\n")
    sys.exit(1)

c_re = re.compile(r"//\s+(NO)?WARN")
expect = {}
lines = {}

with open("format-test.c", "r") as fd:
    for lno, line in enumerate(fd.readlines(), 1):
        lines[lno] = line.strip()
        m = c_re.search(line)
        if m is None:
            continue
        if m.group(1) is None:
            expect[lno] = "warn"
        else:
            expect[lno] = "nowarn"

cmd = shlex.split(
    "-Wall -Wextra -Wno-unused -fplugin=./frr-format.so -fno-diagnostics-show-caret -c -o format-test.o format-test.c"
)

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
