#!/usr/bin/env python3
#
# Quick demo program that checks whether files define commands that aren't
# in vtysh.  Execute after building.
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>

import os
import json
import subprocess

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with open("frr.xref", "r") as fd:
    data = json.load(fd)

vtysh_scan, _ = subprocess.Popen(
    ["make", "var-vtysh_scan"], stdout=subprocess.PIPE
).communicate()
vtysh_scan = set(vtysh_scan.decode("US-ASCII").split())

check = set()
vtysh = {}

for cmd, defs in data["cli"].items():
    for binary, clidef in defs.items():
        if clidef["defun"]["file"].startswith("vtysh/"):
            vtysh[clidef["string"]] = clidef

for cmd, defs in data["cli"].items():
    for binary, clidef in defs.items():
        if clidef["defun"]["file"].startswith("vtysh/"):
            continue

        if clidef["defun"]["file"] not in vtysh_scan:
            vtysh_def = vtysh.get(clidef["string"])
            if vtysh_def is not None:
                print(
                    "\033[33m%s defines %s, has a custom define in vtysh %s\033[m"
                    % (clidef["defun"]["file"], cmd, vtysh_def["defun"]["file"])
                )
            else:
                print(
                    "\033[31m%s defines %s, not in vtysh_scan\033[m"
                    % (clidef["defun"]["file"], cmd)
                )
                check.add(clidef["defun"]["file"])

print("\nfiles to check:\n\t" + " ".join(sorted(check)))
