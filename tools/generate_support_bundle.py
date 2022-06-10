#!/usr/bin/env python3
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#

########################################################
### Python Script to generate the FRR support bundle ###
########################################################
import argparse
import logging
import os
import subprocess
import tempfile


def open_with_backup(path):
    if os.path.exists(path):
        print("Making backup of " + path)
        subprocess.check_call("mv {0} {0}.prev".format(path), shell=True)
    return open(path, "w")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        default="/etc/frr/support_bundle_commands.conf",
        help="input config",
    )
    parser.add_argument(
        "-l", "--log-dir", default="/var/log/frr", help="directory for logfiles"
    )
    args = parser.parse_args()

    collecting = False  # file format has sentinels (seem superfluous)
    proc_cmds = {}
    proc = None
    temp = None

    # Collect all the commands for each daemon
    try:
        for line in open(args.config):
            line = line.rstrip()
            if len(line) == 0 or line[0] == "#":
                continue

            cmd_line = line.split(":")
            if cmd_line[0] == "PROC_NAME":
                proc = cmd_line[1]
                temp = tempfile.NamedTemporaryFile("w+")
                collecting = False
            elif cmd_line[0] == "CMD_LIST_START":
                collecting = True
            elif cmd_line[0] == "CMD_LIST_END":
                collecting = False
                temp.flush()
                proc_cmds[proc] = open(temp.name)
                temp.close()
            elif collecting:
                temp.write(line + "\n")
            else:
                print("Ignoring unexpected input " + line.rstrip())
    except IOError as error:
        logging.fatal("Cannot read config file: %s: %s", args.config, str(error))
        return

    # Spawn a vtysh to fetch each set of commands
    procs = []
    for proc in proc_cmds:
        ofn = os.path.join(args.log_dir, proc + "_support_bundle.log")
        p = subprocess.Popen(
            ["/usr/bin/env", "vtysh", "-t"],
            stdin=proc_cmds[proc],
            stdout=open_with_backup(ofn),
            stderr=subprocess.STDOUT,
        )
        procs.append(p)

    for p in procs:
        p.wait()


if __name__ == "__main__":
    main()
