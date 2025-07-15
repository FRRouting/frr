#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
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
    parser.add_argument(
        "-N", "--pathspace", help="Insert prefix into config & socket paths"
    )
    args = parser.parse_args()

    collecting = False  # file format has sentinels (seem superfluous)
    proc_cmds = {}  # Dictionary to store command lists for each process
    proc = None
    temp = None
    cmd_type = None  # Track whether we're collecting vtysh or ip commands

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
                cmd_type = None
            elif cmd_line[0] == "CMD_LIST_START":
                collecting = True
                cmd_type = "vtysh"
            elif cmd_line[0] == "CMD_LIST_IP_START":
                collecting = True
                cmd_type = "ip"
            elif cmd_line[0] == "CMD_LIST_END" or cmd_line[0] == "CMD_LIST_IP_END":
                collecting = False
                temp.flush()
                if proc not in proc_cmds:
                    proc_cmds[proc] = {}
                proc_cmds[proc][cmd_type] = open(temp.name)
                temp.close()
            elif collecting:
                temp.write(line + "\n")
            else:
                print("Ignoring unexpected input " + line.rstrip())
    except IOError as error:
        logging.fatal("Cannot read config file: %s: %s", args.config, str(error))
        return

    # Spawn processes to fetch each set of commands
    procs = []
    for proc in proc_cmds:
        for cmd_type, cmd_file in proc_cmds[proc].items():
            if args.pathspace:
                ofn = os.path.join(
                    args.log_dir,
                    args.pathspace
                    + "_"
                    + proc
                    + "_"
                    + cmd_type
                    + "_support_bundle.log",
                )
            else:
                ofn = os.path.join(
                    args.log_dir, proc + "_" + cmd_type + "_support_bundle.log"
                )

            if cmd_type == "vtysh":
                if args.pathspace:
                    p = subprocess.Popen(
                        ["/usr/bin/env", "vtysh", "-t", "-N", args.pathspace],
                        stdin=cmd_file,
                        stdout=open_with_backup(ofn),
                        stderr=subprocess.STDOUT,
                    )
                else:
                    p = subprocess.Popen(
                        ["/usr/bin/env", "vtysh", "-t"],
                        stdin=cmd_file,
                        stdout=open_with_backup(ofn),
                        stderr=subprocess.STDOUT,
                    )
            elif cmd_type == "ip":
                # For ip commands, create a shell script that executes each ip command
                cmd_file.seek(0)  # Reset file pointer to beginning
                ip_script = tempfile.NamedTemporaryFile(mode="w+")
                ip_script.write("#!/bin/bash\n")
                ip_script.write("set -e\n")
                for cmd in cmd_file:
                    cmd = cmd.strip()
                    if cmd:
                        ip_script.write(f"echo '=== Command: ip {cmd} ==='\n")
                        ip_script.write(
                            f"ip {cmd} || echo 'Command failed with exit code: $?'\n"
                        )
                        ip_script.write("echo '=== Return code: $? ==='\n")
                        ip_script.write("echo\n")
                ip_script.flush()
                os.chmod(ip_script.name, 0o755)

                p = subprocess.Popen(
                    ["/bin/bash", ip_script.name],
                    stdout=open_with_backup(ofn),
                    stderr=subprocess.STDOUT,
                )

            procs.append(p)

    for p in procs:
        p.wait()


if __name__ == "__main__":
    main()
