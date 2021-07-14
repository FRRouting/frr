# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 24 2021, Christian Hopps <chopps@labn.net>
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
import datetime
import os
import pdb
import pty
import re
import readline
import select
import shlex
import subprocess
import sys
import termios
import time as time_mod
import traceback
import tty


def spawn(unet, host, cmd):
    old_tty = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin.fileno())
    try:
        master_fd, slave_fd = pty.openpty()

        # use os.setsid() make it run in a new process group, or bash job
        # control will not be enabled
        p = unet.hosts[host].popen(
            cmd,
            preexec_fn=os.setsid,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            universal_newlines=True,
        )

        while p.poll() is None:
            r, w, e = select.select([sys.stdin, master_fd], [], [], .25)
            if sys.stdin in r:
                d = os.read(sys.stdin.fileno(), 10240)
                os.write(master_fd, d)
            elif master_fd in r:
                o = os.read(master_fd, 10240)
                if o:
                    os.write(sys.stdout.fileno(), o)
    finally:
        # restore tty settings back
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)


def cli(unet, histfile=None):
    try:
        if histfile is None:
            histfile = os.path.expanduser("~/.micronet-history.txt")
            if not os.path.exists(histfile):
                unet.cmd("touch " + histfile)
        if histfile:
            readline.read_history_file(histfile)
    except Exception:
        pass

    def host_cmd_split(unet, cmd):
        csplit = cmd.split()
        for i, e in enumerate(csplit):
            if e not in unet.hosts:
                break
        hosts = csplit[:i]
        if not hosts:
            hosts = sorted(unet.hosts.keys())
        cmd = " ".join(csplit[i:])
        return hosts, cmd

    try:
        while True:
            if sys.version_info[0] == 2:
                line = raw_input("unet> ")
            else:
                line = input("unet> ")
            line = line.strip()
            m = re.match(r"^(\S+)(?:\s+(.*))?$", line)
            if not m:
                continue
            cmd = m.group(1)
            oargs = m.group(2) if m.group(2) else ""
            if cmd == "q" or cmd == "quit":
                break
            if cmd == "hosts":
                print("%% hosts: %s" % " ".join(sorted(unet.hosts.keys())))
            elif cmd in ["term", "vtysh", "xterm"]:
                args = oargs.split()
                if not args or (len(args) == 1 and args[0] == "*"):
                    args = sorted(unet.hosts.keys())
                hosts = [unet.hosts[x] for x in args]
                for host in hosts:
                    if cmd == "t" or cmd == "term":
                        host.run_in_window("bash")
                    elif cmd == "v" or cmd == "vtysh":
                        host.run_in_window("vtysh")
                    elif cmd == "x" or cmd == "xterm":
                        host.run_in_window("bash", forcex=True)
            elif cmd == "sh":
                hosts, cmd = host_cmd_split(unet, oargs)
                for host in hosts:
                    spawn(unet, host, cmd)
            elif cmd == "h" or cmd == "help":
                print(
                    """
Commands:
  help                       :: this help
  sh [hosts] <shell-command> :: execute <shell-command> on <host>
  term [hosts]               :: open shell terminals for hosts
  vtysh [hosts]              :: open vtysh terminals for hosts
  [hosts] <vtysh-command>    :: execute vtysh-command on hosts
                """
                )
            else:
                hosts, cmd = host_cmd_split(unet, line)
                for host in hosts:
                    print("------ Host: %s ------" % host)
                    output = unet.hosts[host].cmd_legacy('vtysh -c "{}"'.format(cmd))
                    sys.stdout.write(output)
                    print("-------------%s-------" % ("-" * len(host)))
    except EOFError:
        pass
    finally:
        readline.write_history_file(histfile)
