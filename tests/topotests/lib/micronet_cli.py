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
import argparse
import logging
import os
import pty
import re
import readline
import select
import socket
import subprocess
import sys
import tempfile
import termios
import tty


ENDMARKER = b"\x00END\x00"


def lineiter(sock):
    s = ""
    while True:
        sb = sock.recv(256)
        if not sb:
            return

        s += sb.decode("utf-8")
        i = s.find("\n")
        if i != -1:
            yield s[:i]
            s = s[i + 1 :]


def spawn(unet, host, cmd):
    if sys.stdin.isatty():
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
            r, w, e = select.select([sys.stdin, master_fd], [], [], 0.25)
            if sys.stdin in r:
                d = os.read(sys.stdin.fileno(), 10240)
                os.write(master_fd, d)
            elif master_fd in r:
                o = os.read(master_fd, 10240)
                if o:
                    os.write(sys.stdout.fileno(), o)
    finally:
        # restore tty settings back
        if sys.stdin.isatty():
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)


def doline(unet, line, writef):
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

    line = line.strip()
    m = re.match(r"^(\S+)(?:\s+(.*))?$", line)
    if not m:
        return True

    cmd = m.group(1)
    oargs = m.group(2) if m.group(2) else ""
    if cmd == "q" or cmd == "quit":
        return False
    if cmd == "hosts":
        writef("%% hosts: %s\n" % " ".join(sorted(unet.hosts.keys())))
    elif cmd in ["term", "vtysh", "xterm"]:
        args = oargs.split()
        if not args or (len(args) == 1 and args[0] == "*"):
            args = sorted(unet.hosts.keys())
        hosts = [unet.hosts[x] for x in args if x in unet.hosts]
        for host in hosts:
            if cmd == "t" or cmd == "term":
                host.run_in_window("bash", title="sh-%s" % host)
            elif cmd == "v" or cmd == "vtysh":
                host.run_in_window("vtysh", title="vt-%s" % host)
            elif cmd == "x" or cmd == "xterm":
                host.run_in_window("bash", title="sh-%s" % host, forcex=True)
    elif cmd == "sh":
        hosts, cmd = host_cmd_split(unet, oargs)
        for host in hosts:
            if sys.stdin.isatty():
                spawn(unet, host, cmd)
            else:
                if len(hosts) > 1:
                    writef("------ Host: %s ------\n" % host)
                output = unet.hosts[host].cmd_legacy(cmd)
                writef(output)
                if len(hosts) > 1:
                    writef("------- End: %s ------\n" % host)
        writef("\n")
    elif cmd == "h" or cmd == "help":
        writef(
            """
Commands:
  help                       :: this help
  sh [hosts] <shell-command> :: execute <shell-command> on <host>
  term [hosts]               :: open shell terminals for hosts
  vtysh [hosts]              :: open vtysh terminals for hosts
  [hosts] <vtysh-command>    :: execute vtysh-command on hosts\n\n"""
        )
    else:
        hosts, cmd = host_cmd_split(unet, line)
        for host in hosts:
            if len(hosts) > 1:
                writef("------ Host: %s ------\n" % host)
            output = unet.hosts[host].cmd_legacy('vtysh -c "{}"'.format(cmd))
            writef(output)
            if len(hosts) > 1:
                writef("------- End: %s ------\n" % host)
        writef("\n")
    return True


def cli_server_setup(unet):
    sockdir = tempfile.mkdtemp("-sockdir", "pyt")
    sockpath = os.path.join(sockdir, "cli-server.sock")
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.bind(sockpath)
        sock.listen(1)
        return sock, sockdir, sockpath
    except Exception:
        unet.cmd_status("rm -rf " + sockdir)
        raise


def cli_server(unet, server_sock):
    sock, addr = server_sock.accept()

    # Go into full non-blocking mode now
    sock.settimeout(None)

    for line in lineiter(sock):
        line = line.strip()

        def writef(x):
            xb = x.encode("utf-8")
            sock.send(xb)

        if not doline(unet, line, writef):
            return
        sock.send(ENDMARKER)


def cli_client(sockpath, prompt="unet> "):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(sockpath)

    # Go into full non-blocking mode now
    sock.settimeout(None)

    print("\n--- Micronet CLI Starting ---\n\n")
    while True:
        if sys.version_info[0] == 2:
            line = raw_input(prompt)  # pylint: disable=E0602
        else:
            line = input(prompt)
        if line is None:
            return

        # Need to put \n back
        line += "\n"

        # Send the CLI command
        sock.send(line.encode("utf-8"))

        def bendswith(b, sentinel):
            slen = len(sentinel)
            return len(b) >= slen and b[-slen:] == sentinel

        # Collect the output
        rb = b""
        while not bendswith(rb, ENDMARKER):
            lb = sock.recv(4096)
            if not lb:
                return
            rb += lb

        # Remove the marker
        rb = rb[: -len(ENDMARKER)]

        # Write the output
        sys.stdout.write(rb.decode("utf-8"))


def local_cli(unet, outf, prompt="unet> "):
    print("\n--- Micronet CLI Starting ---\n\n")
    while True:
        if sys.version_info[0] == 2:
            line = raw_input(prompt)  # pylint: disable=E0602
        else:
            line = input(prompt)
        if line is None:
            return
        if not doline(unet, line, outf.write):
            return


def cli(
    unet,
    histfile=None,
    sockpath=None,
    force_window=False,
    title=None,
    prompt=None,
    background=True,
):
    logger = logging.getLogger("cli-client")

    if prompt is None:
        prompt = "unet> "

    if force_window or not sys.stdin.isatty():
        # Run CLI in another window b/c we have no tty.
        sock, sockdir, sockpath = cli_server_setup(unet)

        python_path = unet.get_exec_path(["python3", "python"])
        us = os.path.realpath(__file__)
        cmd = "{} {}".format(python_path, us)
        if histfile:
            cmd += " --histfile=" + histfile
        if title:
            cmd += " --prompt={}".format(title)
        cmd += " " + sockpath

        try:
            unet.run_in_window(cmd, new_window=True, title=title, background=background)
            return cli_server(unet, sock)
        finally:
            unet.cmd_status("rm -rf " + sockdir)

    if not unet:
        logger.debug("client-cli using sockpath %s", sockpath)

    try:
        if histfile is None:
            histfile = os.path.expanduser("~/.micronet-history.txt")
            if not os.path.exists(histfile):
                if unet:
                    unet.cmd("touch " + histfile)
                else:
                    subprocess.run("touch " + histfile)
        if histfile:
            readline.read_history_file(histfile)
    except Exception:
        pass

    try:
        if sockpath:
            cli_client(sockpath, prompt=prompt)
        else:
            local_cli(unet, sys.stdout, prompt=prompt)
    except EOFError:
        pass
    except Exception as ex:
        logger.critical("cli: got exception: %s", ex, exc_info=True)
        raise
    finally:
        readline.write_history_file(histfile)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, filename="/tmp/topotests/cli-client.log")
    logger = logging.getLogger("cli-client")
    logger.info("Start logging cli-client")

    parser = argparse.ArgumentParser()
    parser.add_argument("--histfile", help="file to user for history")
    parser.add_argument("--prompt-text", help="prompt string to use")
    parser.add_argument("socket", help="path to pair of sockets to communicate over")
    args = parser.parse_args()

    prompt = "{}> ".format(args.prompt_text) if args.prompt_text else "unet> "
    cli(None, args.histfile, args.socket, prompt=prompt)
