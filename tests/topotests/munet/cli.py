# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# July 24 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021, LabN Consulting, L.L.C.
#
"""A module that implements a CLI."""
import argparse
import asyncio
import functools
import logging
import multiprocessing
import os
import pty
import re
import readline
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import termios
import tty


try:
    from . import linux
    from .config import list_to_dict_with_key
except ImportError:
    # We cannot use relative imports and still run this module directly as a script, and
    # there are some use cases where we want to run this file as a script.
    sys.path.append(os.path.dirname(os.path.realpath(__file__)))
    import linux

    from config import list_to_dict_with_key


ENDMARKER = b"\x00END\x00"

logger = logging.getLogger(__name__)


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


# Would be nice to convert to async, but really not needed as used
def spawn(unet, host, cmd, iow, ns_only):
    if sys.stdin.isatty():
        old_tty = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())

    try:
        master_fd, slave_fd = pty.openpty()

        ns = unet.hosts[host] if host and host != unet else unet
        popenf = ns.popen_nsonly if ns_only else ns.popen

        # use os.setsid() make it run in a new process group, or bash job
        # control will not be enabled
        p = popenf(
            cmd,
            # _common_prologue, later in call chain, only does this for use_pty == False
            preexec_fn=os.setsid,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            universal_newlines=True,
            use_pty=True,
            # XXX this is actually implementing "run on host" for real
            # skip_pre_cmd=ns_only,
        )
        iow.write("\r")
        iow.flush()

        while p.poll() is None:
            r, _, _ = select.select([sys.stdin, master_fd], [], [], 0.25)
            if sys.stdin in r:
                d = os.read(sys.stdin.fileno(), 10240)
                os.write(master_fd, d)
            elif master_fd in r:
                o = os.read(master_fd, 10240)
                if o:
                    iow.write(o.decode("utf-8", "ignore"))
                    iow.flush()
    finally:
        # restore tty settings back
        if sys.stdin.isatty():
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)


def is_host_regex(restr):
    return len(restr) > 2 and restr[0] == "/" and restr[-1] == "/"


def get_host_regex(restr):
    if len(restr) < 3 or restr[0] != "/" or restr[-1] != "/":
        return None
    return re.compile(restr[1:-1])


def host_in(restr, names):
    """Determine if matcher is a regex that matches one of names."""
    if not (regexp := get_host_regex(restr)):
        return restr in names
    for name in names:
        if regexp.fullmatch(name):
            return True
    return False


def expand_host(restr, names):
    """Expand name or regexp into list of hosts."""
    hosts = []
    regexp = get_host_regex(restr)
    if not regexp:
        assert restr in names
        hosts.append(restr)
    else:
        for name in names:
            if regexp.fullmatch(name):
                hosts.append(name)
    return sorted(hosts)


def expand_hosts(restrs, names):
    """Expand list of host names or regex into list of hosts."""
    hosts = []
    for restr in restrs:
        hosts += expand_host(restr, names)
    return sorted(hosts)


def host_cmd_split(unet, line, toplevel):
    all_hosts = set(unet.hosts)
    csplit = line.split()
    i = 0
    banner = False
    for i, e in enumerate(csplit):
        if is_re := is_host_regex(e):
            banner = True
        if not host_in(e, all_hosts):
            if not is_re:
                break
    else:
        i += 1

    if i == 0 and csplit and csplit[0] == "*":
        hosts = sorted(all_hosts)
        csplit = csplit[1:]
        banner = True
    elif i == 0 and csplit and csplit[0] == ".":
        hosts = [unet]
        csplit = csplit[1:]
    else:
        hosts = expand_hosts(csplit[:i], all_hosts)
        csplit = csplit[i:]

        if not hosts and not csplit[:i]:
            if toplevel:
                hosts = [unet]
            else:
                hosts = sorted(all_hosts)
                banner = True

    if not csplit:
        return hosts, "", "", True

    i = line.index(csplit[0])
    i += len(csplit[0])
    return hosts, csplit[0], line[i:].strip(), banner


def win_cmd_host_split(unet, cmd, kinds, defall):
    if kinds:
        all_hosts = {
            x for x in unet.hosts if unet.hosts[x].config.get("kind", "") in kinds
        }
    else:
        all_hosts = set(unet.hosts)

    csplit = cmd.split()
    i = 0
    for i, e in enumerate(csplit):
        if not host_in(e, all_hosts):
            if not is_host_regex(e):
                break
    else:
        i += 1

    if i == 0 and csplit and csplit[0] == "*":
        hosts = sorted(all_hosts)
        csplit = csplit[1:]
    elif i == 0 and csplit and csplit[0] == ".":
        hosts = [unet]
        csplit = csplit[1:]
    else:
        hosts = expand_hosts(csplit[:i], all_hosts)

        if not hosts and defall and not csplit[:i]:
            hosts = sorted(all_hosts)

    # Filter hosts based on cmd
    cmd = " ".join(csplit[i:])
    return hosts, cmd


def proc_readline(fd, prompt, histfile):
    """Read a line of input from user while running in a sub-process."""
    # How do we change the command though, that's what's displayed in ps normally
    linux.set_process_name("Munet CLI")
    try:
        # For some reason sys.stdin is fileno == 16 and useless
        sys.stdin = os.fdopen(0)
        histfile = init_history(None, histfile)
        line = input(prompt)
        readline.write_history_file(histfile)
        if line is None:
            os.write(fd, b"\n")
        os.write(fd, bytes(f":{str(line)}\n", encoding="utf-8"))
    except EOFError:
        os.write(fd, b"\n")
    except KeyboardInterrupt:
        os.write(fd, b"I\n")
    except Exception as error:
        os.write(fd, bytes(f"E{str(error)}\n", encoding="utf-8"))


async def async_input_reader(rfd):
    """Read a line of input from the user input sub-process pipe."""
    rpipe = os.fdopen(rfd, mode="r")
    reader = asyncio.StreamReader()

    def protocol_factory():
        return asyncio.StreamReaderProtocol(reader)

    loop = asyncio.get_event_loop()
    transport, _ = await loop.connect_read_pipe(protocol_factory, rpipe)
    o = await reader.readline()
    transport.close()

    o = o.decode("utf-8").strip()
    if not o:
        return None
    if o[0] == "I":
        raise KeyboardInterrupt()
    if o[0] == "E":
        raise Exception(o[1:])
    assert o[0] == ":"
    return o[1:]


#
# A lot of work to add async `input` handling without creating a thread. We cannot use
# threads when unshare_inline is used with pid namespace per kernel clone(2)
# restriction.
#
async def async_input(prompt, histfile):
    """Asynchronously read a line from the user."""
    rfd, wfd = os.pipe()
    p = multiprocessing.Process(target=proc_readline, args=(wfd, prompt, histfile))
    p.start()
    logging.debug("started async_input input process: %s", p)
    try:
        return await async_input_reader(rfd)
    finally:
        logging.debug("joining async_input input process")
        p.join()


def make_help_str(unet):
    w = sorted([x if x else "" for x in unet.cli_in_window_cmds])
    ww = unet.cli_in_window_cmds
    u = sorted([x if x else "" for x in unet.cli_run_cmds])
    uu = unet.cli_run_cmds

    s = (
        """
Basic Commands:
  cli   :: open a secondary CLI window
  help  :: this help
  hosts :: list hosts
  quit  :: quit the cli

  HOST can be a host or one of the following:
    - '*' for all hosts
    - '.' for the parent munet
    - a regex specified between '/' (e.g., '/rtr.*/')

New Window Commands:\n"""
        + "\n".join([f"  {ww[v][0]}\t:: {ww[v][1]}" for v in w])
        + """\nInline Commands:\n"""
        + "\n".join([f"  {uu[v][0]}\t:: {uu[v][1]}" for v in u])
        + "\n"
    )
    return s


def get_shcmd(unet, host, kinds, execfmt, ucmd):
    if host is None:
        h = None
        kind = None
    elif host is unet or host == "":
        h = unet
        kind = ""
    else:
        h = unet.hosts[host]
        kind = h.config.get("kind", "")
        if kinds and kind not in kinds:
            return ""
    if not isinstance(execfmt, str):
        execfmt = execfmt.get(kind, {}).get("exec", "")
    if not execfmt:
        return ""

    # Do substitutions for {} and {N} in string
    numfmt = len(re.findall(r"{\d*}", execfmt))
    if numfmt > 1:
        ucmd = execfmt.format(*shlex.split(ucmd))
    elif numfmt:
        ucmd = execfmt.format(ucmd)
    # look for any pair of {}s but do not count escaped {{ or }}
    elif len(re.findall(r"{[^}]+}", execfmt.replace("{{", "").replace("}}", ""))):
        if execfmt.endswith('"'):
            fstring = "f'''" + execfmt + "'''"
        else:
            fstring = 'f"""' + execfmt + '"""'
        ucmd = eval(  # pylint: disable=W0123
            fstring,
            globals(),
            {"host": h, "unet": unet, "user_input": ucmd},
        )
    else:
        # No variable or usercmd substitution at all.
        ucmd = execfmt

    # Do substitution for munet variables
    ucmd = ucmd.replace("%CONFIGDIR%", str(unet.config_dirname))
    if host is None or host is unet:
        ucmd = ucmd.replace("%RUNDIR%", str(unet.rundir))
        return ucmd.replace("%NAME%", ".")
    ucmd = ucmd.replace("%RUNDIR%", str(os.path.join(unet.rundir, host)))
    if h.mgmt_ip:
        ucmd = ucmd.replace("%IPADDR%", str(h.mgmt_ip))
    elif h.mgmt_ip6:
        ucmd = ucmd.replace("%IPADDR%", str(h.mgmt_ip6))
    if h.mgmt_ip6:
        ucmd = ucmd.replace("%IP6ADDR%", str(h.mgmt_ip6))
    return ucmd.replace("%NAME%", str(host))


async def run_command(
    unet,
    outf,
    line,
    execfmt,
    banner,
    hosts,
    toplevel,
    kinds,
    ns_only=False,
    interactive=False,
):
    """Runs a command on a set of hosts.

    Runs `execfmt`. Prior to executing the string the following transformations are
    performed on it.

    `execfmt` may also be a dictionary of dicitonaries keyed on kind with `exec` holding
    the kind's execfmt string.

    - if `{}` is present then `str.format` is called to replace `{}` with any extra
       input values after the command and hosts are removed from the input.
    - else if any `{digits}` are present then `str.format` is called to replace
      `{digits}` with positional args obtained from the addittional user input
      first passed to `shlex.split`.
    - else f-string style interpolation is performed on the string with
      the local variables `host` (the current node object or None),
      `unet` (the Munet object), and `user_input` (the additional command input)
      defined.

    The output is sent to `outf`.  If `ns_only` is True then the `execfmt` is
    run using `Commander.cmd_status_nsonly` otherwise it is run with
    `Commander.cmd_status`.
    """
    if kinds:
        logging.info("Filtering hosts to kinds: %s", kinds)
        hosts = [x for x in hosts if unet.hosts[x].config.get("kind", "") in kinds]
        logging.info("Filtered hosts: %s", hosts)

    if not hosts:
        if not toplevel:
            return
        hosts = [unet]

    # if unknowns := [x for x in hosts if x not in unet.hosts]:
    #     outf.write("%% Unknown host[s]: %s\n" % ", ".join(unknowns))
    #     return

    # if sys.stdin.isatty() and interactive:
    if interactive:
        for host in hosts:
            shcmd = get_shcmd(unet, host, kinds, execfmt, line)
            if not shcmd:
                continue
            if len(hosts) > 1 or banner:
                outf.write(f"------ Host: {host} ------\n")
            spawn(unet, host if not toplevel else unet, shcmd, outf, ns_only)
            if len(hosts) > 1 or banner:
                outf.write(f"------- End: {host} ------\n")
        outf.write("\n")
        return

    aws = []
    for host in hosts:
        shcmd = get_shcmd(unet, host, kinds, execfmt, line)
        if not shcmd:
            continue
        if toplevel:
            ns = unet
        else:
            ns = unet.hosts[host] if host and host != unet else unet
        if ns_only:
            cmdf = ns.async_cmd_status_nsonly
        else:
            cmdf = ns.async_cmd_status
        aws.append(cmdf(shcmd, warn=False, stderr=subprocess.STDOUT))

    results = await asyncio.gather(*aws, return_exceptions=True)
    for host, result in zip(hosts, results):
        if isinstance(result, Exception):
            o = str(result) + "\n"
            rc = -1
        else:
            rc, o, _ = result
        if len(hosts) > 1 or banner:
            outf.write(f"------ Host: {host} ------\n")
        if rc:
            outf.write(f"*** non-zero exit status: {rc}\n")
        outf.write(o)
        if len(hosts) > 1 or banner:
            outf.write(f"------- End: {host} ------\n")


cli_builtins = ["cli", "help", "hosts", "quit"]


class Completer:
    """A completer class for the CLI."""

    def __init__(self, unet):
        self.unet = unet

    def complete(self, text, state):
        line = readline.get_line_buffer()
        tokens = line.split()
        # print(f"\nXXX: tokens: {tokens} text: '{text}' state: {state}'\n")

        first_token = not tokens or (text and len(tokens) == 1)

        # If we have already have a builtin command we are done
        if tokens and tokens[0] in cli_builtins:
            return [None]

        cli_run_cmds = set(self.unet.cli_run_cmds.keys())
        top_run_cmds = {x for x in cli_run_cmds if self.unet.cli_run_cmds[x][3]}
        cli_run_cmds -= top_run_cmds
        cli_win_cmds = set(self.unet.cli_in_window_cmds.keys())
        hosts = set(self.unet.hosts.keys())
        is_window_cmd = bool(tokens) and tokens[0] in cli_win_cmds
        done_set = set()
        if bool(tokens):
            if text:
                done_set = set(tokens[:-1])
            else:
                done_set = set(tokens)

        # Determine the domain for completions
        if not tokens or first_token:
            all_cmds = (
                set(cli_builtins) | hosts | cli_run_cmds | cli_win_cmds | top_run_cmds
            )
        elif is_window_cmd:
            all_cmds = hosts
        elif tokens and tokens[0] in top_run_cmds:
            # nothing to complete if a top level command
            pass
        elif not bool(done_set & cli_run_cmds):
            all_cmds = hosts | cli_run_cmds

        if not text:
            completes = all_cmds
        else:
            # print(f"\nXXX: all_cmds: {all_cmds} text: '{text}'\n")
            completes = {x + " " for x in all_cmds if x.startswith(text)}

        # print(f"\nXXX: completes: {completes} text: '{text}' state: {state}'\n")
        # remove any completions already present
        completes -= done_set
        completes = sorted(completes) + [None]
        return completes[state]


async def doline(
    unet, line, outf, background=False, notty=False
):  # pylint: disable=R0911
    line = line.strip()
    m = re.fullmatch(r"^(\S+)(?:\s+(.*))?$", line)
    if not m:
        return True

    cmd = m.group(1)
    nline = m.group(2) if m.group(2) else ""

    if cmd in ("q", "quit"):
        return False

    if cmd == "help":
        outf.write(make_help_str(unet))
        return True
    if cmd in ("h", "hosts"):
        outf.write(f"% Hosts:\t{' '.join(sorted(unet.hosts.keys()))}\n")
        return True
    if cmd == "cli":
        await remote_cli(
            unet,
            "secondary> ",
            "Secondary CLI",
            background,
        )
        return True

    #
    # In window commands
    #

    if cmd in unet.cli_in_window_cmds:
        execfmt, toplevel, kinds, kwargs = unet.cli_in_window_cmds[cmd][2:]

        # if toplevel:
        #     ucmd = " ".join(nline.split())
        # else:
        hosts, ucmd = win_cmd_host_split(unet, nline, kinds, False)
        if not hosts:
            if not toplevel:
                return True
            hosts = [unet]

        if isinstance(execfmt, str):
            found_brace = "{}" in execfmt
        else:
            found_brace = False
            for d in execfmt.values():
                if "{}" in d["exec"]:
                    found_brace = True
                    break
        if not found_brace and ucmd and not toplevel:
            # CLI command does not expect user command so treat as hosts of which some
            # must be unknown
            unknowns = [x for x in ucmd.split() if x not in unet.hosts]
            outf.write(f"% Unknown host[s]: {' '.join(unknowns)}\n")
            return True

        try:
            if not hosts and toplevel:
                hosts = [unet]

            for host in hosts:
                shcmd = get_shcmd(unet, host, kinds, execfmt, ucmd)
                if toplevel or host == unet:
                    unet.run_in_window(shcmd, **kwargs)
                else:
                    unet.hosts[host].run_in_window(shcmd, **kwargs)
        except Exception as error:
            outf.write(f"% Error: {error}\n")
        return True

    #
    # Inline commands
    #

    toplevel = unet.cli_run_cmds[cmd][3] if cmd in unet.cli_run_cmds else False
    # if toplevel:
    #     logging.debug("top-level: cmd: '%s' nline: '%s'", cmd, nline)
    #     hosts = None
    #     banner = False
    # else:

    hosts, cmd, nline, banner = host_cmd_split(unet, line, toplevel)
    hoststr = "munet" if hosts == [unet] else f"{hosts}"
    logging.debug("hosts: '%s' cmd: '%s' nline: '%s'", hoststr, cmd, nline)

    if cmd in unet.cli_run_cmds:
        pass
    elif "" in unet.cli_run_cmds:
        nline = f"{cmd} {nline}"
        cmd = ""
    else:
        outf.write(f"% Unknown command: {cmd} {nline}\n")
        return True

    execfmt, toplevel, kinds, ns_only, interactive = unet.cli_run_cmds[cmd][2:]
    if interactive and notty:
        outf.write("% Error: interactive command must be run from primary CLI\n")
        return True

    await run_command(
        unet,
        outf,
        nline,
        execfmt,
        banner,
        hosts,
        toplevel,
        kinds,
        ns_only,
        interactive,
    )

    return True


async def cli_client(sockpath, prompt="munet> "):
    """Implement the user-facing CLI for a remote munet reached by a socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(sockpath)

    # Go into full non-blocking mode now
    sock.settimeout(None)

    print("\n--- Munet CLI Starting ---\n\n")
    while True:
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
        sys.stdout.write(rb.decode("utf-8", "ignore"))


async def local_cli(unet, outf, prompt, histfile, background):
    """Implement the user-side CLI for local munet."""
    assert unet is not None
    completer = Completer(unet)
    readline.parse_and_bind("tab: complete")
    readline.set_completer(completer.complete)

    print("\n--- Munet CLI Starting ---\n\n")
    while True:
        try:
            line = await async_input(prompt, histfile)
            if line is None:
                return

            if not await doline(unet, line, outf, background):
                return
        except KeyboardInterrupt:
            outf.write("%% Caught KeyboardInterrupt\nUse ^D or 'quit' to exit")


def init_history(unet, histfile):
    try:
        if histfile is None:
            histfile = os.path.expanduser("~/.munet-history.txt")
            if not os.path.exists(histfile):
                if unet:
                    unet.cmd("touch " + histfile)
                else:
                    subprocess.run("touch " + histfile, shell=True, check=True)
        if histfile:
            readline.read_history_file(histfile)
        return histfile
    except Exception as error:
        logging.warning("init_history failed: %s", error)
    return None


async def cli_client_connected(unet, background, reader, writer):
    """Handle CLI commands inside the munet process from a socket."""
    # # Go into full non-blocking mode now
    # client.settimeout(None)
    logging.debug("cli client connected")
    while True:
        line = await reader.readline()
        if not line:
            logging.debug("client closed cli connection")
            break
        line = line.decode("utf-8").strip()

        class EncodingFile:
            """Wrap a writer to encode in utf-8."""

            def __init__(self, writer):
                self.writer = writer

            def write(self, x):
                self.writer.write(x.encode("utf-8", "ignore"))

            def flush(self):
                self.writer.flush()

        if not await doline(unet, line, EncodingFile(writer), background, notty=True):
            logging.debug("server closing cli connection")
            return

        writer.write(ENDMARKER)
        await writer.drain()


async def remote_cli(unet, prompt, title, background):
    """Open a CLI in a new window."""
    try:
        if not unet.cli_sockpath:
            sockpath = os.path.join(tempfile.mkdtemp("-sockdir", "pty-"), "cli.sock")
            ccfunc = functools.partial(cli_client_connected, unet, background)
            s = await asyncio.start_unix_server(ccfunc, path=sockpath)
            unet.cli_server = asyncio.create_task(s.serve_forever(), name="cli-task")
            unet.cli_sockpath = sockpath
            logging.info("server created on :\n%s\n", sockpath)

        # Open a new window with a new CLI
        python_path = await unet.async_get_exec_path(["python3", "python"])
        us = os.path.realpath(__file__)
        cmd = f"{python_path} {us}"
        if unet.cli_histfile:
            cmd += " --histfile=" + unet.cli_histfile
        if prompt:
            cmd += f" --prompt='{prompt}'"
        cmd += " " + unet.cli_sockpath
        unet.run_in_window(cmd, title=title, background=False)
    except Exception as error:
        logging.error("cli server: unexpected exception: %s", error)


def add_cli_in_window_cmd(
    unet, name, helpfmt, helptxt, execfmt, toplevel, kinds, **kwargs
):
    """Adds a CLI command to the CLI.

    The command `cmd` is added to the commands executable by the user from the CLI.  See
    `base.Commander.run_in_window` for the arguments that can be passed in `args` and
    `kwargs` to this function.

    Args:
        unet: unet object
        name: command string (no spaces)
        helpfmt: format of command to display in help (left side)
        helptxt: help string for command (right side)
        execfmt: interpreter `cmd` to pass to `host.run_in_window()`, if {} present then
          allow for user commands to be entered and inserted. May also be a dict of dict
          keyed on kind with sub-key of "exec" providing the `execfmt` string for that
          kind.
        toplevel: run command in common top-level namespaec not inside hosts
        kinds: limit CLI command to nodes which match list of kinds.
        **kwargs: keyword args to pass to `host.run_in_window()`
    """
    unet.cli_in_window_cmds[name] = (helpfmt, helptxt, execfmt, toplevel, kinds, kwargs)


def add_cli_run_cmd(
    unet,
    name,
    helpfmt,
    helptxt,
    execfmt,
    toplevel,
    kinds,
    ns_only=False,
    interactive=False,
):
    """Adds a CLI command to the CLI.

    The command `cmd` is added to the commands executable by the user from the CLI.
    See `run_command` above in the `doline` function and for the arguments that can
    be passed in to this function.

    Args:
        unet: unet object
        name: command string (no spaces)
        helpfmt: format of command to display in help (left side)
        helptxt: help string for command (right side)
        execfmt: format string to insert user cmds into for execution. May also be a
          dict of dict keyed on kind with sub-key of "exec" providing the `execfmt`
          string for that kind.
        toplevel: run command in common top-level namespaec not inside hosts
        kinds: limit CLI command to nodes which match list of kinds.
        ns_only: Should execute the command on the host vs in the node namespace.
        interactive: Should execute the command inside an allocated pty (interactive)
    """
    unet.cli_run_cmds[name] = (
        helpfmt,
        helptxt,
        execfmt,
        toplevel,
        kinds,
        ns_only,
        interactive,
    )


def add_cli_config(unet, config):
    """Adds CLI commands based on config.

    All exec strings will have %CONFIGDIR%, %NAME% and %RUNDIR% replaced with the
    corresponding config directory and the current nodes `name` and `rundir`.
    Additionally, the exec string will have f-string style interpolation performed
    with the local variables `host` (node object or None), `unet` (Munet object) and
    `user_input` (if provided to the CLI command) defined.

    The format of the config dictionary can be seen in the following example.
    The first list entry represents the default command because it has no `name` key.

      commands:
        - help: "run the given FRR command using vtysh"
          format: "[HOST ...] FRR-CLI-COMMAND"
          exec: "vtysh -c {}"
          ns-only: false        # the default
          interactive: false    # the default
        - name: "vtysh"
          help: "Open a FRR CLI inside new terminal[s] on the given HOST[s]"
          format: "vtysh HOST [HOST ...]"
          exec: "vtysh"
          new-window: true
        - name: "capture"
          help: "Capture packets on a given network"
          format: "pcap NETWORK"
          exec: "tshark -s 9200 -i {0} -w /tmp/capture-{0}.pcap"
          new-window: true
          top-level: true # run in top-level container namespace, above hosts

    The `new_window` key can also be a dictionary which will be passed as keyward
    arguments to the `Commander.run_in_window()` function.

    Args:
        unet: unet object
        config: dictionary of cli config
    """
    for cli_cmd in config.get("commands", []):
        name = cli_cmd.get("name", None)
        helpfmt = cli_cmd.get("format", "")
        helptxt = cli_cmd.get("help", "")
        execfmt = list_to_dict_with_key(cli_cmd.get("exec-kind"), "kind")
        if not execfmt:
            execfmt = cli_cmd.get("exec", "bash -c '{}'")
        toplevel = cli_cmd.get("top-level", False)
        kinds = cli_cmd.get("kinds", [])
        stdargs = (unet, name, helpfmt, helptxt, execfmt, toplevel, kinds)
        new_window = cli_cmd.get("new-window", None)
        if isinstance(new_window, dict):
            add_cli_in_window_cmd(*stdargs, **new_window)
        elif bool(new_window):
            add_cli_in_window_cmd(*stdargs)
        else:
            # on-host is deprecated it really implemented "ns-only"
            add_cli_run_cmd(
                *stdargs,
                cli_cmd.get("ns-only", cli_cmd.get("on-host")),
                cli_cmd.get("interactive", False),
            )


def cli(
    unet,
    histfile=None,
    sockpath=None,
    force_window=False,
    title=None,
    prompt=None,
    background=True,
):
    asyncio.run(
        async_cli(unet, histfile, sockpath, force_window, title, prompt, background)
    )


async def async_cli(
    unet,
    histfile=None,
    sockpath=None,
    force_window=False,
    title=None,
    prompt=None,
    background=True,
):
    if prompt is None:
        prompt = "munet> "

    if force_window or not sys.stdin.isatty():
        await remote_cli(unet, prompt, title, background)

    if not unet:
        logger.debug("client-cli using sockpath %s", sockpath)

    try:
        if sockpath:
            await cli_client(sockpath, prompt)
        else:
            await local_cli(unet, sys.stdout, prompt, histfile, background)
    except KeyboardInterrupt:
        print("\n...^C exiting CLI")
    except EOFError:
        pass
    except Exception as ex:
        logger.critical("cli: got exception: %s", ex, exc_info=True)
        raise


if __name__ == "__main__":
    # logging.basicConfig(level=logging.DEBUG, filename="/tmp/topotests/cli-client.log")
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("cli-client")
    logger.info("Start logging cli-client")

    parser = argparse.ArgumentParser()
    parser.add_argument("--histfile", help="file to user for history")
    parser.add_argument("--prompt", help="prompt string to use")
    parser.add_argument("socket", help="path to pair of sockets to communicate over")
    cli_args = parser.parse_args()

    cli_prompt = cli_args.prompt if cli_args.prompt else "munet> "
    asyncio.run(
        async_cli(
            None,
            cli_args.histfile,
            cli_args.socket,
            prompt=cli_prompt,
            background=False,
        )
    )
