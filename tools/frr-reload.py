#!/usr/bin/python
# Frr Reloader
# Copyright (C) 2014 Cumulus Networks, Inc.
#
# This file is part of Frr.
#
# Frr is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# Frr is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Frr; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
#  02111-1307, USA.
#
"""
This program
- reads a frr configuration text file
- reads frr's current running configuration via "vtysh -c 'show running'"
- compares the two configs and determines what commands to execute to
  synchronize frr's running configuration with the configuation in the
  text file
"""

from __future__ import print_function, unicode_literals
import argparse
import copy
import logging
import os, os.path
import random
import re
import string
import subprocess
import sys
from collections import OrderedDict

try:
    from ipaddress import IPv6Address, ip_network
except ImportError:
    from ipaddr import IPv6Address, IPNetwork
from pprint import pformat

try:
    dict.iteritems
except AttributeError:
    # Python 3
    def iteritems(d):
        return iter(d.items())


else:
    # Python 2
    def iteritems(d):
        return d.iteritems()


log = logging.getLogger(__name__)


class VtyshException(Exception):
    pass


class Vtysh(object):
    def __init__(self, bindir=None, confdir=None, sockdir=None, pathspace=None):
        self.bindir = bindir
        self.confdir = confdir
        self.pathspace = pathspace
        self.common_args = [os.path.join(bindir or "", "vtysh")]
        if confdir:
            self.common_args.extend(["--config_dir", confdir])
        if sockdir:
            self.common_args.extend(["--vty_socket", sockdir])
        if pathspace:
            self.common_args.extend(["-N", pathspace])

    def _call(self, args, stdin=None, stdout=None, stderr=None):
        kwargs = {}
        if stdin is not None:
            kwargs["stdin"] = stdin
        if stdout is not None:
            kwargs["stdout"] = stdout
        if stderr is not None:
            kwargs["stderr"] = stderr
        return subprocess.Popen(self.common_args + args, **kwargs)

    def _call_cmd(self, command, stdin=None, stdout=None, stderr=None):
        if isinstance(command, list):
            args = [item for sub in command for item in ["-c", sub]]
        else:
            args = ["-c", command]
        return self._call(args, stdin, stdout, stderr)

    def __call__(self, command):
        """
        Call a CLI command (e.g. "show running-config")

        Output text is automatically redirected, decoded and returned.
        Multiple commands may be passed as list.
        """
        proc = self._call_cmd(command, stdout=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if proc.wait() != 0:
            raise VtyshException(
                'vtysh returned status %d for command "%s"' % (proc.returncode, command)
            )
        return stdout.decode("UTF-8")

    def is_config_available(self):
        """
        Return False if no frr daemon is running or some other vtysh session is
        in 'configuration terminal' mode which will prevent us from making any
        configuration changes.
        """

        output = self("configure")

        if "VTY configuration is locked by other VTY" in output:
            log.error("vtysh 'configure' returned\n%s\n" % (output))
            return False

        return True

    def exec_file(self, filename):
        child = self._call(["-f", filename])
        if child.wait() != 0:
            raise VtyshException(
                "vtysh (exec file) exited with status %d" % (child.returncode)
            )

    def mark_file(self, filename, stdin=None):
        child = self._call(
            ["-m", "-f", filename],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = child.communicate()
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
            raise VtyshException("vtysh call timed out!")

        if child.wait() != 0:
            raise VtyshException(
                "vtysh (mark file) exited with status %d:\n%s"
                % (child.returncode, stderr)
            )

        return stdout.decode("UTF-8")

    def mark_show_run(self, daemon=None):
        cmd = "show running-config"
        if daemon:
            cmd += " %s" % daemon
        cmd += " no-header"
        show_run = self._call_cmd(cmd, stdout=subprocess.PIPE)
        mark = self._call(
            ["-m", "-f", "-"], stdin=show_run.stdout, stdout=subprocess.PIPE
        )

        show_run.wait()
        stdout, stderr = mark.communicate()
        mark.wait()

        if show_run.returncode != 0:
            raise VtyshException(
                "vtysh (show running-config) exited with status %d:"
                % (show_run.returncode)
            )
        if mark.returncode != 0:
            raise VtyshException(
                "vtysh (mark running-config) exited with status %d" % (mark.returncode)
            )

        return stdout.decode("UTF-8")


class Context(object):

    """
    A Context object represents a section of frr configuration such as:
!
interface swp3
 description swp3 -> r8's swp1
 ipv6 nd suppress-ra
 link-detect
!

or a single line context object such as this:

ip forwarding

    """

    def __init__(self, keys, lines):
        self.keys = keys
        self.lines = lines

        # Keep a dictionary of the lines, this is to make it easy to tell if a
        # line exists in this Context
        self.dlines = OrderedDict()

        for ligne in lines:
            self.dlines[ligne] = True

    def add_lines(self, lines):
        """
        Add lines to specified context
        """

        self.lines.extend(lines)

        for ligne in lines:
            self.dlines[ligne] = True

def get_normalized_es_id(line):
    """
    The es-id or es-sys-mac need to be converted to lower case
    """
    sub_strs = ["evpn mh es-id", "evpn mh es-sys-mac"]
    for sub_str in sub_strs:
        obj = re.match(sub_str + " (?P<esi>\S*)", line)
        if obj:
            line = "%s %s" % (sub_str, obj.group("esi").lower())
            break
    return line

def get_normalized_mac_ip_line(line):
    if line.startswith("evpn mh es"):
        return get_normalized_es_id(line)

    if not "ipv6 add" in line:
        return get_normalized_ipv6_line(line)

    return line

class Config(object):

    """
    A frr configuration is stored in a Config object. A Config object
    contains a dictionary of Context objects where the Context keys
    ('router ospf' for example) are our dictionary key.
    """

    def __init__(self, vtysh):
        self.lines = []
        self.contexts = OrderedDict()
        self.vtysh = vtysh

    def load_from_file(self, filename):
        """
        Read configuration from specified file and slurp it into internal memory
        The internal representation has been marked appropriately by passing it
        through vtysh with the -m parameter
        """
        log.info("Loading Config object from file %s", filename)

        file_output = self.vtysh.mark_file(filename)

        for line in file_output.split("\n"):
            line = line.strip()

            # Compress duplicate whitespaces
            line = " ".join(line.split())

            if ":" in line:
                line = get_normalized_mac_ip_line(line)

            self.lines.append(line)

        self.load_contexts()

    def load_from_show_running(self, daemon):
        """
        Read running configuration and slurp it into internal memory
        The internal representation has been marked appropriately by passing it
        through vtysh with the -m parameter
        """
        log.info("Loading Config object from vtysh show running")

        config_text = self.vtysh.mark_show_run(daemon)

        for line in config_text.split("\n"):
            line = line.strip()

            if (
                line == "Building configuration..."
                or line == "Current configuration:"
                or not line
            ):
                continue

            self.lines.append(line)

        self.load_contexts()

    def get_lines(self):
        """
        Return the lines read in from the configuration
        """

        return "\n".join(self.lines)

    def get_contexts(self):
        """
        Return the parsed context as strings for display, log etc.
        """

        for (_, ctx) in sorted(iteritems(self.contexts)):
            print(str(ctx) + "\n")

    def save_contexts(self, key, lines):
        """
        Save the provided key and lines as a context
        """

        if not key:
            return

        """
            IP addresses specified in "network" statements, "ip prefix-lists"
            etc. can differ in the host part of the specification the user
            provides and what the running config displays. For example, user
            can specify 11.1.1.1/24, and the running config displays this as
            11.1.1.0/24. Ensure we don't do a needless operation for such
            lines. IS-IS & OSPFv3 have no "network" support.
        """
        re_key_rt = re.match(r"(ip|ipv6)\s+route\s+([A-Fa-f:.0-9/]+)(.*)$", key[0])
        if re_key_rt:
            addr = re_key_rt.group(2)
            if "/" in addr:
                try:
                    if "ipaddress" not in sys.modules:
                        newaddr = IPNetwork(addr)
                        key[0] = "%s route %s/%s%s" % (
                            re_key_rt.group(1),
                            newaddr.network,
                            newaddr.prefixlen,
                            re_key_rt.group(3),
                        )
                    else:
                        newaddr = ip_network(addr, strict=False)
                        key[0] = "%s route %s/%s%s" % (
                            re_key_rt.group(1),
                            str(newaddr.network_address),
                            newaddr.prefixlen,
                            re_key_rt.group(3),
                        )
                except ValueError:
                    pass

        re_key_rt = re.match(
            r"(ip|ipv6)\s+prefix-list(.*)(permit|deny)\s+([A-Fa-f:.0-9/]+)(.*)$", key[0]
        )
        if re_key_rt:
            addr = re_key_rt.group(4)
            if "/" in addr:
                try:
                    if "ipaddress" not in sys.modules:
                        newaddr = "%s/%s" % (
                            IPNetwork(addr).network,
                            IPNetwork(addr).prefixlen,
                        )
                    else:
                        network_addr = ip_network(addr, strict=False)
                        newaddr = "%s/%s" % (
                            str(network_addr.network_address),
                            network_addr.prefixlen,
                        )
                except ValueError:
                    newaddr = addr
            else:
                newaddr = addr

            legestr = re_key_rt.group(5)
            re_lege = re.search(r"(.*)le\s+(\d+)\s+ge\s+(\d+)(.*)", legestr)
            if re_lege:
                legestr = "%sge %s le %s%s" % (
                    re_lege.group(1),
                    re_lege.group(3),
                    re_lege.group(2),
                    re_lege.group(4),
                )
            re_lege = re.search(r"(.*)ge\s+(\d+)\s+le\s+(\d+)(.*)", legestr)

            if re_lege and (
                (re_key_rt.group(1) == "ip" and re_lege.group(3) == "32")
                or (re_key_rt.group(1) == "ipv6" and re_lege.group(3) == "128")
            ):
                legestr = "%sge %s%s" % (
                    re_lege.group(1),
                    re_lege.group(2),
                    re_lege.group(4),
                )

            key[0] = "%s prefix-list%s%s %s%s" % (
                re_key_rt.group(1),
                re_key_rt.group(2),
                re_key_rt.group(3),
                newaddr,
                legestr,
            )

        if lines and key[0].startswith("router bgp"):
            newlines = []
            for line in lines:
                re_net = re.match(r"network\s+([A-Fa-f:.0-9/]+)(.*)$", line)
                if re_net:
                    addr = re_net.group(1)
                    if "/" not in addr and key[0].startswith("router bgp"):
                        # This is most likely an error because with no
                        # prefixlen, BGP treats the prefixlen as 8
                        addr = addr + "/8"

                    try:
                        if "ipaddress" not in sys.modules:
                            newaddr = IPNetwork(addr)
                            line = "network %s/%s %s" % (
                                newaddr.network,
                                newaddr.prefixlen,
                                re_net.group(2),
                            )
                        else:
                            network_addr = ip_network(addr, strict=False)
                            line = "network %s/%s %s" % (
                                str(network_addr.network_address),
                                network_addr.prefixlen,
                                re_net.group(2),
                            )
                        newlines.append(line)
                    except ValueError:
                        # Really this should be an error. Whats a network
                        # without an IP Address following it ?
                        newlines.append(line)
                else:
                    newlines.append(line)
            lines = newlines

        """
          More fixups in user specification and what running config shows.
          "null0" in routes must be replaced by Null0.
        """
        if (
            key[0].startswith("ip route")
            or key[0].startswith("ipv6 route")
            and "null0" in key[0]
        ):
            key[0] = re.sub(r"\s+null0(\s*$)", " Null0", key[0])

        if lines:
            if tuple(key) not in self.contexts:
                ctx = Context(tuple(key), lines)
                self.contexts[tuple(key)] = ctx
            else:
                ctx = self.contexts[tuple(key)]
                ctx.add_lines(lines)

        else:
            if tuple(key) not in self.contexts:
                ctx = Context(tuple(key), [])
                self.contexts[tuple(key)] = ctx

    def load_contexts(self):
        """
        Parse the configuration and create contexts for each appropriate block
        """

        current_context_lines = []
        ctx_keys = []

        """
        The end of a context is flagged via the 'end' keyword:

!
interface swp52
 ipv6 nd suppress-ra
 link-detect
!
end
router bgp 10
 bgp router-id 10.0.0.1
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 neighbor EBGP peer-group
 neighbor EBGP advertisement-interval 1
 neighbor EBGP timers connect 10
 neighbor 2001:40:1:4::6 remote-as 40
 neighbor 2001:40:1:8::a remote-as 40
!
end
 address-family ipv6
 neighbor IBGPv6 activate
 neighbor 2001:10::2 peer-group IBGPv6
 neighbor 2001:10::3 peer-group IBGPv6
 exit-address-family
!
end
 address-family evpn
  neighbor LEAF activate
  advertise-all-vni
  vni 10100
   rd 65000:10100
   route-target import 10.1.1.1:10100
   route-target export 10.1.1.1:10100
  exit-vni
 exit-address-family
!
end
router ospf
 ospf router-id 10.0.0.1
 log-adjacency-changes detail
 timers throttle spf 0 50 5000
!
end
        """

        # The code assumes that its working on the output from the "vtysh -m"
        # command. That provides the appropriate markers to signify end of
        # a context. This routine uses that to build the contexts for the
        # config.
        #
        # There are single line contexts such as "log file /media/node/zebra.log"
        # and multi-line contexts such as "router ospf" and subcontexts
        # within a context such as "address-family" within "router bgp"
        # In each of these cases, the first line of the context becomes the
        # key of the context. So "router bgp 10" is the key for the non-address
        # family part of bgp, "router bgp 10, address-family ipv6 unicast" is
        # the key for the subcontext and so on.
        ctx_keys = []
        main_ctx_key = []
        new_ctx = True

        # the keywords that we know are single line contexts. bgp in this case
        # is not the main router bgp block, but enabling multi-instance
        oneline_ctx_keywords = (
            "access-list ",
            "agentx",
            "allow-external-route-update",
            "bgp ",
            "debug ",
            "domainname ",
            "dump ",
            "enable ",
            "frr ",
            "fpm ",
            "hostname ",
            "ip ",
            "ipv6 ",
            "log ",
            "mpls lsp",
            "mpls label",
            "no ",
            "password ",
            "ptm-enable",
            "router-id ",
            "service ",
            "table ",
            "username ",
            "zebra ",
            "vrrp autoconfigure",
            "evpn mh",
        )

        for line in self.lines:

            if not line:
                continue

            if line.startswith("!") or line.startswith("#"):
                continue

            # one line contexts
            # there is one exception though: ldpd accepts a 'router-id' clause
            # as part of its 'mpls ldp' config context. If we are processing
            # ldp configuration and encounter a router-id we should NOT switch
            # to a new context
            if (
                new_ctx is True
                and any(line.startswith(keyword) for keyword in oneline_ctx_keywords)
                and not (
                    ctx_keys
                    and ctx_keys[0].startswith("mpls ldp")
                    and line.startswith("router-id ")
                )
            ):
                self.save_contexts(ctx_keys, current_context_lines)

                # Start a new context
                main_ctx_key = []
                ctx_keys = [
                    line,
                ]
                current_context_lines = []

                log.debug("LINE %-50s: entering new context, %-50s", line, ctx_keys)
                self.save_contexts(ctx_keys, current_context_lines)
                new_ctx = True

            elif line == "end":
                self.save_contexts(ctx_keys, current_context_lines)
                log.debug("LINE %-50s: exiting old context, %-50s", line, ctx_keys)

                # Start a new context
                new_ctx = True
                main_ctx_key = []
                ctx_keys = []
                current_context_lines = []

            elif line == "exit-vrf":
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines.append(line)
                log.debug(
                    "LINE %-50s: append to current_context_lines, %-50s", line, ctx_keys
                )

                # Start a new context
                new_ctx = True
                main_ctx_key = []
                ctx_keys = []
                current_context_lines = []

            elif (
                line == "exit"
                and len(ctx_keys) > 1
                and ctx_keys[0].startswith("segment-routing")
            ):
                self.save_contexts(ctx_keys, current_context_lines)

                # Start a new context
                ctx_keys = ctx_keys[:-1]
                current_context_lines = []
                log.debug(
                    "LINE %-50s: popping segment routing sub-context to ctx%-50s",
                    line,
                    ctx_keys
                )

            elif line in ["exit-address-family", "exit", "exit-vnc"]:
                # if this exit is for address-family ipv4 unicast, ignore the pop
                if main_ctx_key:
                    self.save_contexts(ctx_keys, current_context_lines)

                    # Start a new context
                    ctx_keys = copy.deepcopy(main_ctx_key)
                    current_context_lines = []
                    log.debug(
                        "LINE %-50s: popping from subcontext to ctx%-50s",
                        line,
                        ctx_keys
                    )

            elif line in ["exit-vni", "exit-ldp-if"]:
                if sub_main_ctx_key:
                    self.save_contexts(ctx_keys, current_context_lines)

                    # Start a new context
                    ctx_keys = copy.deepcopy(sub_main_ctx_key)
                    current_context_lines = []
                    log.debug(
                        "LINE %-50s: popping from sub-subcontext to ctx%-50s",
                        line,
                        ctx_keys,
                    )

            elif new_ctx is True:
                if not main_ctx_key:
                    ctx_keys = [
                        line,
                    ]
                else:
                    ctx_keys = copy.deepcopy(main_ctx_key)
                    main_ctx_key = []

                current_context_lines = []
                new_ctx = False
                log.debug("LINE %-50s: entering new context, %-50s", line, ctx_keys)

            elif (
                line.startswith("peer ")
                and len(ctx_keys) == 4
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
                and ctx_keys[2].startswith("pcep")
                and ctx_keys[3].startswith("pcc")
            ):
                # If there is no precedence, we add the default one (255) so
                # the line is not removed and added back
                m = re.search('peer ([^ ]*)', line)
                if (m != None):
                    (name,) = m.groups()
                    line = "peer %s precedence 255" % (name,)

                current_context_lines.append(line)
                log.debug(
                    "LINE %-50s: append to current_context_lines, %-50s", line, ctx_keys
                )

            elif (
                line.startswith("address-family ")
                or line.startswith("vnc defaults")
                or line.startswith("vnc l2-group")
                or line.startswith("vnc nve-group")
                or line.startswith("peer")
                or line.startswith("key ")
                or line.startswith("member pseudowire")
            ):
                main_ctx_key = []

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug("LINE %-50s: entering sub-context, append to ctx_keys", line)

                if line == "address-family ipv6" and not ctx_keys[0].startswith(
                    "mpls ldp"
                ):
                    ctx_keys.append("address-family ipv6 unicast")
                elif line == "address-family ipv4" and not ctx_keys[0].startswith(
                    "mpls ldp"
                ):
                    ctx_keys.append("address-family ipv4 unicast")
                elif line == "address-family evpn":
                    ctx_keys.append("address-family l2vpn evpn")
                else:
                    ctx_keys.append(line)

            elif (
                line.startswith("vni ")
                and len(ctx_keys) == 2
                and ctx_keys[0].startswith("router bgp")
                and ctx_keys[1] == "address-family l2vpn evpn"
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                sub_main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug(
                    "LINE %-50s: entering sub-sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("interface ")
                and len(ctx_keys) == 2
                and ctx_keys[0].startswith("mpls ldp")
                and ctx_keys[1].startswith("address-family")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                sub_main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug(
                    "LINE %-50s: entering sub-sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("traffic-eng")
                and len(ctx_keys) == 1
                and ctx_keys[0].startswith("segment-routing")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                log.debug(
                    "LINE %-50s: entering segment routing sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("segment-list ")
                and len(ctx_keys) == 2
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                log.debug(
                    "LINE %-50s: entering segment routing sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("policy ")
                and len(ctx_keys) == 2
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                log.debug(
                    "LINE %-50s: entering segment routing sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("candidate-path ")
                and line.endswith(" dynamic")
                and len(ctx_keys) == 3
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
                and ctx_keys[2].startswith("policy")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug(
                    "LINE %-50s: entering candidate-path sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("pcep")
                and len(ctx_keys) == 2
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug(
                    "LINE %-50s: entering pcep sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("pce-config ")
                and len(ctx_keys) == 3
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
                and ctx_keys[2].startswith("pcep")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug(
                    "LINE %-50s: entering pce-config sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("pce ")
                and len(ctx_keys) == 3
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
                and ctx_keys[2].startswith("pcep")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug(
                    "LINE %-50s: entering pce sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            elif (
                line.startswith("pcc")
                and len(ctx_keys) == 3
                and ctx_keys[0].startswith("segment-routing")
                and ctx_keys[1].startswith("traffic-eng")
                and ctx_keys[2].startswith("pcep")
            ):

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                main_ctx_key = copy.deepcopy(ctx_keys)
                log.debug(
                    "LINE %-50s: entering pcc sub-context, append to ctx_keys", line
                )
                ctx_keys.append(line)

            else:
                # Continuing in an existing context, add non-commented lines to it
                current_context_lines.append(line)
                log.debug(
                    "LINE %-50s: append to current_context_lines, %-50s", line, ctx_keys
                )

        # Save the context of the last one
        self.save_contexts(ctx_keys, current_context_lines)


def lines_to_config(ctx_keys, line, delete):
    """
    Return the command as it would appear in frr.conf
    """
    cmd = []

    if line:
        for (i, ctx_key) in enumerate(ctx_keys):
            cmd.append(" " * i + ctx_key)

        line = line.lstrip()
        indent = len(ctx_keys) * " "

        # There are some commands that are on by default so their "no" form will be
        # displayed in the config.  "no bgp default ipv4-unicast" is one of these.
        # If we need to remove this line we do so by adding "bgp default ipv4-unicast",
        # not by doing a "no no bgp default ipv4-unicast"
        if delete:
            if line.startswith("no "):
                cmd.append("%s%s" % (indent, line[3:]))
            else:
                cmd.append("%sno %s" % (indent, line))

        else:
            cmd.append(indent + line)

    # If line is None then we are typically deleting an entire
    # context ('no router ospf' for example)
    else:
        for i, ctx_key in enumerate(ctx_keys[:-1]):
            cmd.append("%s%s" % (" " * i, ctx_key))

        # Only put the 'no' on the last sub-context
        if delete:
            if ctx_keys[-1].startswith("no "):
                cmd.append("%s%s" % (" " * (len(ctx_keys) - 1), ctx_keys[-1][3:]))
            else:
                cmd.append("%sno %s" % (" " * (len(ctx_keys) - 1), ctx_keys[-1]))
        else:
            cmd.append("%s%s" % (" " * (len(ctx_keys) - 1), ctx_keys[-1]))

    return cmd


def get_normalized_ipv6_line(line):
    """
    Return a normalized IPv6 line as produced by frr,
    with all letters in lower case and trailing and leading
    zeros removed, and only the network portion present if
    the IPv6 word is a network
    """
    norm_line = ""
    words = line.split(" ")
    for word in words:
        if ":" in word:
            norm_word = None
            if "/" in word:
                try:
                    if "ipaddress" not in sys.modules:
                        v6word = IPNetwork(word)
                        norm_word = "%s/%s" % (v6word.network, v6word.prefixlen)
                    else:
                        v6word = ip_network(word, strict=False)
                        norm_word = "%s/%s" % (
                            str(v6word.network_address),
                            v6word.prefixlen,
                        )
                except ValueError:
                    pass
            if not norm_word:
                try:
                    norm_word = "%s" % IPv6Address(word)
                except ValueError:
                    norm_word = word
        else:
            norm_word = word
        norm_line = norm_line + " " + norm_word

    return norm_line.strip()


def line_exist(lines, target_ctx_keys, target_line, exact_match=True):
    for (ctx_keys, line) in lines:
        if ctx_keys == target_ctx_keys:
            if exact_match:
                if line == target_line:
                    return True
            else:
                if line.startswith(target_line):
                    return True
    return False


def check_for_exit_vrf(lines_to_add, lines_to_del):

    # exit-vrf is a bit tricky.  If the new config is missing it but we
    # have configs under a vrf, we need to add it at the end to do the
    # right context changes.  If exit-vrf exists in both the running and
    # new config, we cannot delete it or it will break context changes.
    add_exit_vrf = False
    index = 0

    for (ctx_keys, line) in lines_to_add:
        if add_exit_vrf == True:
            if ctx_keys[0] != prior_ctx_key:
                insert_key = ((prior_ctx_key),)
                lines_to_add.insert(index, ((insert_key, "exit-vrf")))
                add_exit_vrf = False

        if ctx_keys[0].startswith("vrf") and line:
            if line is not "exit-vrf":
                add_exit_vrf = True
                prior_ctx_key = ctx_keys[0]
            else:
                add_exit_vrf = False
        index += 1

    for (ctx_keys, line) in lines_to_del:
        if line == "exit-vrf":
            if line_exist(lines_to_add, ctx_keys, line):
                lines_to_del.remove((ctx_keys, line))

    return (lines_to_add, lines_to_del)


def ignore_delete_re_add_lines(lines_to_add, lines_to_del):

    # Quite possibly the most confusing (while accurate) variable names in history
    lines_to_add_to_del = []
    lines_to_del_to_del = []

    for (ctx_keys, line) in lines_to_del:
        deleted = False

        if ctx_keys[0].startswith("router bgp") and line:

            if line.startswith("neighbor "):
                """
                BGP changed how it displays swpX peers that are part of peer-group. Older
                versions of frr would display these on separate lines:
                    neighbor swp1 interface
                    neighbor swp1 peer-group FOO

                but today we display via a single line
                    neighbor swp1 interface peer-group FOO

                This change confuses frr-reload.py so check to see if we are deleting
                    neighbor swp1 interface peer-group FOO

                and adding
                    neighbor swp1 interface
                    neighbor swp1 peer-group FOO

                If so then chop the del line and the corresponding add lines
                """

                re_swpx_int_peergroup = re.search(
                    "neighbor (\S+) interface peer-group (\S+)", line
                )
                re_swpx_int_v6only_peergroup = re.search(
                    "neighbor (\S+) interface v6only peer-group (\S+)", line
                )

                if re_swpx_int_peergroup or re_swpx_int_v6only_peergroup:
                    swpx_interface = None
                    swpx_peergroup = None

                    if re_swpx_int_peergroup:
                        swpx = re_swpx_int_peergroup.group(1)
                        peergroup = re_swpx_int_peergroup.group(2)
                        swpx_interface = "neighbor %s interface" % swpx
                    elif re_swpx_int_v6only_peergroup:
                        swpx = re_swpx_int_v6only_peergroup.group(1)
                        peergroup = re_swpx_int_v6only_peergroup.group(2)
                        swpx_interface = "neighbor %s interface v6only" % swpx

                    swpx_peergroup = "neighbor %s peer-group %s" % (swpx, peergroup)
                    found_add_swpx_interface = line_exist(
                        lines_to_add, ctx_keys, swpx_interface
                    )
                    found_add_swpx_peergroup = line_exist(
                        lines_to_add, ctx_keys, swpx_peergroup
                    )
                    tmp_ctx_keys = tuple(list(ctx_keys))

                    if not found_add_swpx_peergroup:
                        tmp_ctx_keys = list(ctx_keys)
                        tmp_ctx_keys.append("address-family ipv4 unicast")
                        tmp_ctx_keys = tuple(tmp_ctx_keys)
                        found_add_swpx_peergroup = line_exist(
                            lines_to_add, tmp_ctx_keys, swpx_peergroup
                        )

                        if not found_add_swpx_peergroup:
                            tmp_ctx_keys = list(ctx_keys)
                            tmp_ctx_keys.append("address-family ipv6 unicast")
                            tmp_ctx_keys = tuple(tmp_ctx_keys)
                            found_add_swpx_peergroup = line_exist(
                                lines_to_add, tmp_ctx_keys, swpx_peergroup
                            )

                    if found_add_swpx_interface and found_add_swpx_peergroup:
                        deleted = True
                        lines_to_del_to_del.append((ctx_keys, line))
                        lines_to_add_to_del.append((ctx_keys, swpx_interface))
                        lines_to_add_to_del.append((tmp_ctx_keys, swpx_peergroup))

                """
                Changing the bfd timers on neighbors is allowed without doing
                a delete/add process. Since doing a "no neighbor blah bfd ..."
                will cause the peer to bounce unnecessarily, just skip the delete
                and just do the add.
                """
                re_nbr_bfd_timers = re.search(
                    r"neighbor (\S+) bfd (\S+) (\S+) (\S+)", line
                )

                if re_nbr_bfd_timers:
                    nbr = re_nbr_bfd_timers.group(1)
                    bfd_nbr = "neighbor %s" % nbr
                    bfd_search_string = bfd_nbr + r" bfd (\S+) (\S+) (\S+)"

                    for (ctx_keys, add_line) in lines_to_add:
                        if ctx_keys[0].startswith("router bgp"):
                            re_add_nbr_bfd_timers = re.search(
                                bfd_search_string, add_line
                            )

                            if re_add_nbr_bfd_timers:
                                found_add_bfd_nbr = line_exist(
                                    lines_to_add, ctx_keys, bfd_nbr, False
                                )

                                if found_add_bfd_nbr:
                                    lines_to_del_to_del.append((ctx_keys, line))

                """
                We changed how we display the neighbor interface command. Older
                versions of frr would display the following:
                    neighbor swp1 interface
                    neighbor swp1 remote-as external
                    neighbor swp1 capability extended-nexthop

                but today we display via a single line
                    neighbor swp1 interface remote-as external

                and capability extended-nexthop is no longer needed because we
                automatically enable it when the neighbor is of type interface.

                This change confuses frr-reload.py so check to see if we are deleting
                    neighbor swp1 interface remote-as (external|internal|ASNUM)

                and adding
                    neighbor swp1 interface
                    neighbor swp1 remote-as (external|internal|ASNUM)
                    neighbor swp1 capability extended-nexthop

                If so then chop the del line and the corresponding add lines
                """
                re_swpx_int_remoteas = re.search(
                    "neighbor (\S+) interface remote-as (\S+)", line
                )
                re_swpx_int_v6only_remoteas = re.search(
                    "neighbor (\S+) interface v6only remote-as (\S+)", line
                )

                if re_swpx_int_remoteas or re_swpx_int_v6only_remoteas:
                    swpx_interface = None
                    swpx_remoteas = None

                    if re_swpx_int_remoteas:
                        swpx = re_swpx_int_remoteas.group(1)
                        remoteas = re_swpx_int_remoteas.group(2)
                        swpx_interface = "neighbor %s interface" % swpx
                    elif re_swpx_int_v6only_remoteas:
                        swpx = re_swpx_int_v6only_remoteas.group(1)
                        remoteas = re_swpx_int_v6only_remoteas.group(2)
                        swpx_interface = "neighbor %s interface v6only" % swpx

                    swpx_remoteas = "neighbor %s remote-as %s" % (swpx, remoteas)
                    found_add_swpx_interface = line_exist(
                        lines_to_add, ctx_keys, swpx_interface
                    )
                    found_add_swpx_remoteas = line_exist(
                        lines_to_add, ctx_keys, swpx_remoteas
                    )
                    tmp_ctx_keys = tuple(list(ctx_keys))

                    if found_add_swpx_interface and found_add_swpx_remoteas:
                        deleted = True
                        lines_to_del_to_del.append((ctx_keys, line))
                        lines_to_add_to_del.append((ctx_keys, swpx_interface))
                        lines_to_add_to_del.append((tmp_ctx_keys, swpx_remoteas))

            """
            We made the 'bgp bestpath as-path multipath-relax' command
            automatically assume 'no-as-set' since the lack of this option caused
            weird routing problems. When the running config is shown in
            releases with this change, the no-as-set keyword is not shown as it
            is the default. This causes frr-reload to unnecessarily unapply
            this option only to apply it back again, causing unnecessary session
            resets.
            """
            if "multipath-relax" in line:
                re_asrelax_new = re.search(
                    "^bgp\s+bestpath\s+as-path\s+multipath-relax$", line
                )
                old_asrelax_cmd = "bgp bestpath as-path multipath-relax no-as-set"
                found_asrelax_old = line_exist(lines_to_add, ctx_keys, old_asrelax_cmd)

                if re_asrelax_new and found_asrelax_old:
                    deleted = True
                    lines_to_del_to_del.append((ctx_keys, line))
                    lines_to_add_to_del.append((ctx_keys, old_asrelax_cmd))

            """
            If we are modifying the BGP table-map we need to avoid a del/add and
            instead modify the table-map in place via an add.  This is needed to
            avoid installing all routes in the RIB the second the 'no table-map'
            is issued.
            """
            if line.startswith("table-map"):
                found_table_map = line_exist(lines_to_add, ctx_keys, "table-map", False)

                if found_table_map:
                    lines_to_del_to_del.append((ctx_keys, line))

        """
        More old-to-new config handling. ip import-table no longer accepts
        distance, but we honor the old syntax. But 'show running' shows only
        the new syntax. This causes an unnecessary 'no import-table' followed
        by the same old 'ip import-table' which causes perturbations in
        announced routes leading to traffic blackholes. Fix this issue.
        """
        re_importtbl = re.search("^ip\s+import-table\s+(\d+)$", ctx_keys[0])
        if re_importtbl:
            table_num = re_importtbl.group(1)
            for ctx in lines_to_add:
                if ctx[0][0].startswith("ip import-table %s distance" % table_num):
                    lines_to_del_to_del.append(
                        (("ip import-table %s" % table_num,), None)
                    )
                    lines_to_add_to_del.append((ctx[0], None))

        """
        ip/ipv6 prefix-list can be specified without a seq number. However,
        the running config always adds 'seq x', where x is a number incremented
        by 5 for every element, to the prefix list. So, ignore such lines as
        well. Sample prefix-list lines:
             ip prefix-list PR-TABLE-2 seq 5 permit 20.8.2.0/24 le 32
             ip prefix-list PR-TABLE-2 seq 10 permit 20.8.2.0/24 le 32
             ipv6 prefix-list vrfdev6-12 permit 2000:9:2::/64 gt 64
        """
        re_ip_pfxlst = re.search(
            "^(ip|ipv6)(\s+prefix-list\s+)(\S+\s+)(seq \d+\s+)(permit|deny)(.*)$",
            ctx_keys[0],
        )
        if re_ip_pfxlst:
            tmpline = (
                re_ip_pfxlst.group(1)
                + re_ip_pfxlst.group(2)
                + re_ip_pfxlst.group(3)
                + re_ip_pfxlst.group(5)
                + re_ip_pfxlst.group(6)
            )
            for ctx in lines_to_add:
                if ctx[0][0] == tmpline:
                    lines_to_del_to_del.append((ctx_keys, None))
                    lines_to_add_to_del.append(((tmpline,), None))

        if (
            len(ctx_keys) == 3
            and ctx_keys[0].startswith("router bgp")
            and ctx_keys[1] == "address-family l2vpn evpn"
            and ctx_keys[2].startswith("vni")
        ):

            re_route_target = (
                re.search("^route-target import (.*)$", line)
                if line is not None
                else False
            )

            if re_route_target:
                rt = re_route_target.group(1).strip()
                route_target_import_line = line
                route_target_export_line = "route-target export %s" % rt
                route_target_both_line = "route-target both %s" % rt

                found_route_target_export_line = line_exist(
                    lines_to_del, ctx_keys, route_target_export_line
                )
                found_route_target_both_line = line_exist(
                    lines_to_add, ctx_keys, route_target_both_line
                )

                """
                If the running configs has
                    route-target import 1:1
                    route-target export 1:1

                and the config we are reloading against has
                    route-target both 1:1

                then we can ignore deleting the import/export and ignore adding the 'both'
                """
                if found_route_target_export_line and found_route_target_both_line:
                    lines_to_del_to_del.append((ctx_keys, route_target_import_line))
                    lines_to_del_to_del.append((ctx_keys, route_target_export_line))
                    lines_to_add_to_del.append((ctx_keys, route_target_both_line))

        # Deleting static routes under a vrf can lead to time-outs if each is sent
        # as separate vtysh -c commands. Change them from being in lines_to_del and
        # put the "no" form in lines_to_add
        if ctx_keys[0].startswith("vrf ") and line:
            if line.startswith("ip route") or line.startswith("ipv6 route"):
                add_cmd = "no " + line
                lines_to_add.append((ctx_keys, add_cmd))
                lines_to_del_to_del.append((ctx_keys, line))

        if not deleted:
            found_add_line = line_exist(lines_to_add, ctx_keys, line)

            if found_add_line:
                lines_to_del_to_del.append((ctx_keys, line))
                lines_to_add_to_del.append((ctx_keys, line))
            else:
                """
                We have commands that used to be displayed in the global part
                of 'router bgp' that are now displayed under 'address-family ipv4 unicast'

                # old way
                router bgp 64900
                  neighbor ISL advertisement-interval 0

                vs.

                # new way
                router bgp 64900
                  address-family ipv4 unicast
                    neighbor ISL advertisement-interval 0

                Look to see if we are deleting it in one format just to add it back in the other
                """
                if (
                    ctx_keys[0].startswith("router bgp")
                    and len(ctx_keys) > 1
                    and ctx_keys[1] == "address-family ipv4 unicast"
                ):
                    tmp_ctx_keys = list(ctx_keys)[:-1]
                    tmp_ctx_keys = tuple(tmp_ctx_keys)

                    found_add_line = line_exist(lines_to_add, tmp_ctx_keys, line)

                    if found_add_line:
                        lines_to_del_to_del.append((ctx_keys, line))
                        lines_to_add_to_del.append((tmp_ctx_keys, line))

    for (ctx_keys, line) in lines_to_del_to_del:
        lines_to_del.remove((ctx_keys, line))

    for (ctx_keys, line) in lines_to_add_to_del:
        lines_to_add.remove((ctx_keys, line))

    return (lines_to_add, lines_to_del)


def ignore_unconfigurable_lines(lines_to_add, lines_to_del):
    """
    There are certain commands that cannot be removed.  Remove
    those commands from lines_to_del.
    """
    lines_to_del_to_del = []

    for (ctx_keys, line) in lines_to_del:

        if (
            ctx_keys[0].startswith("frr version")
            or ctx_keys[0].startswith("frr defaults")
            or ctx_keys[0].startswith("username")
            or ctx_keys[0].startswith("password")
            or ctx_keys[0].startswith("line vty")
            or
            # This is technically "no"able but if we did so frr-reload would
            # stop working so do not let the user shoot themselves in the foot
            # by removing this.
            ctx_keys[0].startswith("service integrated-vtysh-config")
        ):

            log.info('"%s" cannot be removed' % (ctx_keys[-1],))
            lines_to_del_to_del.append((ctx_keys, line))

    for (ctx_keys, line) in lines_to_del_to_del:
        lines_to_del.remove((ctx_keys, line))

    return (lines_to_add, lines_to_del)


def compare_context_objects(newconf, running):
    """
    Create a context diff for the two specified contexts
    """

    # Compare the two Config objects to find the lines that we need to add/del
    lines_to_add = []
    lines_to_del = []
    pollist_to_del = []
    seglist_to_del = []
    candidates_to_add = []
    delete_bgpd = False

    # Find contexts that are in newconf but not in running
    # Find contexts that are in running but not in newconf
    for (running_ctx_keys, running_ctx) in iteritems(running.contexts):

        if running_ctx_keys not in newconf.contexts:

            # We check that the len is 1 here so that we only look at ('router bgp 10')
            # and not ('router bgp 10', 'address-family ipv4 unicast'). The
            # latter could cause a false delete_bgpd positive if ipv4 unicast is in
            # running but not in newconf.
            if "router bgp" in running_ctx_keys[0] and len(running_ctx_keys) == 1:
                delete_bgpd = True
                lines_to_del.append((running_ctx_keys, None))

            # We cannot do 'no interface' or 'no vrf' in FRR, and so deal with it
            elif running_ctx_keys[0].startswith("interface") or running_ctx_keys[
                0
            ].startswith("vrf"):
                for line in running_ctx.lines:
                    lines_to_del.append((running_ctx_keys, line))

            # If this is an address-family under 'router bgp' and we are already deleting the
            # entire 'router bgp' context then ignore this sub-context
            elif (
                "router bgp" in running_ctx_keys[0]
                and len(running_ctx_keys) > 1
                and delete_bgpd
            ):
                continue

            # Delete an entire vni sub-context under "address-family l2vpn evpn"
            elif (
                "router bgp" in running_ctx_keys[0]
                and len(running_ctx_keys) > 2
                and running_ctx_keys[1].startswith("address-family l2vpn evpn")
                and running_ctx_keys[2].startswith("vni ")
            ):
                lines_to_del.append((running_ctx_keys, None))

            elif (
                "router bgp" in running_ctx_keys[0]
                and len(running_ctx_keys) > 1
                and running_ctx_keys[1].startswith("address-family")
            ):
                # There's no 'no address-family' support and so we have to
                # delete each line individually again
                for line in running_ctx.lines:
                    lines_to_del.append((running_ctx_keys, line))

            # Some commands can happen at higher counts that make
            # doing vtysh -c inefficient (and can time out.)  For
            # these commands, instead of adding them to lines_to_del,
            # add the "no " version to lines_to_add.
            elif (
                running_ctx_keys[0].startswith("ip route")
                or running_ctx_keys[0].startswith("ipv6 route")
                or running_ctx_keys[0].startswith("access-list")
                or running_ctx_keys[0].startswith("ipv6 access-list")
                or running_ctx_keys[0].startswith("ip prefix-list")
                or running_ctx_keys[0].startswith("ipv6 prefix-list")
            ):
                add_cmd = ("no " + running_ctx_keys[0],)
                lines_to_add.append((add_cmd, None))

            # if this an interface sub-subcontext in an address-family block in ldpd and
            # we are already deleting the whole context, then ignore this
            elif (
                len(running_ctx_keys) > 2
                and running_ctx_keys[0].startswith("mpls ldp")
                and running_ctx_keys[1].startswith("address-family")
                and (running_ctx_keys[:2], None) in lines_to_del
            ):
                continue

            # same thing for a pseudowire sub-context inside an l2vpn context
            elif (len(running_ctx_keys) > 1 and running_ctx_keys[0].startswith('l2vpn') and
                  running_ctx_keys[1].startswith('member pseudowire') and
                  (running_ctx_keys[:1], None) in lines_to_del):
                continue

            # Segment routing and traffic engineering never need to be deleted
            elif (
                len(running_ctx_keys) > 1
                and len(running_ctx_keys) < 3
                and running_ctx_keys[0].startswith('segment-routing')
            ):
                continue

            # Neither the pcep command
            elif (
                len(running_ctx_keys) == 3
                and running_ctx_keys[0].startswith('segment-routing')
                and running_ctx_keys[2].startswith('pcep4')
            ):
                continue

            # Segment lists can only be deleted after we removed all the candidate paths that
            # use them, so add them to a separate array that is going to be appended at the end
            elif (
                len(running_ctx_keys) == 3
                and running_ctx_keys[0].startswith('segment-routing')
                and running_ctx_keys[2].startswith('segment-list')
            ):
                seglist_to_del.append((running_ctx_keys, None))

            # Policies must be deleted after there candidate path, to be sure
            # we add them to a separate array that is going to be appended at the end
            elif (
                len(running_ctx_keys) == 3
                and running_ctx_keys[0].startswith('segment-routing')
                and running_ctx_keys[2].startswith('policy')
            ):
                pollist_to_del.append((running_ctx_keys, None))

            # Non-global context
            elif running_ctx_keys and not any(
                "address-family" in key for key in running_ctx_keys
            ):
                lines_to_del.append((running_ctx_keys, None))

            elif running_ctx_keys and not any("vni" in key for key in running_ctx_keys):
                lines_to_del.append((running_ctx_keys, None))

            # Global context
            else:
                for line in running_ctx.lines:
                    lines_to_del.append((running_ctx_keys, line))

    # if we have some policies commands to delete, append them to lines_to_del
    if len(pollist_to_del) > 0:
        lines_to_del.extend(pollist_to_del)

    # if we have some segment list commands to delete, append them to lines_to_del
    if len(seglist_to_del) > 0:
        lines_to_del.extend(seglist_to_del)

    # Find the lines within each context to add
    # Find the lines within each context to del
    for (newconf_ctx_keys, newconf_ctx) in iteritems(newconf.contexts):

        if newconf_ctx_keys in running.contexts:
            running_ctx = running.contexts[newconf_ctx_keys]

            for line in newconf_ctx.lines:
                if line not in running_ctx.dlines:

                    # candidate paths can only be added after the policy and segment list,
                    # so add them to a separate array that is going to be appended at the end
                    if (
                        len(newconf_ctx_keys) == 3
                        and newconf_ctx_keys[0].startswith('segment-routing')
                        and newconf_ctx_keys[2].startswith('policy ')
                        and line.startswith('candidate-path ')
                    ):
                        candidates_to_add.append((newconf_ctx_keys, line))

                    else:
                        lines_to_add.append((newconf_ctx_keys, line))

            for line in running_ctx.lines:
                if line not in newconf_ctx.dlines:
                    lines_to_del.append((newconf_ctx_keys, line))

    for (newconf_ctx_keys, newconf_ctx) in iteritems(newconf.contexts):

        if newconf_ctx_keys not in running.contexts:

            # candidate paths can only be added after the policy and segment list,
            # so add them to a separate array that is going to be appended at the end
            if (
                len(newconf_ctx_keys) == 4
                and newconf_ctx_keys[0].startswith('segment-routing')
                and newconf_ctx_keys[3].startswith('candidate-path')
            ):
                candidates_to_add.append((newconf_ctx_keys, None))
                for line in newconf_ctx.lines:
                    candidates_to_add.append((newconf_ctx_keys, line))

            else:
                lines_to_add.append((newconf_ctx_keys, None))

                for line in newconf_ctx.lines:
                    lines_to_add.append((newconf_ctx_keys, line))

    # if we have some candidate paths commands to add, append them to lines_to_add
    if len(candidates_to_add) > 0:
        lines_to_add.extend(candidates_to_add)

    (lines_to_add, lines_to_del) = check_for_exit_vrf(lines_to_add, lines_to_del)
    (lines_to_add, lines_to_del) = ignore_delete_re_add_lines(
        lines_to_add, lines_to_del
    )
    (lines_to_add, lines_to_del) = ignore_unconfigurable_lines(
        lines_to_add, lines_to_del
    )

    return (lines_to_add, lines_to_del)


if __name__ == "__main__":
    # Command line options
    parser = argparse.ArgumentParser(
        description="Dynamically apply diff in frr configs"
    )
    parser.add_argument(
        "--input", help='Read running config from file instead of "show running"'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--reload", action="store_true", help="Apply the deltas", default=False
    )
    group.add_argument(
        "--test", action="store_true", help="Show the deltas", default=False
    )
    level_group = parser.add_mutually_exclusive_group()
    level_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debugs (synonym for --log-level=debug)",
        default=False,
    )
    level_group.add_argument(
        "--log-level",
        help="Log level",
        default="info",
        choices=("critical", "error", "warning", "info", "debug"),
    )
    parser.add_argument(
        "--stdout", action="store_true", help="Log to STDOUT", default=False
    )
    parser.add_argument(
        "--pathspace",
        "-N",
        metavar="NAME",
        help="Reload specified path/namespace",
        default=None,
    )
    parser.add_argument("filename", help="Location of new frr config file")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite frr.conf with running config output",
        default=False,
    )
    parser.add_argument(
        "--bindir", help="path to the vtysh executable", default="/usr/bin"
    )
    parser.add_argument(
        "--confdir", help="path to the daemon config files", default="/etc/frr"
    )
    parser.add_argument(
        "--rundir", help="path for the temp config file", default="/var/run/frr"
    )
    parser.add_argument(
        "--vty_socket",
        help="socket to be used by vtysh to connect to the daemons",
        default=None,
    )
    parser.add_argument(
        "--daemon", help="daemon for which want to replace the config", default=""
    )

    args = parser.parse_args()

    # Logging
    # For --test log to stdout
    # For --reload log to /var/log/frr/frr-reload.log
    if args.test or args.stdout:
        logging.basicConfig(format="%(asctime)s %(levelname)5s: %(message)s")

        # Color the errors and warnings in red
        logging.addLevelName(
            logging.ERROR, "\033[91m  %s\033[0m" % logging.getLevelName(logging.ERROR)
        )
        logging.addLevelName(
            logging.WARNING, "\033[91m%s\033[0m" % logging.getLevelName(logging.WARNING)
        )

    elif args.reload:
        if not os.path.isdir("/var/log/frr/"):
            os.makedirs("/var/log/frr/")

        logging.basicConfig(
            filename="/var/log/frr/frr-reload.log",
            format="%(asctime)s %(levelname)5s: %(message)s",
        )

    # argparse should prevent this from happening but just to be safe...
    else:
        raise Exception("Must specify --reload or --test")
    log = logging.getLogger(__name__)

    if args.debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(args.log_level.upper())

    if args.reload and not args.stdout:
        # Additionally send errors and above to STDOUT, with no metadata,
        # when we are logging to a file. This specifically does not follow
        # args.log_level, and is analagous to behaviour in earlier versions
        # which additionally logged most errors using print().

        stdout_hdlr = logging.StreamHandler(sys.stdout)
        stdout_hdlr.setLevel(logging.ERROR)
        stdout_hdlr.setFormatter(logging.Formatter())
        log.addHandler(stdout_hdlr)

    # Verify the new config file is valid
    if not os.path.isfile(args.filename):
        log.error("Filename %s does not exist" % args.filename)
        sys.exit(1)

    if not os.path.getsize(args.filename):
        log.error("Filename %s is an empty file" % args.filename)
        sys.exit(1)

    # Verify that confdir is correct
    if not os.path.isdir(args.confdir):
        log.error("Confdir %s is not a valid path" % args.confdir)
        sys.exit(1)

    # Verify that bindir is correct
    if not os.path.isdir(args.bindir) or not os.path.isfile(args.bindir + "/vtysh"):
        log.error("Bindir %s is not a valid path to vtysh" % args.bindir)
        sys.exit(1)

    # verify that the vty_socket, if specified, is valid
    if args.vty_socket and not os.path.isdir(args.vty_socket):
        log.error("vty_socket %s is not a valid path" % args.vty_socket)
        sys.exit(1)

    # verify that the daemon, if specified, is valid
    if args.daemon and args.daemon not in [
        "zebra",
        "bgpd",
        "fabricd",
        "isisd",
        "ospf6d",
        "ospfd",
        "pbrd",
        "pimd",
        "ripd",
        "ripngd",
        "sharpd",
        "staticd",
        "vrrpd",
        "ldpd",
        "pathd",
    ]:
        msg = "Daemon %s is not a valid option for 'show running-config'" % args.daemon
        print(msg)
        log.error(msg)
        sys.exit(1)

    vtysh = Vtysh(args.bindir, args.confdir, args.vty_socket, args.pathspace)

    # Verify that 'service integrated-vtysh-config' is configured
    if args.pathspace:
        vtysh_filename = args.confdir + "/" + args.pathspace + "/vtysh.conf"
    else:
        vtysh_filename = args.confdir + "/vtysh.conf"
    service_integrated_vtysh_config = True

    if os.path.isfile(vtysh_filename):
        with open(vtysh_filename, "r") as fh:
            for line in fh.readlines():
                line = line.strip()

                if line == "no service integrated-vtysh-config":
                    service_integrated_vtysh_config = False
                    break

    if not service_integrated_vtysh_config and not args.daemon:
        log.error(
            "'service integrated-vtysh-config' is not configured, this is required for 'service frr reload'"
        )
        sys.exit(1)

    log.info('Called via "%s"', str(args))

    # Create a Config object from the config generated by newconf
    newconf = Config(vtysh)
    try:
        newconf.load_from_file(args.filename)
        reload_ok = True
    except VtyshException as ve:
        log.error("vtysh failed to process new configuration: {}".format(ve))
        reload_ok = False

    if args.test:

        # Create a Config object from the running config
        running = Config(vtysh)

        if args.input:
            running.load_from_file(args.input)
        else:
            running.load_from_show_running(args.daemon)



        (lines_to_add, lines_to_del) = compare_context_objects(newconf, running)
        lines_to_configure = []

        if lines_to_del:
            print("\nLines To Delete")
            print("===============")

            for (ctx_keys, line) in lines_to_del:

                if line == "!":
                    continue

                cmd = "\n".join(lines_to_config(ctx_keys, line, True))
                lines_to_configure.append(cmd)
                print(cmd)

        if lines_to_add:
            print("\nLines To Add")
            print("============")

            for (ctx_keys, line) in lines_to_add:

                if line == "!":
                    continue

                cmd = "\n".join(lines_to_config(ctx_keys, line, False))
                lines_to_configure.append(cmd)
                print(cmd)

    elif args.reload:

        # We will not be able to do anything, go ahead and exit(1)
        if not vtysh.is_config_available():
            sys.exit(1)

        log.debug("New Frr Config\n%s", newconf.get_lines())

        # This looks a little odd but we have to do this twice...here is why
        # If the user had this running bgp config:
        #
        # router bgp 10
        #  neighbor 1.1.1.1 remote-as 50
        #  neighbor 1.1.1.1 route-map FOO out
        #
        # and this config in the newconf config file
        #
        # router bgp 10
        #  neighbor 1.1.1.1 remote-as 999
        #  neighbor 1.1.1.1 route-map FOO out
        #
        #
        # Then the script will do
        # - no neighbor 1.1.1.1 remote-as 50
        # - neighbor 1.1.1.1 remote-as 999
        #
        # The problem is the "no neighbor 1.1.1.1 remote-as 50" will also remove
        # the "neighbor 1.1.1.1 route-map FOO out" line...so we compare the
        # configs again to put this line back.

        # There are many keywords in FRR that can only appear one time under
        # a context, take "bgp router-id" for example. If the config that we are
        # reloading against has the following:
        #
        # router bgp 10
        #   bgp router-id 1.1.1.1
        #   bgp router-id 2.2.2.2
        #
        # The final config needs to contain "bgp router-id 2.2.2.2". On the
        # first pass we will add "bgp router-id 2.2.2.2" but then on the second
        # pass we will see that "bgp router-id 1.1.1.1" is missing and add that
        # back which cancels out the "bgp router-id 2.2.2.2". The fix is for the
        # second pass to include all of the "adds" from the first pass.
        lines_to_add_first_pass = []

        for x in range(2):
            running = Config(vtysh)
            running.load_from_show_running(args.daemon)
            log.debug("Running Frr Config (Pass #%d)\n%s", x, running.get_lines())

            (lines_to_add, lines_to_del) = compare_context_objects(newconf, running)

            if x == 0:
                lines_to_add_first_pass = lines_to_add
            else:
                lines_to_add.extend(lines_to_add_first_pass)

            # Only do deletes on the first pass. The reason being if we
            # configure a bgp neighbor via "neighbor swp1 interface" FRR
            # will automatically add:
            #
            # interface swp1
            #  ipv6 nd ra-interval 10
            #  no ipv6 nd suppress-ra
            # !
            #
            # but those lines aren't in the config we are reloading against so
            # on the 2nd pass they will show up in lines_to_del.  This could
            # apply to other scenarios as well where configuring FOO adds BAR
            # to the config.
            if lines_to_del and x == 0:
                for (ctx_keys, line) in lines_to_del:

                    if line == "!":
                        continue

                    # 'no' commands are tricky, we can't just put them in a file and
                    # vtysh -f that file. See the next comment for an explanation
                    # of their quirks
                    cmd = lines_to_config(ctx_keys, line, True)
                    original_cmd = cmd

                    # Some commands in frr are picky about taking a "no" of the entire line.
                    # OSPF is bad about this, you can't "no" the entire line, you have to "no"
                    # only the beginning. If we hit one of these command an exception will be
                    # thrown.  Catch it and remove the last '-c', 'FOO' from cmd and try again.
                    #
                    # Example:
                    # frr(config-if)# ip ospf authentication message-digest 1.1.1.1
                    # frr(config-if)# no ip ospf authentication message-digest 1.1.1.1
                    #  % Unknown command.
                    # frr(config-if)# no ip ospf authentication message-digest
                    #  % Unknown command.
                    # frr(config-if)# no ip ospf authentication
                    # frr(config-if)#

                    while True:
                        try:
                            vtysh(["configure"] + cmd)

                        except VtyshException:

                            # - Pull the last entry from cmd (this would be
                            #   'no ip ospf authentication message-digest 1.1.1.1' in
                            #   our example above
                            # - Split that last entry by whitespace and drop the last word
                            log.info("Failed to execute %s", " ".join(cmd))
                            last_arg = cmd[-1].split(" ")

                            if len(last_arg) <= 2:
                                log.error(
                                    '"%s" we failed to remove this command',
                                    " -- ".join(original_cmd),
                                )
                                break

                            new_last_arg = last_arg[0:-1]
                            cmd[-1] = " ".join(new_last_arg)
                        else:
                            log.info('Executed "%s"', " ".join(cmd))
                            break

            if lines_to_add:
                lines_to_configure = []

                for (ctx_keys, line) in lines_to_add:

                    if line == "!":
                        continue

                    # Don't run "no" commands twice since they can error
                    # out the second time due to first deletion
                    if x == 1 and ctx_keys[0].startswith("no "):
                        continue

                    cmd = "\n".join(lines_to_config(ctx_keys, line, False)) + "\n"
                    lines_to_configure.append(cmd)

                if lines_to_configure:
                    random_string = "".join(
                        random.SystemRandom().choice(
                            string.ascii_uppercase + string.digits
                        )
                        for _ in range(6)
                    )

                    filename = args.rundir + "/reload-%s.txt" % random_string
                    log.info("%s content\n%s" % (filename, pformat(lines_to_configure)))

                    with open(filename, "w") as fh:
                        for line in lines_to_configure:
                            fh.write(line + "\n")

                    try:
                        vtysh.exec_file(filename)
                    except VtyshException as e:
                        log.warning("frr-reload.py failed due to\n%s" % e.args)
                        reload_ok = False
                    os.unlink(filename)

        # Make these changes persistent
        target = str(args.confdir + "/frr.conf")
        if args.overwrite or (not args.daemon and args.filename != target):
            vtysh("write")

    if not reload_ok:
        sys.exit(1)
