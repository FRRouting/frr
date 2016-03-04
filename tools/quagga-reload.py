#!/usr/bin/python

"""
This program
- reads a quagga configuration text file
- reads quagga's current running configuration via "vtysh -c 'show running'"
- compares the two configs and determines what commands to execute to
  synchronize quagga's running configuration with the configuation in the
  text file
"""

import argparse
import copy
import logging
import os
import random
import string
import subprocess
import sys
from collections import OrderedDict
from ipaddr import IPv6Address
from pprint import pformat


class Context(object):

    """
    A Context object represents a section of quagga configuration such as:
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


class Config(object):

    """
    A quagga configuration is stored in a Config object. A Config object
    contains a dictionary of Context objects where the Context keys
    ('router ospf' for example) are our dictionary key.
    """

    def __init__(self):
        self.lines = []
        self.contexts = OrderedDict()

    def load_from_file(self, filename):
        """
        Read configuration from specified file and slurp it into internal memory
        The internal representation has been marked appropriately by passing it
        through vtysh with the -m parameter
        """
        logger.info('Loading Config object from file %s', filename)

        try:
            file_output = subprocess.check_output(['/usr/bin/vtysh', '-m', '-f', filename])
        except subprocess.CalledProcessError as e:
            logger.error('vtysh marking of config file %s failed with error %s:', filename, str(e))
            print "vtysh marking of file %s failed with error: %s" % (filename, str(e))
            sys.exit(1)

        for line in file_output.split('\n'):
            line = line.strip()
            if ":" in line:
                qv6_line = get_normalized_ipv6_line(line)
                self.lines.append(qv6_line)
            else:
                self.lines.append(line)

        self.load_contexts()

    def load_from_show_running(self):
        """
        Read running configuration and slurp it into internal memory
        The internal representation has been marked appropriately by passing it
        through vtysh with the -m parameter
        """
        logger.info('Loading Config object from vtysh show running')

        try:
            config_text = subprocess.check_output(
                "/usr/bin/vtysh -c 'show run' | /usr/bin/tail -n +4 | /usr/bin/vtysh -m -f -",
                shell=True)
        except subprocess.CalledProcessError as e:
            logger.error('vtysh marking of running config failed with error %s:', str(e))
            print "vtysh marking of running config failed with error %s:" % (str(e))
            sys.exit(1)

        for line in config_text.split('\n'):
            line = line.strip()

            if (line == 'Building configuration...' or
                line == 'Current configuration:' or
                    not line):
                continue

            self.lines.append(line)

        self.load_contexts()

    def get_lines(self):
        """
        Return the lines read in from the configuration
        """

        return '\n'.join(self.lines)

    def get_contexts(self):
        """
        Return the parsed context as strings for display, log etc.
        """

        for (_, ctx) in sorted(self.contexts.iteritems()):
            print str(ctx) + '\n'

    def save_contexts(self, key, lines):
        """
        Save the provided key and lines as a context
        """

        if not key:
            return

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

        '''
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
router ospf
 ospf router-id 10.0.0.1
 log-adjacency-changes detail
 timers throttle spf 0 50 5000
!
end
        '''

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
        oneline_ctx_keywords = ("access-list ",
                                "bgp ",
                                "debug ",
                                "dump ",
                                "enable ",
                                "hostname ",
                                "ip ",
                                "ipv6 ",
                                "log ",
                                "password ",
                                "ptm-enable",
                                "router-id ",
                                "service ",
                                "table ",
                                "username ",
                                "zebra ")

        for line in self.lines:

            if not line:
                continue

            if line.startswith('!') or line.startswith('#'):
                continue

            # one line contexts
            if new_ctx is True and any(line.startswith(keyword) for keyword in oneline_ctx_keywords):
                self.save_contexts(ctx_keys, current_context_lines)

                # Start a new context
                main_ctx_key = []
                ctx_keys = [line, ]
                current_context_lines = []

                logger.debug('LINE %-50s: entering new context, %-50s', line, ctx_keys)
                self.save_contexts(ctx_keys, current_context_lines)
                new_ctx = True

            elif line == "end":
                self.save_contexts(ctx_keys, current_context_lines)
                logger.debug('LINE %-50s: exiting old context, %-50s', line, ctx_keys)

                # Start a new context
                new_ctx = True
                main_ctx_key = []
                ctx_keys = []
                current_context_lines = []

            elif line == "exit-address-family" or line == "exit":
                # if this exit is for address-family ipv4 unicast, ignore the pop
                if main_ctx_key:
                    self.save_contexts(ctx_keys, current_context_lines)

                    # Start a new context
                    ctx_keys = copy.deepcopy(main_ctx_key)
                    current_context_lines = []
                    logger.debug('LINE %-50s: popping from subcontext to ctx%-50s', line, ctx_keys)

            elif new_ctx is True:
                if not main_ctx_key:
                    ctx_keys = [line, ]
                else:
                    ctx_keys = copy.deepcopy(main_ctx_key)
                    main_ctx_key = []

                current_context_lines = []
                new_ctx = False
                logger.debug('LINE %-50s: entering new context, %-50s', line, ctx_keys)

            elif "address-family " in line:
                main_ctx_key = []

                # Save old context first
                self.save_contexts(ctx_keys, current_context_lines)
                current_context_lines = []
                main_ctx_key = copy.deepcopy(ctx_keys)
                logger.debug('LINE %-50s: entering sub-context, append to ctx_keys', line)

                if line == "address-family ipv6":
                    ctx_keys.append("address-family ipv6 unicast")
                elif line == "address-family ipv4":
                    ctx_keys.append("address-family ipv4 unicast")
                else:
                    ctx_keys.append(line)

            else:
                # Continuing in an existing context, add non-commented lines to it
                current_context_lines.append(line)
                logger.debug('LINE %-50s: append to current_context_lines, %-50s', line, ctx_keys)

        # Save the context of the last one
        self.save_contexts(ctx_keys, current_context_lines)


def line_to_vtysh_conft(ctx_keys, line, delete):
    """
    Return the vtysh command for the specified context line
    """

    cmd = []
    cmd.append('vtysh')
    cmd.append('-c')
    cmd.append('conf t')

    if line:
        for ctx_key in ctx_keys:
            cmd.append('-c')
            cmd.append(ctx_key)

        line = line.lstrip()

        if delete:
            cmd.append('-c')

            if line.startswith('no '):
                cmd.append('%s' % line[3:])
            else:
                cmd.append('no %s' % line)

        else:
            cmd.append('-c')
            cmd.append(line)

    # If line is None then we are typically deleting an entire
    # context ('no router ospf' for example)
    else:

        if delete:

            # Only put the 'no' on the last sub-context
            for ctx_key in ctx_keys:
                cmd.append('-c')

                if ctx_key == ctx_keys[-1]:
                    cmd.append('no %s' % ctx_key)
                else:
                    cmd.append('%s' % ctx_key)
        else:
            for ctx_key in ctx_keys:
                cmd.append('-c')
                cmd.append(ctx_key)

    return cmd


def line_for_vtysh_file(ctx_keys, line, delete):
    """
    Return the command as it would appear in Quagga.conf
    """
    cmd = []

    if line:
        for (i, ctx_key) in enumerate(ctx_keys):
            cmd.append(' ' * i + ctx_key)

        line = line.lstrip()
        indent = len(ctx_keys) * ' '

        if delete:
            if line.startswith('no '):
                cmd.append('%s%s' % (indent, line[3:]))
            else:
                cmd.append('%sno %s' % (indent, line))

        else:
            cmd.append(indent + line)

    # If line is None then we are typically deleting an entire
    # context ('no router ospf' for example)
    else:
        if delete:

            # Only put the 'no' on the last sub-context
            for ctx_key in ctx_keys:

                if ctx_key == ctx_keys[-1]:
                    cmd.append('no %s' % ctx_key)
                else:
                    cmd.append('%s' % ctx_key)
        else:
            for ctx_key in ctx_keys:
                cmd.append(ctx_key)

    return '\n' + '\n'.join(cmd)


def get_normalized_ipv6_line(line):
    """
    Return a normalized IPv6 line as produced by quagga,
    with all letters in lower case and trailing and leading
    zeros removed
    """
    norm_line = ""
    words = line.split(' ')
    for word in words:
        if ":" in word:
            try:
                norm_word = str(IPv6Address(word)).lower()
            except:
                norm_word = word
        else:
            norm_word = word
        norm_line = norm_line + " " + norm_word

    return norm_line.strip()


def compare_context_objects(newconf, running):
    """
    Create a context diff for the two specified contexts
    """

    # Compare the two Config objects to find the lines that we need to add/del
    lines_to_add = []
    lines_to_del = []
    restart_bgpd = False

    # Find contexts that are in newconf but not in running
    # Find contexts that are in running but not in newconf
    for (running_ctx_keys, running_ctx) in running.contexts.iteritems():

        if running_ctx_keys not in newconf.contexts:

            # Check if bgp's local ASN has changed. If yes, just restart it
            if "router bgp" in running_ctx_keys[0]:
                restart_bgpd = True
                continue

            # Non-global context
            if running_ctx_keys and not any("address-family" in key for key in running_ctx_keys):
                lines_to_del.append((running_ctx_keys, None))

            # Global context
            else:
                for line in running_ctx.lines:
                    lines_to_del.append((running_ctx_keys, line))

    # Find the lines within each context to add
    # Find the lines within each context to del
    for (newconf_ctx_keys, newconf_ctx) in newconf.contexts.iteritems():

        if newconf_ctx_keys in running.contexts:
            running_ctx = running.contexts[newconf_ctx_keys]

            for line in newconf_ctx.lines:
                if line not in running_ctx.dlines:
                    lines_to_add.append((newconf_ctx_keys, line))

            for line in running_ctx.lines:
                if line not in newconf_ctx.dlines:
                    lines_to_del.append((newconf_ctx_keys, line))

    for (newconf_ctx_keys, newconf_ctx) in newconf.contexts.iteritems():

        if newconf_ctx_keys not in running.contexts:

            # If its "router bgp" and we're restarting bgp, skip doing
            # anything specific for bgp
            if "router bgp" in newconf_ctx_keys[0] and restart_bgpd:
                continue
            lines_to_add.append((newconf_ctx_keys, None))

            for line in newconf_ctx.lines:
                lines_to_add.append((newconf_ctx_keys, line))

    return (lines_to_add, lines_to_del, restart_bgpd)

if __name__ == '__main__':
    # Command line options
    parser = argparse.ArgumentParser(description='Dynamically apply diff in quagga configs')
    parser.add_argument('--input', help='Read running config from file instead of "show running"')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--reload', action='store_true', help='Apply the deltas', default=False)
    group.add_argument('--test', action='store_true', help='Show the deltas', default=False)
    parser.add_argument('--debug', action='store_true', help='Enable debugs', default=False)
    parser.add_argument('filename', help='Location of new quagga config file')
    args = parser.parse_args()

    # Logging
    # For --test log to stdout
    # For --reload log to /var/log/quagga/quagga-reload.log
    if args.test:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)5s: %(message)s')
    elif args.reload:
        if not os.path.isdir('/var/log/quagga/'):
            os.makedirs('/var/log/quagga/')

        logging.basicConfig(filename='/var/log/quagga/quagga-reload.log',
                            level=logging.INFO,
                            format='%(asctime)s %(levelname)5s: %(message)s')

    # argparse should prevent this from happening but just to be safe...
    else:
        raise Exception('Must specify --reload or --test')
    logger = logging.getLogger(__name__)

    # Verify the new config file is valid
    if not os.path.isfile(args.filename):
        print "Filename %s does not exist" % args.filename
        sys.exit(1)

    if not os.path.getsize(args.filename):
        print "Filename %s is an empty file" % args.filename
        sys.exit(1)

    # Verify that 'service integrated-vtysh-config' is configured
    vtysh_filename = '/etc/quagga/vtysh.conf'
    service_integrated_vtysh_config = False

    if os.path.isfile(vtysh_filename):
        with open(vtysh_filename, 'r') as fh:
            for line in fh.readlines():
                line = line.strip()

                if line == 'service integrated-vtysh-config':
                    service_integrated_vtysh_config = True
                    break

    if not service_integrated_vtysh_config:
        print "'service integrated-vtysh-config' is not configured, this is required for 'service quagga reload'"
        sys.exit(1)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.info('Called via "%s"', str(args))

    # Create a Config object from the config generated by newconf
    newconf = Config()
    newconf.load_from_file(args.filename)

    if args.test:

        # Create a Config object from the running config
        running = Config()

        if args.input:
            running.load_from_file(args.input)
        else:
            running.load_from_show_running()

        (lines_to_add, lines_to_del, restart_bgp) = compare_context_objects(newconf, running)
        lines_to_configure = []

        if lines_to_del:
            print "\nLines To Delete"
            print "==============="

            for (ctx_keys, line) in lines_to_del:

                if line == '!':
                    continue

                cmd = line_for_vtysh_file(ctx_keys, line, True)
                lines_to_configure.append(cmd)

        if lines_to_add:
            print "\nLines To Add"
            print "============"

            for (ctx_keys, line) in lines_to_add:

                if line == '!':
                    continue

                cmd = line_for_vtysh_file(ctx_keys, line, False)
                lines_to_configure.append(cmd)

        if lines_to_configure:
            print '\n'.join(lines_to_configure)

        if restart_bgp:
            print "BGP local AS changed, bgpd would restart"

    elif args.reload:

        logger.debug('New Quagga Config\n%s', newconf.get_lines())

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

        for x in range(2):
            running = Config()
            running.load_from_show_running()
            logger.debug('Running Quagga Config (Pass #%d)\n%s', x, running.get_lines())

            (lines_to_add, lines_to_del, restart_bgp) = compare_context_objects(newconf, running)

            if lines_to_del:
                for (ctx_keys, line) in lines_to_del:

                    if line == '!':
                        continue

                    # 'no' commands are tricky, we can't just put them in a file and
                    # vtysh -f that file. See the next comment for an explanation
                    # of their quirks
                    cmd = line_to_vtysh_conft(ctx_keys, line, True)
                    original_cmd = cmd

                    # Some commands in quagga are picky about taking a "no" of the entire line.
                    # OSPF is bad about this, you can't "no" the entire line, you have to "no"
                    # only the beginning. If we hit one of these command an exception will be
                    # thrown.  Catch it and remove the last '-c', 'FOO' from cmd and try again.
                    #
                    # Example:
                    # quagga(config-if)# ip ospf authentication message-digest 1.1.1.1
                    # quagga(config-if)# no ip ospf authentication message-digest 1.1.1.1
                    #  % Unknown command.
                    # quagga(config-if)# no ip ospf authentication message-digest
                    #  % Unknown command.
                    # quagga(config-if)# no ip ospf authentication
                    # quagga(config-if)#

                    while True:
                        try:
                            _ = subprocess.check_output(cmd)

                        except subprocess.CalledProcessError:

                            # - Pull the last entry from cmd (this would be
                            #   'no ip ospf authentication message-digest 1.1.1.1' in
                            #   our example above
                            # - Split that last entry by whitespace and drop the last word
                            logger.warning('Failed to execute %s', ' '.join(cmd))
                            last_arg = cmd[-1].split(' ')

                            if len(last_arg) <= 2:
                                logger.error('"%s" we failed to remove this command', original_cmd)
                                break

                            new_last_arg = last_arg[0:-1]
                            cmd[-1] = ' '.join(new_last_arg)
                        else:
                            logger.info('Executed "%s"', ' '.join(cmd))
                            break

            if lines_to_add:
                lines_to_configure = []

                for (ctx_keys, line) in lines_to_add:

                    if line == '!':
                        continue

                    cmd = line_for_vtysh_file(ctx_keys, line, False)
                    lines_to_configure.append(cmd)

                if lines_to_configure:
                    random_string = ''.join(random.SystemRandom().choice(
                                            string.ascii_uppercase +
                                            string.digits) for _ in range(6))

                    filename = "/var/run/quagga/reload-%s.txt" % random_string
                    logger.info("%s content\n%s" % (filename, pformat(lines_to_configure)))

                    with open(filename, 'w') as fh:
                        for line in lines_to_configure:
                            fh.write(line + '\n')
                    subprocess.call(['/usr/bin/vtysh', '-f', filename])
                    os.unlink(filename)

            if restart_bgp:
                subprocess.call(['sudo', 'systemctl', 'restart', 'bgpd'])
