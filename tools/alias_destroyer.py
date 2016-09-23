#!/usr/bin/env python

import re
import sys
import os
from pprint import pformat, pprint


class DEFUN(object):

    def __init__(self, lines):
        # name, name_cmd, command_string, help_strings, guts):
        self.name = None
        self.name_cmd = None
        self.command_string = None
        self.help_strings = []
        self.guts = []
        self.aliases = []

        '''
DEFUN (no_bgp_maxmed_onstartup,
       no_bgp_maxmed_onstartup_cmd,
       "no bgp max-med on-startup",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n")

        '''
        state = 'HEADER'
        for (line_number, line) in enumerate(lines):

            if state == 'HEADER':
                if line_number == 0:
                    re_name = re.search('DEFUN \((.*),', line.strip())
                    self.name = re_name.group(1)

                elif line_number == 1:
                    self.name_cmd = line.strip()[0:-1] # chop the trailing comma

                elif line_number == 2:
                    self.command_string = line
                    state = 'HELP'

            elif state == 'HELP':
                if line.strip() == '{':
                    self.guts.append(line)
                    state = 'BODY'
                else:
                    self.help_strings.append(line)

            elif state == 'BODY':
                if line.rstrip() == '}':
                    self.guts.append(line)
                    state = None
                else:
                    self.guts.append(line)

            else:
                raise Exception("invalid state %s" % state)

            # print "%d %7s: %s" % (line_number, state, line.rstrip())

        assert self.command_string, "No command string for\n%s" % pformat(lines)

    def __str__(self):
        return self.name

    def dump(self):
        lines = []

        if self.aliases:
            lines.append("/*\n")
            lines.append(" * CHECK ME - The following ALIASes need to be implemented in this DEFUN\n")

            for alias in self.aliases:
                lines.append(" * %s\n" % alias.command_string.strip())
                for line in alias.help_strings:
                    lines.append(" *     %s\n" % line)
                lines.append(" *\n")

            lines.append(" */\n")

        lines.append("DEFUN (%s,\n" % self.name)
        lines.append("       %s,\n" % self.name_cmd)
        lines.append(self.command_string)
        lines.extend(self.help_strings)
        lines.extend(self.guts)
        return ''.join(lines)


class ALIAS(object):

    def __init__(self, lines):
        self.name = None
        self.name_cmd = None
        self.command_string = None
        self.help_strings = []

        '''
ALIAS (no_bgp_maxmed_onstartup,
       no_bgp_maxmed_onstartup_period_cmd,
       "no bgp max-med on-startup <5-86400>",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n")
        '''
        state = 'HEADER'
        for (line_number, line) in enumerate(lines):

            if state == 'HEADER':
                if line_number == 0:
                    re_name = re.search('ALIAS \((.*),', line)

                    try:
                        self.name = re_name.group(1)
                    except AttributeError:
                        pprint(lines)
                        raise

                elif line_number == 1:
                    self.name_cmd = line.strip()[0:-1] # chop the trailing comma

                elif line_number == 2:
                    self.command_string = line
                    state = 'HELP'

            elif state == 'HELP':
                if line.strip() == '{':
                    raise Exception("should not see { in an ALIAS")
                else:
                    line = line.strip()
                    if line.endswith(')'):
                        line = line[0:-1] # strip the trailing )
                    self.help_strings.append(line)

            else:
                raise Exception("invalid state %s" % state)

        assert self.command_string, "No command string for\n%s" % pformat(lines)

    def __str__(self):
        return self.name_cmd


def alias_destroy(filename):
    lines = []
    defuns = {}
    aliases = {}

    with open(filename,  'r') as fh:
        state = None
        defun_lines = []
        alias_lines = []

        for (line_number, line) in enumerate(fh.readlines()):

            if state is None:
                if line.startswith('DEFUN ('):
                    assert line.count(',') == 1, "%d: Too many commas in\n%s" % (line_number, line)
                    defun_lines.append(line)
                    state = 'DEFUN_HEADER'

                elif line.startswith('ALIAS ('):
                    assert line.count(',') == 1, "%d: Too many commas in\n%s" % (line_number, line)
                    alias_lines.append(line)
                    state = 'ALIAS_HEADER'

            elif state == 'DEFUN_HEADER':
                defun_lines.append(line)

                if line.startswith('DEFUN'):
                    raise Exception("ERROR on line %d, found DEFUN inside DEFUN" % line_number)

                elif line.startswith('ALIAS'):
                    raise Exception("ERROR on line %d, found ALIAS inside DEFUN" % line_number)

                elif line.strip() == '{':
                    state = 'DEFUN_BODY'

            elif state == 'ALIAS_HEADER':
                alias_lines.append(line)

                if line.startswith('ALIAS'):
                    raise Exception("ERROR on line %d, found ALIAS inside ALIAS" % line_number)

                elif line.startswith('DEFUN'):
                    raise Exception("ERROR on line %d, found DEFUN inside ALIAS" % line_number)

                if line.rstrip().endswith(')'):
                    new_alias = ALIAS(alias_lines)
                    aliases[new_alias.name_cmd] = new_alias
                    state = None
                    alias_lines = []

            elif state == 'DEFUN_BODY':
                defun_lines.append(line)

                if line.rstrip() == '}':
                    new_defun = DEFUN(defun_lines)
                    defuns[new_defun.name] = new_defun
                    state = None
                    defun_lines = []

            # uncomment to debug state machine
            print "%5d %12s: %s" % (line_number, state, line.rstrip())

            lines.append(line)


    # At this point we know all of the aliases and all of the tokens
    # Assign each ALIAS to its parent DEFUN
    for alias in aliases.itervalues():
        defun = defuns.get(alias.name)
        assert defun, "Could not find DEFUN for %s" % alias
        defun.aliases.append(alias)

    # Now write the file but:
    # - do not write any ALIASes
    # - do not write the install_element for any ALIASes
    # - when you write the DEFUN include a comment that contains the ALIAS command strings it needs to cover
    with open(filename, 'w') as fh:
        state = None

        for line in lines:

            if state is None:
                if line.startswith('DEFUN ('):
                    state = 'DEFUN_HEADER'
                    re_name = re.search('DEFUN \((.*),', line.strip())
                    name = re_name.group(1)
                    defun = defuns.get(name)
                    fh.write(defun.dump())

                elif line.startswith('ALIAS ('):
                    state = 'ALIAS_HEADER'

                else:
                    if 'install_element' in line:
                        # install_element (CONFIG_NODE, &ip_community_list_name_standard_cmd);
                        re_install_element = re.search('install_element\s*\(\w+,\s*&(.*)\s*\)', line.strip())

                        if re_install_element:
                            cmd = re_install_element.group(1)
                            if cmd not in aliases:
                                fh.write(line)
                        else:
                            fh.write(line)
                    else:
                        fh.write(line)

            elif state == 'DEFUN_HEADER':
                if line.strip() == '{':
                    state = 'DEFUN_BODY'

            elif state == 'ALIAS_HEADER':
                if line.rstrip().endswith(')'):
                    state = None

            elif state == 'DEFUN_BODY':
                if line.rstrip() == '}':
                    state = None


if __name__ == '__main__':

    filename = sys.argv[1]
    if os.path.exists(filename):
        alias_destroy(filename)
    else:
        print "ERROR: could not find file %s" % filename
