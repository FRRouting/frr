#!/usr/bin/env python

import re
import sys
import os
import subprocess
from copy import deepcopy
from pprint import pformat, pprint


def token_is_variable(line_number, token):

    if token.isdigit():
        return True

    if token.startswith('('):
        assert token.endswith(')'), "%d: token %s should end with )" % (line_number, token)
        return True

    if token.startswith('['):
        assert token.endswith(']'), "%d: token %s should end with ]" % (line_number, token)
        return True

    if token.startswith('{'):
        # I don't really care about checking for this I just put
        # these asserts in here to bug sharpd
        assert token.endswith('}'), "%d: token %s should end with }" % (line_number, token)
        return True

    assert '|' not in token, "%d: Weird token %s has a | but does not start with [ or (" % (line_number, token)

    if token in ('WORD',
                 '.LINE',
                 '.AA:NN',
                 'A.B.C.D',
                 'A.B.C.D/M',
                 'X:X::X:X',
                 'X:X::X:X/M',
                 'ASN:nn_or_IP-address:nn'):
        return True

    # Anything in all caps in a variable
    if token.upper() == token:
        return True

    re_number_range = re.search('^<\d+-\d+>$', token)
    if re_number_range:
        return True

    return False


def line_to_tokens(line_number, text):
    """
    Most of the time whitespace can be used to split tokens
        (set|clear) <interface> clagd-enable (no|yes)

    tokens
    - (set|clear)
    - <interface>
    - clagd-enable
    - (no|yes)

    But if we are dealing with multiword keywords, such as "soft in", that approach
    does not work. We can only split on whitespaces if we are not inside a () or []
        bgp (<ipv4>|<ipv6>|<interface>|*) [soft in|soft out]

    tokens:
    - bgp
    - (<ipv4>|<ipv6>|<interface>|*)
    - [soft in|soft out]
    """
    tokens = []
    token_index = 0
    token_text = []
    parens = 0
    curlys = 0
    brackets = 0
    less_greater = 0

    for char in text:
        if char == ' ':
            if parens == 0 and brackets == 0 and curlys == 0 and less_greater == 0:
                if token_text:
                    tokens.append(''.join(token_text))
                token_index += 1
                token_text = []
            else:
                token_text.append(char)
        else:
            if char == '(':
                parens += 1

            elif char == ')':
                parens -= 1

            elif char == '[':
                brackets += 1

            elif char == ']':
                brackets -= 1

            elif char == '{':
                curlys += 1

            elif char == '}':
                curlys -= 1

            elif char == '<':
                less_greater += 1

            elif char == '>':
                less_greater -= 1

            if char:
                token_text.append(char)

    if token_text:
        tokens.append(''.join(token_text))

    return tokens


'''
# No longer used now that all indexes have been updated
def get_argv_translator(line_number, line):
    table = {}
    line = line.strip()
    assert line.startswith('"'), "%d: line does not start with \"\n%s" % (line_number, line)
    assert line.endswith('",'), "%d: line does not end with \",\n%s" % (line_number, line)

    line = line[1:-2]

    funky_chars = ('+', '"')
    for char in funky_chars:
        if char in line:
            raise Exception("%d: Add support for tokens in\n%s\n\nsee BGP_INSTANCE_CMD down below" % (line_number, line))

    old_style_index = 0
    for (token_index, token) in enumerate(line_to_tokens(line)):
        if not token:
            continue

        if token_is_variable(line_number, token):
            # print "%s is a token" % token
            table[old_style_index] = token_index
            old_style_index += 1
        else:
            # print "%s is NOT a token" % token
            pass

    return table
'''

def get_argv_variable_indexes(line_number, line):
    indexes = {}

    line = line.strip()
    assert line.startswith('"'), "%d: line does not start with \"\n%s" % (line_number, line)
    assert line.endswith('",'), "%d: line does not end with \",\n%s" % (line_number, line)
    line = line[1:-2]
    max_index = 0

    for (token_index, token) in enumerate(line_to_tokens(line_number, line)):
        if not token:
            raise Exception("%d: empty token" % line_number)

        if token_is_variable(line_number, token):
            # print "%s is a token" % token
            indexes[token_index] = True
            max_index = token_index

    return (max_index, indexes)


class DEFUN(object):

    def __init__(self, line_number, command_string_expanded, lines):
        # name, name_cmd, command_string, help_strings, guts):
        self.line_number = line_number
        self.name = None
        self.name_cmd = None
        self.command_string = None
        self.command_string_expanded = command_string_expanded
        self.help_strings = []
        self.guts = []

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

    def sanity_check(self):
        (max_index, variable_indexes) = get_argv_variable_indexes(self.line_number, self.command_string_expanded)

        # sanity check that each argv index matches a variable in the command string
        for line in self.guts:
            if 'argv[' in line and '->arg' in line:
                tmp_line = deepcopy(line)
                re_argv = re.search('^.*?argv\[(\d+)\]->arg(.*)$', tmp_line)

                while re_argv:
                    index = int(re_argv.group(1))
                    if index not in variable_indexes and index <= max_index:
                        raise Exception("%d: index %s is not a variable in the command string" % (self.line_number, index))
                    tmp_line = re_argv.group(2)
                    re_argv = re.search('^.*?argv\[(\d+)\]->arg(.*)$', tmp_line)

    def get_new_command_string(self):
        line = self.command_string
        # dwalton
        # Change <1-255> to (1-255)
        # Change (foo|bar) to <foo|bar>
        # Change {wazzup} to [wazzup]....there shouldn't be many of these

        line = line.replace('(', '<')
        line = line.replace(')', '>')
        line = line.replace('{', '[')
        line = line.replace('}', ']')
        re_range = re.search('^(.*?)<(\d+-\d+)>(.*)$', line)

        while re_range:
            line = "%s(%s)%s" % (re_range.group(1), re_range.group(2), re_range.group(3))
            re_range = re.search('^(.*?)<(\d+-\d+)>(.*)$', line)

        if not line.endswith('\n'):
            line += '\n'

        return line

    def dump(self):
        lines = []
        lines.append("DEFUN (%s,\n" % self.name)
        lines.append("       %s,\n" % self.name_cmd)
        lines.append(self.get_new_command_string())
        lines.extend(self.help_strings)
        lines.extend(self.guts)
        return ''.join(lines)




def update_argvs(filename):
    lines = []

    with open(filename,  'r') as fh:
        state = None
        defun_line_number = None
        cmd_string = None
        # argv_translator = {}
        # print_translator = False
        variable_indexes = {}
        max_index = 0
        defun_lines = []
        defuns = {}
        command_string = None

        for (line_number, line) in enumerate(fh.readlines()):
            # new_line = line

            if state is None:
                if line.startswith('DEFUN ('):
                    assert line.count(',') == 1, "%d: Too many commas in\n%s" % (line_number, line)
                    state = 'DEFUN_HEADER'
                    defun_line_number = line_number
                    defun_lines.append(line)

            elif state == 'DEFUN_HEADER':
                defun_lines.append(line)

                if line.startswith('DEFUN'):
                    raise Exception("ERROR on line %d, found DEFUN inside DEFUN" % line_number)

                elif line.startswith('ALIAS'):
                    raise Exception("ERROR on line %d, found ALIAS inside DEFUN" % line_number)

                elif line.strip() == '{':
                    state = 'DEFUN_BODY'

                elif line_number == defun_line_number + 2:

                    # in the middle
                    line = line.replace('" CMD_AS_RANGE "', '<1-4294967295>')
                    line = line.replace('" DYNAMIC_NEIGHBOR_LIMIT_RANGE "', '<1-5000>')
                    line = line.replace('" BGP_INSTANCE_CMD "', '(view|vrf) WORD')
                    line = line.replace('" BGP_INSTANCE_ALL_CMD "', '(view|vrf) all')
                    line = line.replace('" CMD_RANGE_STR(1, MULTIPATH_NUM) "', '<1-255>')
                    line = line.replace('" QUAGGA_IP_REDIST_STR_BGPD "', '(kernel|connected|static|rip|ospf|isis|pim|table)')
                    line = line.replace('" QUAGGA_IP6_REDIST_STR_BGPD "', '(kernel|connected|static|ripng|ospf6|isis|table)')
                    line = line.replace('" OSPF_LSA_TYPES_CMD_STR "', 'asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as')
                    line = line.replace('" QUAGGA_REDIST_STR_OSPFD "', '(kernel|connected|static|rip|isis|bgp|pim|table)')
                    line = line.replace('" VRF_CMD_STR "', 'vrf NAME')
                    line = line.replace('" VRF_ALL_CMD_STR "', 'vrf all')
                    line = line.replace('" QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA "', '(kernel|connected|static|rip|ospf|isis|bgp|pim|table|any)')
                    line = line.replace('" QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA "', '(kernel|connected|static|ripng|ospf6|isis|bgp|table|any)')
                    line = line.replace('" QUAGGA_REDIST_STR_RIPNGD "', '(kernel|connected|static|ospf6|isis|bgp|table)')
                    line = line.replace('" QUAGGA_REDIST_STR_RIPD "', '(kernel|connected|static|ospf|isis|bgp|pim|table)')
                    line = line.replace('" QUAGGA_REDIST_STR_OSPF6D "', '(kernel|connected|static|ripng|isis|bgp|table)')
                    line = line.replace('" QUAGGA_REDIST_STR_ISISD "', '(kernel|connected|static|rip|ripng|ospf|ospf6|bgp|pim|table)')

                    # endswith
                    line = line.replace('" CMD_AS_RANGE,', ' <1-4294967295>",')
                    line = line.replace('" DYNAMIC_NEIGHBOR_LIMIT_RANGE,', ' <1-5000>",')
                    line = line.replace('" BGP_INSTANCE_CMD,', ' (view|vrf) WORD",')
                    line = line.replace('" BGP_INSTANCE_ALL_CMD,', ' (view|vrf) all",')
                    line = line.replace('" CMD_RANGE_STR(1, MULTIPATH_NUM),', '<1-255>",')
                    line = line.replace('" CMD_RANGE_STR(1, MAXTTL),', '<1-255>",')
                    line = line.replace('" BFD_CMD_DETECT_MULT_RANGE BFD_CMD_MIN_RX_RANGE BFD_CMD_MIN_TX_RANGE,', '<2-255> <50-60000> <50-60000>",')
                    line = line.replace('" OSPF_LSA_TYPES_CMD_STR,',
                                        ' asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as",')
                    line = line.replace('" BGP_UPDATE_SOURCE_REQ_STR,', ' (A.B.C.D|X:X::X:X|WORD)",')
                    line = line.replace('" BGP_UPDATE_SOURCE_OPT_STR,', ' {A.B.C.D|X:X::X:X|WORD}",')
                    line = line.replace('" QUAGGA_IP_REDIST_STR_BGPD,', ' (kernel|connected|static|rip|ospf|isis|pim|table)",')
                    line = line.replace('" QUAGGA_IP6_REDIST_STR_BGPD,', ' (kernel|connected|static|ripng|ospf6|isis|table)",')
                    line = line.replace('" QUAGGA_REDIST_STR_OSPFD,', ' (kernel|connected|static|rip|isis|bgp|pim|table)",')
                    line = line.replace('" VRF_CMD_STR,', ' vrf NAME",')
                    line = line.replace('" VRF_ALL_CMD_STR,', ' vrf all",')
                    line = line.replace('" QUAGGA_IP_REDIST_STR_ZEBRA,', ' (kernel|connected|static|rip|ospf|isis|bgp|pim|table)",')
                    line = line.replace('" QUAGGA_IP6_REDIST_STR_ZEBRA,', ' (kernel|connected|static|ripng|ospf6|isis|bgp|table)",')
                    line = line.replace('" QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA,', ' (kernel|connected|static|rip|ospf|isis|bgp|pim|table|any)",')
                    line = line.replace('" QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA,', ' (kernel|connected|static|ripng|ospf6|isis|bgp|table|any)",')
                    line = line.replace('" QUAGGA_REDIST_STR_RIPNGD,', ' (kernel|connected|static|ospf6|isis|bgp|table)",')
                    line = line.replace('" QUAGGA_REDIST_STR_RIPD,', ' (kernel|connected|static|ospf|isis|bgp|pim|table)",')
                    line = line.replace('" PIM_CMD_IP_MULTICAST_ROUTING,', ' ip multicast-routing",')
                    line = line.replace('" PIM_CMD_IP_IGMP_QUERY_INTERVAL,', ' ip igmp query-interval",')
                    line = line.replace('" PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC,', ' ip igmp query-max-response-time-dsec",')
                    line = line.replace('" PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME,', ' ip igmp query-max-response-time",')
                    line = line.replace('" QUAGGA_REDIST_STR_OSPF6D,', ' (kernel|connected|static|ripng|isis|bgp|table)",')
                    line = line.replace('" QUAGGA_REDIST_STR_ISISD,', ' (kernel|connected|static|rip|ripng|ospf|ospf6|bgp|pim|table)",')

                    # startswith
                    line = line.replace('LISTEN_RANGE_CMD "', '"bgp listen range (A.B.C.D/M|X:X::X:X/M) ')
                    line = line.replace('NO_NEIGHBOR_CMD2 "', '"no neighbor (A.B.C.D|X:X::X:X|WORD) ')
                    line = line.replace('NEIGHBOR_CMD2 "', '"neighbor (A.B.C.D|X:X::X:X|WORD) ')
                    line = line.replace('NO_NEIGHBOR_CMD "', '"no neighbor (A.B.C.D|X:X::X:X) ')
                    line = line.replace('NEIGHBOR_CMD "', '"neighbor (A.B.C.D|X:X::X:X) ')
                    line = line.replace('PIM_CMD_NO "', '"no ')
                    line = line.replace('PIM_CMD_IP_IGMP_QUERY_INTERVAL "', '"ip igmp query-interval ')
                    line = line.replace('PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME "', '"ip igmp query-max-response-time ')
                    line = line.replace('PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC "', '"ip igmp query-max-response-time-dsec ')

                    # solo
                    line = line.replace('NO_NEIGHBOR_CMD2,', '"no neighbor (A.B.C.D|X:X::X:X|WORD)",')
                    line = line.replace('NEIGHBOR_CMD2,', '"neighbor (A.B.C.D|X:X::X:X|WORD)",')
                    line = line.replace('NO_NEIGHBOR_CMD,', '"no neighbor (A.B.C.D|X:X::X:X)",')
                    line = line.replace('NEIGHBOR_CMD,', '"neighbor (A.B.C.D|X:X::X:X)",')
                    line = line.replace('PIM_CMD_IP_MULTICAST_ROUTING,', '"ip multicast-routing",')

                    if line.rstrip().endswith('" ,'):
                        line = line.replace('" ,', '",')
                    command_string = line

                    '''
                    # No longer used now that all indexes have been updated
                    argv_translator = get_argv_translator(line_number, line)
                    print_translator = True
                    '''

            elif state == 'DEFUN_BODY':
                defun_lines.append(line)

                if line.rstrip() == '}':
                    new_defun = DEFUN(defun_line_number, command_string, defun_lines)
                    defuns[new_defun.name] = new_defun
                    state = None
                    command_string = None
                    defun_lines = []

                    # cmd_string = None
                    # defun_line_number = None
                    # argv_translator = {}

                    '''
                # No longer used now that all indexes have been updated
                elif 'argv[' in new_line and '->arg' not in new_line:
                    for index in reversed(argv_translator.keys()):
                        old_argv = "argv[%d]" % index
                        new_argv = "argv[%d]->arg" % argv_translator[index]
                        new_line = new_line.replace(old_argv, new_argv)
                    '''

            # uncomment to debug state machine
            # print "%5d %12s: %s" % (line_number, state, line.rstrip())

            '''
            # No longer used now that all indexes have been updated
            if print_translator:
                print "%s\n" % pformat(argv_translator)
                print_translator = False
            '''

            lines.append(line)


    for defun in defuns.itervalues():
        defun.sanity_check()


    # Now write the file but allow the DEFUN object to update the contents of the DEFUN ()
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
                else:
                    fh.write(line)

            elif state == 'DEFUN_HEADER':
                if line.strip() == '{':
                    state = 'DEFUN_BODY'

            elif state == 'DEFUN_BODY':
                if line.rstrip() == '}':
                    state = None



if __name__ == '__main__':

    if len(sys.argv) == 2:
        filename = sys.argv[1]
        update_argvs(filename)

    else:
        output = subprocess.check_output("grep -l DEFUN *.c", shell=True).splitlines()
        for filename in output:
            filename = filename.strip()
            print "crunching %s" % filename
            update_argvs(filename)
