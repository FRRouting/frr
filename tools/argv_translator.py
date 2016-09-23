#!/usr/bin/env python

import re
import sys
import os
from pprint import pformat


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
                 '.LINE', # where is this defined?
                 'LINE',
                 'BANDWIDTH',
                 'RMAP_NAME',
                 'ROUTEMAP_NAME',
                 'IPV6ADDR',
                 'IF_OR_ADDR',
                 'INTERFACE',
                 'PERCENTAGE',
                 'IFNAME',
                 'NAME',
                 'BITPATTERN',
                 'PATH',
                 'A.B.C.D',
                 'A.B.C.D/M',
                 'X:X::X:X',
                 'X:X::X:X/M',
                 'ASN:nn_or_IP-address:nn'): # where is this defined?
        return True

    if token.upper() == token:
        return True

    re_number_range = re.search('^<\d+-\d+>$', token)
    if re_number_range:
        return True

    return False


    tokens = []


def line_to_tokens(text):
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

            token_text.append(char)

    if token_text:
        tokens.append(''.join(token_text))

    return tokens


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
            print "%s is a token" % token
            table[old_style_index] = token_index
            old_style_index += 1
        else:
            print "%s is NOT a token" % token
            pass

    return table


def update_argvs(filename):
    lines = []

    with open(filename,  'r') as fh:
        state = None
        defun_line_number = None
        cmd_string = None
        argv_translator = {}
        print_translator = False

        for (line_number, line) in enumerate(fh.readlines()):
            new_line = line

            if state is None:
                if line.startswith('DEFUN ('):
                    assert line.count(',') == 1, "%d: Too many commas in\n%s" % (line_number, line)
                    state = 'DEFUN_HEADER'
                    defun_line_number = line_number

            elif state == 'DEFUN_HEADER':
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

                    argv_translator = get_argv_translator(line_number, line)
                    print_translator = True

            elif state == 'DEFUN_BODY':
                if line.rstrip() == '}':
                    state = None
                    defun_line_number = None
                    cmd_string = None
                    argv_translator = {}

                elif 'argv[' in new_line and '->arg' not in new_line:
                    for index in reversed(argv_translator.keys()):
                        old_argv = "argv[%d]" % index
                        new_argv = "argv[%d]->arg" % argv_translator[index]
                        new_line = new_line.replace(old_argv, new_argv)

            # uncomment to debug state machine
            print "%5d %12s: %s" % (line_number, state, new_line.rstrip())
            if print_translator:
                print "%s\n" % pformat(argv_translator)
                print_translator = False

            lines.append(new_line)

    with open(filename, 'w') as fh:
        for line in lines:
            fh.write(line)


if __name__ == '__main__':

    filename = sys.argv[1]
    if os.path.exists(filename):
        update_argvs(filename)
    else:
        print "ERROR: could not find file %s" % filename
