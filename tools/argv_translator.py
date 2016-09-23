#!/usr/bin/env python

import re
import sys
import os
import subprocess
from collections import OrderedDict
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

    if token.startswith('<'):
        assert token.endswith('>'), "%d: token %s should end with >" % (line_number, token)
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

def get_command_string_variable_indexes(line_number, line):
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


def get_token_index_variable_name(line_number, token):

    re_range = re.search('\(\d+-\d+\)', token)

    if token.startswith('['):
        assert token.endswith(']'), "Token %s should end with ]" % token
        token = token[1:-1]

    if token.startswith('<'):
        assert token.endswith('>'), "Token %s should end with >" % token
        token = token[1:-1]

    if token == 'A.B.C.D':
        return 'idx_ipv4'

    elif token == 'A.B.C.D/M':
        return 'idx_ipv4_prefixlen'

    elif token == 'X:X::X:X':
        return 'idx_ipv6'

    elif token == 'X:X::X:X/M':
        return 'idx_ipv6_prefixlen'

    elif token == 'ASN:nn_or_IP-address:nn':
        return 'idx_ext_community'

    elif token == '.AA:NN':
        return 'idx_community'

    elif token == 'WORD':
        return 'idx_word'

    elif token == 'json':
        return 'idx_json'

    elif token == '.LINE':
        return 'idx_regex'

    elif token == 'A.B.C.D|INTERFACE':
        return 'idx_ipv4_ifname'

    elif token == 'A.B.C.D|INTERFACE|null0':
        return 'idx_ipv4_ifname_null'

    elif token == 'X:X::X:X|INTERFACE':
        return 'idx_ipv6_ifname'

    elif token == 'reject|blackhole':
        return 'idx_reject_blackhole'

    elif token == 'route-map NAME':
        return 'idx_route_map'

    elif token == 'recv|send|detail':
        return 'idx_recv_send'

    elif token == 'recv|send':
        return 'idx_recv_send'

    elif token == 'up|down':
        return 'idx_up_down'

    elif token == 'off-link':
        return 'idx_off_link'

    elif token == 'no-autoconfig':
        return 'idx_no_autoconfig'

    elif token == 'router-address':
        return 'idx_router_address'

    elif token == 'high|medium|low':
        return 'idx_high_medium_low'

    elif token == '(0-4294967295)|infinite':
        return 'idx_number_infinite'

    elif token == '(1-199)|(1300-2699)|WORD':
        return 'idx_acl'

    elif token == 'A.B.C.D|X:X::X:X':
        return 'idx_ip'

    elif token == 'in|out':
        return 'idx_in_out'

    elif token == 'deny|permit':
        return 'idx_permit_deny'

    elif token == 'view|vrf':
        return 'idx_view_vrf'

    elif token == 'unicast|multicast':
        return 'idx_safi'

    elif token == 'bestpath|multipath':
        return 'idx_bestpath'

    elif token == 'egp|igp|incomplete':
        return 'idx_origin'

    elif token == 'cisco|zebra':
        return 'idx_vendor'

    elif token == 'as-set|no-as-set':
        return 'idx_as_set'

    elif token == 'confed|missing-as-worst':
        return 'idx_med_knob'

    elif token == 'both|send|receive' or token == 'send|recv':
        return 'idx_send_recv'

    elif token == 'both|extended|standard':
        return 'idx_type'

    elif token == 'A.B.C.D|WORD':
        return 'idx_ipv4_word'

    elif token == 'advertise-queue|advertised-routes|packet-queue':
        return 'idx_type'

    elif token == 'ospf|table':
        return 'idx_ospf_table'

    elif token == 'as-path|next-hop|med' or token == 'next-hop|med' or token == 'as-path|med' or token == 'as-path|next-hop':
        return 'idx_attribute'

    elif token == '(1-4294967295)|external|internal' or token == '(1-4294967295)|internal|external':
        return 'idx_remote_as'

    elif token == '(1-500)|WORD' or token == '(1-99)|(100-500)|WORD':
        return 'idx_comm_list'

    elif token == 'ipv4|ipv6' or token == 'ip|ipv6':
        return 'idx_afi'

    elif token == 'md5|clear':
        return 'idx_encryption'

    elif token == 'type-1|type-2':
        return 'idx_external'

    elif token == 'table|intra-area|inter-area|memory':
        return 'idx_type'

    elif token == 'unknown|hello|dbdesc|lsreq|lsupdate|lsack|all':
        return 'idx_packet'

    elif token == 'router|network|inter-prefix|inter-router|as-external|link|intra-prefix|unknown' or token == 'intra-area|inter-area|external-1|external-2' or token == 'router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix':
        return 'idx_lsa'

    elif token == 'broadcast|point-to-point':
        return 'idx_network'

    elif token == 'A.B.C.D|(0-4294967295)':
        return 'idx_ipv4_number'

    elif token == 'narrow|transition|wide':
        return 'idx_metric_style'

    elif token == 'area-password|domain-password':
        return 'idx_password'

    elif token == 'param':
        return 'idx_param'

    elif token == 'advertised-routes|received-routes':
        return 'idx_adv_rcvd_routes'

    elif token == 'encap|multicast|unicast|vpn' or token == 'unicast|multicast|vpn|encap':
        return 'idx_safi'

    elif token == 'AA:NN|local-AS|no-advertise|no-export':
        return 'idx_community'

    elif token == 'all|all-et|updates|updates-et|routes-mrt':
        return 'idx_dump_routes'

    elif token == 'A.B.C.D|X:X::X:X|WORD':
        return 'idx_peer'

    elif token == 'A.B.C.D/M|X:X::X:X/M':
        return 'idx_ipv4_ipv6_prefixlen'

    elif token == 'level-1|level-2' or token == 'level-1|level-1-2|level-2-only':
        return 'idx_level'

    elif token == 'metric (0-16777215)|route-map WORD' or token == 'always|metric (0-16777215)|route-map WORD':
        return 'idx_metric_rmap'

    elif token == 'urib-only|mrib-only|mrib-then-urib|lower-distance|longer-prefix':
        return 'idx_rpf_lookup_mode'

    elif token in ('kernel|connected|static|rip|ospf|isis|pim|table',
                   'kernel|connected|static|ripng|ospf6|isis|table',
                   'kernel|connected|static|rip|isis|bgp|pim|table',
                   'kernel|connected|static|rip|ospf|isis|bgp|pim|table',
                   'kernel|connected|static|rip|ospf|isis|bgp|pim|table',
                   'kernel|connected|static|rip|ospf|isis|bgp|pim|table|any',
                   'kernel|connected|static|ripng|ospf6|isis|bgp|table|any',
                   'kernel|connected|static|ripng|ospf6|isis|bgp|table',
                   'kernel|connected|static|ospf6|isis|bgp|table',
                   'kernel|connected|static|ospf|isis|bgp|pim|table',
                   'kernel|connected|static|ripng|isis|bgp|table',
                   # '',
                   'bgp|ospf|rip|ripng|isis|ospf6|connected|system|kernel|static',
                   'kernel|connected|static|rip|ripng|ospf|ospf6|bgp|pim|table'):
        return 'idx_protocol'

    elif '|' in token:
        raise Exception("%d: what variable name for %s" % (line_number, token))

    elif re_range:
        return 'idx_number'

    elif token.upper() == token:
        return 'idx_%s' % token.lower()

    else:
        raise Exception("%d: what variable name for %s" % (line_number, token))


def get_command_string_index_variable_table(line_number, line):
    """
    Return a table that maps an index position to a variable name such as 'idx_ipv4'
    """
    indexes = OrderedDict()

    line = line.strip()
    assert line.startswith('"'), "line does not start with \"\n%s" % (line)
    assert line.endswith('",'), "line does not end with \",\n%s" % (line)
    line = line[1:-2]
    max_index = 0

    for (token_index, token) in enumerate(line_to_tokens(line_number, line)):
        if not token:
            raise Exception("%d: empty token" % line_number)

        if token_is_variable(line_number, token):
            # print "%s is a token" % token
            idx_variable_name = get_token_index_variable_name(line_number, token)
            count = 0
            for tmp in indexes.itervalues():
                if tmp == idx_variable_name:
                    count += 1
                elif re.search('^%s_\d+' % idx_variable_name, tmp):
                    count += 1
            if count:
                idx_variable_name = "%s_%d" % (idx_variable_name, count + 1)
            indexes[token_index] = idx_variable_name

    return indexes

def expand_command_string(line):

    # in the middle
    line = line.replace('" CMD_AS_RANGE "', '(1-4294967295)')
    line = line.replace('" DYNAMIC_NEIGHBOR_LIMIT_RANGE "', '(1-5000)')
    line = line.replace('" BGP_INSTANCE_CMD "', '<view|vrf> WORD')
    line = line.replace('" BGP_INSTANCE_ALL_CMD "', '<view|vrf> all')
    line = line.replace('" CMD_RANGE_STR(1, MULTIPATH_NUM) "', '(1-255)')
    line = line.replace('" QUAGGA_IP_REDIST_STR_BGPD "', '<kernel|connected|static|rip|ospf|isis|pim|table>')
    line = line.replace('" QUAGGA_IP6_REDIST_STR_BGPD "', '<kernel|connected|static|ripng|ospf6|isis|table>')
    line = line.replace('" OSPF_LSA_TYPES_CMD_STR "', 'asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as')
    line = line.replace('" QUAGGA_REDIST_STR_OSPFD "', '<kernel|connected|static|rip|isis|bgp|pim|table>')
    line = line.replace('" VRF_CMD_STR "', 'vrf NAME')
    line = line.replace('" VRF_ALL_CMD_STR "', 'vrf all')
    line = line.replace('" QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA "', '<kernel|connected|static|rip|ospf|isis|bgp|pim|table|any>')
    line = line.replace('" QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA "', '<kernel|connected|static|ripng|ospf6|isis|bgp|table|any>')
    line = line.replace('" QUAGGA_REDIST_STR_RIPNGD "', '<kernel|connected|static|ospf6|isis|bgp|table>')
    line = line.replace('" QUAGGA_REDIST_STR_RIPD "', '<kernel|connected|static|ospf|isis|bgp|pim|table>')
    line = line.replace('" QUAGGA_REDIST_STR_OSPF6D "', '<kernel|connected|static|ripng|isis|bgp|table>')
    line = line.replace('" QUAGGA_REDIST_STR_ISISD "', '<kernel|connected|static|rip|ripng|ospf|ospf6|bgp|pim|table>')
    line = line.replace('" LOG_FACILITIES "', '<kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>')

    # endswith
    line = line.replace('" CMD_AS_RANGE,', ' (1-4294967295)",')
    line = line.replace('" DYNAMIC_NEIGHBOR_LIMIT_RANGE,', ' (1-5000)",')
    line = line.replace('" BGP_INSTANCE_CMD,', ' <view|vrf> WORD",')
    line = line.replace('" BGP_INSTANCE_ALL_CMD,', ' <view|vrf> all",')
    line = line.replace('" CMD_RANGE_STR(1, MULTIPATH_NUM),', '(1-255)",')
    line = line.replace('" CMD_RANGE_STR(1, MAXTTL),', '(1-255)",')
    line = line.replace('" BFD_CMD_DETECT_MULT_RANGE BFD_CMD_MIN_RX_RANGE BFD_CMD_MIN_TX_RANGE,', '(2-255) (50-60000) (50-60000)",')
    line = line.replace('" OSPF_LSA_TYPES_CMD_STR,',
                        ' asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as",')
    line = line.replace('" BGP_UPDATE_SOURCE_REQ_STR,', ' <A.B.C.D|X:X::X:X|WORD>",')
    line = line.replace('" BGP_UPDATE_SOURCE_OPT_STR,', ' [A.B.C.D|X:X::X:X|WORD]",')
    line = line.replace('" QUAGGA_IP_REDIST_STR_BGPD,', ' <kernel|connected|static|rip|ospf|isis|pim|table>",')
    line = line.replace('" QUAGGA_IP6_REDIST_STR_BGPD,', ' <kernel|connected|static|ripng|ospf6|isis|table>",')
    line = line.replace('" QUAGGA_REDIST_STR_OSPFD,', ' <kernel|connected|static|rip|isis|bgp|pim|table>",')
    line = line.replace('" VRF_CMD_STR,', ' vrf NAME",')
    line = line.replace('" VRF_ALL_CMD_STR,', ' vrf all",')
    line = line.replace('" QUAGGA_IP_REDIST_STR_ZEBRA,', ' <kernel|connected|static|rip|ospf|isis|bgp|pim|table>",')
    line = line.replace('" QUAGGA_IP6_REDIST_STR_ZEBRA,', ' <kernel|connected|static|ripng|ospf6|isis|bgp|table>",')
    line = line.replace('" QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA,', ' <kernel|connected|static|rip|ospf|isis|bgp|pim|table|any>",')
    line = line.replace('" QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA,', ' <kernel|connected|static|ripng|ospf6|isis|bgp|table|any>",')
    line = line.replace('" QUAGGA_REDIST_STR_RIPNGD,', ' <kernel|connected|static|ospf6|isis|bgp|table>",')
    line = line.replace('" QUAGGA_REDIST_STR_RIPD,', ' <kernel|connected|static|ospf|isis|bgp|pim|table>",')
    line = line.replace('" PIM_CMD_IP_MULTICAST_ROUTING,', ' ip multicast-routing",')
    line = line.replace('" PIM_CMD_IP_IGMP_QUERY_INTERVAL,', ' ip igmp query-interval",')
    line = line.replace('" PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC,', ' ip igmp query-max-response-time-dsec",')
    line = line.replace('" PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME,', ' ip igmp query-max-response-time",')
    line = line.replace('" QUAGGA_REDIST_STR_OSPF6D,', ' <kernel|connected|static|ripng|isis|bgp|table>",')
    line = line.replace('" QUAGGA_REDIST_STR_ISISD,', ' <kernel|connected|static|rip|ripng|ospf|ospf6|bgp|pim|table>",')
    line = line.replace('" LOG_FACILITIES,', ' <kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>",')

    # startswith
    line = line.replace('LISTEN_RANGE_CMD "', '"bgp listen range <A.B.C.D/M|X:X::X:X/M> ')
    line = line.replace('NO_NEIGHBOR_CMD2 "', '"no neighbor <A.B.C.D|X:X::X:X|WORD> ')
    line = line.replace('NEIGHBOR_CMD2 "', '"neighbor <A.B.C.D|X:X::X:X|WORD> ')
    line = line.replace('NO_NEIGHBOR_CMD "', '"no neighbor <A.B.C.D|X:X::X:X> ')
    line = line.replace('NEIGHBOR_CMD "', '"neighbor <A.B.C.D|X:X::X:X> ')
    line = line.replace('PIM_CMD_NO "', '"no ')
    line = line.replace('PIM_CMD_IP_IGMP_QUERY_INTERVAL "', '"ip igmp query-interval ')
    line = line.replace('PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME "', '"ip igmp query-max-response-time ')
    line = line.replace('PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC "', '"ip igmp query-max-response-time-dsec ')

    # solo
    line = line.replace('NO_NEIGHBOR_CMD2,', '"no neighbor <A.B.C.D|X:X::X:X|WORD>",')
    line = line.replace('NEIGHBOR_CMD2,', '"neighbor <A.B.C.D|X:X::X:X|WORD>",')
    line = line.replace('NO_NEIGHBOR_CMD,', '"no neighbor <A.B.C.D|X:X::X:X>",')
    line = line.replace('NEIGHBOR_CMD,', '"neighbor <A.B.C.D|X:X::X:X>",')
    line = line.replace('PIM_CMD_IP_MULTICAST_ROUTING,', '"ip multicast-routing",')

    if line.rstrip().endswith('" ,'):
        line = line.replace('" ,', '",')

    return line


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
                    # self.guts.append(line)
                    state = 'BODY'
                else:
                    self.help_strings.append(line)

            elif state == 'BODY':
                if line.rstrip() == '}':
                    # self.guts.append(line)
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
        (max_index, variable_indexes) = get_command_string_variable_indexes(self.line_number, self.command_string_expanded)

        # sanity check that each argv index matches a variable in the command string
        for line in self.guts:
            if 'argv[' in line and '->arg' in line:
                tmp_line = deepcopy(line)
                re_argv = re.search('^.*?argv\[(\d+)\]->arg(.*)$', tmp_line)

                while re_argv:
                    index = int(re_argv.group(1))
                    if index not in variable_indexes and index <= max_index:
                        print "%d: index %s is not a variable in the command string" % (self.line_number, index)
                    tmp_line = re_argv.group(2)
                    re_argv = re.search('^.*?argv\[(\d+)\]->arg(.*)$', tmp_line)

    def get_new_command_string(self):
        line = self.command_string
        # Change <1-255> to (1-255)
        # Change (foo|bar) to <foo|bar>
        # Change {wazzup} to [wazzup]....there shouldn't be many of these

        line = line.replace('(', '<')
        line = line.replace(')', '>')
        line = line.replace('{', '[')
        line = line.replace('}', ']')
        re_range = re.search('^(.*?)<(\d+-\d+)>(.*)$', line)

        # A one off to handle "CMD_RANGE_STR(1, MULTIPATH_NUM)"
        if 'CMD_RANGE_STR<' in line:
            line = line.replace('CMD_RANGE_STR<', 'CMD_RANGE_STR(')
            line = line.replace('>', ')')

        while re_range:
            line = "%s(%s)%s" % (re_range.group(1), re_range.group(2), re_range.group(3))
            re_range = re.search('^(.*?)<(\d+-\d+)>(.*)$', line)

        if not line.endswith('\n'):
            line += '\n'

        # compress duplicate whitespaces
        re_space = re.search('^(\s*).*(\s*)$', line)
        line = re_space.group(1) + ' '.join(line.split()) + re_space.group(2)
        return line

    def get_used_idx_variables(self, idx_table):
        used = {}

        # sanity check that each argv index matches a variable in the command string
        for line in self.guts:
            if 'argv[' in line and '->arg' in line:
                tmp_line = deepcopy(line)
                re_argv = re.search('^.*?argv\[(\w+)\]->arg(.*)$', tmp_line)

                while re_argv:
                    index = re_argv.group(1)

                    if index.isdigit():
                        index = int(index)
                        if index in idx_table:
                            used[index] = idx_table[index]
                        else:
                            print "%d: could not find idx variable for %d" % (self.line_number, index)
                    else:
                        for (key, value) in idx_table.iteritems():
                            if value == index:
                                used[key] = value
                                break

                    tmp_line = re_argv.group(2)
                    re_argv = re.search('^.*?argv\[(\w+)\]->arg(.*)$', tmp_line)

        return used

    def dump(self):
        new_command_string = self.get_new_command_string()
        new_command_string_expanded = expand_command_string(new_command_string)
        lines = []
        lines.append("DEFUN (%s,\n" % self.name)
        lines.append("       %s,\n" % self.name_cmd)
        lines.append(new_command_string)
        lines.extend(self.help_strings)
        lines.append('{\n')

        # only print the variables that will be used else we get a compile error
        idx_table = get_command_string_index_variable_table(self.line_number, new_command_string_expanded)
        idx_table_used = self.get_used_idx_variables(idx_table)

        for index in sorted(idx_table_used.keys()):
            idx_variable = idx_table_used[index]
            lines.append("  int %s = %d;\n" % (idx_variable, index))

        # sanity check that each argv index matches a variable in the command string
        for line in self.guts:
            if line.startswith('  int idx_'):
                pass
            elif 'argv[' in line and '->arg' in line:
                for (index, idx_variable) in idx_table.iteritems():
                    line = line.replace("argv[%d]->arg" % index, "argv[%s]->arg" % idx_variable)
                lines.append(line)
            else:
                lines.append(line)

        lines.append('}\n')
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
                    line = expand_command_string(line)
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
