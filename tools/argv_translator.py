#!/usr/bin/env python

import re
import sys
import os
from pprint import pformat


def token_is_variable(token):

    if token.isdigit():
        return True

    if token.startswith('('):
        assert token.endswith(')'), "token %s should end with )" % token
        return True

    if token.startswith('['):
        assert token.endswith(']'), "token %s should end with ]" % token
        return True

    if token.startswith('{'):
        # I don't really care about checking for this I just put
        # these asserts in here to bug sharpd
        assert token.endswith('}'), "token %s should end with }" % token
        return True

    assert '|' not in token, "Weird token %s has a | but does not start with [ or (" % token

    if token in ('WORD',
                 '.LINE', # where is this defined?
                 'A.B.C.D',
                 'A.B.C.D/M',
                 'X:X::X:X',
                 'X:X::X:X/M',
                 'ASN:nn_or_IP-address:nn'): # where is this defined?
        return True

    re_number_range = re.search('^<\d+-\d+>$', token)
    if re_number_range:
        return True

    return False


def get_argv_translator(line):
    table = {}
    line = line.strip()
    assert line.startswith('"'), "line does not start with \"\n%s" % line
    assert line.endswith('",'), "line does not end with \",\n%s" % line

    line = line[1:-2]

    funky_chars = ('+', '"')
    for char in funky_chars:
        if char in line:
            raise Exception("Add support for tokens in\n%s\n\nsee BGP_INSTANCE_CMD down below" % line)

    old_style_index = 0
    for (token_index, token) in enumerate(line.split()):
        if token_is_variable(token):
            # print "%s is a token" % token
            table[old_style_index] = token_index
            old_style_index += 1
        else:
            # print "%s is NOT a token" % token
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

                    # bgpd/bgp_vty.h
                    line = line.replace('" CMD_AS_RANGE "', '<1-4294967295>')
                    line = line.replace('" DYNAMIC_NEIGHBOR_LIMIT_RANGE "', '<1-5000>')
                    line = line.replace('" BGP_INSTANCE_CMD "', '(view|vrf) WORD')
                    line = line.replace('" BGP_INSTANCE_ALL_CMD "', '(view|vrf) all')
                    argv_translator = get_argv_translator(line)
                    print_translator = True

            elif state == 'DEFUN_BODY':
                if line.rstrip() == '}':
                    state = None
                    defun_line_number = None
                    cmd_string = None
                    argv_translator = {}

                elif 'argv[' in new_line:
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
