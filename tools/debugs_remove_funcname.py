#!/usr/bin/env python3
#
# edit FRR source code to remove __func__ from zlog_debug calls
# 2022 by David Lamparter, placed in public domain
#
# this is left here in case PRs/branches need to be fixed up.  note you need
# to run clang-format after this because the formatting will be borked

import sys
import os
import re

# some places have/had the line number too
funcname_line_re = re.compile(
    r"""
    (?P<pre>zlog_debug\s*\([\s\n]*")
    \s*%s[:, \t]*%d[:, \t]*
    (?P<post>.*")
    \s*,\s*__func__\s*,\s*__LINE__\s*
    """,
    re.X,
)

# and some places have/had the file name...
funcname_file_re = re.compile(
    r"""
    (?P<pre>zlog_debug\s*\([\s\n]*")
    \s*%s[:, \t]*%s[:, \t]*
    (?P<post>.*")
    \s*,\s*__FILE__\s*,\s*__func__\s*
    """,
    re.X,
)

# basic cases
funcname_re = re.compile(
    r"""
    (?P<pre>(z?log_debug|vnc_zlog_debug_verbose|vnc_zlog_debug_any|grpc_debug|zfpm_debug|ils_debug|ols_debug|(?:ospf|bgp)_orr_debug|bgp_cond_adv_debug|PCEP_DEBUG(_PATH)?|LOG_GR|PATH_TED_DEBUG)\s*\([\s\n]*")
    :?\s*(%s|\(%s\)|\[%s\])[:, \t]*
    (?P<post>.*")
    \s*,\s*(__func__|__PRETTY_FUNCTION__)\s*
    """,
    re.X,
)

# string prefix before function name, e.g. "SR: %s: ..."
funcname_hdr_re = re.compile(
    r"""
    (?P<pre>(z?log_debug|osr_debug|o?te_debug)\s*\([\s\n]*")
    (?P<hdr>EXT|\[BGP_GR\]|MPLS-TE|ISIS-TE|RI|SR|API|LSA\[Refresh\]|\[(?:OSPF|BGP)-ORR\]):?\s*(%s?|\(%s\)|\[%s\])
    (?P<post>.*")
    \s*,\s*(__func__|__PRETTY_FUNCTION__)\s*
    """,
    re.X,
)

# DEBUGD has an extra arg before the format string
funcname_debugd_re = re.compile(
    r"""
    (?P<pre>DEBUGD\s*\([^(),"]*,\s*")
    :?\s*(%s|\(%s\)|\[%s\])[:, \t]*
    (?P<post>.*")
    \s*,\s*(__func__|__PRETTY_FUNCTION__)\s*
    """,
    re.X,
)

for filename in sys.argv[1:]:
    with open(filename, "r") as fd:
        orig_text = text = fd.read()

    text = funcname_line_re.sub(r"\g<pre>\g<post>", text)
    text = funcname_file_re.sub(r"\g<pre>\g<post>", text)
    text = funcname_re.sub(r"\g<pre>\g<post>", text)
    text = funcname_hdr_re.sub(r"\g<pre>\g<hdr>\g<post>", text)
    text = funcname_debugd_re.sub(r"\g<pre>\g<post>", text)

    if text == orig_text:
        continue

    with open(filename + ".tmp", "w") as fd:
        fd.write(text)
    os.rename(filename + ".tmp", filename)
