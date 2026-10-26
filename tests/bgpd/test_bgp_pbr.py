# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpPbr(frrtest.TestMultiOut):
    program = "./test_bgp_pbr"


TestBgpPbr.okfail("TCP source and destination port ranges")
TestBgpPbr.okfail("ICMP type and code")
TestBgpPbr.okfail("UDP packet length range")
TestBgpPbr.okfail("DSCP and flow label are both shown")
TestBgpPbr.okfail("negated packet length value")
TestBgpPbr.okfail("ports are not shown for a protocol other than TCP, UDP or ICMP")
TestBgpPbr.okfail("NULL filter logs nothing")
TestBgpPbr.okfail("63-character match text fits")
TestBgpPbr.okfail("64-character match text is not truncated")
TestBgpPbr.okfail("64-character match text followed by DSCP")
TestBgpPbr.okfail("65-character match text followed by DSCP")
TestBgpPbr.okfail("every field at its maximum gives the longest match text")
TestBgpPbr.okfail("default route source prefix /0")
TestBgpPbr.okfail("host source prefix /32")
TestBgpPbr.okfail("TCP flags set the protocol to TCP")
TestBgpPbr.okfail("port range with max 0 shows min twice")
TestBgpPbr.okfail("removal with a source prefix and no match fields")
TestBgpPbr.okfail("IPv6 source prefix")
