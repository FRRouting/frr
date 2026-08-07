# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""Session-reset cases for the RFC 7606 conformance suite.

RFC 7606 section 7.11 keeps "session reset" for a malformed MP_REACH_NLRI:

    "If the Length of Next Hop Network Address field of the MP_REACH_NLRI
     attribute is inconsistent with that which was expected, the attribute is
     considered malformed.  Since the next hop precedes the NLRI field in the
     attribute, in this case it will not be possible to reliably locate the
     NLRI; thus, the 'session reset' or 'AFI/SAFI disable' approach MUST be
     used."

Every case here therefore ends its own BGP session, which is why this
directory uses a single eBGP peer driven one case per ExaBGP lifetime rather
than the three concurrent peers the other two directories use: section 7.11
does not vary by peer sort, and three peers would mean three interleaved
session flaps.

The NOTIFICATION each case must produce is recorded here as well, so a change
in how bgpd classifies the error shows up as a test failure rather than as a
silently different reset.
"""

from bgp_rfc7606 import SESSION_RESET, Case, number_variants

# NOTIFICATION error code, RFC 4271 section 4.5.
UPDATE_ERR = 3

# UPDATE Message Error subcodes, RFC 4271 section 6.3.
MAL_ATTR_LIST = 1
ATTR_LENG_ERR = 5
OPT_ATTR_ERR = 9

CASES = number_variants([
    # Next-hop length 9 is not one of the lengths RFC 4760 / RFC 8950 define
    # for AFI 2 (4, 12, 16, 24, 32, 48), so bgp_mp_reach_parse() cannot know
    # where the NLRI starts.
    Case("mp-reach-nexthop-len-bogus", 14, 0x80,
         "000201" "09" "20010db80000000000" "00" "4020010db800000001",
         outcome=SESSION_RESET, spec="RFC 7606 section 7.11"),
    # Next-hop length 64 with only 17 octets left in the attribute.
    Case("mp-reach-nexthop-len-overrun", 14, 0x80,
         "000201" "40" "20010db8000000000000000000000001" "00",
         outcome=SESSION_RESET, spec="RFC 7606 section 7.11"),
    # Next-hop length 16 with only 8 octets of next hop, and no reserved
    # octet or NLRI at all.
    Case("mp-reach-truncated", 14, 0x80,
         "000201" "10" "20010db800000000",
         outcome=SESSION_RESET, spec="RFC 7606 section 7.11"),
    # MP_UNREACH whose withdrawn-routes field claims a /64 but carries only
    # four octets of prefix.
    Case("mp-unreach-truncated", 15, 0x80,
         "000201" "40" "20010db8",
         outcome=SESSION_RESET, spec="RFC 7606 section 7.11 / section 3"),
])

# Expected NOTIFICATION (code, subcode) per case.
#
# The three MP_REACH cases all fail inside bgp_mp_reach_parse() with
# BGP_ATTR_PARSE_ERROR_NOTIFYPLS, and bgp_attr_parse() turns that into
# UPDATE_ERR / MAL_ATTR_LIST unconditionally (bgpd/bgp_attr.c, the
# `if (ret == BGP_ATTR_PARSE_ERROR_NOTIFYPLS)` arm). It is *not*
# ATTR_LENG_ERR even though the fault is a length: bgp_attr_malformed()'s
# MP_REACH/MP_UNREACH arm, which would have preserved the caller's subcode,
# is never reached from these three paths.
#
# mp-unreach-truncated is different in kind. The attribute itself parses --
# bgp_mp_unreach_parse() only needs AFI/SAFI plus a byte count -- and the
# damage is found later, when bgp_nlri_parse_ip() walks the withdrawn NLRI
# and overruns. bgp_update_receive() maps an NLRI error in the MP_WITHDRAW
# slot to UPDATE_ERR / OPT_ATTR_ERR.
EXPECTED_NOTIFICATION = {
    "mp-reach-nexthop-len-bogus": (UPDATE_ERR, MAL_ATTR_LIST),
    "mp-reach-nexthop-len-overrun": (UPDATE_ERR, MAL_ATTR_LIST),
    "mp-reach-truncated": (UPDATE_ERR, MAL_ATTR_LIST),
    "mp-unreach-truncated": (UPDATE_ERR, OPT_ATTR_ERR),
}
