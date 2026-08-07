# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""Treat-as-withdraw cases for the RFC 7606 conformance suite."""

from bgp_rfc7606 import DISCARD, EBGP, EBGP_OAD, WITHDRAW, Case, number_variants

CASES = number_variants(
    [
        # -- ORIGIN (1), RFC 7606 section 7.1 -------------------------------
        Case("origin-flag-optional", 1, 0xC0, "00", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("origin-flag-partial", 1, 0x60, "00", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("origin-len-0", 1, 0x40, "", outcome=WITHDRAW,
             spec="RFC 7606 section 7.1"),
        Case("origin-len-2", 1, 0x40, "0000", outcome=WITHDRAW,
             spec="RFC 7606 section 7.1"),
        Case("origin-value-3", 1, 0x40, "03", outcome=WITHDRAW,
             spec="RFC 7606 section 7.1"),
        Case("origin-value-4", 1, 0x40, "04", outcome=WITHDRAW,
             spec="RFC 7606 section 7.1"),
        Case("origin-value-255", 1, 0x40, "ff", outcome=WITHDRAW,
             spec="RFC 7606 section 7.1"),

        # -- AS_PATH (2), RFC 7606 section 7.2 ------------------------------
        Case("aspath-flag-optional", 2, 0xC0, "02010000fde9", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("aspath-flag-partial", 2, 0x60, "02010000fde9", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("aspath-seg-type-0", 2, 0x40, "00010000fde9", outcome=WITHDRAW,
             spec="RFC 7606 section 7.2"),
        Case("aspath-seg-type-5", 2, 0x40, "05010000fde9", outcome=WITHDRAW,
             spec="RFC 7606 section 7.2"),
        Case("aspath-seg-len-0", 2, 0x40, "0200", outcome=WITHDRAW,
             spec="RFC 7606 section 7.2"),
        Case("aspath-seg-len-overrun", 2, 0x40, "02ff0000fde9", outcome=WITHDRAW,
             spec="RFC 7606 section 7.2"),
        Case("aspath-as-zero", 2, 0x40, "020100000000", outcome=WITHDRAW,
             spec="RFC 7607 section 2"),

        # -- NEXT_HOP (3), semantic cases only ------------------------------
        # ExaBGP cannot emit a raw NEXT_HOP attribute in any token ordering,
        # so flag and length cases live in tests/bgpd/test_attr_parse.c.
        # These go through ExaBGP's own next-hop keyword.
        Case("nexthop-zero", None, 0, "", outcome=WITHDRAW,
             nexthop="0.0.0.0",
             spec="RFC 4271 section 6.3, martian next hop"),
        Case("nexthop-loopback", None, 0, "", outcome=WITHDRAW,
             nexthop="127.0.0.1",
             spec="RFC 4271 section 6.3, martian next hop"),
        Case("nexthop-multicast", None, 0, "", outcome=WITHDRAW,
             nexthop="224.0.0.1",
             spec="RFC 4271 section 6.3, martian next hop"),

        # -- MULTI_EXIT_DISC (4), RFC 7606 section 7.4 ----------------------
        Case("med-flag-trans", 4, 0xC0, "0000000a", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("med-len-3", 4, 0x80, "000000", outcome=WITHDRAW,
             spec="RFC 7606 section 7.4"),
        Case("med-len-5", 4, 0x80, "000000000a", outcome=WITHDRAW,
             spec="RFC 7606 section 7.4"),
        Case("med-len-0", 4, 0x80, "", outcome=WITHDRAW,
             spec="RFC 7606 section 7.4"),

        # -- LOCAL_PREF (5) -------------------------------------------------
        # ExaBGP's skip[LOCAL_PREF] lambda drops the attribute whenever
        # local-as != peer-as, so only the iBGP peer can carry one. The eBGP
        # and eBGP-OAD expectations are covered in tests/bgpd/test_attr_parse.c.
        Case("local-pref-len-3", 5, 0x40, "000000", outcome=WITHDRAW,
             skip_sorts=(EBGP, EBGP_OAD),
             spec="RFC 7606 section 7.5; draft-uttaro-idr-bgp-oad"),
        Case("local-pref-len-5", 5, 0x40, "0000000064", outcome=WITHDRAW,
             skip_sorts=(EBGP, EBGP_OAD),
             spec="RFC 7606 section 7.5; draft-uttaro-idr-bgp-oad"),
        Case("local-pref-len-0", 5, 0x40, "", outcome=WITHDRAW,
             skip_sorts=(EBGP, EBGP_OAD),
             spec="RFC 7606 section 7.5; draft-uttaro-idr-bgp-oad"),
        Case("local-pref-flag-optional", 5, 0xC0, "00000064", outcome=WITHDRAW,
             skip_sorts=(EBGP, EBGP_OAD),
             spec="RFC 7606 section 3(c); ambiguous vs section 7.5"),

        # -- COMMUNITIES (8), RFC 7606 section 7.8 --------------------------
        Case("comm-flag-nontrans", 8, 0x80, "ffff0001", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("comm-len-0", 8, 0xC0, "", outcome=WITHDRAW,
             spec="RFC 7606 section 7.8"),
        Case("comm-len-5", 8, 0xC0, "ffff000100", outcome=WITHDRAW,
             spec="RFC 7606 section 7.8"),

        # -- ORIGINATOR_ID (9), RFC 7606 section 7.9 ------------------------
        # Attribute discard from an external neighbour, treat-as-withdraw from
        # an internal one. Only the iBGP rows belong in this directory.
        Case("originator-id-len-3", 9, 0x80, "0a0000",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW,
             spec="RFC 7606 section 7.9; draft-uttaro-idr-bgp-oad"),
        Case("originator-id-len-5", 9, 0x80, "0a00000200",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW,
             spec="RFC 7606 section 7.9; draft-uttaro-idr-bgp-oad"),
        Case("originator-id-flag-trans", 9, 0xC0, "0a000002", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c); ambiguous vs section 7.9"),

        # -- CLUSTER_LIST (10), RFC 7606 section 7.10 -----------------------
        Case("cluster-list-len-0", 10, 0x80, "",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW,
             spec="RFC 7606 section 7.10; draft-uttaro-idr-bgp-oad"),
        Case("cluster-list-len-5", 10, 0x80, "0a00000200",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW,
             spec="RFC 7606 section 7.10; draft-uttaro-idr-bgp-oad"),
        Case("cluster-list-flag-trans", 10, 0xC0, "0a000002", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c); ambiguous vs section 7.10"),

        # -- EXT_COMMUNITIES (16), RFC 7606 section 7.14 --------------------
        Case("extcomm-flag-nontrans", 16, 0x80, "0002fde900000001",
             outcome=WITHDRAW, spec="RFC 7606 section 3(c)"),
        Case("extcomm-len-0", 16, 0xC0, "", outcome=WITHDRAW,
             spec="RFC 7606 section 7.14"),
        Case("extcomm-len-9", 16, 0xC0, "0002fde90000000100", outcome=WITHDRAW,
             spec="RFC 7606 section 7.14"),

        # -- AS4_PATH (17), RFC 6793 section 6 ------------------------------
        # No AS 0 row here. RFC 7607 section 2 defers AS4_PATH to RFC 6793,
        # and RFC 6793 section 4.1 says a NEW speaker that receives AS4_PATH
        # from another NEW speaker "MUST discard the path attribute and
        # continue processing the UPDATE message". Every peer here is 4-octet
        # AS capable, so a semantically bad AS4_PATH is discarded rather than
        # inspected, and the route is correctly accepted. Only structural
        # damage, which aspath_parse() rejects before that point, reaches
        # treat-as-withdraw.
        Case("as4path-flag-nontrans", 17, 0x80, "020100010001", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("as4path-seg-type-0", 17, 0xC0, "000100010001", outcome=WITHDRAW,
             spec="RFC 6793 section 6"),

        # -- PMSI_TUNNEL (22), RFC 6514 -------------------------------------
        # RFC 7606 does not cover PMSI_TUNNEL; these pin FRR's chosen
        # behaviour rather than a mandated one.
        Case("pmsi-flag-nontrans", 22, 0x80, "00060000000a000002",
             outcome=WITHDRAW, spec="RFC 7606 section 3(c)"),
        Case("pmsi-len-4", 22, 0xC0, "00060000", outcome=WITHDRAW,
             spec="FRR behaviour; RFC 6514 silent"),
        Case("pmsi-type-8", 22, 0xC0, "00080000000a000002",
             outcome=WITHDRAW, spec="FRR behaviour; RFC 6514 silent"),
        Case("pmsi-type-255", 22, 0xC0, "00ff0000000a000002",
             outcome=WITHDRAW, spec="FRR behaviour; RFC 6514 silent"),
        Case("pmsi-ingress-repl-len-10", 22, 0xC0, "00060000000a00000200",
             outcome=WITHDRAW, spec="FRR behaviour; RFC 6514 silent"),

        # -- ENCAP (23), RFC 9012 -------------------------------------------
        Case("encap-flag-nontrans", 23, 0x80, "00070000", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("encap-len-3", 23, 0xC0, "000700", outcome=WITHDRAW,
             spec="RFC 9012; FRR treats as withdraw"),
        Case("encap-outer-len-mismatch", 23, 0xC0, "0007000401", outcome=WITHDRAW,
             spec="RFC 9012; FRR treats as withdraw"),
        Case("encap-subtlv-overrun", 23, 0xC0, "0007000401ff", outcome=WITHDRAW,
             spec="RFC 9012; FRR treats as withdraw"),

        # -- IPV6_EXT_COMMUNITIES (25), RFC 7606 section 7.15 ---------------
        Case("ipv6-extcomm-flag-nontrans", 25, 0x80,
             "000220010db80000000000000000000000010001",
             outcome=WITHDRAW, spec="RFC 7606 section 3(c)"),
        Case("ipv6-extcomm-len-0", 25, 0xC0, "", outcome=WITHDRAW,
             spec="RFC 7606 section 7.15"),
        Case("ipv6-extcomm-len-21", 25, 0xC0,
             "000220010db8000000000000000000000001000100",
             outcome=WITHDRAW, spec="RFC 7606 section 7.15"),

        # -- LARGE_COMMUNITIES (32), RFC 8092 -------------------------------
        Case("large-comm-flag-nontrans", 32, 0x80,
             "0000fde90000000100000002", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("large-comm-len-0", 32, 0xC0, "", outcome=WITHDRAW,
             spec="RFC 8092 section 6"),
        Case("large-comm-len-13", 32, 0xC0,
             "0000fde9000000010000000200", outcome=WITHDRAW,
             spec="RFC 8092 section 6"),

        # -- OTC (35), RFC 9234 ---------------------------------------------
        Case("otc-flag-nontrans", 35, 0x80, "0000fde9", outcome=WITHDRAW,
             spec="RFC 7606 section 3(c)"),
        Case("otc-len-3", 35, 0xC0, "0000fd", outcome=WITHDRAW,
             spec="RFC 9234 section 6"),
        Case("otc-len-5", 35, 0xC0, "0000fde900", outcome=WITHDRAW,
             spec="RFC 9234 section 6"),
        Case("otc-value-0", 35, 0xC0, "00000000", outcome=WITHDRAW,
             spec="RFC 9234 section 6"),
    ]
)
