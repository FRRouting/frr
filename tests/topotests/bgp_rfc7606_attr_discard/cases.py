# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""Attribute-discard cases for the RFC 7606 conformance suite.

"Attribute discard" means the UPDATE is accepted, the NLRI installed, and only
the offending attribute thrown away. Proving the second half of that -- that
the attribute is not passed along -- needs a downstream router, which is why
this directory carries an extra FRR router r2 behind r1.
"""

from bgp_rfc7606 import DISCARD, EBGP, WITHDRAW, Case, number_variants

CASES = number_variants(
    [
        # -- ATOMIC_AGGREGATE (6), RFC 7606 section 7.6 ---------------------
        Case("atomic-aggregate-len-1", 6, 0x40, "00", outcome=DISCARD,
             json_key="atomicAggregate", spec="RFC 7606 section 7.6"),

        # -- AGGREGATOR (7), RFC 7606 section 7.7 ---------------------------
        # Peers negotiate 4-octet AS, so bgp_attr_aggregator() wants length 8.
        Case("aggregator-len-5", 7, 0xC0, "0000fde90a", outcome=DISCARD,
             json_key="aggregatorAs", spec="RFC 7606 section 7.7"),
        Case("aggregator-len-7", 7, 0xC0, "0000fde90a0000", outcome=DISCARD,
             json_key="aggregatorAs", spec="RFC 7606 section 7.7"),
        Case("aggregator-len-9", 7, 0xC0, "0000fde90a00000200", outcome=DISCARD,
             json_key="aggregatorAs", spec="RFC 7606 section 7.7"),
        Case("aggregator-as-zero", 7, 0xC0, "000000000a000002", outcome=DISCARD,
             json_key="aggregatorAs", spec="RFC 7607 section 2"),

        # -- AS4_AGGREGATOR (18), RFC 6793 section 4.1 ----------------------
        Case("as4-aggregator-len-7", 18, 0xC0, "0000fde90a0000", outcome=DISCARD,
             json_key=None, spec="RFC 6793 section 4.1"),
        Case("as4-aggregator-len-9", 18, 0xC0, "0000fde90a00000200",
             outcome=DISCARD, json_key=None, spec="RFC 6793 section 4.1"),

        # -- ORIGINATOR_ID (9) / CLUSTER_LIST (10) from external peers ------
        # RFC 7606 sections 7.9/7.10: attribute discard from an external
        # neighbour, treat-as-withdraw from an internal one. Only the two
        # external sorts belong in this directory.
        Case("originator-id-len-3", 9, 0x80, "0a0000",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW, json_key="originatorId",
             spec="RFC 7606 section 7.9; draft-uttaro-idr-bgp-oad"),
        Case("originator-id-len-5", 9, 0x80, "0a00000200",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW, json_key="originatorId",
             spec="RFC 7606 section 7.9; draft-uttaro-idr-bgp-oad"),
        Case("cluster-list-len-0", 10, 0x80, "",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW, json_key="clusterList",
             spec="RFC 7606 section 7.10; draft-uttaro-idr-bgp-oad"),
        Case("cluster-list-len-5", 10, 0x80, "0a00000200",
             outcome_ebgp=DISCARD, outcome_ebgp_oad=DISCARD,
             outcome_ibgp=WITHDRAW, json_key="clusterList",
             spec="RFC 7606 section 7.10; draft-uttaro-idr-bgp-oad"),

        # -- AIGP (26), RFC 7311 section 4 ----------------------------------
        # AIGP_TRANSMIT_ALLOWED() (bgp_attr.h:694) ignores AIGP before any
        # validation for a BGP_PEER_EBGP peer without `neighbor X aigp`, so
        # length and value cases are meaningful only from iBGP and from the
        # OAD peer (which has `neighbor 10.0.0.4 aigp`). The flag case is
        # caught by bgp_attr_flag_invalid() before the handler, so it applies
        # to every sort.
        Case("aigp-flag-trans", 26, 0xC0, "01000b0000000000000000000a",
             outcome=DISCARD, json_key="aigpMetric", spec="RFC 7311 section 4"),
        Case("aigp-tlv-unknown-type", 26, 0x80, "09000b0000000000000000000a",
             outcome=DISCARD, json_key="aigpMetric", spec="RFC 7311 section 4",
             skip_sorts=(EBGP,)),
        Case("aigp-tlv-len-not-11", 26, 0x80, "0100050000000000000000000a",
             outcome=DISCARD, json_key="aigpMetric", spec="RFC 7311 section 4",
             skip_sorts=(EBGP,)),
        Case("aigp-len-0", 26, 0x80, "", outcome=DISCARD,
             json_key="aigpMetric", spec="RFC 7311 section 4",
             skip_sorts=(EBGP,)),

        # -- PREFIX_SID (40), RFC 8669 section 6 ----------------------------
        # "MUST ignore the received BGP Prefix-SID attribute and not advertise
        # it to other BGP peers ... equivalent to the 'Attribute discard'
        # action specified in [RFC7606]."
        Case("prefix-sid-flag-nontrans", 40, 0x80, "010007000000000001",
             outcome=DISCARD, json_key=None, spec="RFC 7606 section 3(c)"),
        Case("prefix-sid-tlv-overrun", 40, 0xC0, "0100ff000000",
             outcome=DISCARD, json_key=None, spec="RFC 8669 section 6"),
        Case("prefix-sid-truncated-header", 40, 0xC0, "0100",
             outcome=DISCARD, json_key=None, spec="RFC 8669 section 6"),
        Case("prefix-sid-bad-label-index", 40, 0xC0, "010000",
             outcome=DISCARD, json_key=None, spec="RFC 8669 section 6"),

        # -- LINK_STATE (29), RFC 9552 section 6.3.2 ------------------------
        Case("link-state-flag-trans", 29, 0xC0, "0400000100", outcome=DISCARD,
             json_key=None, spec="RFC 9552 section 6.3.2"),
        Case("link-state-tlv-overrun", 29, 0x80, "040000ff00", outcome=DISCARD,
             json_key=None, spec="RFC 9552 section 6.3.2"),
        Case("link-state-truncated-tlv", 29, 0x80, "0400", outcome=DISCARD,
             json_key=None, spec="RFC 9552 section 6.3.2"),

        # -- NHC (39) -------------------------------------------------------
        Case("nhc-bad-afi-safi", 39, 0xC0, "00ff010001000100", outcome=DISCARD,
             json_key=None, spec="FRR behaviour; draft, no RFC"),
        Case("nhc-tlv-overrun", 39, 0xC0, "0001010001ff00", outcome=DISCARD,
             json_key=None, spec="FRR behaviour; draft, no RFC"),

        # -- Unknown attributes, RFC 7606 section 5.2 / RFC 4271 section 5 --
        Case("unknown-fd-nontransitive", 0xFD, 0x80, "deadbeef",
             outcome=DISCARD, json_key=None, spec="RFC 7606 section 5.2"),
        Case("unknown-fe-transitive", 0xFE, 0xC0, "deadbeef",
             outcome=DISCARD, json_key=None,
             spec="RFC 4271 section 5, optional transitive"),
    ]
)

# Unknown non-transitive optional attributes must not be passed along.
MUST_NOT_REACH_R2 = ("unknown-fd-nontransitive",)

# Unknown transitive optional attributes MUST be passed along (RFC 4271
# section 5). Used as the positive control for the log-based check that backs
# MUST_NOT_REACH_R2: without it, "the attribute never showed up on r2" could
# equally mean "we are not looking at a working log".
MUST_REACH_R2 = ("unknown-fe-transitive",)
