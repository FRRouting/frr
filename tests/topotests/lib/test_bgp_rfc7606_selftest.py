#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Self-test for the shared RFC 7606 case model in lib/bgp_rfc7606.py.
#
# Pure Python: no topology, no ExaBGP, no root. The case model encodes several
# hard-won facts about what ExaBGP 4.2 can and cannot emit, so it is worth
# testing on its own -- a silent change here would make every RFC 7606
# topotest pass or fail for the wrong reason.
#
# Run with:
#     python3 -m pytest tests/topotests/lib/test_bgp_rfc7606_selftest.py -v

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(CWD)

# pylint: disable=C0413
from bgp_rfc7606 import (
    ALL_SORTS,
    DISCARD,
    EBGP,
    EBGP_OAD,
    IBGP,
    PEER_ADDR,
    PEER_NAME,
    SENTINEL_ATTR_TYPE,
    SENTINEL_VARIANT,
    SESSION_RESET,
    SORT_OCTET,
    WITHDRAW,
    Case,
    cases_for,
    number_variants,
    sentinel_announce,
    sentinel_prefix,
)


def make_case(name="c", attr_type=1, flags=0x40, data="04", **kwargs):
    kwargs.setdefault("outcome", WITHDRAW)
    return Case(name, attr_type=attr_type, flags=flags, data=data, **kwargs)


#
# Outcomes: shorthand and per-sort.
#


def test_shorthand_outcome_applies_to_every_sort():
    case = make_case(outcome=DISCARD)
    for sort in ALL_SORTS:
        assert case.outcome_for(sort) == DISCARD


def test_per_sort_outcomes_are_independent():
    case = Case(
        "mixed",
        attr_type=1,
        flags=0x40,
        data="04",
        outcome_ebgp=WITHDRAW,
        outcome_ebgp_oad=DISCARD,
        outcome_ibgp=SESSION_RESET,
    )
    assert case.outcome_for(EBGP) == WITHDRAW
    assert case.outcome_for(EBGP_OAD) == DISCARD
    assert case.outcome_for(IBGP) == SESSION_RESET


def test_per_sort_outcomes_fall_back_to_shorthand():
    case = Case(
        "partial",
        attr_type=1,
        flags=0x40,
        data="04",
        outcome=WITHDRAW,
        outcome_ebgp_oad=DISCARD,
    )
    assert case.outcome_for(EBGP) == WITHDRAW
    assert case.outcome_for(EBGP_OAD) == DISCARD
    assert case.outcome_for(IBGP) == WITHDRAW


def test_no_outcome_at_all_is_rejected():
    with pytest.raises(ValueError):
        Case("nope", attr_type=1, flags=0x40, data="04")


def test_only_ebgp_outcome_is_enough_to_construct():
    case = Case("only-ebgp", attr_type=1, flags=0x40, data="04", outcome_ebgp=WITHDRAW)
    assert case.outcome_for(EBGP) == WITHDRAW
    assert case.outcome_for(IBGP) is None


#
# number_variants() and the prefix encoding.
#


def test_number_variants_counts_per_attribute_type():
    cases = number_variants(
        [
            make_case("origin-a", attr_type=1),
            make_case("med-a", attr_type=4, data="000000"),
            make_case("origin-b", attr_type=1, data="05"),
            make_case("origin-c", attr_type=1, data="06"),
            make_case("med-b", attr_type=4, data=""),
        ]
    )
    assert [c.variant for c in cases] == [0, 0, 1, 2, 1]


def test_number_variants_returns_the_same_list_object():
    cases = [make_case()]
    assert number_variants(cases) is cases


def test_number_variants_rejects_overflow():
    cases = [make_case("c%d" % i, attr_type=1) for i in range(SENTINEL_VARIANT + 1)]
    with pytest.raises(ValueError):
        number_variants(cases)


def test_prefix_encodes_sort_attr_type_and_variant():
    cases = number_variants(
        [make_case("first", attr_type=4), make_case("second", attr_type=4)]
    )
    assert cases[0].prefix(EBGP) == "10.4.0.1/32"
    assert cases[0].prefix(IBGP) == "20.4.0.1/32"
    assert cases[0].prefix(EBGP_OAD) == "30.4.0.1/32"
    assert cases[1].prefix(EBGP) == "10.4.1.1/32"


def test_prefix_uses_the_declared_sort_octet_for_every_sort():
    case = number_variants([make_case(attr_type=17)])[0]
    for sort in ALL_SORTS:
        assert case.prefix(sort).startswith("%d.17.0." % SORT_OCTET[sort])


def test_prefix_before_numbering_raises():
    # Asserts the behaviour, not how "not yet numbered" is represented: an
    # unnumbered case must refuse to render a prefix rather than silently
    # returning variant 0, which would collide with the first real case.
    case = make_case()
    with pytest.raises(ValueError):
        case.prefix(EBGP)


def test_numbering_is_observable():
    case = make_case()
    numbered = number_variants([case])[0]
    assert numbered.variant == 0
    assert numbered.prefix(EBGP).endswith(".0.1/32")


def test_announce_before_numbering_raises():
    case = make_case()
    with pytest.raises(ValueError):
        case.announce(EBGP)


#
# The announce line.
#


def test_announce_has_no_origin_or_as_path_keyword():
    # ExaBGP substitutes its defaults only for attribute codes absent from the
    # route, so spelling out `origin`/`as-path` would defeat a raw ORIGIN case.
    for case in number_variants([make_case(attr_type=1), make_case(attr_type=4)]):
        for sort in ALL_SORTS:
            line = case.announce(sort)
            assert " origin " not in line
            assert " as-path " not in line


def test_announce_renders_type_flags_and_data():
    case = number_variants([make_case(attr_type=4, flags=0x80, data="000000")])[0]
    assert case.announce(EBGP) == (
        "announce route 10.4.0.1/32 next-hop 10.0.0.2 "
        "attribute [0x04 0x80 0x000000]\n"
    )


def test_announce_puts_the_raw_attribute_after_next_hop():
    # With the raw token first, ExaBGP dies with an AttributeError inside its
    # NEXT_HOP skip lambda.
    case = number_variants([make_case()])[0]
    line = case.announce(EBGP)
    assert line.index("next-hop") < line.index("attribute [")


def test_announce_uses_the_peer_address_of_its_sort():
    case = number_variants([make_case()])[0]
    for sort in ALL_SORTS:
        assert " next-hop %s " % PEER_ADDR[sort] in case.announce(sort)


def test_announce_ends_with_a_newline():
    case = number_variants([make_case()])[0]
    assert case.announce(EBGP).endswith("\n")


#
# data validation.
#


def test_empty_data_is_allowed():
    case = number_variants([make_case(attr_type=4, flags=0x80, data="")])[0]
    assert case.data == ""
    assert case.announce(EBGP) == (
        "announce route 10.4.0.1/32 next-hop 10.0.0.2 attribute [0x04 0x80 0x]\n"
    )


@pytest.mark.parametrize("data", ["00 11", " 0011", "0011 ", "\t0011", "0011\n"])
def test_data_with_whitespace_is_rejected(data):
    with pytest.raises(ValueError):
        make_case(data=data)


def test_data_with_odd_nibble_count_is_rejected():
    with pytest.raises(ValueError):
        make_case(data="123")


@pytest.mark.parametrize("data", ["zz", "0g", "ff!!"])
def test_non_hex_data_is_rejected(data):
    with pytest.raises(ValueError):
        make_case(data=data)


def test_data_must_not_carry_its_own_0x_prefix():
    # int("0x00", 16) is accepted by Python, so the hex check alone would let a
    # doubled prefix through: announce() adds its own 0x, rendering "0x0x00",
    # and ExaBGP rejects the configuration at startup. Fail at construction
    # instead, where the case author can see it.
    with pytest.raises(ValueError):
        make_case(attr_type=4, flags=0x80, data="0x00")


#
# NEXT_HOP handling.
#


def test_raw_next_hop_attribute_is_rejected():
    with pytest.raises(ValueError) as exc:
        make_case(attr_type=3, data="00000000")
    assert "NEXT_HOP" in str(exc.value)


def test_nexthop_case_renders_without_a_raw_attribute():
    case = number_variants(
        [
            Case(
                "nh-zero",
                attr_type=None,
                flags=0,
                data="",
                outcome=WITHDRAW,
                nexthop="0.0.0.0",
            )
        ]
    )[0]
    assert case.announce(EBGP) == "announce route 10.3.0.1/32 next-hop 0.0.0.0\n"
    assert "attribute" not in case.announce(EBGP)


def test_nexthop_case_uses_prefix_octet_three():
    case = Case(
        "nh", attr_type=None, flags=0, data="", outcome=WITHDRAW, nexthop="0.0.0.0"
    )
    assert case.prefix_octet == 3


def test_raw_attribute_case_uses_its_type_as_prefix_octet():
    assert make_case(attr_type=17).prefix_octet == 17


def test_nexthop_and_attr_type_together_is_rejected():
    with pytest.raises(ValueError):
        Case(
            "both",
            attr_type=1,
            flags=0x40,
            data="04",
            outcome=WITHDRAW,
            nexthop="0.0.0.0",
        )


def test_neither_nexthop_nor_attr_type_is_rejected():
    with pytest.raises(ValueError):
        Case("neither", attr_type=None, flags=0, data="", outcome=WITHDRAW)


#
# skip_sorts and cases_for().
#


def test_skip_sorts_marks_a_case_inapplicable():
    case = make_case(skip_sorts=[IBGP])
    assert case.applies_to(EBGP)
    assert case.applies_to(EBGP_OAD)
    assert not case.applies_to(IBGP)


def test_skip_sorts_defaults_to_everything_applying():
    case = make_case()
    assert all(case.applies_to(sort) for sort in ALL_SORTS)
    assert case.skip_sorts == ()


def test_cases_for_filters_on_outcome_and_skip_sorts():
    withdrawn = make_case("w", attr_type=1)
    discarded = make_case("d", attr_type=4, data="", outcome=DISCARD)
    ibgp_only = make_case(
        "i", attr_type=5, data="00000000", skip_sorts=[EBGP, EBGP_OAD]
    )
    cases = number_variants([withdrawn, discarded, ibgp_only])

    assert cases_for(cases, EBGP, WITHDRAW) == [withdrawn]
    assert cases_for(cases, IBGP, WITHDRAW) == [withdrawn, ibgp_only]
    assert cases_for(cases, EBGP, DISCARD) == [discarded]
    assert cases_for(cases, EBGP, SESSION_RESET) == []


def test_cases_for_respects_per_sort_outcomes():
    case = Case(
        "split",
        attr_type=1,
        flags=0x40,
        data="04",
        outcome=WITHDRAW,
        outcome_ebgp_oad=DISCARD,
    )
    cases = number_variants([case])
    assert cases_for(cases, EBGP, WITHDRAW) == [case]
    assert cases_for(cases, EBGP_OAD, WITHDRAW) == []
    assert cases_for(cases, EBGP_OAD, DISCARD) == [case]


#
# Sentinel and per-sort tables.
#


def test_sentinel_prefix_is_distinct_per_sort():
    prefixes = {sentinel_prefix(sort) for sort in ALL_SORTS}
    assert len(prefixes) == len(ALL_SORTS)
    assert sentinel_prefix(EBGP) == "10.%d.%d.1/32" % (
        SENTINEL_ATTR_TYPE,
        SENTINEL_VARIANT,
    )


def test_sentinel_announce_is_a_plain_route():
    line = sentinel_announce(IBGP)
    assert line == "announce route %s next-hop %s\n" % (
        sentinel_prefix(IBGP),
        PEER_ADDR[IBGP],
    )
    assert "attribute" not in line


def test_sentinel_cannot_collide_with_a_real_case():
    # No attribute type reaches 255, and number_variants() refuses to hand out
    # variant 254, so the sentinel prefix is unreachable by any case.
    case = number_variants([make_case(attr_type=1)])[0]
    for sort in ALL_SORTS:
        assert case.prefix(sort) != sentinel_prefix(sort)


def test_per_sort_tables_cover_every_sort_uniquely():
    for table in (SORT_OCTET, PEER_ADDR, PEER_NAME):
        assert set(table) == set(ALL_SORTS)
        assert len(set(table.values())) == len(ALL_SORTS)


if __name__ == "__main__":
    sys.exit(pytest.main(["-v"] + sys.argv[1:]))
