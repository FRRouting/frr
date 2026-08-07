# SPDX-License-Identifier: ISC
#
# Shared case model for the RFC 7606 / EBGP-OAD malformed-attribute topotests.
#
# Imported by both the ExaBGP sender (exa-send.py, running inside the ExaBGP
# namespace) and the pytest asserter, so the announced case and the asserted
# case can never drift apart.

# RFC 7606 error-handling approaches.
DISCARD = "discard"
WITHDRAW = "withdraw"
SESSION_RESET = "session-reset"

# Peer sorts under test.
EBGP = "ebgp"
EBGP_OAD = "ebgp-oad"
IBGP = "ibgp"

ALL_SORTS = (EBGP, EBGP_OAD, IBGP)

# First octet of the announced prefix, per peer sort. Keeps every peer's
# routes in a distinct /8 so a failure names the peer as well as the attribute.
SORT_OCTET = {EBGP: 10, EBGP_OAD: 30, IBGP: 20}

# Per-peer addressing on the shared segment.
PEER_ADDR = {EBGP: "10.0.0.2", IBGP: "10.0.0.3", EBGP_OAD: "10.0.0.4"}
PEER_NAME = {EBGP: "peer1", IBGP: "peer2", EBGP_OAD: "peer3"}

# Announced last by every peer; its arrival proves all preceding announcements
# have been processed, which removes the need for a fixed sleep.
SENTINEL_VARIANT = 254
SENTINEL_ATTR_TYPE = 255


class Case:
    """One malformed-attribute test case.

    attr_type -- BGP path attribute type code
    flags     -- the attribute flags octet, emitted verbatim by ExaBGP
    data      -- attribute value as a lowercase hex string, no 0x prefix;
                 may be "" for a zero-length attribute
    outcome   -- shorthand when all three peer sorts expect the same result
    outcome_ebgp / outcome_ebgp_oad / outcome_ibgp -- per-sort expectations
    json_key  -- for DISCARD cases, the `show bgp ... json` key that must be
                 absent from the accepted path; None when the attribute has no
                 JSON surface
    spec      -- the governing RFC or draft clause, for the failure message
    skip_sorts -- peer sorts this case is not meaningful for
    nexthop   -- override for the `next-hop` keyword. Semantic NEXT_HOP cases
                 must use this, NOT a raw attribute: ExaBGP cannot emit a raw
                 NEXT_HOP at all. When set, attr_type must be None.
    """

    def __init__(
        self,
        name,
        attr_type,
        flags,
        data,
        outcome=None,
        outcome_ebgp=None,
        outcome_ebgp_oad=None,
        outcome_ibgp=None,
        json_key=None,
        spec="",
        skip_sorts=(),
        nexthop=None,
    ):
        if outcome is None and outcome_ebgp is None:
            raise ValueError("%s: needs outcome or per-sort outcomes" % name)
        # A stray space or odd nibble count silently produces a differently
        # malformed attribute, which would pass the test for the wrong reason.
        if data != data.strip() or " " in data:
            raise ValueError("%s: data must not contain spaces" % name)
        if len(data) % 2:
            raise ValueError(
                "%s: data has an odd number of hex digits (%d)" % (name, len(data))
            )
        # int(x, 16) happily accepts a "0x" prefix, but announce() already
        # supplies one -- "0x00" would render as "0x0x00" and ExaBGP would
        # reject the configuration at startup.
        if data[:2].lower() == "0x":
            raise ValueError(
                "%s: data must be bare hex digits; announce() adds the 0x" % name
            )
        int(data or "0", 16)  # raises ValueError on a non-hex digit
        # ExaBGP silently drops a raw attribute [0x03 ...] that follows the
        # next-hop keyword, and crashes if it precedes one. A NEXT_HOP case
        # must therefore go through `nexthop`, never through attr_type=3.
        if attr_type == 3:
            raise ValueError(
                "%s: ExaBGP cannot emit a raw NEXT_HOP attribute; use "
                "nexthop=... for semantic cases, or the C unit test for flag "
                "and length cases" % name
            )
        if nexthop is not None and attr_type is not None:
            raise ValueError(
                "%s: nexthop cases must not also carry a raw attribute" % name
            )
        if nexthop is None and attr_type is None:
            raise ValueError("%s: needs either attr_type or nexthop" % name)
        self.nexthop = nexthop
        self.name = name
        self.attr_type = attr_type
        self.flags = flags
        self.data = data
        self.json_key = json_key
        self.spec = spec
        self.skip_sorts = tuple(skip_sorts)
        self._outcomes = {
            EBGP: outcome_ebgp if outcome_ebgp is not None else outcome,
            EBGP_OAD: outcome_ebgp_oad if outcome_ebgp_oad is not None else outcome,
            IBGP: outcome_ibgp if outcome_ibgp is not None else outcome,
        }
        # Assigned by number_variants(), via assign_variant(). Kept a plain
        # int rather than None-until-numbered: pylint does not narrow an
        # Optional attribute through a guard, and reports the %d in prefix()
        # against it as E1307. _numbered carries the "not yet numbered" state
        # instead, so the guard survives without the Optional.
        self.variant = 0
        self._numbered = False

    def outcome_for(self, sort):
        return self._outcomes[sort]

    def applies_to(self, sort):
        return sort not in self.skip_sorts

    @property
    def prefix_octet(self):
        """Second octet of the announced prefix.

        Raw-attribute cases use their attribute type code. A `nexthop` case
        uses 3, the NEXT_HOP type code it stands in for; no raw attr_type=3
        case can exist, so there is no collision.
        """
        return self.attr_type if self.attr_type is not None else 3

    def assign_variant(self, index):
        """Set this case's per-attribute-type index. Called by number_variants()."""
        self.variant = index
        self._numbered = True

    def prefix(self, sort):
        if not self._numbered:
            raise ValueError("%s: number_variants() not called" % self.name)
        return "%d.%d.%d.1/32" % (SORT_OCTET[sort], self.prefix_octet, self.variant)

    def announce(self, sort):
        """ExaBGP announce line for this case.

        No `origin` or `as-path` keyword is used. ExaBGP's Attributes.pack()
        substitutes its default ORIGIN/AS_PATH only for codes absent from the
        route, so a raw `attribute [0x01 ...]` replaces the default ORIGIN
        rather than duplicating it, and every other case still gets a
        well-formed ORIGIN and AS_PATH for free.

        The raw attribute deliberately comes AFTER the next-hop keyword. That
        ordering matters: with the raw token first, ExaBGP evaluates its
        NEXT_HOP skip lambda against a GenericAttribute and dies with
        AttributeError.
        """
        if self.nexthop is not None:
            return "announce route %s next-hop %s\n" % (
                self.prefix(sort),
                self.nexthop,
            )
        return "announce route %s next-hop %s attribute [0x%02x 0x%02x 0x%s]\n" % (
            self.prefix(sort),
            PEER_ADDR[sort],
            self.attr_type,
            self.flags,
            self.data if self.data else "",
        )

    def __repr__(self):
        return "<Case %s>" % self.name


def number_variants(cases):
    """Assign each case a per-attribute-type index, used in its prefix.

    Mutates and returns the list so a module can do:
        CASES = number_variants([...])
    """
    counters = {}
    for case in cases:
        idx = counters.get(case.prefix_octet, 0)
        if idx >= SENTINEL_VARIANT:
            raise ValueError(
                "attr type %d has too many variants for the prefix encoding"
                % case.prefix_octet
            )
        case.assign_variant(idx)
        counters[case.prefix_octet] = idx + 1
    return cases


def sentinel_prefix(sort):
    return "%d.%d.%d.1/32" % (SORT_OCTET[sort], SENTINEL_ATTR_TYPE, SENTINEL_VARIANT)


def sentinel_announce(sort):
    """A well-formed route announced after every case."""
    return "announce route %s next-hop %s\n" % (
        sentinel_prefix(sort),
        PEER_ADDR[sort],
    )


def cases_for(cases, sort, outcome):
    """Cases from `cases` that this peer sort should produce `outcome` for."""
    return [c for c in cases if c.applies_to(sort) and c.outcome_for(sort) == outcome]
