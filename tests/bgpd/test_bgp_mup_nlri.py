# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpMupNlri(frrtest.TestMultiOut):
    program = "./test_bgp_mup_nlri"


TestBgpMupNlri.okfail("isd-v4-ok: ISD IPv4, /24 prefix, well-formed")
TestBgpMupNlri.okfail("dsd-v4-ok: DSD IPv4, PE address 10.0.0.1, well-formed")
TestBgpMupNlri.okfail(
    "t1st-v4-ok: T1ST IPv4, /0 UE prefix, TEID 1, QFI 9, EP 10.1.2.3/32, no SA, well-formed"
)
TestBgpMupNlri.okfail(
    "t2st-v4-ok: T2ST IPv4, EP 10.2.0.1, TEID 2, ea_len=64, well-formed"
)
TestBgpMupNlri.okfail("truncated-header: NLRI truncated before 4-byte header completes")
TestBgpMupNlri.okfail(
    "body-overflow: Route-type length field claims more bytes than the NLRI holds"
)
TestBgpMupNlri.okfail(
    "trailing-garbage: Single trailing byte re-enters header check, returns MUP_MISSING_TYPE"
)
TestBgpMupNlri.okfail(
    "isd-prefix-len-overflow: ISD IPv4, prefix_len=33 (>32) -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "t1st-teid-zero: T1ST IPv4, TEID=0 -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "t1st-ep-len-overflow: T1ST IPv4, endpoint_length=33 (not 32) -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "t2st-teid-zero: T2ST IPv4, TEID=0 -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "dsd-wrong-size: DSD IPv4, body=13 (not 12) -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "unknown-arch-type: Unknown arch_type=0xFF -- outer loop skips, returns OK"
)
TestBgpMupNlri.okfail("isd-v6-ok: ISD IPv6, /64 prefix, well-formed")
TestBgpMupNlri.okfail("dsd-v6-ok: DSD IPv6, PE address 2001:db8::1, well-formed")
TestBgpMupNlri.okfail(
    "t1st-v6-ok: T1ST IPv6, /0 UE prefix, TEID 1, QFI 9, EP 2001:db8::5/128, no SA, well-formed"
)
TestBgpMupNlri.okfail(
    "t2st-v6-ok: T2ST IPv6, EP 2001:db8::9, TEID 2, ea_len=160, well-formed"
)
TestBgpMupNlri.okfail(
    "t2st-v4-ea32-no-teid: T2ST IPv4, ea_len=32, no TEID field (endpoint aggregate), well-formed"
)
TestBgpMupNlri.okfail(
    "t2st-v6-ea128-no-teid: T2ST IPv6, ea_len=128, no TEID field (endpoint aggregate), well-formed"
)
TestBgpMupNlri.okfail(
    "t2st-v4-teid-padded: T2ST IPv4, ea_len=35, TEID octet 0xff -- significant bits 0b111, padding masked"
)
TestBgpMupNlri.okfail(
    "t2st-v4-teid-pad-only: T2ST IPv4, ea_len=35, TEID octet 0x1f -- significant bits 0, skipped as TEID=0"
)
TestBgpMupNlri.okfail(
    "isd-v6-prefix-len-overflow: ISD IPv6, prefix_len=129 (>128) -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "dsd-v6-wrong-size: DSD IPv6, body=25 (not 24) -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail("t1st-v4-with-sa: T1ST IPv4 with SA 10.9.9.9/32, well-formed")
TestBgpMupNlri.okfail(
    "t1st-src-truncated: T1ST IPv4, src_len=32 but only 2 SA bytes -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "t1st-ep-len-24: T1ST IPv4, endpoint_length=24 (not 32) -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "t1st-src-len-24: T1ST IPv4, source_length=24 (not 0 or 32) -- skipped (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "unknown-route-type: Unknown route_type=5 -- outer loop skips, returns OK"
)
TestBgpMupNlri.okfail(
    "two-valid-nlris: ISD + DSD concatenated -- both parsed, returns OK"
)
TestBgpMupNlri.okfail(
    "malformed-then-valid: T1ST TEID=0 then valid ISD -- malformed one skipped, rest processed"
)
TestBgpMupNlri.okfail("encode-isd-v4-ok: encode matches the isd-v4-ok parse vector")
TestBgpMupNlri.okfail("encode-isd-v6-ok: encode matches the isd-v6-ok parse vector")
TestBgpMupNlri.okfail(
    "encode-t1st-v4-with-sa: encode matches the t1st-v4-with-sa parse vector"
)
TestBgpMupNlri.okfail("encode-t2st-v4-ok: encode matches the t2st-v4-ok parse vector")
TestBgpMupNlri.okfail(
    "encode-t2st-v4-ea32-no-teid: encode matches the t2st-v4-ea32-no-teid parse vector"
)
TestBgpMupNlri.okfail("encode-t2st-v6-ok: encode matches the t2st-v6-ok parse vector")
TestBgpMupNlri.okfail(
    "teid-padding-t2st-v4-teid-padded: route key TEID after parse with attr"
)
TestBgpMupNlri.okfail(
    "teid-padding-t2st-v4-teid-pad-only: route key TEID after parse with attr"
)
