import frrtest


class TestCapability(frrtest.TestMultiOut):
    program = "./test_capability"


TestCapability.okfail("MP4: MP IP/Uni")
TestCapability.okfail("MPv6: MP IPv6/Uni")
TestCapability.okfail("MP2: MP IP/Multicast")
TestCapability.okfail("MP3: MP IP6/MPLS-labeled VPN")
TestCapability.okfail("MP5: MP IP6/MPLS-VPN")
TestCapability.okfail("MP6: MP IP4/MPLS-labeled VPN")
TestCapability.okfail("MP8: MP unknown AFI/SAFI")
TestCapability.okfail("MP-short: MP IP4/Unicast, length too short (< minimum)")
TestCapability.okfail("MP-overflow: MP IP4/Unicast, length too long")
TestCapability.okfail("caphdr: capability header, and no more")
TestCapability.okfail("nodata: header, no data but length says there is")
TestCapability.okfail("padded: valid, with padding")
TestCapability.okfail("minsize: violates minsize requirement")
TestCapability.okfail("ORF: ORF, simple, single entry, single tuple")
TestCapability.okfail("ORF-many: ORF, multi entry/tuple")
TestCapability.okfail("ORFlo: ORF, multi entry/tuple, hdr length too short")
TestCapability.okfail("ORFlu: ORF, multi entry/tuple, length too long")
TestCapability.okfail("ORFnu: ORF, multi entry/tuple, entry number too long")
TestCapability.okfail("ORFno: ORF, multi entry/tuple, entry number too short")
TestCapability.okfail("ORFpad: ORF, multi entry/tuple, padded to align")
TestCapability.okfail("AS4: AS4 capability")
TestCapability.okfail("GR: GR capability")
TestCapability.okfail("GR-short: GR capability, but header length too short")
TestCapability.okfail("GR-long: GR capability, but header length too long")
TestCapability.okfail("GR-trunc: GR capability, but truncated")
TestCapability.okfail("GR-empty: GR capability, but empty.")
TestCapability.okfail("MP-empty: MP capability, but empty.")
TestCapability.okfail("ORF-empty: ORF capability, but empty.")
TestCapability.okfail("AS4-empty: AS4 capability, but empty.")
TestCapability.okfail("dyn-empty: Dynamic capability, but empty.")
TestCapability.okfail("dyn-old: Dynamic capability (deprecated version)")
TestCapability.okfail("Role: Role capability")
TestCapability.okfail("Role-long: Role capability, but too long")
TestCapability.okfail("Role-empty: Role capability, but empty.")
TestCapability.okfail("Cap-singlets: One capability per Optional-Param")
TestCapability.okfail("Cap-series: Series of capability, one Optional-Param")
TestCapability.okfail("AS4more: AS4 capability after other caps (singlets)")
TestCapability.okfail("AS4series: AS4 capability, in series of capabilities")
TestCapability.okfail("AS4real: AS4 capability, in series of capabilities")
TestCapability.okfail("AS4real2: AS4 capability, in series of capabilities")
TestCapability.okfail("DynCap: Dynamic Capability Message, IP/Multicast")
TestCapability.okfail("DynCapLong: Dynamic Capability Message, IP/Multicast, truncated")
TestCapability.okfail("DynCapPadded: Dynamic Capability Message, IP/Multicast, padded")
TestCapability.okfail(
    "DynCapMPCpadded: Dynamic Capability Message, IP/Multicast, cap data padded"
)
TestCapability.okfail(
    "DynCapMPCoverflow: Dynamic Capability Message, IP/Multicast, cap data != length"
)
