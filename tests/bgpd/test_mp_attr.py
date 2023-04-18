import frrtest


class TestMpAttr(frrtest.TestMultiOut):
    program = "./test_mp_attr"


TestMpAttr.okfail("IPv6: IPV6 MP Reach, global nexthop, 1 NLRI")
TestMpAttr.okfail("IPv6-2: IPV6 MP Reach, global nexthop, 2 NLRIs")
TestMpAttr.okfail("IPv6-default: IPV6 MP Reach, global nexthop, 2 NLRIs + default")
TestMpAttr.okfail("IPv6-lnh: IPV6 MP Reach, global+local nexthops, 2 NLRIs + default")
TestMpAttr.okfail("IPv6-nhlen: IPV6 MP Reach, inappropriate nexthop length")
TestMpAttr.okfail("IPv6-nhlen2: IPV6 MP Reach, invalid nexthop length")
TestMpAttr.okfail("IPv6-nhlen3: IPV6 MP Reach, nexthop length overflow")
TestMpAttr.okfail("IPv6-nhlen4: IPV6 MP Reach, nexthop length short")
TestMpAttr.okfail("IPv6-nlri: IPV6 MP Reach, NLRI bitlen overflow")
TestMpAttr.okfail("IPv4: IPv4 MP Reach, 2 NLRIs + default")
TestMpAttr.okfail("IPv4-nhlen: IPv4 MP Reach, nexthop lenth overflow")
TestMpAttr.okfail("IPv4-nlrilen: IPv4 MP Reach, nlri lenth overflow")
TestMpAttr.okfail("IPv4-VPNv4: IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs")
TestMpAttr.okfail(
    "IPv4-VPNv4-bogus-plen: IPv4/MPLS-labeled VPN MP Reach, RD, Nexthop, NLRI / bogus p'len"
)
TestMpAttr.okfail(
    "IPv4-VPNv4-plen1-short: IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs, 1st plen short"
)
TestMpAttr.okfail(
    "IPv4-VPNv4-plen1-long: IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs, 1st plen long"
)
TestMpAttr.okfail(
    "IPv4-VPNv4-plenn-long: IPv4/VPNv4 MP Reach, RD, Nexthop, 3 NLRIs, last plen long"
)
TestMpAttr.okfail(
    "IPv4-VPNv4-plenn-short: IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs, last plen short"
)
TestMpAttr.okfail(
    "IPv4-VPNv4-bogus-rd-type: IPv4/VPNv4 MP Reach, RD, NH, 2 NLRI, unknown RD in 1st (log, but parse)"
)
TestMpAttr.okfail(
    "IPv4-VPNv4-0-nlri: IPv4/VPNv4 MP Reach, RD, Nexthop, 3 NLRI, 3rd 0 bogus"
)
TestMpAttr.okfail("IPv6-bug: IPv6, global nexthop, 1 default NLRI")
TestMpAttr.okfail("IPv6-unreach: IPV6 MP Unreach, 1 NLRI")
TestMpAttr.okfail("IPv6-unreach2: IPV6 MP Unreach, 2 NLRIs")
TestMpAttr.okfail("IPv6-unreach-default: IPV6 MP Unreach, 2 NLRIs + default")
TestMpAttr.okfail("IPv6-unreach-nlri: IPV6 MP Unreach, NLRI bitlen overflow")
TestMpAttr.okfail("IPv4-unreach: IPv4 MP Unreach, 2 NLRIs + default")
TestMpAttr.okfail("IPv4-unreach-nlrilen: IPv4 MP Unreach, nlri length overflow")
TestMpAttr.okfail("IPv4-unreach-VPNv4: IPv4/MPLS-labeled VPN MP Unreach, RD, 3 NLRIs")
