from lib.lutil import luCommand

rtrs = ["r1", "r2"]
for rtr in rtrs:
    luCommand(
        rtr,
        "ip link show type vrf {}-cust1".format(rtr),
        "cust1: .*UP",
        "pass",
        "VRF cust1 intf up",
    )
    luCommand(
        rtr,
        "ip addr show vrf {}-cust1".format(rtr),
        "192.168",
        "pass",
        "VRF cust1 IP config",
    )
    luCommand(
        rtr,
        "ip route show vrf {}-cust1".format(rtr),
        "192.168...0/24 dev r.-eth",
        "pass",
        "VRF cust1 interface route",
    )
for rtr in rtrs:
    luCommand(
        rtr,
        "ip link show type vrf {}-cust2".format(rtr),
        "cust2: .*UP",
        "pass",
        "VRF cust2 intf up",
    )
    luCommand(
        rtr,
        "ip addr show vrf {}-cust2".format(rtr),
        "192.168",
        "pass",
        "VRF cust2 IP config",
    )
    luCommand(
        rtr,
        "ip route show vrf {}-cust2".format(rtr),
        "192.168...0/24 dev r.-eth",
        "pass",
        "VRF cust2 interface route",
    )