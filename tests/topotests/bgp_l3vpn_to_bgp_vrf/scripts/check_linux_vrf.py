from lib.lutil import luCommand

rtrs = ["r1", "r3", "r4"]
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
        "ip add show vrf {}-cust1".format(rtr),
        "r..eth4.*UP",
        "pass",
        "VRF cust1 IP intf up",
    )
    luCommand(
        rtr,
        "ip add show vrf {}-cust1".format(rtr),
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
luCommand("r4", "ip link show type vrf r4-cust2", "cust2: .*UP", "pass", "VRF cust2 up")
luCommand(
    "r4",
    "ip add show vrf r4-cust2",
    "r..eth5.*UP.* 192.168",
    "pass",
    "VRF cust1 IP config",
)
luCommand(
    "r4",
    "ip route show vrf r4-cust2",
    "192.168...0/24 dev r.-eth",
    "pass",
    "VRF cust2 interface route",
)
rtrs = ["ce1", "ce2", "ce3"]
for rtr in rtrs:
    luCommand(
        rtr,
        "ip route show",
        "192.168...0/24 dev ce.-eth0",
        "pass",
        "CE interface route",
    )
    luCommand(rtr, "ping 192.168.1.1 -c 1", " 0. packet loss", "wait", "CE->PE ping")
luCommand(
    "ce4", "ip link show type vrf ce4-cust2", "cust2: .*UP", "pass", "VRF cust2 up"
)
luCommand(
    "ce4",
    "ip route show vrf ce4-cust2",
    "192.168...0/24 dev ce.-eth0",
    "pass",
    "CE interface route",
)
luCommand(
    "ce4",
    "ping 192.168.2.1 -c 1 -I ce4-cust2",
    " 0. packet loss",
    "wait",
    "CE4->PE4 ping",
)
luCommand(
    "r1",
    'ip route show table 10 | wc -l',
    "24",
    "wait",
    "Check r1 r1-cust1 routing table",
    time=60,
)
luCommand(
    "r1",
    'ip route show table 10 | wc -l',
    "24",
    "pass",
    "Check r1 r1-cust1 routing table",
)
luCommand(
    "r1",
    'ip route show table 20 | wc -l',
    "18",
    "wait",
    "Check r1 r1-cust3 routing table",
)
luCommand(
    "r1",
    'ip route show table 20 | wc -l',
    "18",
    "pass",
    "Check r1 r1-cust3 routing table",
)
luCommand(
    "r1",
    'ip route show table 30 | wc -l',
    "0",
    "wait",
    "Check r1 r1-cust4 routing table",
)
luCommand(
    "r1",
    'ip route show table 30 | wc -l',
    "0",
    "pass",
    "Check r1 r1-cust4 routing table",
)
luCommand(
    "r1",
    'ip route show table 40 | wc -l',
    "19",
    "wait",
    "Check r1 r1-cust5 routing table",
)
luCommand(
    "r1",
    'ip route show table 40 | wc -l',
    "19",
    "pass",
    "Check r1 r1-cust5 routing table",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 29.0.0.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "wait",
    "Ping its own IP.",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 29.0.0.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "pass",
    "Ping its own IP. Check https://bugzilla.kernel.org/show_bug.cgi?id=203483 if it fails",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 192.168.1.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->R1(r1-cust1 - r1-eth4) ping",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 192.168.1.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->R1(r1-cust1 - r1-eth4) ping",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 192.168.1.2 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->CE1 ping",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 192.168.1.2 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->CE1 ping",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 99.0.0.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 99.0.0.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 5.1.0.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
luCommand(
    "r1",
    'ip vrf exec r1-cust5 bash -c "ping 5.1.0.1 -I 29.0.0.1 -c 1"',
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
