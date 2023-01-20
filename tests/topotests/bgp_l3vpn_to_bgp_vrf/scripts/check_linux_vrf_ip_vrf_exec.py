from lib.lutil import luCommand

luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 29.0.0.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "wait",
    "Ping its own IP.",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 29.0.0.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "pass",
    "Ping its own IP. Check https://bugzilla.kernel.org/show_bug.cgi?id=203483 if it fails",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 192.168.1.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->R1(r1-cust1 - r1-eth4) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 192.168.1.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->R1(r1-cust1 - r1-eth4) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 192.168.1.2 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->CE1 ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 192.168.1.2 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->CE1 ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 99.0.0.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 99.0.0.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 5.1.0.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "wait",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 5.1.0.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->CE1 (loopback) ping",
)
