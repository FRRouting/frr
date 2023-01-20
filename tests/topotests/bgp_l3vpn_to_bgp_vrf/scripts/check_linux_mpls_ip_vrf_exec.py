from lib.lutil import luCommand

luCommand(
    "r1",
    "ip vrf exec r1-cust1 ping 6.0.3.1 -I 192.168.131.6 -c 1",
    " 0. packet loss",
    "wait",
    "R1(r1-cust1)->CE3/4 (loopback) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust1 ping 6.0.3.1 -I 192.168.131.6 -c 1",
    " 0. packet loss",
    "pass",
    "R1(r1-cust1)->CE3/4 (loopback) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust1 ping 6.0.3.1 -I 192.168.131.6 -c 1",
    " 0. packet loss",
    "wait",
    "R1(r1-cust1)->CE3/4 (loopback) ping",
)
luCommand(
    "r1",
    "ip vrf exec r1-cust5 ping 6.0.3.1 -I 29.0.0.1 -c 1",
    " 0. packet loss",
    "pass",
    "R1(r1-cust5)->CE3/4 ( (loopback) ping",
)
