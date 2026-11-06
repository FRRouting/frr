from lib.checkping import check_ping
from lib.lutil import luCommand, luLast
from lib import topotest

ret = luCommand(
    "r2",
    "ip -M route show",
    r"\d*(?= via inet 10.0.2.4 dev r2-eth1)",
    "wait",
    "See mpls route to r4",
)
found = luLast()

if ret != False and found != None:
    label4r4 = found.group(0)
    luCommand("r2", "ip -M route show", ".", "pass", "See %s as label to r4" % label4r4)
    ret = luCommand(
        "r2",
        "ip -M route show",
        r"\d*(?= via inet 10.0.1.1 dev r2-eth0)",
        "wait",
        "See mpls route to r1",
    )
    found = luLast()

if ret != False and found != None:
    label4r1 = found.group(0)
    luCommand("r2", "ip -M route show", ".", "pass", "See %s as label to r1" % label4r1)

    luCommand(
        "r1",
        "ip route show vrf r1-cust1",
        "99.0.0.4",
        "pass",
        "VRF->MPLS PHP route installed",
    )
    luCommand(
        "r4",
        "ip route show vrf r4-cust2",
        "99.0.0.1",
        "pass",
        "VRF->MPLS PHP route installed",
    )

    luCommand("r1", "ip -M route show", "101", "pass", "MPLS->VRF route installed")
    luCommand("r4", "ip -M route show", "1041", "pass", "MPLS->VRF1 route installed")
    luCommand("r4", "ip -M route show", "1042", "pass", "MPLS->VRF2 route installed")

    check_ping("ce1", "99.0.0.4", True, 10, 1, "99.0.0.1")
    # skip due to VRF weirdness
    # luCommand('ce4', 'ping 99.0.0.1 -I 99.0.0.4 -c 1',
    # 	' 0. packet loss','wait','CE->CE (loopback) ping - l3vpn+zebra case')

    check_ping("ce1", "99.0.0.4", True, 10, 1, "99.0.0.1")
    # luCommand('ce4', 'ping 99.0.0.1 -I 99.0.0.4 -c 1',
    # 	' 0. packet loss','wait','CE->CE (loopback) ping')

    luCommand("r3", "ip -M route show", "103", "pass", "MPLS->VRF route installed")
    check_ping("ce2", "99.0.0.3", True, 10, 1, "99.0.0.2")
    check_ping("ce3", "99.0.0.4", True, 10, 1, "99.0.0.3")
