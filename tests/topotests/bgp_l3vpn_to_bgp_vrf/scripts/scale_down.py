from lib.lutil import luCommand, luLast

ret = luCommand(
    "ce1",
    'vtysh -c "show ip route" | grep -c \\ 10\\.\\*/32',
    "(.*)",
    "pass",
    "Looking for sharp routes",
)
found = luLast()
if ret != False and found != None:
    num = int(found.group())
    luCommand(
        "ce3", 'vtysh -c "show bgp sum"', ".", "pass", "See %s sharp routes" % num
    )
    if num > 0:
        rtrs = ["ce1", "ce2", "ce3"]
        for rtr in rtrs:
            luCommand(
                rtr,
                'vtysh -c "show bgp ipv4 uni" | grep Display',
                ".",
                "none",
                "BGP routes pre remove",
            )
            luCommand(
                rtr,
                "ip route show | cat -n | tail",
                ".",
                "none",
                "Linux routes pre remove",
            )
        wait = 2 * num / 500
        luCommand(
            "ce1",
            'vtysh -c "sharp remove routes 10.0.0.0 {}"'.format(num),
            ".",
            "none",
            "Removing {} routes".format(num),
        )
        luCommand(
            "ce2",
            'vtysh -c "sharp remove routes 10.0.0.0 {}"'.format(num),
            ".",
            "none",
            "Removing {} routes".format(num),
        )
        for rtr in rtrs:
            luCommand(
                rtr,
                'vtysh -c "show bgp ipv4 uni" | grep Display',
                " 14 route",
                "wait",
                "BGP routes removed",
                wait,
                wait_time=10,
            )
            luCommand(
                rtr,
                'vtysh -c "show bgp ipv4 uni"',
                ".",
                "none",
                "BGP routes post remove",
            )
        for rtr in rtrs:
            luCommand(
                rtr,
                "ip route show | grep -c \\^10\\.",
                "^0$",
                "wait",
                "Linux routes removed",
                wait,
                wait_time=10,
            )
            luCommand(rtr, "ip route show", ".", "none", "Linux routes post remove")
        rtrs = ["r1", "r3", "r4"]
        for rtr in rtrs:
            luCommand(
                rtr,
                "ip route show vrf {}-cust1 | grep -c \\^10\\.".format(rtr),
                "^0$",
                "wait",
                "VRF route removed",
                wait,
                wait_time=10,
            )
# done
