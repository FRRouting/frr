from lib.lutil import luCommand, luLast

num = 50000
b = int(num / (256 * 256))
if b > 0:
    r = num - b * (256 * 256)
else:
    r = num
c = int(r / 256)
if c > 0:
    d = r - c * 256 - 1
else:
    d = r
wait = 2 * num / 1000
mem_z = {}
mem_b = {}
rtrs = ["ce1", "ce2", "ce3", "r1", "r2", "r3", "r4"]
for rtr in rtrs:
    mem_z[rtr] = {"value": 0, "units": "unknown"}
    mem_b[rtr] = {"value": 0, "units": "unknown"}
    ret = luCommand(
        rtr,
        'vtysh -c "show memory"',
        r"zebra: System allocator statistics:   Total heap allocated: *(\d*) ([A-Za-z]*) .*bgpd: System allocator statistics:   Total heap allocated: *(\d*) ([A-Za-z]*)",
        "none",
        "collect bgpd memory stats",
    )
    found = luLast()
    if ret != False and found != None:
        mem_z[rtr] = {"value": int(found.group(1)), "units": found.group(2)}
        mem_b[rtr] = {"value": int(found.group(3)), "units": found.group(4)}

luCommand(
    "ce1", 'vtysh -c "show mem"', "qmem sharpd", "none", "check if sharpd running"
)
doSharp = False
found = luLast()
if ret != False and found != None:
    if len(found.group()):
        doSharp = True

if doSharp != True:
    luCommand(
        "ce1",
        'vtysh -c "sharp data nexthop"',
        ".",
        "pass",
        "sharpd NOT running, skipping test",
    )
else:
    luCommand(
        "ce1",
        'vtysh -c "sharp install routes 10.0.0.0 nexthop 99.0.0.1 {}"'.format(num),
        "",
        "pass",
        "Adding {} routes".format(num),
    )
    luCommand(
        "ce2",
        'vtysh -c "sharp install routes 10.0.0.0 nexthop 99.0.0.2 {}"'.format(num),
        "",
        "pass",
        "Adding {} routes".format(num),
    )
    luCommand(
        "ce1",
        'vtysh -c "show ip route summ" | grep "sharp" | cut -d " " -f 33',
        str(num),
        "wait",
        "See all sharp routes in rib on ce1",
        wait,
        wait_time=10,
        )
    luCommand(
        "ce2",
        'vtysh -c "show ip route summ" | grep "sharp" | cut -d " " -f 33',
        str(num),
        "wait",
        "See all sharp routes in rib on ce2",
        wait,
        wait_time=10,
        )

    rtrs = ["ce1", "ce2", "ce3"]
    for rtr in rtrs:
        luCommand(
            rtr,
            'vtysh -c "show bgp ipv4 uni 10.{}.{}.{}"'.format(b, c, d),
            "Last update:",
            "wait",
            "RXed last route, 10.{}.{}.{}".format(b, c, d),
            wait,
            wait_time=10,
        )
        luCommand(
            rtr,
            'vtysh -c "show bgp ipv4 uni" | grep -c 10\\.\\*/32',
            str(num),
            "wait",
            "See all sharp routes in BGP",
            wait,
            wait_time=10,
        )
    luCommand(
        "r1",
        'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 10.{}.{}.{}"'.format(b, c, d),
        "99.0.0.1",
        "wait",
        "RXed -> 10.{}.{}.{} from CE1".format(b, c, d),
        wait,
        wait_time=10,
    )
    luCommand(
        "r3",
        'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 10.{}.{}.{}"'.format(b, c, d),
        "99.0.0.2",
        "wait",
        "RXed -> 10.{}.{}.{} from CE2".format(b, c, d),
        wait,
        wait_time=10,
    )
    luCommand(
        "r1",
        'vtysh -c "show bgp  ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
        "99.0.0.1",
        "wait",
        "see VPN safi -> 10.{}.{}.{} from CE1".format(b, c, d),
    )
    luCommand(
        "r3",
        'vtysh -c "show bgp  ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
        "99.0.0.2",
        "wait",
        "see VPN safi -> 10.{}.{}.{} from CE2".format(b, c, d),
    )
    luCommand(
        "r3",
        'vtysh -c "show bgp  ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
        "1.1.1.1",
        "wait",
        "see VPN safi -> 10.{}.{}.{} from CE1".format(b, c, d),
    )
    luCommand(
        "r1",
        'vtysh -c "show bgp  ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
        "3.3.3.3",
        "wait",
        "see VPN safi -> 10.{}.{}.{} from CE2".format(b, c, d),
    )
    luCommand(
        "r4",
        'vtysh -c "show bgp  ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
        "1.1.1.1",
        "wait",
        "see VPN safi -> 10.{}.{}.{} from CE1".format(b, c, d),
    )
    luCommand(
        "r4",
        'vtysh -c "show bgp  ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
        "3.3.3.3",
        "wait",
        "see VPN safi -> 10.{}.{}.{} from CE2".format(b, c, d),
    )
    rtrs = ["ce1", "ce2", "ce3"]
    for rtr in rtrs:
        luCommand(
            rtr,
            "ip route get 10.{}.{}.{}".format(b, c, d),
            "dev",
            "wait",
            "Route to 10.{}.{}.{} available".format(b, c, d),
            wait,
            wait_time=10,
        )
        luCommand(
            rtr,
            "ip route show | grep -c \\^10\\.",
            str(num),
            "wait",
            "See {} linux routes".format(num),
            wait,
            wait_time=10,
        )

    rtrs = ["r1", "r3", "r4"]
    for rtr in rtrs:
        luCommand(
            rtr,
            "ip route get vrf {}-cust1 10.{}.{}.{}".format(rtr, b, c, d),
            "dev",
            "wait",
            "VRF route available",
            wait,
            wait_time=10,
        )
        luCommand(
            rtr,
            "ip route show vrf {}-cust1 | grep -c \\^10\\.".format(rtr),
            str(num),
            "wait",
            "See {} linux routes".format(num),
            wait,
            wait_time=10,
        )
    rtrs = ["ce1", "ce2", "ce3", "r1", "r2", "r3", "r4"]
    for rtr in rtrs:
        ret = luCommand(
            rtr,
            'vtysh -c "show memory"',
            r"zebra: System allocator statistics:   Total heap allocated: *(\d*) ([A-Za-z]*) .*bgpd: System allocator statistics:   Total heap allocated: *(\d*) ([A-Za-z]*)",
            "none",
            "collect bgpd memory stats",
        )
        found = luLast()
        if ret != False and found != None:
            val_z = int(found.group(1))
            if mem_z[rtr]["units"] != found.group(2):
                val_z *= 1000
            delta_z = val_z - int(mem_z[rtr]["value"])
            ave_z = float(delta_z) / float(num)

            val_b = int(found.group(3))
            if mem_b[rtr]["units"] != found.group(4):
                val_b *= 1000
            delta_b = val_b - int(mem_b[rtr]["value"])
            ave_b = float(delta_b) / float(num)
            luCommand(
                rtr,
                'vtysh -c "show event cpu"',
                ".",
                "pass",
                "BGPd heap: {0} {1} --> {2} {3} ({4} {1}/vpn route)".format(
                    mem_b[rtr]["value"],
                    mem_b[rtr]["units"],
                    found.group(3),
                    found.group(4),
                    round(ave_b, 4),
                ),
            )
            luCommand(
                rtr,
                'vtysh -c "show event cpu"',
                ".",
                "pass",
                "Zebra heap: {0} {1} --> {2} {3} ({4} {1}/vpn route)".format(
                    mem_z[rtr]["value"],
                    mem_z[rtr]["units"],
                    found.group(1),
                    found.group(2),
                    round(ave_z, 4),
                ),
            )
# done
