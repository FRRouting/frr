from lib.lutil import luCommand

luCommand(
    "r1", 'vtysh -c "show bgp nexthop"', "99.0.0.. valid", "wait", "See CE static NH"
)
luCommand(
    "r3", 'vtysh -c "show bgp nexthop"', "99.0.0.. valid", "wait", "See CE static NH"
)
luCommand(
    "r4", 'vtysh -c "show bgp nexthop"', "99.0.0.. valid", "wait", "See CE static NH"
)
luCommand("r1", 'vtysh -c "show bgp ipv4 uni"', "i 5.*i 5", "wait", "See CE routes")
luCommand("r3", 'vtysh -c "show bgp ipv4 uni"', "i 5.*i 5", "wait", "See CE routes")
luCommand("r4", 'vtysh -c "show bgp ipv4 uni"', "i 5.*i 5", "wait", "See CE routes")
luCommand("ce1", 'vtysh -c "show bgp ipv4 uni 5.1.0.0/24"', "", "none", "See CE routes")
luCommand("r1", 'vtysh -c "show bgp ipv4 uni 5.1.0.0/24"', "", "none", "See CE routes")
luCommand("ce2", 'vtysh -c "show bgp ipv4 uni 5.1.0.0/24"', "", "none", "See CE routes")
luCommand("r3", 'vtysh -c "show bgp ipv4 uni 5.1.0.0/24"', "", "none", "See CE routes")
luCommand("ce3", 'vtysh -c "show bgp ipv4 uni 5.1.2.0/24"', "", "none", "See CE routes")
luCommand("r4", 'vtysh -c "show bgp ipv4 uni 5.1.2.0/24"', "", "none", "See CE routes")

luCommand(
    "r1", 'vtysh -c "add vrf cust1 prefix 99.0.0.1/32"', ".", "none", "IP Address"
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.1",
    "wait",
    "Local Registration",
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations imported"',
    "2 out of 2 imported",
    "wait",
    "Imported Registrations",
)
luCommand(
    "r3",
    'vtysh -c "show bgp ipv4 vpn"',
    "i 99.0.0.1/32",
    "wait",
    "See R1s static address",
)
luCommand(
    "r4",
    'vtysh -c "show bgp ipv4 vpn"',
    "i 99.0.0.1/32",
    "wait",
    "See R1s static address",
)
luCommand(
    "r3", 'vtysh -c "show bgp ipv4 vpn rd 10:1"', "i 5.*i 5", "wait", "See R1s imports"
)
luCommand(
    "r4", 'vtysh -c "show bgp ipv4 vpn rd 10:1"', "i 5.*i 5", "wait", "See R1s imports"
)

luCommand(
    "r3", 'vtysh -c "add vrf cust1 prefix 99.0.0.2/32"', ".", "none", "IP Address"
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.2",
    "wait",
    "Local Registration",
)
have2ndImports = luCommand(
    "r3",
    'vtysh -c "show vnc registrations imported"',
    "2 out of 2 imported",
    "none",
    "Imported Registrations",
    2,
)
if have2ndImports:
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations imported"',
        "2 out of 2 imported",
        "pass",
        "Imported Registrations",
    )
luCommand(
    "r1",
    'vtysh -c "show bgp ipv4 vpn"',
    "i 99.0.0.2/32",
    "wait",
    "See R3s static address",
)
luCommand(
    "r4",
    'vtysh -c "show bgp ipv4 vpn"',
    "i 99.0.0.2/32",
    "wait",
    "See R3s static address",
)
if have2ndImports:
    luCommand(
        "r1",
        'vtysh -c "show bgp ipv4 vpn rd 10:3"',
        "i 5.*i 5",
        "none",
        "See R3s imports",
    )
    luCommand(
        "r4",
        'vtysh -c "show bgp ipv4 vpn rd 10:3"',
        "i 5.*i 5",
        "none",
        "See R3s imports",
    )

luCommand(
    "r4", 'vtysh -c "add vrf cust1 prefix 99.0.0.3/32"', ".", "none", "IP Address"
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.3",
    "wait",
    "Local Registration",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations imported"',
    "2 out of 2 imported",
    "wait",
    "Imported Registrations",
)
luCommand(
    "r1",
    'vtysh -c "show bgp ipv4 vpn"',
    "i 99.0.0.3/32",
    "wait",
    "See R4s static address",
)
luCommand(
    "r3",
    'vtysh -c "show bgp ipv4 vpn"',
    "i 99.0.0.3/32",
    "wait",
    "See R4s static address",
)
luCommand(
    "r1", 'vtysh -c "show bgp ipv4 vpn rd 10:4"', "i 5.*i 5", "wait", "See R4s imports"
)
luCommand(
    "r3", 'vtysh -c "show bgp ipv4 vpn rd 10:4"', "i 5.*i 5", "wait", "See R4s imports"
)


luCommand(
    "r1",
    'vtysh -c "show vnc registrations remote"',
    "5.1.2.0/24 .*5.1.3.0/24",
    "wait",
    "R4s registrations",
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations remote"',
    "5.1.2.0/24 .*5.1.3.0/24",
    "wait",
    "R4s registrations",
)
if have2ndImports:
    luCommand(
        "r1",
        'vtysh -c "show vnc registrations remote"',
        "5.1.0.0/24 .*5.1.1.0/24",
        "wait",
        "Remote registrations",
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations remote"',
        "5.1.0.0/24 .*5.1.1.0/24",
        "wait",
        "Remote registrations",
    )
luCommand(
    "r4",
    'vtysh -c "show vnc registrations remote"',
    "5.1.0.0/24 .*5.1.1.0/24",
    "wait",
    "Remote registrations",
)
luCommand("r1", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r3", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r4", 'vtysh -c "show vnc registrations"', ".", "none")
