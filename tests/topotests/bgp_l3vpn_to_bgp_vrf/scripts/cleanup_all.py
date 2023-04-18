from lib.lutil import luCommand

luCommand(
    "r1",
    'vtysh -c "clear vrf r1-cust1 prefix 99.0.0.1/32"',
    ".",
    "none",
    "Cleared VRF route",
)
luCommand(
    "r3",
    'vtysh -c "clear vrf r3-cust1 prefix 99.0.0.2/32"',
    ".",
    "none",
    "Cleared VRF route",
)
luCommand(
    "r4",
    'vtysh -c "clear vrf r3-cust1 prefix 99.0.0.3/32"',
    ".",
    "none",
    "Cleared VRF route",
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.1",
    "fail",
    "Local Registration cleared",
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.2",
    "fail",
    "Local Registration cleared",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.3",
    "fail",
    "Local Registration cleared",
)
luCommand(
    "r1",
    'vtysh -c "show bgp ipv4 uni"',
    "2 routes and 2",
    "wait",
    "Unicast SAFI updated",
    10,
)
luCommand(
    "r2",
    'vtysh -c "show bgp ipv4 uni"',
    "No BGP prefixes displayed",
    "pass",
    "Unicast SAFI",
)
luCommand(
    "r3",
    'vtysh -c "show bgp ipv4 uni"',
    "2 routes and 2",
    "wait",
    "Unicast SAFI updated",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp ipv4 uni"',
    "2 routes and 2",
    "wait",
    "Unicast SAFI updated",
    10,
)
luCommand(
    "ce1",
    'vtysh -c "show bgp ipv4 uni"',
    "2 routes and 2",
    "wait",
    "Local and remote routes",
    10,
)
luCommand(
    "ce2",
    'vtysh -c "show bgp ipv4 uni"',
    "2 routes and 2",
    "wait",
    "Local and remote routes",
    10,
)
luCommand(
    "ce3",
    'vtysh -c "show bgp ipv4 uni"',
    "2 routes and 2",
    "wait",
    "Local and remote routes",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations remote"',
    "Prefix ",
    "fail",
    "Remote Registration cleared",
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations remote"',
    "Prefix ",
    "fail",
    "Remote Registration cleared",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations remote"',
    "Prefix ",
    "fail",
    "Remote Registration cleared",
)
