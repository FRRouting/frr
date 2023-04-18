from lib.lutil import luCommand

luCommand("r1", 'vtysh -c "show bgp ipv4 vpn"', "", "none", "VPN SAFI")
luCommand("r2", 'vtysh -c "show bgp ipv4 vpn"', "", "none", "VPN SAFI")
luCommand("r3", 'vtysh -c "show bgp ipv4 vpn"', "", "none", "VPN SAFI")
luCommand("r4", 'vtysh -c "show bgp ipv4 vpn"', "", "none", "VPN SAFI")
luCommand(
    "r1",
    'vtysh -c "show vnc registrations"',
    "Locally: *Active:  1 .* Remotely: *Active:  3",
    "wait",
    "See all registrations",
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations"',
    "Locally: *Active:  1 .* Remotely: *Active:  3",
    "wait",
    "See all registrations",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations"',
    "Locally: *Active:  2 .* Remotely: *Active:  2",
    "wait",
    "See all registrations",
)
num = "4 routes and 4"
luCommand("r1", 'vtysh -c "show bgp ipv4 vpn"', num, "pass", "VPN SAFI okay")
luCommand("r2", 'vtysh -c "show bgp ipv4 vpn"', num, "pass", "VPN SAFI okay")
luCommand("r3", 'vtysh -c "show bgp ipv4 vpn"', num, "pass", "VPN SAFI okay")
luCommand("r4", 'vtysh -c "show bgp ipv4 vpn"', num, "pass", "VPN SAFI okay")
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.1 un 1.1.1.1 target 22.22.22.22"',
    "pfx=",
    "pass",
    "Query R2s info",
)
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.1 un 1.1.1.1 target 33.33.33.33"',
    "pfx=",
    "pass",
    "Query R4s info",
)
luCommand(
    "r3",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.2 un 2.2.2.2 target 11.11.11.11"',
    "11.11.11.0/24.*11.11.11.0/24.*",
    "pass",
    "Query R1s+R4s info",
)
luCommand(
    "r3",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.2 un 2.2.2.2 target 33.33.33.33"',
    "pfx=",
    "pass",
    "Query R4s info",
)
luCommand(
    "r4",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.3 un 3.3.3.3 target 11.11.11.11"',
    "11.11.11.0/24.*11.11.11.0/24.*",
    "pass",
    "Query R1s+R4s info",
)
luCommand(
    "r4",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.3 un 3.3.3.3 target 22.22.22.22"',
    "pfx=",
    "pass",
    "Query R2s info",
)
