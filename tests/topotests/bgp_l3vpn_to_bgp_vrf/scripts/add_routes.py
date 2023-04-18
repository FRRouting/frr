from lib.lutil import luCommand

luCommand(
    "r1", 'vtysh -c "add vrf r1-cust1 prefix 99.0.0.1/32"', ".", "none", "IP Address"
)
luCommand(
    "r3", 'vtysh -c "add vrf r3-cust1 prefix 99.0.0.2/32"', ".", "none", "IP Address"
)
luCommand(
    "r4", 'vtysh -c "add vrf r4-cust1 prefix 99.0.0.3/32"', ".", "none", "IP Address"
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.1",
    "pass",
    "Local Registration",
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.2",
    "pass",
    "Local Registration",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations local"',
    "99.0.0.3",
    "pass",
    "Local Registration",
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations remote"',
    "4 out of 4",
    "wait",
    "Remote Registration",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations remote"',
    "6 out of 6",
    "wait",
    "Remote Registration",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations remote"',
    "4 out of 4",
    "wait",
    "Remote Registration",
    10,
)
luCommand("r1", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r3", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r4", 'vtysh -c "show vnc registrations"', ".", "none")
