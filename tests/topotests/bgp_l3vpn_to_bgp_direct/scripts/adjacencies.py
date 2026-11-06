from lib.checkping import check_ping
from lib.lutil import luCommand

check_ping("ce1", "192.168.1.1", True, 10, 1)
check_ping("ce2", "192.168.1.1", True, 10, 1)
check_ping("ce3", "192.168.1.1", True, 10, 1)
luCommand("ce1", 'vtysh -c "show bgp summary"', " 00:0", "wait", "Adjacencies up", 180)
luCommand("ce2", 'vtysh -c "show bgp summary"', " 00:0", "wait", "Adjacencies up", 180)
luCommand("ce3", 'vtysh -c "show bgp summary"', " 00:0", "wait", "Adjacencies up", 180)
luCommand(
    "r1",
    'vtysh -c "show ip route ospf"',
    "2.2.2.2",
    "wait",
    "OSPF Route has Arrived",
    60,
)
check_ping("r1", "2.2.2.2", True, 60, 1)
luCommand(
    "r3",
    'vtysh -c "show ip route ospf"',
    "2.2.2.2",
    "wait",
    "OSPF Route has Arrived",
    60,
)
check_ping("r3", "2.2.2.2", True, 60, 1)

luCommand(
    "r4",
    'vtysh -c "show ip route ospf"',
    "2.2.2.2",
    "wait",
    "OSPF Route has Arrived",
    60,
)
check_ping("r4", "2.2.2.2", True, 60, 1)
luCommand(
    "r2",
    'vtysh -c "show bgp summary"',
    " 00:0.* 00:0.* 00:0",
    "wait",
    "Core adjacencies up",
    180,
)
luCommand(
    "r1", 'vtysh -c "show bgp summary"', " 00:0", "wait", "Core adjacencies up", 180
)
luCommand(
    "r3", 'vtysh -c "show bgp summary"', " 00:0", "wait", "Core adjacencies up", 180
)
luCommand(
    "r4", 'vtysh -c "show bgp summary"', " 00:0", "wait", "Core adjacencies up", 180
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf all summary"',
    " 00:0.* 00:0",
    "pass",
    "All adjacencies up",
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf all summary"',
    " 00:0.* 00:0",
    "pass",
    "All adjacencies up",
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf all summary"',
    " 00:0.* 00:0",
    "pass",
    "All adjacencies up",
)
check_ping("r1", "3.3.3.3", True, 10, 1)
check_ping("r1", "4.4.4.4", True, 10, 1)
check_ping("r4", "3.3.3.3", True, 10, 1)
