from lib.checkping import check_ping
from lib.lutil import luCommand

check_ping("r1", "2.2.2.2", True, 60, 1)
check_ping("r3", "2.2.2.2", True, 60, 1)
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
    "r1",
    'vtysh -c "show bgp vrf all summary"',
    " 00:0",
    "wait",
    "All adjacencies up",
    180,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf all summary"',
    " 00:0",
    "wait",
    "All adjacencies up",
    180,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf all summary"',
    " 00:0",
    "wait",
    "All adjacencies up",
    180,
)
check_ping("r1", "3.3.3.3", True, 10, 1)
check_ping("r1", "4.4.4.4", True, 10, 1)
# luCommand('r4','ping 3.3.3.3 -c 1',' 0. packet loss','wait','PE->PE3 (loopback) ping')
