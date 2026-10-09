from lib.lutil import luCommand

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "no router bgp 5227 vrf r1-cust1" -c "no router bgp 5226"',
    ".",
    "none",
    "Cleared bgp instances",
)
luCommand(
    "r2",
    'vtysh -c "conf ter" -c "no router bgp 5226"',
    ".",
    "none",
    "Cleared bgp instances",
)
luCommand(
    "r3",
    'vtysh -c "conf ter" -c "no router bgp 5227 vrf r3-cust1" -c "no router bgp 5226"',
    ".",
    "none",
    "Cleared bgp instances",
)
luCommand(
    "r4",
    'vtysh -c "conf ter" -c "no router bgp 5228 vrf r4-cust2" -c "no router bgp 5227 vrf r4-cust1"  -c "no router bgp 5226"',
    ".",
    "none",
    "Cleared bgp instances",
)
