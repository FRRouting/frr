from lib.lutil import luCommand
from time import sleep

luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11 vrf r1-cust1" -c "address-family ipv4 unicast" -c "redistribute vrf r1-cust2"',
    ".",
    "none",
    "Config ip nht route-map",
)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "47 routes and 88", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11 vrf r1-cust2" -c "address-family ipv4 unicast" -c "redistribute vrf r1-cust1"',
    ".",
    "none",
    "Config ip nht route-map",
)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "47 routes and 88", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "47 routes and 88", "wait", "Local and remote routes",)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11 vrf r1-cust2" -c "address-family ipv4 unicast" -c "no redistribute vrf r1-cust1"',
    ".",
    "none",
    "Config ip nht route-map",
)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "47 routes and 88", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11 vrf r1-cust1" -c "address-family ipv4 unicast" -c "no redistribute vrf r1-cust2"',
    ".",
    "none",
    "Config ip nht route-map",
)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11 vrf r1-cust1" -c "address-family ipv4 unicast" -c "redistribute vrf r1-cust2 route-map ip-redistribute-map"',
    ".",
    "none",
    "Config ip nht route-map",
)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "44 routes and 55", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "ip prefix-list ip_redistribute seq 110 permit 10.202.0.0/24"',
    "none",
    "Config ip nht route-map",
)
sleep(8)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "44 routes and 56", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "no ip prefix-list ip_redistribute seq 110 permit 10.202.0.0/24"',
    "none",
    "Config ip nht route-map",
)
sleep(8)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "44 routes and 55", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11 vrf r1-cust1" -c "address-family ipv4 unicast" -c "no redistribute vrf r1-cust2 route-map ip-redistribute-map"',
    ".",
    "none",
    "Config ip nht route-map",
)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust1 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)
luCommand("r1", 'vtysh -c "show bgp vrf r1-cust2 ipv4 uni"', "44 routes and 45", "wait", "Local and remote routes",)