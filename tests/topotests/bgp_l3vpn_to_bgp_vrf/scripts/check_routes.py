from lib.lutil import luCommand
from lib.bgprib import bgpribRequireVpnRoutes, bgpribRequireUnicastRoutes

########################################################################
# CE routers: contain routes they originate
########################################################################
#
# mininet CLI commands
# ce1 vtysh -c "show bgp ipv4 uni"
# ce2 vtysh -c "show bgp ipv4 uni"
# ce3 vtysh -c "show bgp ipv4 uni"
# ce4 vtysh -c "show bgp ipv4 uni"

want = [
    {"p": "5.1.0.0/24", "n": "99.0.0.1"},
    {"p": "5.1.1.0/24", "n": "99.0.0.1"},
    {"p": "6.0.1.0/24", "n": "99.0.0.1"},
    {"p": "6.0.2.0/24", "n": "99.0.0.1"},
    {"p": "99.0.0.1/32", "n": "0.0.0.0"},
]
bgpribRequireUnicastRoutes("ce1", "ipv4", "", "Cust 1 routes in ce1", want)

want = [
    {"p": "5.1.0.0/24", "n": "99.0.0.2"},
    {"p": "5.1.1.0/24", "n": "99.0.0.2"},
    {"p": "6.0.1.0/24", "n": "99.0.0.2"},
    {"p": "6.0.2.0/24", "n": "99.0.0.2"},
    {"p": "99.0.0.2/32", "n": "0.0.0.0"},
]
bgpribRequireUnicastRoutes("ce2", "ipv4", "", "Cust 2 routes in ce1", want)

want = [
    {"p": "5.1.2.0/24", "n": "99.0.0.3"},
    {"p": "5.1.3.0/24", "n": "99.0.0.3"},
    {"p": "6.0.1.0/24", "n": "99.0.0.3"},
    {"p": "6.0.2.0/24", "n": "99.0.0.3"},
    {"p": "99.0.0.3/32", "n": "0.0.0.0"},
]
bgpribRequireUnicastRoutes("ce3", "ipv4", "", "Cust 3 routes in ce1", want)

want = [
    {"p": "5.4.2.0/24", "n": "99.0.0.4"},
    {"p": "5.4.3.0/24", "n": "99.0.0.4"},
    {"p": "6.0.1.0/24", "n": "99.0.0.4"},
    {"p": "6.0.2.0/24", "n": "99.0.0.4"},
    {"p": "99.0.0.4/32", "n": "0.0.0.0"},
]
bgpribRequireUnicastRoutes("ce4", "ipv4", "ce4-cust2", "Cust 4 routes in ce1", want)


########################################################################
# PE routers: VRFs contain routes from locally-attached customer nets
########################################################################
#
# r1 vtysh -c "show bgp vrf r1-cust1 ipv4"
#
want_r1_cust1_routes = [
    {"p": "5.1.0.0/24", "n": "99.0.0.1"},
    {"p": "5.1.1.0/24", "n": "99.0.0.1"},
    {"p": "6.0.1.0/24", "n": "99.0.0.1"},
    {"p": "6.0.2.0/24", "n": "99.0.0.1"},
    {"p": "172.16.0.0/24", "n": "0.0.0.0", "bp": True},
    {"p": "172.16.1.1/32", "n": "0.0.0.0", "bp": True},
    {"p": "99.0.0.1/32", "n": "192.168.1.2"},
]
bgpribRequireUnicastRoutes(
    "r1", "ipv4", "r1-cust1", "Customer 1 routes in r1 vrf", want_r1_cust1_routes
)

want_r1_cust4_routes = [
    {"p": "172.16.0.0/24", "n": "0.0.0.0", "bp": True},
]
bgpribRequireUnicastRoutes(
    "r1", "ipv4", "r1-cust4", "Customer 4 routes in r1 vrf", want_r1_cust4_routes
)

want_r1_cust5_routes = [
    {"p": "172.16.1.1/32", "n": "0.0.0.0", "bp": True},
]
bgpribRequireUnicastRoutes(
    "r1", "ipv4", "r1-cust5", "Customer 5 routes in r1 vrf", want_r1_cust5_routes
)

want_r3_cust1_routes = [
    {"p": "5.1.0.0/24", "n": "99.0.0.2"},
    {"p": "5.1.1.0/24", "n": "99.0.0.2"},
    {"p": "6.0.1.0/24", "n": "99.0.0.2"},
    {"p": "6.0.2.0/24", "n": "99.0.0.2"},
    {"p": "99.0.0.2/32", "n": "192.168.1.2"},
]
bgpribRequireUnicastRoutes(
    "r3", "ipv4", "r3-cust1", "Customer 1 routes in r3 vrf", want_r3_cust1_routes
)

want_r4_cust1_routes = [
    {"p": "5.1.2.0/24", "n": "99.0.0.3"},
    {"p": "5.1.3.0/24", "n": "99.0.0.3"},
    {"p": "6.0.1.0/24", "n": "99.0.0.3"},
    {"p": "6.0.2.0/24", "n": "99.0.0.3"},
    {"p": "99.0.0.3/32", "n": "192.168.1.2"},
]
bgpribRequireUnicastRoutes(
    "r4", "ipv4", "r4-cust1", "Customer 1 routes in r4 vrf", want_r4_cust1_routes
)

want_r4_cust2_routes = [
    {"p": "5.4.2.0/24", "n": "99.0.0.4"},
    {"p": "5.4.3.0/24", "n": "99.0.0.4"},
    {"p": "6.0.1.0/24", "n": "99.0.0.4"},
    {"p": "6.0.2.0/24", "n": "99.0.0.4"},
    {"p": "99.0.0.4/32", "n": "192.168.2.2"},
]
bgpribRequireUnicastRoutes(
    "r4", "ipv4", "r4-cust2", "Customer 2 routes in r4 vrf", want_r4_cust2_routes
)

########################################################################
# PE routers: core unicast routes are empty
########################################################################

luCommand(
    "r1",
    'vtysh -c "show bgp ipv4 uni"',
    "No BGP prefixes displayed",
    "pass",
    "Core Unicast SAFI clean",
)
luCommand(
    "r2",
    'vtysh -c "show bgp ipv4 uni"',
    "No BGP prefixes displayed",
    "pass",
    "Core Unicast SAFI clean",
)
luCommand(
    "r3",
    'vtysh -c "show bgp ipv4 uni"',
    "No BGP prefixes displayed",
    "pass",
    "Core Unicast SAFI clean",
)
luCommand(
    "r4",
    'vtysh -c "show bgp ipv4 uni"',
    "No BGP prefixes displayed",
    "pass",
    "Core Unicast SAFI clean",
)

########################################################################
# PE routers: local ce-originated routes are leaked to vpn
########################################################################

# nhzero is for the new code that sets nh of locally-leaked routes to 0
# nhzero = 1
nhzero = 0

if nhzero:
    luCommand(
        "r1",
        'vtysh -c "show bgp ipv4 vpn"',
        "Distinguisher:  *10:1.*5.1.0.0/24 *0.0.0.0 .*5.1.1.0/24 *0.0.0.0 .*99.0.0.1/32 *0.0.0.0 ",
        "pass",
        "vrf->vpn routes",
    )
    luCommand(
        "r3",
        'vtysh -c "show bgp ipv4 vpn"',
        "Distinguisher:  *10:3.*5.1.0.0/24 *0.0.0.0 .*5.1.1.0/24 *0.0.0.0 .*99.0.0.2/32 *0.0.0.0 ",
        "pass",
        "vrf->vpn routes",
    )
    want = [
        {"rd": "10:41", "p": "5.1.2.0/24", "n": "0.0.0.0"},
        {"rd": "10:41", "p": "5.1.3.0/24", "n": "0.0.0.0"},
        {"rd": "10:41", "p": "99.0.0.3/32", "n": "0.0.0.0"},
        {"rd": "10:42", "p": "5.4.2.0/24", "n": "0.0.0.0"},
        {"rd": "10:42", "p": "5.4.3.0/24", "n": "0.0.0.0"},
        {"rd": "10:42", "p": "99.0.0.4/32", "n": "0.0.0.0"},
    ]
    bgpribRequireVpnRoutes("r4", "vrf->vpn routes", want)

else:
    luCommand(
        "r1",
        'vtysh -c "show bgp ipv4 vpn"',
        r"Distinguisher:  *10:1.*5.1.0.0/24 *99.0.0.1\b.*5.1.1.0/24 *99.0.0.1\b.*6.0.1.0/24 *99.0.0.1\b.*6.0.2.0/24 *99.0.0.1\b.*99.0.0.1/32 *192.168.1.2\b",
        "pass",
        "vrf->vpn routes",
    )
    luCommand(
        "r3",
        'vtysh -c "show bgp ipv4 vpn"',
        r"Distinguisher:  *10:3.*5.1.0.0/24 *99.0.0.2\b.*5.1.1.0/24 *99.0.0.2\b.*6.0.1.0/24 *99.0.0.2\b.*6.0.2.0/24 *99.0.0.2\b.*99.0.0.2/32 *192.168.1.2\b",
        "pass",
        "vrf->vpn routes",
    )
    want = [
        {"rd": "10:41", "p": "5.1.2.0/24", "n": "99.0.0.3"},
        {"rd": "10:41", "p": "5.1.3.0/24", "n": "99.0.0.3"},
        {"rd": "10:41", "p": "6.0.1.0/24", "n": "99.0.0.3"},
        {"rd": "10:41", "p": "6.0.2.0/24", "n": "99.0.0.3"},
        {"rd": "10:41", "p": "99.0.0.3/32", "n": "192.168.1.2"},
        {"rd": "10:42", "p": "5.4.2.0/24", "n": "99.0.0.4"},
        {"rd": "10:42", "p": "5.4.3.0/24", "n": "99.0.0.4"},
        {"rd": "10:42", "p": "6.0.1.0/24", "n": "99.0.0.4"},
        {"rd": "10:42", "p": "6.0.2.0/24", "n": "99.0.0.4"},
        {"rd": "10:42", "p": "99.0.0.4/32", "n": "192.168.2.2"},
    ]
    bgpribRequireVpnRoutes("r4", "vrf->vpn routes", want)

########################################################################
# PE routers: exporting vrfs set MPLS vrf labels in kernel
########################################################################

luCommand(
    "r1", 'vtysh -c "show mpls table"', " 101 *BGP *r1-cust1", "pass", "vrf labels"
)
luCommand(
    "r3", 'vtysh -c "show mpls table"', " 103 *BGP *r3-cust1", "pass", "vrf labels"
)
luCommand(
    "r4",
    'vtysh -c "show mpls table"',
    " 1041 *BGP *r4-cust1 .*1042 *BGP *r4-cust2",
    "pass",
    "vrf labels",
)

########################################################################
# Core VPN router: all customer routes
########################################################################

want_rd_routes = [
    {"rd": "10:1", "p": "5.1.0.0/24", "n": "1.1.1.1"},
    {"rd": "10:1", "p": "5.1.0.0/24", "n": "1.1.1.1"},
    {"rd": "10:1", "p": "99.0.0.1/32", "n": "1.1.1.1"},
    {"rd": "10:3", "p": "5.1.0.0/24", "n": "3.3.3.3"},
    {"rd": "10:3", "p": "5.1.0.0/24", "n": "3.3.3.3"},
    {"rd": "10:3", "p": "99.0.0.2/32", "n": "3.3.3.3"},
    {"rd": "10:41", "p": "5.1.2.0/24", "n": "4.4.4.4"},
    {"rd": "10:41", "p": "5.1.3.0/24", "n": "4.4.4.4"},
    {"rd": "10:41", "p": "99.0.0.3/32", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "5.4.2.0/24", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "5.4.3.0/24", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "99.0.0.4/32", "n": "4.4.4.4"},
]
bgpribRequireVpnRoutes("r2", "Customer routes in provider vpn core", want_rd_routes)

########################################################################
# PE routers: VPN routes from remote customers
########################################################################
#
# r1 vtysh -c "show bgp ipv4 vpn"
#
want_r1_remote_vpn_routes = [
    {"rd": "10:3", "p": "5.1.0.0/24", "n": "3.3.3.3"},
    {"rd": "10:3", "p": "5.1.1.0/24", "n": "3.3.3.3"},
    {"rd": "10:3", "p": "99.0.0.2/32", "n": "3.3.3.3"},
    {"rd": "10:41", "p": "5.1.2.0/24", "n": "4.4.4.4"},
    {"rd": "10:41", "p": "5.1.3.0/24", "n": "4.4.4.4"},
    {"rd": "10:41", "p": "99.0.0.3/32", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "5.4.2.0/24", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "5.4.3.0/24", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "99.0.0.4/32", "n": "4.4.4.4"},
]
bgpribRequireVpnRoutes(
    "r1", "Remote Customer routes in R1 vpn", want_r1_remote_vpn_routes
)

want_r3_remote_vpn_routes = [
    {"rd": "10:1", "p": "5.1.0.0/24", "n": "1.1.1.1"},
    {"rd": "10:1", "p": "5.1.1.0/24", "n": "1.1.1.1"},
    {"rd": "10:1", "p": "99.0.0.1/32", "n": "1.1.1.1"},
    {"rd": "10:41", "p": "5.1.2.0/24", "n": "4.4.4.4"},
    {"rd": "10:41", "p": "5.1.3.0/24", "n": "4.4.4.4"},
    {"rd": "10:41", "p": "99.0.0.3/32", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "5.4.2.0/24", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "5.4.3.0/24", "n": "4.4.4.4"},
    {"rd": "10:42", "p": "99.0.0.4/32", "n": "4.4.4.4"},
]
bgpribRequireVpnRoutes(
    "r3", "Remote Customer routes in R3 vpn", want_r3_remote_vpn_routes
)

want_r4_remote_vpn_routes = [
    {"rd": "10:1", "p": "5.1.0.0/24", "n": "1.1.1.1"},
    {"rd": "10:1", "p": "5.1.1.0/24", "n": "1.1.1.1"},
    {"rd": "10:1", "p": "99.0.0.1/32", "n": "1.1.1.1"},
    {"rd": "10:3", "p": "5.1.0.0/24", "n": "3.3.3.3"},
    {"rd": "10:3", "p": "5.1.1.0/24", "n": "3.3.3.3"},
    {"rd": "10:3", "p": "99.0.0.2/32", "n": "3.3.3.3"},
]
bgpribRequireVpnRoutes(
    "r4", "Remote Customer routes in R4 vpn", want_r4_remote_vpn_routes
)


# r1 vtysh -c "show bgp vrf r1-cust1 ipv4"
########################################################################
# PE routers: VRFs contain routes from remote customer nets
########################################################################
# First let's spot check and ensure that some of the routes
# have showed up and been best path'd
# After the first two are good.  It's probably ok
# to look at the rest of the routes in the vrf
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 5.1.0.0/24"',
    "2 available, best",
    "wait",
    "Ensure 5.1.0.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 5.1.1.0/24"',
    "2 available, best",
    "wait",
    "Ensure 5.1.1.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 5.1.2.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.1.2.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 5.1.3.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.1.3.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 5.4.2.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.4.2.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 5.4.2.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.4.3.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 6.0.1.0/24"',
    "4 available, best",
    "wait",
    "Ensure 6.0.1.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 6.0.2.0/24"',
    "4 available, best",
    "wait",
    "Ensure 6.0.2.0 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 99.0.0.1/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.1 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 99.0.0.2/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.2 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 99.0.0.3/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.3 shows up on r1",
    10,
)
luCommand(
    "r1",
    'vtysh -c "show bgp vrf r1-cust1 ipv4 uni 99.0.0.4/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.4 shows up on r1",
    10,
)
want_r1_remote_cust1_routes = [
    {"p": "5.1.0.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "5.1.0.0/24", "n": "99.0.0.1", "bp": True},
    {"p": "5.1.1.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "5.1.1.0/24", "n": "99.0.0.1", "bp": True},
    {"p": "5.1.2.0/24", "n": "4.4.4.4"},
    {"p": "5.1.3.0/24", "n": "4.4.4.4"},
    {"p": "5.4.2.0/24", "n": "4.4.4.4"},
    {"p": "5.4.3.0/24", "n": "4.4.4.4"},
    {"p": "6.0.1.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.1.0/24", "n": "4.4.4.4", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.1", "bp": True},
    {"p": "6.0.2.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.2.0/24", "n": "4.4.4.4", "bp": False},
    {"p": "6.0.2.0/24", "n": "99.0.0.1", "bp": True},
    {"p": "99.0.0.1/32", "n": "192.168.1.2", "bp": True},
    {"p": "99.0.0.2/32", "n": "3.3.3.3"},
    {"p": "99.0.0.3/32", "n": "4.4.4.4"},
    {"p": "99.0.0.4/32", "n": "4.4.4.4"},
]
bgpribRequireUnicastRoutes(
    "r1",
    "ipv4",
    "r1-cust1",
    "Customer 1 routes in r1 vrf (2)",
    want_r1_remote_cust1_routes,
    debug=False,
)


luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 5.1.0.0/24"',
    "2 available, best",
    "wait",
    "Ensure 5.1.0.0 shows up r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 5.1.1.0/24"',
    "2 available, best",
    "wait",
    "Ensure 5.1.1.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 5.1.2.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.1.2.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 5.1.3.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.1.3.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 5.4.3.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.4.3.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 5.4.3.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.4.3.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 5.4.3.0/24"',
    "1 available, best",
    "wait",
    "Ensure 5.4.3.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 6.0.1.0/24"',
    "4 available, best",
    "wait",
    "Ensure 6.0.1.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 6.0.2.0/24"',
    "4 available, best",
    "wait",
    "Ensure 6.0.2.0 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 99.0.0.1/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.1 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 99.0.0.3/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.3 shows up on r3",
    10,
)
luCommand(
    "r3",
    'vtysh -c "show bgp vrf r3-cust1 ipv4 uni 99.0.0.4/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.4 shows up on r3",
    10,
)
want_r3_remote_cust1_routes = [
    {"p": "5.1.0.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "5.1.0.0/24", "n": "99.0.0.2", "bp": False},
    {"p": "5.1.1.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "5.1.1.0/24", "n": "99.0.0.2", "bp": False},
    {"p": "5.1.2.0/24", "n": "4.4.4.4", "bp": True},
    {"p": "5.1.3.0/24", "n": "4.4.4.4", "bp": True},
    {"p": "5.4.2.0/24", "n": "4.4.4.4", "bp": True},
    {"p": "5.4.3.0/24", "n": "4.4.4.4", "bp": True},
    {"p": "6.0.1.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "6.0.1.0/24", "n": "4.4.4.4", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.2", "bp": False},
    {"p": "6.0.2.0/24", "n": "1.1.1.1", "bp": False},
    {"p": "6.0.2.0/24", "n": "4.4.4.4", "bp": False},
    {"p": "6.0.2.0/24", "n": "99.0.0.2", "bp": True},
    {"p": "99.0.0.1/32", "n": "1.1.1.1", "bp": True},
    {"p": "99.0.0.3/32", "n": "4.4.4.4", "bp": True},
    {"p": "99.0.0.4/32", "n": "4.4.4.4", "bp": True},
]
bgpribRequireUnicastRoutes(
    "r3",
    "ipv4",
    "r3-cust1",
    "Customer 1 routes in r3 vrf (2)",
    want_r3_remote_cust1_routes,
    debug=False,
)

luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 5.1.0.0/24"',
    "2 available, best",
    "wait",
    "Ensure 5.1.0.0 shows up on r4",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 5.1.1.0/24"',
    "2 available, best",
    "wait",
    "Ensure 5.1.1.0 shows up on r4",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 6.0.1.0/24"',
    "4 available, best",
    "wait",
    "Ensure 6.0.1.0 shows up on r4",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 6.0.2.0/24"',
    "4 available, best",
    "wait",
    "Ensure 6.0.2.0 shows up on r4",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 99.0.0.1/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.1 shows up on r4",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 99.0.0.2/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.2 shows up on r4",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 99.0.0.3/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.3 shows up on r4",
    10,
)
luCommand(
    "r4",
    'vtysh -c "show bgp vrf r4-cust1 ipv4 uni 99.0.0.4/32"',
    "1 available, best",
    "wait",
    "Ensure 99.0.0.4 shows up on r4",
    10,
)
want_r4_remote_cust1_routes = [
    {"p": "5.1.0.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "5.1.0.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "5.1.1.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "5.1.1.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.1.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "6.0.1.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.3", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.4", "bp": False},
    {"p": "6.0.2.0/24", "n": "1.1.1.1", "bp": False},
    {"p": "6.0.2.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.2.0/24", "n": "99.0.0.3", "bp": True},
    {"p": "6.0.2.0/24", "n": "99.0.0.4", "bp": False},
    {"p": "99.0.0.1/32", "n": "1.1.1.1", "bp": True},
    {"p": "99.0.0.2/32", "n": "3.3.3.3", "bp": True},
    {"p": "99.0.0.3/32", "n": "192.168.1.2", "bp": True},
    {"p": "99.0.0.4/32", "n": "192.168.2.2", "bp": True},
]
bgpribRequireUnicastRoutes(
    "r4",
    "ipv4",
    "r4-cust1",
    "Customer 1 routes in r4 vrf (2)",
    want_r4_remote_cust1_routes,
    debug=False,
)

want_r4_remote_cust2_routes = [
    {"p": "5.1.0.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "5.1.0.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "5.1.1.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "5.1.1.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.1.0/24", "n": "1.1.1.1", "bp": True},
    {"p": "6.0.1.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.3", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.4", "bp": False},
    {"p": "6.0.2.0/24", "n": "1.1.1.1", "bp": False},
    {"p": "6.0.2.0/24", "n": "3.3.3.3", "bp": False},
    {"p": "6.0.2.0/24", "n": "99.0.0.3", "bp": True},
    {"p": "6.0.2.0/24", "n": "99.0.0.4", "bp": False},
    {"p": "99.0.0.1/32", "n": "1.1.1.1", "bp": True},
    {"p": "99.0.0.2/32", "n": "3.3.3.3", "bp": True},
    {"p": "99.0.0.3/32", "n": "192.168.1.2", "bp": True},
    {"p": "99.0.0.4/32", "n": "192.168.2.2", "bp": True},
]
bgpribRequireUnicastRoutes(
    "r4",
    "ipv4",
    "r4-cust2",
    "Customer 2 routes in r4 vrf (2)",
    want_r4_remote_cust2_routes,
    debug=False,
)


#########################################################################
# CE routers: contain routes from remote customer nets
#########################################################################
# ce1 vtysh -c "show bgp ipv4 uni"
# r1 vtysh -c "show bgp vrf r1-cust1 ipv4"
# r1 vtysh -c "show bgp vrf r1-cust1 ipv4 5.1.2.0/24"

luCommand(
    "ce1",
    'vtysh -c "show bgp ipv4 uni"',
    "14 routes and 14",
    "wait",
    "Local and remote routes",
    10,
)
want = [
    {"p": "5.1.0.0/24", "n": "99.0.0.1", "bp": True},
    {"p": "5.1.1.0/24", "n": "99.0.0.1", "bp": True},
    {"p": "5.1.2.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.1.3.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.4.2.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.4.3.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "6.0.1.0/24", "n": "99.0.0.1", "bp": True},
    {"p": "6.0.2.0/24", "n": "99.0.0.1", "bp": True},
]
bgpribRequireUnicastRoutes(
    "ce1", "ipv4", "", "Cust 1 routes from remote", want, debug=False
)

luCommand(
    "ce2",
    'vtysh -c "show bgp ipv4 uni"',
    "14 routes and 17",
    "wait",
    "Local and remote routes",
    10,
)
want = [
    {"p": "5.1.0.0/24", "n": "192.168.1.1", "bp": False},
    {"p": "5.1.0.0/24", "n": "99.0.0.2", "bp": True},
    {"p": "5.1.1.0/24", "n": "192.168.1.1", "bp": False},
    {"p": "5.1.1.0/24", "n": "99.0.0.2", "bp": True},
    {"p": "5.1.2.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.1.3.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.4.2.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.4.3.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "6.0.1.0/24", "n": "192.168.1.1", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.2", "bp": True},
    {"p": "6.0.2.0/24", "n": "99.0.0.2", "bp": True},
]
bgpribRequireUnicastRoutes(
    "ce2", "ipv4", "", "Cust 1 routes from remote", want, debug=False
)

# human readable output for debugging
luCommand("r4", 'vtysh -c "show bgp vrf r4-cust1 ipv4 uni"')
luCommand("r4", 'vtysh -c "show bgp vrf r4-cust2 ipv4 uni"')
luCommand("r4", 'vtysh -c "show bgp ipv4 vpn"')
luCommand("r4", 'vtysh -c "show ip route vrf r4-cust1"')
luCommand("r4", 'vtysh -c "show ip route vrf r4-cust2"')

luCommand(
    "ce3",
    'vtysh -c "show bgp ipv4 uni"',
    "14 routes and 15",
    "wait",
    "Local and remote routes",
    10,
)
# Requires bvl-bug-degenerate-no-label fix (FRR PR #2053)
want = [
    {"p": "5.1.0.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.1.1.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.4.2.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "5.4.3.0/24", "n": "192.168.1.1", "bp": True},
    {"p": "6.0.1.0/24", "n": "192.168.1.1", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.3", "bp": True},
    {"p": "6.0.2.0/24", "n": "99.0.0.3", "bp": True},
]
bgpribRequireUnicastRoutes(
    "ce3", "ipv4", "", "Cust 1 routes from remote", want, debug=False
)

luCommand(
    "ce4",
    'vtysh -c "show bgp vrf ce4-cust2 ipv4 uni"',
    "14 routes and 16",
    "wait",
    "Local and remote routes",
    10,
)
want = [
    {"p": "5.1.0.0/24", "n": "192.168.2.1", "bp": True},
    {"p": "5.1.1.0/24", "n": "192.168.2.1", "bp": True},
    {"p": "5.1.2.0/24", "n": "192.168.2.1", "bp": True},
    {"p": "5.1.3.0/24", "n": "192.168.2.1", "bp": True},
    {"p": "6.0.1.0/24", "n": "192.168.2.1", "bp": False},
    {"p": "6.0.2.0/24", "n": "192.168.2.1", "bp": False},
    {"p": "6.0.1.0/24", "n": "99.0.0.4", "bp": True},
    {"p": "6.0.2.0/24", "n": "99.0.0.4", "bp": True},
]
bgpribRequireUnicastRoutes(
    "ce4", "ipv4", "ce4-cust2", "Cust 2 routes from remote", want, debug=False
)

# verify details of exported/imported routes
luCommand(
    "ce1",
    'vtysh -c "show bgp ipv4 uni 6.0.1.0"',
    "1 available.*192.168.1.1.*99.0.0.1.*Community: 0:67.*Extended Community: RT:89:123.*Large Community: 12:34:56",
    "pass",
    "Redundant route 1 details",
)
luCommand(
    "ce2",
    'vtysh -c "show bgp ipv4 uni 6.0.1.0"',
    "2 available, best .*192.168.1.1.* Local.* 192.168.1.1 from 192.168.1.1 .192.168.1.1"
    + ".* Origin IGP, metric 98, localpref 123, valid, internal"
    + ".* Community: 0:67.* Extended Community: RT:52:100 RT:89:123.* Large Community: 12:34:56",
    "pass",
    "Redundant route 1 details",
)
luCommand(
    "ce2",
    'vtysh -c "show bgp ipv4 uni 6.0.1.0"',
    "2 available, best .*192.168.1.1.* Local.* 99.0.0.2 from 0.0.0.0 .99.0.0.2"
    + ".* Origin IGP, metric 100, localpref 100, weight 32768, valid, sourced, local, best .Weight"
    + ".* Community: 0:67.* Extended Community: RT:89:123.* Large Community: 12:34:56",
    "pass",
    "Redundant route 1 details",
)
luCommand(
    "ce3",
    'vtysh -c "show bgp ipv4 uni 6.0.1.0"',
    "2 available, best "
    ".* Local.* 99.0.0.3 from 0.0.0.0 .99.0.0.3"
    + ".* Origin IGP, metric 200, localpref 50, weight 32768, valid, sourced, local, best .Weight"
    + ".* Community: 0:67.* Extended Community: RT:89:123.* Large Community: 12:34:56",
    "pass",
    "Redundant route 1 details",
)
luCommand(
    "ce3",
    'vtysh -c "show bgp ipv4 uni 6.0.1.0"',
    "2 available, best "
    ".* Local.* 192.168.1.1 from 192.168.1.1 .192.168.1.1"
    + ".* Origin IGP, metric 98, localpref 123, valid, internal"
    + ".* Community: 0:67.* Extended Community: RT:52:100 RT:89:123.* Large Community: 12:34:56",
    "pass",
    "Redundant route 1 details",
)
luCommand(
    "ce4",
    'vtysh -c "show bgp vrf ce4-cust2 ipv4 6.0.1.0 json"',
    (
        '{"paths":['
        + '{"aspath":{"string":"Local"},"origin":"IGP","metric":200,"locPrf":50,'
        + '"weight":32768,"valid":true,"sourced":true,"local":true,'
        + '"bestpath":{"overall":true,"selectionReason":"Weight"},'
        + '"community":{"string":"0:67"},"extendedCommunity":{"string":"RT:89:123"},'
        + '"largeCommunity":{"string":"12:34:56"},'
        + '"peer":{"peerId":"0.0.0.0","routerId":"99.0.0.4"}},'
        + '{"aspath":{"string":"Local"},"origin":"IGP","metric":98,"locPrf":123,'
        + '"valid":true,'
        + '"community":{"string":"0:67"},"extendedCommunity":{'
        + '"string":"RT:52:100 RT:89:123"},"largeCommunity":{"string":"12:34:56"},'
        + '"peer":{"peerId":"192.168.2.1","routerId":"192.168.2.1"}}'
        + "]}"
    ),
    "jsoncmp_pass",
    "Redundant route 1 details",
)

luCommand(
    "ce1",
    'vtysh -c "show bgp ipv4 uni 6.0.2.0"',
    "1 available, best .*192.168.1.1.* Local.* 99.0.0.1 from 0.0.0.0 .99.0.0.1"
    + ".* Origin IGP, metric 100, localpref 100, weight 32768, valid, sourced, local, best .First path received"
    + ".* Community: 0:67.* Extended Community: RT:89:123.* Large Community: 12:34:11",
    "pass",
    "Route 2 details",
)
luCommand(
    "ce2",
    'vtysh -c "show bgp ipv4 uni 6.0.2.0"',
    "1 available, best .*192.168.1.1.* Local.* 99.0.0.2 from 0.0.0.0 .99.0.0.2"
    + ".* Origin IGP, metric 100, localpref 100, weight 32768, valid, sourced, local, best .First path received"
    + ".* Community: 0:67.* Extended Community: RT:89:123.* Large Community: 12:34:12",
    "pass",
    "Route 2 details",
)
luCommand(
    "ce3",
    'vtysh -c "show bgp ipv4 uni 6.0.2.0"',
    "1 available, best .*192.168.1.1.* Local.* 99.0.0.3 from 0.0.0.0 .99.0.0.3"
    + ".* Origin IGP, metric 100, localpref 100, weight 32768, valid, sourced, local, best .First path received"
    + ".* Community: 0:67.* Extended Community: RT:89:123.* Large Community: 12:34:13",
    "pass",
    "Route 2 details",
)
luCommand(
    "ce4",
    'vtysh -c "show bgp  vrf ce4-cust2 ipv4 6.0.2.0"',
    "2 available, best .*192.168.2.1.* Local.* 192.168.2.1 from 192.168.2.1 .192.168.2.1"
    + ".* Origin IGP, metric 100, localpref 100, valid, internal"
    + ".* Community: 0:67.* Extended Community: RT:52:100 RT:89:123.* Large Community: 12:34:13",
    "pass",
    "Redundant route 2 details",
)
luCommand(
    "ce4",
    'vtysh -c "show bgp  vrf ce4-cust2 ipv4 6.0.2.0"',
    "2 available, best .*192.168.2.1.* Local.* 99.0.0.4 from 0.0.0.0 .99.0.0.4"
    + ".* Origin IGP, metric 100, localpref 100, weight 32768, valid, sourced, local, best .Weight"
    + ".* Community: 0:67.* Extended Community: RT:89:123.* Large Community: 12:34:14",
    "pass",
    "Redundant route 2 details",
)
luCommand(
    "r1",
    'vtysh -c "show ip route vrf r1-cust5 5.1.0.0/24"',
    "Known via .bgp., distance 200, .* vrf r1-cust5, best",
    "pass",
    "Recursive route leak details",
)
# done
