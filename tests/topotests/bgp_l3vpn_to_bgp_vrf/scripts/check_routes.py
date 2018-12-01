from lutil import luCommand
from bgprib import bgpribRequireVpnRoutes,bgpribRequireUnicastRoutes

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
    {'p':'5.1.0.0/24', 'n':'99.0.0.1'},
    {'p':'5.1.1.0/24', 'n':'99.0.0.1'},
    {'p':'99.0.0.1/32', 'n':'0.0.0.0'},
]
bgpribRequireUnicastRoutes('ce1','ipv4','','Cust 1 routes in ce1',want)

want = [
    {'p':'5.1.0.0/24', 'n':'99.0.0.2'},
    {'p':'5.1.1.0/24', 'n':'99.0.0.2'},
    {'p':'99.0.0.2/32', 'n':'0.0.0.0'},
]
bgpribRequireUnicastRoutes('ce2','ipv4','','Cust 2 routes in ce1',want)

want = [
    {'p':'5.1.2.0/24', 'n':'99.0.0.3'},
    {'p':'5.1.3.0/24', 'n':'99.0.0.3'},
    {'p':'99.0.0.3/32', 'n':'0.0.0.0'},
]
bgpribRequireUnicastRoutes('ce3','ipv4','','Cust 3 routes in ce1',want)

want = [
    {'p':'5.4.2.0/24', 'n':'99.0.0.4'},
    {'p':'5.4.3.0/24', 'n':'99.0.0.4'},
    {'p':'99.0.0.4/32', 'n':'0.0.0.0'},
]
bgpribRequireUnicastRoutes('ce4','ipv4','ce4-cust2','Cust 4 routes in ce1',want)


########################################################################
# PE routers: VRFs contain routes from locally-attached customer nets
########################################################################
#
# r1 vtysh -c "show bgp vrf r1-cust1 ipv4"
#
want_r1_cust1_routes = [
    {'p':'5.1.0.0/24', 'n':'99.0.0.1'},
    {'p':'5.1.1.0/24', 'n':'99.0.0.1'},
    {'p':'99.0.0.1/32', 'n':'192.168.1.2'},
]
bgpribRequireUnicastRoutes('r1','ipv4','r1-cust1','Customer 1 routes in r1 vrf',want_r1_cust1_routes)

want_r3_cust1_routes = [
    {'p':'5.1.0.0/24', 'n':'99.0.0.2'},
    {'p':'5.1.1.0/24', 'n':'99.0.0.2'},
    {'p':'99.0.0.2/32', 'n':'192.168.1.2'},
]
bgpribRequireUnicastRoutes('r3','ipv4','r3-cust1','Customer 1 routes in r3 vrf',want_r3_cust1_routes)

want_r4_cust1_routes = [
    {'p':'5.1.2.0/24', 'n':'99.0.0.3'},
    {'p':'5.1.3.0/24', 'n':'99.0.0.3'},
    {'p':'99.0.0.3/32', 'n':'192.168.1.2'},
]
bgpribRequireUnicastRoutes('r4','ipv4','r4-cust1','Customer 1 routes in r4 vrf',want_r4_cust1_routes)

want_r4_cust2_routes = [
    {'p':'5.4.2.0/24', 'n':'99.0.0.4'},
    {'p':'5.4.3.0/24', 'n':'99.0.0.4'},
    {'p':'99.0.0.4/32', 'n':'192.168.2.2'},
]
bgpribRequireUnicastRoutes('r4','ipv4','r4-cust2','Customer 2 routes in r4 vrf',want_r4_cust2_routes)

########################################################################
# PE routers: core unicast routes are empty
########################################################################

luCommand('r1','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')
luCommand('r2','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')
luCommand('r3','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')
luCommand('r4','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')

########################################################################
# PE routers: local ce-originated routes are leaked to vpn
########################################################################

# nhzero is for the new code that sets nh of locally-leaked routes to 0
#nhzero = 1
nhzero = 0

if nhzero:
    luCommand('r1','vtysh -c "show bgp ipv4 vpn"',
	'Distinguisher:  *10:1.*5.1.0.0/24 *0.0.0.0 .*5.1.1.0/24 *0.0.0.0 .*99.0.0.1/32 *0.0.0.0 ',
	'pass','vrf->vpn routes')
    luCommand('r3','vtysh -c "show bgp ipv4 vpn"',
	'Distinguisher:  *10:3.*5.1.0.0/24 *0.0.0.0 .*5.1.1.0/24 *0.0.0.0 .*99.0.0.2/32 *0.0.0.0 ',
	'pass','vrf->vpn routes')
    want = [
	{'rd':'10:41', 'p':'5.1.2.0/24', 'n':'0.0.0.0'},
	{'rd':'10:41', 'p':'5.1.3.0/24', 'n':'0.0.0.0'},
	{'rd':'10:41', 'p':'99.0.0.3/32', 'n':'0.0.0.0'},

	{'rd':'10:42', 'p':'5.4.2.0/24', 'n':'0.0.0.0'},
	{'rd':'10:42', 'p':'5.4.3.0/24', 'n':'0.0.0.0'},
	{'rd':'10:42', 'p':'99.0.0.4/32', 'n':'0.0.0.0'},
    ]
    bgpribRequireVpnRoutes('r4','vrf->vpn routes',want)

else:
    luCommand('r1','vtysh -c "show bgp ipv4 vpn"',
	r'Distinguisher:  *10:1.*5.1.0.0/24 *99.0.0.1\b.*5.1.1.0/24 *99.0.0.1\b.*99.0.0.1/32 *192.168.1.2\b',
	'pass','vrf->vpn routes')
    luCommand('r3','vtysh -c "show bgp ipv4 vpn"',
	r'Distinguisher:  *10:3.*5.1.0.0/24 *99.0.0.2\b.*5.1.1.0/24 *99.0.0.2\b.*99.0.0.2/32 *192.168.1.2\b',
	'pass','vrf->vpn routes')
    want = [
	{'rd':'10:41', 'p':'5.1.2.0/24', 'n':'99.0.0.3'},
	{'rd':'10:41', 'p':'5.1.3.0/24', 'n':'99.0.0.3'},
	{'rd':'10:41', 'p':'99.0.0.3/32', 'n':'192.168.1.2'},

	{'rd':'10:42', 'p':'5.4.2.0/24', 'n':'99.0.0.4'},
	{'rd':'10:42', 'p':'5.4.3.0/24', 'n':'99.0.0.4'},
	{'rd':'10:42', 'p':'99.0.0.4/32', 'n':'192.168.2.2'},
    ]
    bgpribRequireVpnRoutes('r4','vrf->vpn routes',want)

########################################################################
# PE routers: exporting vrfs set MPLS vrf labels in kernel
########################################################################

luCommand('r1','vtysh -c "show mpls table"',' 101 *BGP *r1-cust1','pass','vrf labels')
luCommand('r3','vtysh -c "show mpls table"',' 103 *BGP *r3-cust1','pass','vrf labels')
luCommand('r4','vtysh -c "show mpls table"',' 1041 *BGP *r4-cust1 .*1042 *BGP *r4-cust2','pass','vrf labels')

########################################################################
# Core VPN router: all customer routes
########################################################################

want_rd_routes = [
    {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1'},
    {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1'},
    {'rd':'10:1', 'p':'99.0.0.1/32', 'n':'1.1.1.1'},

    {'rd':'10:3', 'p':'5.1.0.0/24', 'n':'3.3.3.3'},
    {'rd':'10:3', 'p':'5.1.0.0/24', 'n':'3.3.3.3'},
    {'rd':'10:3', 'p':'99.0.0.2/32', 'n':'3.3.3.3'},

    {'rd':'10:41', 'p':'5.1.2.0/24', 'n':'4.4.4.4'},
    {'rd':'10:41', 'p':'5.1.3.0/24', 'n':'4.4.4.4'},
    {'rd':'10:41', 'p':'99.0.0.3/32', 'n':'4.4.4.4'},

    {'rd':'10:42', 'p':'5.4.2.0/24', 'n':'4.4.4.4'},
    {'rd':'10:42', 'p':'5.4.3.0/24', 'n':'4.4.4.4'},
    {'rd':'10:42', 'p':'99.0.0.4/32', 'n':'4.4.4.4'},
]
bgpribRequireVpnRoutes('r2','Customer routes in provider vpn core',want_rd_routes)

########################################################################
# PE routers: VPN routes from remote customers
########################################################################
#
# r1 vtysh -c "show bgp ipv4 vpn"
#
want_r1_remote_vpn_routes = [
    {'rd':'10:3', 'p':'5.1.0.0/24', 'n':'3.3.3.3'},
    {'rd':'10:3', 'p':'5.1.1.0/24', 'n':'3.3.3.3'},
    {'rd':'10:3', 'p':'99.0.0.2/32', 'n':'3.3.3.3'},

    {'rd':'10:41', 'p':'5.1.2.0/24', 'n':'4.4.4.4'},
    {'rd':'10:41', 'p':'5.1.3.0/24', 'n':'4.4.4.4'},
    {'rd':'10:41', 'p':'99.0.0.3/32', 'n':'4.4.4.4'},

    {'rd':'10:42', 'p':'5.4.2.0/24', 'n':'4.4.4.4'},
    {'rd':'10:42', 'p':'5.4.3.0/24', 'n':'4.4.4.4'},
    {'rd':'10:42', 'p':'99.0.0.4/32', 'n':'4.4.4.4'},
]
bgpribRequireVpnRoutes('r1','Remote Customer routes in R1 vpn',want_r1_remote_vpn_routes)

want_r3_remote_vpn_routes = [
    {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1'},
    {'rd':'10:1', 'p':'5.1.1.0/24', 'n':'1.1.1.1'},
    {'rd':'10:1', 'p':'99.0.0.1/32', 'n':'1.1.1.1'},

    {'rd':'10:41', 'p':'5.1.2.0/24', 'n':'4.4.4.4'},
    {'rd':'10:41', 'p':'5.1.3.0/24', 'n':'4.4.4.4'},
    {'rd':'10:41', 'p':'99.0.0.3/32', 'n':'4.4.4.4'},

    {'rd':'10:42', 'p':'5.4.2.0/24', 'n':'4.4.4.4'},
    {'rd':'10:42', 'p':'5.4.3.0/24', 'n':'4.4.4.4'},
    {'rd':'10:42', 'p':'99.0.0.4/32', 'n':'4.4.4.4'},
]
bgpribRequireVpnRoutes('r3','Remote Customer routes in R3 vpn',want_r3_remote_vpn_routes)

want_r4_remote_vpn_routes = [
    {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1'},
    {'rd':'10:1', 'p':'5.1.1.0/24', 'n':'1.1.1.1'},
    {'rd':'10:1', 'p':'99.0.0.1/32', 'n':'1.1.1.1'},

    {'rd':'10:3', 'p':'5.1.0.0/24', 'n':'3.3.3.3'},
    {'rd':'10:3', 'p':'5.1.1.0/24', 'n':'3.3.3.3'},
    {'rd':'10:3', 'p':'99.0.0.2/32', 'n':'3.3.3.3'},
]
bgpribRequireVpnRoutes('r4','Remote Customer routes in R4 vpn',want_r4_remote_vpn_routes)



# r1 vtysh -c "show bgp vrf r1-cust1 ipv4"

########################################################################
# PE routers: VRFs contain routes from remote customer nets
########################################################################
want_r1_remote_cust1_routes = [
    {'p':'5.1.0.0/24', 'n':'3.3.3.3'},
    {'p':'5.1.1.0/24', 'n':'3.3.3.3'},
    {'p':'99.0.0.2/32', 'n':'3.3.3.3'},

    {'p':'5.1.2.0/24', 'n':'4.4.4.4'},
    {'p':'5.1.3.0/24', 'n':'4.4.4.4'},
    {'p':'99.0.0.3/32', 'n':'4.4.4.4'},

    {'p':'5.4.2.0/24', 'n':'4.4.4.4'},
    {'p':'5.4.3.0/24', 'n':'4.4.4.4'},
    {'p':'99.0.0.3/32', 'n':'4.4.4.4'},
]
bgpribRequireUnicastRoutes('r1','ipv4','r1-cust1','Customer 1 routes in r1 vrf',want_r1_remote_cust1_routes)

want_r3_remote_cust1_routes = [
    {'p':'5.1.0.0/24', 'n':'1.1.1.1'},
    {'p':'5.1.1.0/24', 'n':'1.1.1.1'},
    {'p':'99.0.0.1/32', 'n':'1.1.1.1'},

    {'p':'5.1.2.0/24', 'n':'4.4.4.4'},
    {'p':'5.1.3.0/24', 'n':'4.4.4.4'},
    {'p':'99.0.0.3/32', 'n':'4.4.4.4'},

    {'p':'5.4.2.0/24', 'n':'4.4.4.4'},
    {'p':'5.4.3.0/24', 'n':'4.4.4.4'},
    {'p':'99.0.0.3/32', 'n':'4.4.4.4'},
]
bgpribRequireUnicastRoutes('r3','ipv4','r3-cust1','Customer 1 routes in r3 vrf',want_r3_remote_cust1_routes)

want_r4_remote_cust1_routes = [
    {'p':'5.1.0.0/24', 'n':'1.1.1.1'},
    {'p':'5.1.1.0/24', 'n':'1.1.1.1'},
    {'p':'5.1.0.0/24', 'n':'3.3.3.3'},
    {'p':'5.1.1.0/24', 'n':'3.3.3.3'},
    {'p':'99.0.0.1/32', 'n':'1.1.1.1'},
    {'p':'99.0.0.2/32', 'n':'3.3.3.3'},
]
bgpribRequireUnicastRoutes('r4','ipv4','r4-cust1','Customer 1 routes in r4 vrf',want_r4_remote_cust1_routes)

want_r4_remote_cust2_routes = [
    {'p':'5.1.0.0/24', 'n':'1.1.1.1'},
    {'p':'5.1.1.0/24', 'n':'1.1.1.1'},
    {'p':'5.1.0.0/24', 'n':'3.3.3.3'},
    {'p':'5.1.1.0/24', 'n':'3.3.3.3'},
    {'p':'99.0.0.1/32', 'n':'1.1.1.1'},
    {'p':'99.0.0.2/32', 'n':'3.3.3.3'},
]
bgpribRequireUnicastRoutes('r4','ipv4','r4-cust2','Customer 2 routes in r4 vrf',want_r4_remote_cust2_routes)


#########################################################################
# CE routers: contain routes from remote customer nets
#########################################################################
# ce1 vtysh -c "show bgp ipv4 uni"
# r1 vtysh -c "show bgp vrf r1-cust1 ipv4"
# r1 vtysh -c "show bgp vrf r1-cust1 ipv4 5.1.2.0/24"

luCommand('ce1','vtysh -c "show bgp ipv4 uni"','10 routes and 10','wait','Local and remote routes', 10)
want = [
    {'p':'5.1.2.0/24', 'n':'192.168.1.1'},
    {'p':'5.1.3.0/24', 'n':'192.168.1.1'},
    {'p':'5.4.2.0/24', 'n':'192.168.1.1'},
    {'p':'5.4.3.0/24', 'n':'192.168.1.1'},
]
bgpribRequireUnicastRoutes('ce1','ipv4','','Cust 1 routes from remote',want)

luCommand('ce2','vtysh -c "show bgp ipv4 uni"','10 routes and 12','wait','Local and remote routes', 10)
want = [
    {'p':'5.1.0.0/24', 'n':'192.168.1.1'},
    {'p':'5.1.1.0/24', 'n':'192.168.1.1'},
    {'p':'5.1.2.0/24', 'n':'192.168.1.1'},
    {'p':'5.1.3.0/24', 'n':'192.168.1.1'},
    {'p':'5.4.2.0/24', 'n':'192.168.1.1'},
    {'p':'5.4.3.0/24', 'n':'192.168.1.1'},
]
bgpribRequireUnicastRoutes('ce2','ipv4','','Cust 1 routes from remote',want)

# human readable output for debugging
luCommand('r4','vtysh -c "show bgp vrf r4-cust1 ipv4 uni"')
luCommand('r4','vtysh -c "show bgp vrf r4-cust2 ipv4 uni"')
luCommand('r4','vtysh -c "show bgp ipv4 vpn"')
luCommand('r4','vtysh -c "show ip route vrf r4-cust1"')
luCommand('r4','vtysh -c "show ip route vrf r4-cust2"')

luCommand('ce3','vtysh -c "show bgp ipv4 uni"','10 routes and 10','wait','Local and remote routes', 10)
# Requires bvl-bug-degenerate-no-label fix (FRR PR #2053)
want = [
    {'p':'5.1.0.0/24', 'n':'192.168.1.1'},
    {'p':'5.1.1.0/24', 'n':'192.168.1.1'},
    {'p':'5.4.2.0/24', 'n':'192.168.1.1'},
    {'p':'5.4.3.0/24', 'n':'192.168.1.1'},
]
bgpribRequireUnicastRoutes('ce3','ipv4','','Cust 1 routes from remote',want)

luCommand('ce4','vtysh -c "show bgp vrf ce4-cust2 ipv4 uni"','10 routes and 10','wait','Local and remote routes', 10)
want = [
    {'p':'5.1.0.0/24', 'n':'192.168.2.1'},
    {'p':'5.1.1.0/24', 'n':'192.168.2.1'},
    {'p':'5.1.2.0/24', 'n':'192.168.2.1'},
    {'p':'5.1.3.0/24', 'n':'192.168.2.1'},
]
bgpribRequireUnicastRoutes('ce4','ipv4','ce4-cust2','Cust 2 routes from remote',want)

