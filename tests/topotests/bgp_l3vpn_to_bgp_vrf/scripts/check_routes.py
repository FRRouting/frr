from lutil import luCommand
luCommand('ce1','vtysh -c "show bgp ipv4 uni"','5.1.0.0/24 .* 5.1.1.0/24 *99.0.0.1 .*2 routes and 2','pass','Local routes')
luCommand('ce2','vtysh -c "show bgp ipv4 uni"','5.1.0.0/24 .* 5.1.1.0/24 *99.0.0.2 .*2 routes and 2','pass','Local routes')
luCommand('ce3','vtysh -c "show bgp ipv4 uni"','5.1.2.0/24 .* 5.1.3.0/24 *99.0.0.3 .*2 routes and 2','pass','Local routes')
luCommand('ce4','vtysh -c "show bgp ipv4 uni"','5.4.2.0/24 .* 5.4.3.0/24 *99.0.0.4 .*2 routes and 2','pass','Local routes')
luCommand('r1','vtysh -c "show bgp vrf r1-cust1 ipv4 uni"','5.1.0.0/24 .*5.1.1.0/24 *99.0.0.1 .*2 routes and 2','wait','Cust1 unicast routes', 10)
luCommand('r3','vtysh -c "show bgp vrf r3-cust1 ipv4 uni"','5.1.0.0/24 .*5.1.1.0/24 *99.0.0.2 .*2 routes and 2','wait','Cust1 unicast routes', 10)
luCommand('r4','vtysh -c "show bgp vrf r4-cust1 ipv4 uni"','5.1.2.0/24 .*5.1.3.0/24 *99.0.0.3 .*2 routes and 2','wait','Cust1 unicast routes', 10)
luCommand('r4','vtysh -c "show bgp vrf r4-cust2 ipv4 uni"','5.4.2.0/24 .*5.4.3.0/24 *99.0.0.4 .*2 routes and 2','wait','Cust2 unicast routes', 10)
luCommand('r1','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')
luCommand('r2','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')
luCommand('r3','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')
luCommand('r4','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Core Unicast SAFI clean')

# Core VPN routes
luCommand('r1','vtysh -c "show bgp ipv4 vpn"','5.1.0.0/24 .*1.1.1.1 .*5.1.1.0/24 .*1.1.1.1 .*2 routes and 2','pass','vrf->vpn routes')
luCommand('r3','vtysh -c "show bgp ipv4 vpn"','5.1.0.0/24 .*3.3.3.3 .*5.1.1.0/24 .*3.3.3.3 .*2 routes and 2','pass','vrf->vpn routes')
luCommand('r4','vtysh -c "show bgp ipv4 vpn"','5.1.2.0/24 .*4.4.4.4 .*5.1.3.0/24 .*4.4.4.4 .*5.4.2.0/24 .*4.4.4.4 .*5.4.3.0/24 .*4.4.4.4 .*4 routes and 4','pass','vrf->vpn routes')

# MPLS vrf labels
luCommand('r1','vtysh -c "show mpls table"',' 101 *BGP *r1-cust1','pass','vrf labels')
luCommand('r3','vtysh -c "show mpls table"',' 103 *BGP *r3-cust1','pass','vrf labels')
luCommand('r4','vtysh -c "show mpls table"',' 1041 *BGP *r4-cust1 .*1042 *BGP *r4-cust2','pass','vrf labels')

