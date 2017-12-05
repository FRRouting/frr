from lutil import luCommand
luCommand('ce1','vtysh -c "show bgp ipv4 uni"','7 routes and 7','wait','Local and remote routes')
luCommand('ce2','vtysh -c "show bgp ipv4 uni"','7 routes and 7','wait','Local and remote routes')
luCommand('ce3','vtysh -c "show bgp ipv4 uni"','7 routes and 7','wait','Local and remote routes')
luCommand('r1','vtysh -c "show bgp ipv4 uni"','7 routes and 9','pass','Unicast SAFI')
luCommand('r2','vtysh -c "show bgp ipv4 uni"','No BGP prefixes displayed','pass','Unicast SAFI')
luCommand('r3','vtysh -c "show bgp ipv4 uni"','7 routes and 9','pass','Unicast SAFI')
luCommand('r4','vtysh -c "show bgp ipv4 uni"','7 routes and 9','pass','Unicast SAFI')
luCommand('r1','vtysh -c "show bgp ipv4 vpn"','9 routes and 9','pass','VPN SAFI')
luCommand('r2','vtysh -c "show bgp ipv4 vpn"','9 routes and 9','pass','VPN SAFI')
luCommand('r3','vtysh -c "show bgp ipv4 vpn"','9 routes and 9','pass','VPN SAFI')
luCommand('r4','vtysh -c "show bgp ipv4 vpn"','9 routes and 9','pass','VPN SAFI')

