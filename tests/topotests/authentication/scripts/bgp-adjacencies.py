from lutil import luCommand

########################################################################
# ipv4
########################################################################

luCommand('r0','vtysh -c "show bgp ipv4 summary"',' 00:0','wait','BGP v4 Adjacencies up',60)
luCommand('r5','vtysh -c "show bgp ipv4 summary"',' 00:0','wait','BGP v4 Adjacencies up',10)
#luCommand('r6','vtysh -c "show bgp summary"',' 00:0','wait','BGP v4 Adjacencies up',10)
#luCommand('r7','vtysh -c "show bgp summary"',' 00:0','wait','BGP v4 Adjacencies up',10)

luCommand('r1','ping 2.2.2.2 -c 1',' 0. packet loss','wait','PE->P2 (loopback) ping',10)
luCommand('r3','ping 2.2.2.2 -c 1',' 0. packet loss','wait','PE->P2 (loopback) ping',10)
luCommand('r4','ping 2.2.2.2 -c 1',' 0. packet loss','wait','PE->P2 (loopback) ping',10)

luCommand('r2','vtysh -c "show bgp summary"',' 00:0.* 00:0.* 00:0','wait','Core adjacencies up',10)
luCommand('r1','vtysh -c "show bgp summary"',' 00:0.* 00:0','wait','Core adjacencies up',10)
luCommand('r3','vtysh -c "show bgp summary"',' 00:0.* 00:0','wait','Core adjacencies up',10)
luCommand('r4','vtysh -c "show bgp summary"',' 00:0.* 00:0.* 00:0','wait','Core adjacencies up',10)

########################################################################
# ipv6
########################################################################

#luCommand('r0','vtysh -c "show bgp ipv6 summary"',' 00:0','wait','BGP v6 Adjacencies up',60)
luCommand('r5','vtysh -c "show bgp ipv6 summary"',' 00:0','wait','BGP v6 Adjacencies up',60)
luCommand('r6','vtysh -c "show bgp ipv6 summary"',' 00:0','wait','BGP v6 Adjacencies up',60)
luCommand('r7','vtysh -c "show bgp ipv6 summary"',' 00:0','wait','BGP v6 Adjacencies up',60)

luCommand('r1','ping6 2001:db8:beed:2::2 -c 1',' 0. packet loss','wait','PE->P2 (loopback) ping v6',10)
luCommand('r3','ping6 2001:db8:beed:2::2 -c 1',' 0. packet loss','wait','PE->P2 (loopback) ping v6',10)
luCommand('r4','ping6 2001:db8:beed:2::2 -c 1',' 0. packet loss','wait','PE->P2 (loopback) ping v6',10)

luCommand('r2','vtysh -c "show bgp ipv6 summary"',' 00:0.* 00:0.* 00:0','wait','Core ipv6 adjacencies up',10)
luCommand('r1','vtysh -c "show bgp ipv6 summary"',' 00:0','wait','Core ipv6 adjacencies up',10)
luCommand('r3','vtysh -c "show bgp ipv6 summary"',' 00:0.* 00:0','wait','Core ipv6 adjacencies up',10)
luCommand('r4','vtysh -c "show bgp ipv6 summary"',' 00:0.* 00:0.* 00:0','wait','Core ipv6 adjacencies up',10)
