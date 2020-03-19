from lutil import luCommand

luCommand('r3','vtysh -c "show mpls ldp interface"','r3-eth2','pass','LDP interface', 60)
luCommand('r5','vtysh -c "show mpls ldp interface"','r5-eth0','pass','LDP interface', 60)
luCommand('r3','vtysh -c "show mpls ldp neigh"','192.168.2.2.*OPERAT','wait','LDPD operational', 60)
luCommand('r5','vtysh -c "show mpls ldp neigh"','192.168.2.1.*OPERAT','wait','LDPD operational', 60)
