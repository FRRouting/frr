from lutil import luCommand

oneIntf   = 'eth0.*message.digest.key 1 md5 101 .*='
twoIntf   = oneIntf + '.*eth1.*message.digest.key 1 md5 101 .*='
threeIntf = twoIntf + '.*eth2.*message.digest.key 1 md5 101 .*='

#check configs for encrypted keys
luCommand('r1','vtysh -c "show run ospfd"',oneIntf,'pass','Auth key encrypted')
luCommand('r2','vtysh -c "show run ospfd"',threeIntf,'pass','Auth key encrypted')
luCommand('r3','vtysh -c "show run ospfd"',twoIntf,'pass','Auth key encrypted')
luCommand('r4','vtysh -c "show run ospfd"',oneIntf,'pass','Auth key encrypted')

luCommand('r1','vtysh -c "show ip ospf neigh"','Full.*eth0','wait','OSPF Full', 60)
luCommand('r4','vtysh -c "show ip ospf neigh"','Full.*eth0.*Full.*eth0','wait','OSPF Full', 20)
luCommand('r3','vtysh -c "show ip ospf neigh"','Full.*eth0.*Full.*eth0.*Full.*eth1','wait','OSPF Full', 10)
luCommand('r2','vtysh -c "show ip ospf neigh"','Full.*eth0.*Full.*eth1.*Full.*eth1.*Full.*eth2','wait','OSPF Full', 60)
