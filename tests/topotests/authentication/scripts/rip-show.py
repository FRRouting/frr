from lutil import luCommand

oneIntf   = 'eth0.*authentication string 101 .*ip rip send'
twoIntf   = oneIntf + '.*eth1.*authentication string 101 .*ip rip send'
threeIntf = twoIntf + '.*eth2.*authentication string 101 .*ip rip send'

#check configs for encrypted keys
luCommand('r0','vtysh -c "show run ripd"',oneIntf,'pass','Auth key encrypted')
luCommand('r1','vtysh -c "show run ripd"',twoIntf,'pass','Auth key encrypted')
luCommand('r2','vtysh -c "show run ripd"',threeIntf,'pass','Auth key encrypted')
luCommand('r3','vtysh -c "show run ripd"',threeIntf,'pass','Auth key encrypted')
luCommand('r4','vtysh -c "show run ripd"',threeIntf,'pass','Auth key encrypted')
luCommand('r5','vtysh -c "show run ripd"',oneIntf,'pass','Auth key encrypted')
luCommand('r6','vtysh -c "show run ripd"',oneIntf,'pass','Auth key encrypted')
luCommand('r7','vtysh -c "show run ripd"',oneIntf,'pass','Auth key encrypted')

#check that keys are working
luCommand('r0','vtysh -c "show ip rip status"',' 00:0','wait','RIP Peers', 60)
luCommand('r1','vtysh -c "show ip rip status"',' 00:0.* 00:0','wait','RIP Peers', 30)
luCommand('r2','vtysh -c "show ip rip status"',' 00:0.* 00:0.* 00:0.* 00:0','wait','RIP Peers', 30)
luCommand('r3','vtysh -c "show ip rip status"',' 00:0.* 00:0.* 00:0.* 00:0','wait','RIP Peers', 30)
luCommand('r4','vtysh -c "show ip rip status"',' 00:0.* 00:0.* 00:0.* 00:0','wait','RIP Peers', 30)
luCommand('r5','vtysh -c "show ip rip status"',' 00:0','wait','RIP Peers', 10)
luCommand('r6','vtysh -c "show ip rip status"',' 00:0','wait','RIP Peers', 10)
luCommand('r7','vtysh -c "show ip rip status"',' 00:0','wait','RIP Peers', 10)
