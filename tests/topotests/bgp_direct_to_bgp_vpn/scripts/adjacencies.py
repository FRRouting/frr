from lutil import luCommand
luCommand('r1','vtysh -c "show bgp summary"',' 00:0.* 00:0','wait','Adjacencies up', 60)
luCommand('r2','vtysh -c "show bgp summary"',' 00:0.* 00:0','wait','Adjacencies up')
luCommand('r3','vtysh -c "show bgp summary"',' 00:0.* 00:0','wait','Adjacencies up')
luCommand('r4','vtysh -c "show bgp summary"',' 00:0.* 00:0','wait','Adjacencies up')
