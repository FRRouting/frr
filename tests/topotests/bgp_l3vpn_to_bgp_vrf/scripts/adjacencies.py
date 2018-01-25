from lutil import luCommand
luCommand('r2','vtysh -c "show bgp summary"',' 00:0.* 00:0.* 00:0','wait','Core adjacencies up',90)
luCommand('r1','vtysh -c "show bgp summary"',' 00:0','pass','Core adjacencies up')
luCommand('r3','vtysh -c "show bgp summary"',' 00:0','pass','Core adjacencies up')
luCommand('r4','vtysh -c "show bgp summary"',' 00:0','pass','Core adjacencies up')

luCommand('ce1','vtysh -c "show bgp summary"',' 00:0','wait','Adjacencies up',90)
luCommand('ce2','vtysh -c "show bgp summary"',' 00:0','wait','Adjacencies up')
luCommand('ce3','vtysh -c "show bgp summary"',' 00:0','wait','Adjacencies up')
luCommand('ce4','vtysh -c "show bgp summary"',' 00:0','wait','Adjacencies up')
luCommand('r1','vtysh -c "show bgp vrf all summary"',' 00:0.* 00:0','pass','All adjacencies up')
luCommand('r3','vtysh -c "show bgp vrf all summary"',' 00:0.* 00:0','pass','All adjacencies up')
luCommand('r4','vtysh -c "show bgp vrf all summary"',' 00:0.* 00:0.* 00:0','pass','All adjacencies up')
