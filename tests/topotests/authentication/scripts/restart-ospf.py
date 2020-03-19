from lutil import luCommand

oneIntf   = 'eth0.*message.digest.key 1 md5 101 .*='
rtrs = ['r2']
for rtr in rtrs:
    luCommand(rtr,'vtysh -c "write memory"','.','none','wrote file')
    luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')
    luCommand(rtr,'cat /etc/frr/ospfd.conf',oneIntf,'pass','Auth key encrypted in config')
    luCommand(rtr,'kill `cat /var/run/frr/ospfd.pid`','.','none','kill ospfd')
    luCommand(rtr,'ps `cat /var/run/frr/ospfd.pid` | wc -l ','1','wait','ospfd killed', 10)
    luCommand(rtr,'/usr/lib/frr/ospfd -d','.','none','restart ospfd')
    luCommand(rtr,'ps `cat /var/run/frr/ospfd.pid` | wc -l ','2','wait','ospfd restarted', 10)
    
