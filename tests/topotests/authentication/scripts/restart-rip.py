from lutil import luCommand
oneIntf   = 'eth0.*authentication string 101 .*=.*ip rip send'

rtrs = ['r1', 'r2', 'r4']
for rtr in rtrs:
    luCommand(rtr,'vtysh -c "write memory"','.','none','wrote file')
    luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')
    luCommand(rtr,'cat /etc/frr/ripd.conf',oneIntf,'pass','Auth key encrypted in config')
    luCommand(rtr,'kill `cat /var/run/frr/ripd.pid`','.','none','kill ripd')
    luCommand(rtr,'ps `cat /var/run/frr/ripd.pid` | wc -l ','1','wait','ripd killed', 10)
    luCommand(rtr,'/usr/lib/frr/ripd -d','.','none','restart ripd')
    luCommand(rtr,'ps `cat /var/run/frr/ripd.pid` | wc -l ','2','wait','ripd restarted', 10)
    
