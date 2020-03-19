from lutil import luCommand
import time

stamp = time.strftime("%y%m%d-%H%M%S")
oneIntf   = 'neighbor.*password 101 '

rtrs = ['r3', 'r5']
for rtr in rtrs:
    luCommand(rtr,'vtysh -c "write memory"','.','none','wrote file')
    luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')
    luCommand(rtr,'cat /etc/frr/ldpd.conf',oneIntf,'pass','Auth key encrypted in config')
    luCommand(rtr,'kill `cat /var/run/frr/ldpd.pid`','.','none','kill ldpd')
    luCommand(rtr,'ps `cat /var/run/frr/ldpd.pid` | wc -l ','1','wait','ldpd killed', 10)
    luCommand(rtr,'/usr/lib/frr/ldpd -d --log ' +
        'file:/tmp/topotests/authentication.test_authentication/%s/ldpd-%s.log'
            % (rtr, stamp),
        '.','none','restart ldpd')
    luCommand(rtr,'ps `cat /var/run/frr/ldpd.pid` | wc -l ','2','wait','ldpd restarted', 10)
    
