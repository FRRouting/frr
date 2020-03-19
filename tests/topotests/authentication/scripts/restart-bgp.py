from lutil import luCommand
import time

stamp = time.strftime("%y%m%d-%H%M%S")

oneIntf   = 'neighbor.*password 101 '
#note restart of r0 results in a hung connection
rtrs = ['r0', 'r2', 'r4', 'r5', 'r7']
for rtr in rtrs:
    luCommand(rtr,'vtysh -c "write memory"','.','none','wrote file')
    luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')
    luCommand(rtr,'cat /etc/frr/bgpd.conf',oneIntf,'pass','Auth key encrypted in config')
    luCommand(rtr,'cat /var/run/frr/bgpd.pid','.','none')
    luCommand(rtr,'kill `cat /var/run/frr/bgpd.pid`','.','none','kill bgpd')
    luCommand(rtr,'ps `cat /var/run/frr/bgpd.pid` | wc -l ','1','wait','bgpd killed', 10)
    luCommand(rtr,
        '/usr/lib/frr/bgpd -d --log ' +
        'file:/tmp/topotests/authentication.test_authentication/%s/bgpd-%s.log'
            % (rtr, stamp),
        '.','none','restart bgpd')
    luCommand(rtr,'ps `cat /var/run/frr/bgpd.pid` | wc -l ','2','wait','bgpd restarted', 10)
    luCommand(rtr,'cat /var/run/frr/bgpd.pid','.','none')
