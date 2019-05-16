from lutil import luCommand
ret = luCommand('ce1', 'vtysh -c "show ip route" | grep -c \\ 10\\.\\*/32','(.*)','pass', 'Looking for sharp routes')
found = luLast()
if ret != False and found != None:
    num = int(found.group())
    luCommand('ce3', 'vtysh -c "show bgp sum"',
	      '.', 'pass', 'See %s sharp routes' % num)
    if num > 0:
        wait = num/500
        luCommand('ce1', 'vtysh -c "sharp remove routes 10.0.0.0 {}"'.format(num),'.','none','Removing {} routes'.format(num))
        luCommand('ce2', 'vtysh -c "sharp remove routes 10.0.0.0 {}"'.format(num),'.','none','Removing {} routes'.format(num))
        rtrs = ['ce1', 'ce2', 'ce3']
        for rtr in rtrs:
            luCommand(rtr, 'vtysh -c "show bgp ipv4 uni" | grep -c 10\\.\\*/32','^0$', 'wait', 'BGP routes removed', wait)
        for rtr in rtrs:
            luCommand(rtr, 'ip route show | grep -c \\^10\\.','^0$', 'wait', 'Linux routes removed', wait)
        rtrs = ['r1', 'r3', 'r4']
        for rtr in rtrs:
            luCommand(rtr, 'ip route show vrf {}-cust1 | grep -c \\^10\\.'.format(rtr),'^0$','wait','VRF route removed',wait)
#done
