from lutil import luCommand
for routern in range(0, 8):
    rtr='r{}'.format(routern)
    ret = luCommand(rtr, 'vtysh -c "show bgp neigh" | grep -v Cease/', 'Notification received .([A-Za-z0-9/ ]*)', 'none', 'collect neighbor stats')
    found = luLast()
    if ret != False and found != None:
        val = found.group(1)
        ret = luCommand(rtr, 'vtysh -c "show bgp neigh"', 'Notification received', 'fail', 'Notify RXed! {}'.format(val))
#done
