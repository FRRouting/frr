from lutil import luCommand

# show routes: "show ip ripng"
# show status: "show ip ripng status"

# foreign routers can use link-local addresses in their advertisements so
# it's not straightforward to parse the "gateway" field of the status output.

# the patterns below are pretty loose

luCommand('r0','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* r0-eth0 .* 2001:db8:beed:2::2/128 .* r0-eth0 .* 2001:db8:beed:3::3/128 .* r0-eth0 .* 2001:db8:beed:4::4/128 .* r0-eth0 ',
    'wait','RIPng Routes', 60)

luCommand('r1','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* self .* 2001:db8:beed:2::2/128 .* r1-eth0 .* 2001:db8:beed:3::3/128 .* r1-eth0 .* 2001:db8:beed:4::4/128 .* r1-eth0 ',
    'wait','RIPng Routes', 30)

luCommand('r2','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* r2-eth0 .* 2001:db8:beed:2::2/128 .* self .* 2001:db8:beed:3::3/128 .* r2-eth[12] .* 2001:db8:beed:4::4/128 .* r2-eth1 ',
    'wait','RIPng Routes', 30)

luCommand('r3','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* r3-eth[01] .* 2001:db8:beed:2::2/128 .* r3-eth[01] .* 2001:db8:beed:3::3/128 .* self .* 2001:db8:beed:4::4/128 .* r3-eth0 ',
    'wait','RIPng Routes', 30)

luCommand('r4','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* r4-eth0 .* 2001:db8:beed:2::2/128 .* r4-eth0 .* 2001:db8:beed:3::3/128 .* r4-eth0 .* 2001:db8:beed:4::4/128 .* self ',
    'wait','RIPng Routes', 30)

luCommand('r5','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* r5-eth0 .* 2001:db8:beed:2::2/128 .* r5-eth0 .* 2001:db8:beed:3::3/128 .* r5-eth0 .* 2001:db8:beed:4::4/128 .* r5-eth0 ',
    'wait','RIPng Routes', 10)

luCommand('r6','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* r6-eth0 .* 2001:db8:beed:2::2/128 .* r6-eth0 .* 2001:db8:beed:3::3/128 .* r6-eth0 .* 2001:db8:beed:4::4/128 .* r6-eth0 ',
    'wait','RIPng Routes', 10)

luCommand('r7','vtysh -c "show ip ripng"',
    ' 2001:db8:beed:1::1/128 .* r7-eth0 .* 2001:db8:beed:2::2/128 .* r7-eth0 .* 2001:db8:beed:3::3/128 .* r7-eth0 .* 2001:db8:beed:4::4/128 .* r7-eth0 ',
    'wait','RIPng Routes', 10)
