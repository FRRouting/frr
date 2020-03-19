from lutil import luCommand

#
# Number of decrypt failure warnings we expect in the various
# protocol configuration outputs
#
want = {
    'r0': {'bgp': 1},
    'r1': {'rip': 3},				# 2 rip, 1 keychain
    'r2': {'bgp': 6, 'ospf': 3, 'rip': 3,},
    'r4': {'bgp': 6, 'rip': 3,},
    'r5': {'bgp': 2, 'ldp': 1},
    'r7': {'bgp': 1},
}

for router,protoinfo in want.items():
    for proto,count in protoinfo.items():
        cmd = "grep '!!! Error: Unable to decrypt' /etc/frr/{}d.conf|wc -l".format(proto)
        luCommand(router, cmd, '{}'.format(count), 'pass',
            "{} number of decrypt fail warnings".format(proto))
