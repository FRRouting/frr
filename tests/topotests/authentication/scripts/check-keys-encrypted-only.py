from lutil import luCommand

#
# Only routers 1,2,4 had rip restarted by restart script
# Only routers 2 had ospf restarted by restart script
# Only routers 0,2,4,5,7 had bgp restarted by restart script
#

want = {
    'r0': {
        'bgp': {
            'plain': 0,
            'crypt': 1,
        },
    },
    'r1': {
        'rip': {
            'plain': 0,
            'crypt': 2,
        },
        'rip-keychain': {
            'plain': 0,
            'crypt': 1,
        },
    },
    'r2': {
        'bgp': {
            'plain': 0,
            'crypt': 6,
        },
        'rip': {
            'plain': 0,
            'crypt': 3,
        },
        'ospf': {		# message-digest keys
            'plain': 0,
            'crypt': 3,
        },
    },
    'r4': {
        'bgp': {
            'plain': 0,
            'crypt': 6,
        },
        'rip': {
            'plain': 0,
            'crypt': 3,
        },
    },
    'r5': {
        'ldp': {
            'plain': 0,
            'crypt': 1,
        },
        'bgp': {
            'plain': 0,
            'crypt': 2,
        },
    },
    'r7': {
        'bgp': {
            'plain': 0,
            'crypt': 1,
        },
    },
}

for router,protoinfo in want.items():
    for proto,keyinfo in protoinfo.items():
        match = None
        if proto == 'bgp':
            match = 'passwords: {}, encrypted: {}'.format(
                keyinfo['plain'], keyinfo['crypt'])
        if proto == 'ospf':
            match = 'OSPF: vrf default: message-digest-keys keys: {}, encrypted: {}'.format(keyinfo['plain'], keyinfo['crypt'])
        if proto == 'rip':
            match = 'RIP: authentication strings: {}, encrypted: {}'.format(
                keyinfo['plain'], keyinfo['crypt'])
        if proto == 'rip-keychain':
            match = 'RIP: Keychain: keys: {}, encrypted: {}'.format(
                keyinfo['plain'], keyinfo['crypt'])
	if proto == 'ldp':
	    match = 'LDP: neighbor passwords: {}, encrypted: {}'.format(
                keyinfo['plain'], keyinfo['crypt'])
        if match == None:
            luResult(router, False, "Invalid Protocol: test coding error")
        else:
            luCommand(router, 'vtysh -c "show k s"', match, 'pass',
                '{} Keycrypt Status'.format(proto))

