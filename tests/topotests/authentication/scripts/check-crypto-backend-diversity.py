from lutil import luCommand, luLast

#
# Set and verify crypto backends. This test requires that the specified
# backends are actually built into FRR (specified/detected at "configure"
# time)
#

#
# Only routers 1,2,4 had rip restarted by restart script
# Only routers 2 had ospf restarted by restart script
# Only routers 0,2,4,5,7 had bgp restarted by restart script
#

want = {
    'r0': {
        'set-backend': 'gcrypt',
        'BGP': 'gcrypt',
    },
    'r1': {
	'set-backend':'openssl',
	'RIP':'openssl',
    },
    'r2': {
	'set-backend':'gcrypt',
	'BGP':'gcrypt',
	'RIP':'gcrypt',
	'OSPF':'gcrypt',
    },
    'r4': {
	'set-backend':'gcrypt',
	'BGP':'gcrypt',
	'RIP':'gcrypt',
    },
    'r5': {
	'set-backend':'openssl',
        'LDP': 'openssl',
        'BGP': 'openssl',
    },
    'r7': {
	'set-backend':'openssl',
        'BGP': 'openssl',
    },
}

for router,protoinfo in want.items():

    #
    # Backends should be set in config files before any passwords appear.
    # Availability of backends depends on build-time configuration.
    #

    # set backend (should set all protocols at once)
    # logic here should be improved
    available = 0
    for proto,backend in protoinfo.items():
	if proto == 'set-backend':
            # Is desired backend available?
            match = '[\s\*]({}):'.format(backend)
            ret = luCommand(router, 'vtysh -c "debug keycrypt show backends"',
                match, 'none', "match desired backend")
            found = luLast()
            if ret != False and found != None:
                available = 1

    # check backend on each active protocol
    if available:
        for proto,backend in protoinfo.items():
            if proto != 'set-backend':
                # Is desired backend set?
                match = '{}: Keycrypt backend: {}'.format(proto,backend)
                luCommand(router, 'vtysh -c "show keycrypt status"',
                    match, 'pass',
                    '{} Has desired keycrypt backend ({})'.format(proto,backend))
