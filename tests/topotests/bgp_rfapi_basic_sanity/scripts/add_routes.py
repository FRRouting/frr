from lib.lutil import luCommand

holddownFactorSet = luCommand(
    "r1",
    'vtysh -c "show running"',
    "rfp holddown-factor",
    "none",
    "Holddown factor set",
)
if not holddownFactorSet:
    to = "-1"
    cost = ""
else:
    to = "6"
    cost = "cost 50"
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev open vn 10.0.0.1 un 1.1.1.1"',
    "rfapi_set_response_cb: status 0",
    "pass",
    "Opened RFAPI",
)
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.1 un 1.1.1.1 target 11.11.11.11"',
    "rc=2",
    "pass",
    "Clean query",
)
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev register vn 10.0.0.1 un 1.1.1.1 prefix 11.11.11.0/24 lifetime {}"'.format(
        to
    ),
    "",
    "none",
    "Prefix registered",
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations local"',
    "1 out of 1",
    "wait",
    "Local registration",
)
luCommand("r1", 'vtysh -c "debug rfapi-dev response-omit-self off"', ".", "none")
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.1 un 1.1.1.1 target 11.11.11.11"',
    "11.11.11.0/24",
    "pass",
    "Query self",
)

luCommand(
    "r3",
    'vtysh -c "debug rfapi-dev open vn 10.0.0.2 un 2.2.2.2"',
    "rfapi_set_response_cb: status 0",
    "pass",
    "Opened RFAPI",
)
luCommand(
    "r3",
    'vtysh -c "debug rfapi-dev register vn 10.0.0.2 un 2.2.2.2 prefix 22.22.22.0/24 lifetime {}"'.format(
        to
    ),
    "",
    "none",
    "Prefix registered",
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations local"',
    "1 out of 1",
    "wait",
    "Local registration",
)
luCommand("r3", 'vtysh -c "debug rfapi-dev response-omit-self on"', ".", "none")
luCommand(
    "r3",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.2 un 2.2.2.2 target 22.22.22.22"',
    "rc=2",
    "pass",
    "Self excluded",
)
luCommand(
    "r3",
    'vtysh -c "debug rfapi-dev open vn 10.0.1.2 un 2.1.1.2"',
    "rfapi_set_response_cb: status 0",
    "pass",
    "Opened query only RFAPI",
)
luCommand(
    "r3",
    'vtysh -c "debug rfapi-dev query vn 10.0.1.2 un 2.1.1.2 target 22.22.22.22"',
    "22.22.22.0/24",
    "pass",
    "See local",
)

luCommand(
    "r4",
    'vtysh -c "debug rfapi-dev open vn 10.0.0.3 un 3.3.3.3"',
    "rfapi_set_response_cb: status 0",
    "pass",
    "Opened RFAPI",
)
luCommand(
    "r4",
    'vtysh -c "debug rfapi-dev register vn 10.0.0.3 un 3.3.3.3 prefix 33.33.33.0/24 lifetime {}"'.format(
        to
    ),
    "",
    "none",
    "Prefix registered",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations local"',
    "1 out of 1",
    "wait",
    "Local registration",
)
luCommand("r4", 'vtysh -c "debug rfapi-dev response-omit-self off"', ".", "none")
luCommand(
    "r4",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.3 un 3.3.3.3 target 33.33.33.33"',
    "33.33.33.0/24",
    "pass",
    "Query self",
)

luCommand(
    "r4",
    'vtysh -c "debug rfapi-dev register vn 10.0.0.3 un 3.3.3.3 prefix 11.11.11.0/24 lifetime {} {}"'.format(
        to, cost
    ),
    "",
    "none",
    "MP Prefix registered",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations local"',
    "2 out of 2",
    "wait",
    "Local registration",
)
luCommand(
    "r4",
    'vtysh -c "debug rfapi-dev query vn 10.0.0.3 un 3.3.3.3 target 11.11.11.11"',
    "11.11.11.0/24",
    "pass",
    "Query self MP",
)

luCommand("r1", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r3", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r4", 'vtysh -c "show vnc registrations"', ".", "none")
