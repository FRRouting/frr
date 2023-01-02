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
else:
    to = "1"
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev open vn 20.0.0.1 un 1.1.1.21"',
    "rfapi_set_response_cb: status 0",
    "pass",
    "Opened RFAPI",
)
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev register vn 20.0.0.1 un 1.1.1.21 prefix 111.111.111.0/24 lifetime {}"'.format(
        to
    ),
    "",
    "none",
    "Prefix registered",
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations local"',
    "111.111.111.0/24",
    "wait",
    "Local registration",
    1,
)
luCommand("r1", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand(
    "r3",
    'vtysh -c "show vnc registrations"',
    "111.111.111.0/24",
    "wait",
    "See registration",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations"',
    "111.111.111.0/24",
    "wait",
    "See registration",
)
luCommand(
    "r1",
    'vtysh -c "debug rfapi-dev close vn 20.0.0.1 un 1.1.1.21"',
    "status 0",
    "pass",
    "Closed RFAPI",
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations"',
    "Locally: *Active:  1 .* Remotely: *Active:  3",
    "wait",
    "See cleanup",
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations"',
    "Locally: *Active:  1 .* Remotely: *Active:  3",
    "wait",
    "See cleanup",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations"',
    "Locally: *Active:  2 .* Remotely: *Active:  2",
    "wait",
    "See cleanup",
)
luCommand(
    "r1",
    'vtysh -c "show vnc registrations"',
    "In Holddown: *Active:  0",
    "wait",
    "Out of holddown",
    20,
)
luCommand(
    "r3",
    'vtysh -c "show vnc registrations"',
    "In Holddown: *Active:  0",
    "wait",
    "Out of holddown",
)
luCommand(
    "r4",
    'vtysh -c "show vnc registrations"',
    "In Holddown: *Active:  0",
    "wait",
    "Out of holddown",
)
