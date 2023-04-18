from lib.lutil import luCommand

holddownFactorSet = luCommand(
    "r1",
    'vtysh -c "show running"',
    "rfp holddown-factor",
    "none",
    "Holddown factor set",
)
luCommand("r1", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r3", 'vtysh -c "show vnc registrations"', ".", "none")
luCommand("r4", 'vtysh -c "show vnc registrations"', ".", "none")
if not holddownFactorSet:
    luCommand(
        "r1",
        'vtysh -c "show vnc summary"',
        ".",
        "pass",
        "Holddown factor not set -- skipping test",
    )
else:
    # holddown time test
    luCommand(
        "r1",
        'vtysh -c "debug rfapi-dev register vn 10.0.0.1 un 1.1.1.1 prefix 1.111.0.0/16 lifetime 10"',
        "",
        "none",
        "Prefix registered",
    )
    luCommand(
        "r1",
        'vtysh -c "show vnc registrations local"',
        "1.111.0.0/16",
        "wait",
        "Local registration",
    )

    luCommand(
        "r3",
        'vtysh -c "debug rfapi-dev register vn 10.0.0.2 un 2.2.2.2 prefix 1.222.0.0/16 lifetime 10"',
        "",
        "none",
        "Prefix registered",
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations local"',
        "1.222.0.0/16",
        "wait",
        "Local registration",
    )

    luCommand(
        "r4",
        'vtysh -c "show vnc registrations"',
        "Remotely: *Active:  4 ",
        "wait",
        "See registrations, L=10",
    )

    luCommand(
        "r4",
        'vtysh -c "debug rfapi-dev register vn 10.0.0.3 un 3.3.3.3 prefix 1.222.0.0/16 lifetime 5 cost 50"',
        "",
        "none",
        "MP Prefix registered",
    )
    luCommand(
        "r4",
        'vtysh -c "show vnc registrations local"',
        "1.222.0.0/16",
        "wait",
        "Local registration (MP prefix)",
    )

    luCommand("r1", 'vtysh -c "show vnc registrations"', ".", "none")
    luCommand("r3", 'vtysh -c "show vnc registrations"', ".", "none")

    luCommand(
        "r4",
        'vtysh -c "debug rfapi-dev query vn 10.0.0.3 un 3.3.3.3 target 1.111.111.111"',
        "pfx=",
        "pass",
        "Query R1s info",
    )
    luCommand(
        "r4",
        'vtysh -c "debug rfapi-dev query vn 10.0.0.3 un 3.3.3.3 target 1.222.222.222"',
        "1.222.0.0/16.*1.222.0.0/16",
        "pass",
        "Query R3s+R4s info",
    )

    luCommand(
        "r4",
        'vtysh -c "debug rfapi-dev unregister vn 10.0.0.3 un 3.3.3.3 prefix 1.222.0.0/16"',
        "",
        "none",
        "MP Prefix removed",
    )
    luCommand(
        "r4",
        'vtysh -c "show vnc registrations"',
        "In Holddown: *Active:  1 ",
        "wait",
        "MP prefix in holddown",
    )
    luCommand(
        "r1",
        'vtysh -c "show vnc registrations"',
        "In Holddown: *Active:  1 ",
        "wait",
        "MP prefix in holddown",
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations"',
        "In Holddown: *Active:  1 ",
        "wait",
        "MP prefix in holddown",
    )
    luCommand(
        "r1",
        'vtysh -c "debug rfapi-dev query vn 10.0.0.1 un 1.1.1.1 target 1.222.222.222"',
        "1.222.0.0/16",
        "pass",
        "Query R3s info",
    )
    luCommand(
        "r1",
        'vtysh -c "debug rfapi-dev unregister vn 10.0.0.1 un 1.1.1.1 prefix 1.111.0.0/16"',
        "",
        "none",
        "Prefix timeout",
    )
    luCommand(
        "r1",
        'vtysh -c "show vnc registrations holddown"',
        "1.111.0.0/16",
        "wait",
        "Local holddown",
        1,
    )
    luCommand(
        "r3",
        'vtysh -c "debug rfapi-dev unregister vn 10.0.0.2 un 2.2.2.2 prefix 1.222.0.0/16"',
        "",
        "none",
        "Prefix timeout",
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations holddown"',
        "1.222.0.0/16",
        "wait",
        "Local holddown",
        1,
    )
    luCommand("r4", 'vtysh -c "show vnc registrations"', ".", "none")
    luCommand("r4", 'vtysh -c "show vnc registrations"', ".", "none")

    luCommand(
        "r4",
        'vtysh -c "show vnc registrations"',
        "In Holddown: *Active:  2 ",
        "wait",
        "In holddown",
    )
    luCommand(
        "r1",
        'vtysh -c "show vnc registrations"',
        "In Holddown: *Active:  2 ",
        "wait",
        "In holddown",
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations"',
        "In Holddown: *Active:  2 ",
        "wait",
        "In holddown",
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

    # kill test
    luCommand(
        "r1",
        'vtysh -c "debug rfapi-dev register vn 10.0.0.1 un 1.1.1.1 prefix 1.111.0.0/16 lifetime 10"',
        "",
        "none",
        "Prefix registered",
    )
    luCommand(
        "r1",
        'vtysh -c "show vnc registrations local"',
        "1.111.0.0/16",
        "wait",
        "Local registration",
    )

    luCommand(
        "r3",
        'vtysh -c "debug rfapi-dev register vn 10.0.0.2 un 2.2.2.2 prefix 1.222.0.0/16 lifetime 10"',
        "",
        "none",
        "Prefix registered",
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations local"',
        "1.222.0.0/16",
        "wait",
        "Local registration",
    )

    luCommand(
        "r4",
        'vtysh -c "show vnc registrations"',
        "Remotely: *Active:  4 ",
        "wait",
        "See registrations L=10 (pre-kill)",
        5,
    )
    luCommand("r1", 'vtysh -c "show vnc registrations"', ".", "none")
    luCommand("r3", 'vtysh -c "show vnc registrations"', ".", "none")
    luCommand(
        "r1",
        'vtysh -c "debug rfapi-dev unregister vn 10.0.0.1 un 1.1.1.1 prefix 1.111.0.0/16 kill"',
        "",
        "none",
        "Prefix kill",
    )
    luCommand(
        "r1",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  1 .* Remotely: *Active:  4 .*In Holddown: *Active:  0",
        "wait",
        "Registration killed",
        1,
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  2 .* Remotely: *Active:  3 .*In Holddown: *Active:  1",
        "wait",
        "Remote in holddown",
        5,
    )
    luCommand(
        "r4",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  2 .* Remotely: *Active:  3 .*In Holddown: *Active:  1",
        "wait",
        "Remote in holddown",
        5,
    )

    luCommand(
        "r3",
        'vtysh -c "debug rfapi-dev unregister vn 10.0.0.2 un 2.2.2.2 prefix 1.222.0.0/16 kill"',
        "",
        "none",
        "Prefix kill",
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  1 .* Remotely: *Active:  3 .*In Holddown: *Active:  1",
        "wait",
        "Registration killed",
        1,
    )
    luCommand(
        "r4",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  2 .* Remotely: *Active:  2 .*In Holddown: *Active:  2",
        "wait",
        "Remote in holddown",
        5,
    )

    luCommand(
        "r1",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  1 .* Remotely: *Active:  3 .*In Holddown: *Active:  0",
        "wait",
        "Out of holddown",
        20,
    )
    luCommand(
        "r3",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  1 .* Remotely: *Active:  3 .*In Holddown: *Active:  0",
        "wait",
        "Out of holddown",
    )
    luCommand(
        "r4",
        'vtysh -c "show vnc registrations"',
        "Locally: *Active:  2 .* Remotely: *Active:  2 .*In Holddown: *Active:  0",
        "wait",
        "Out of holddown",
    )
