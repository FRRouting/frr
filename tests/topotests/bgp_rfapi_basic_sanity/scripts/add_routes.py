from lutil import luCommand
luCommand('r1','vtysh -c "debug rfapi-dev open vn 10.0.0.1 un 1.1.1.1"','rfapi_set_response_cb: status 0', 'pass', 'Opened RFAPI')
luCommand('r1','vtysh -c "debug rfapi-dev register vn 10.0.0.1 un 1.1.1.1 prefix 11.11.11.0/24 lifetime -1"','', 'none', 'Prefix registered')
luCommand('r1','vtysh -c "show vnc registrations local"','1 out of 1','wait','Local registration')

luCommand('r3','vtysh -c "debug rfapi-dev open vn 10.0.0.2 un 2.2.2.2"','rfapi_set_response_cb: status 0', 'pass', 'Opened RFAPI')
luCommand('r3','vtysh -c "debug rfapi-dev register vn 10.0.0.2 un 2.2.2.2 prefix 22.22.22.0/24 lifetime -1"','', 'none', 'Prefix registered')
luCommand('r3','vtysh -c "show vnc registrations local"','1 out of 1','wait','Local registration')

luCommand('r4','vtysh -c "debug rfapi-dev open vn 10.0.0.3 un 3.3.3.3"','rfapi_set_response_cb: status 0', 'pass', 'Opened RFAPI')
luCommand('r4','vtysh -c "debug rfapi-dev register vn 10.0.0.3 un 3.3.3.3 prefix 33.33.33.0/24 lifetime -1"','', 'none', 'Prefix registered')
luCommand('r4','vtysh -c "show vnc registrations local"','1 out of 1','wait','Local registration')
luCommand('r1','vtysh -c "show vnc registrations"','.','none')
luCommand('r3','vtysh -c "show vnc registrations"','.','none')
luCommand('r4','vtysh -c "show vnc registrations"','.','none')
