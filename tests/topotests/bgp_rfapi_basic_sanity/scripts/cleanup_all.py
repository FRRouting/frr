from lutil import luCommand
luCommand('r1','vtysh -c "debug rfapi-dev unregister vn 10.0.0.1 un 1.1.1.1 prefix 11.11.11.0/24"','', 'none', 'Prefix removed')
luCommand('r1','vtysh -c "show vnc registrations"','Locally: *Active:  0 ','wait','Local registration removed')
luCommand('r1','vtysh -c "debug rfapi-dev close vn 10.0.0.1 un 1.1.1.1"','status 0', 'pass', 'Closed RFAPI')

luCommand('r3','vtysh -c "debug rfapi-dev unregister vn 10.0.0.2 un 2.2.2.2 prefix 22.22.22.0/24"','', 'none', 'Prefix removed')
luCommand('r3','vtysh -c "show vnc registrations"','Locally: *Active:  0 ','wait','Local registration removed')
luCommand('r3','vtysh -c "debug rfapi-dev close vn 10.0.0.2 un 2.2.2.2"','status 0', 'pass', 'Closed RFAPI')

luCommand('r4','vtysh -c "debug rfapi-dev unregister vn 10.0.0.3 un 3.3.3.3 prefix 33.33.33.0/24"','', 'none', 'Prefix removed')
luCommand('r4','vtysh -c "debug rfapi-dev unregister vn 10.0.0.3 un 3.3.3.3 prefix 11.11.11.0/24"','', 'none', 'MP prefix removed')
luCommand('r4','vtysh -c "show vnc registrations"','Locally: *Active:  0 ','wait','Local registration removed')
luCommand('r4','vtysh -c "debug rfapi-dev close vn 10.0.0.3 un 3.3.3.3"','status 0', 'pass', 'Closed RFAPI')

luCommand('r1','vtysh -c "show vnc registrations"','Locally: *Active:  0 .* Remotely: *Active:  0','wait','All registrations cleared')
luCommand('r3','vtysh -c "show vnc registrations"','Locally: *Active:  0 .* Remotely: *Active:  0','wait','All registrations cleared')
luCommand('r4','vtysh -c "show vnc registrations"','Locally: *Active:  0 .* Remotely: *Active:  0','wait','All registrations cleared')

num = '0 exist'
luCommand('r1','vtysh -c "show bgp ipv4 vpn"',num,'pass','VPN SAFI clear')
luCommand('r2','vtysh -c "show bgp ipv4 vpn"',num,'pass','VPN SAFI clear')
luCommand('r3','vtysh -c "show bgp ipv4 vpn"',num,'pass','VPN SAFI clear')
luCommand('r4','vtysh -c "show bgp ipv4 vpn"',num,'pass','VPN SAFI clear')

luCommand('r1','vtysh -c "show vnc registrations"','Locally: *Active:  0 .* Remotely: *Active:  0 .*In Holddown: *Active:  0','wait','No holddowns',20)
luCommand('r3','vtysh -c "show vnc registrations"','Locally: *Active:  0 .* Remotely: *Active:  0 .*In Holddown: *Active:  0','wait','No holddowns')
luCommand('r4','vtysh -c "show vnc registrations"','Locally: *Active:  0 .* Remotely: *Active:  0 .*In Holddown: *Active:  0','wait','No holddowns')

luCommand('r1','vtysh -c "show vnc summary"','.','none')
luCommand('r3','vtysh -c "show vnc summary"','.','none')
luCommand('r4','vtysh -c "show vnc summary"','.','none')

