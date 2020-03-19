from lutil import luCommand

for r in range(0, 8):
    luCommand('r{}'.format(r),'vtysh -c "show k s"','Keycrypt status: ON.*Keycrypt status: ON.*Keycrypt status: ON','pass','Keycrypt ON')

rtrs = ['r0', 'r6', 'r7']
for rtr in rtrs:
    luCommand(rtr,'vtysh -c "show k s"', 'RIP: authentication strings: 1, encrypted: 1','pass','RIP Keycrypt status')
    luCommand(rtr,'vtysh -c "show k s"', 'passwords: 1, encrypted: 1','pass','BGP Keycrypt status')

luCommand('r5','vtysh -c "show k s"', 'RIP: authentication strings: 1, encrypted: 1','pass','RIP Keycrypt status')
luCommand('r5','vtysh -c "show k s"', 'passwords: 2, encrypted: 2','pass','BGP Keycrypt status')
luCommand('r5','vtysh -c "show k s"', 'LDP: neighbor passwords: 1, encrypted: 1','pass','LDP Keycrypt status')

luCommand('r1','vtysh -c "show k s"', 'RIP: authentication strings: 2, encrypted: 2','pass','RIP Keycrypt status')
luCommand('r1','vtysh -c "show k s"', 'RIP: Keychain: keys: 1, encrypted: 1','pass','RIP Keychain Keycrypt status')
luCommand('r1','vtysh -c "show k s"', 'OSPF: vrf default: message-digest-keys keys: 1, encrypted: 1','pass','OSPF Keycrypt status')
luCommand('r1','vtysh -c "show k s"', 'passwords: 3, encrypted: 3','pass','BGP Keycrypt status')

luCommand('r2','vtysh -c "show k s"', 'RIP: authentication strings: 3, encrypted: 3','pass','RIP Keycrypt status')
luCommand('r2','vtysh -c "show k s"', 'OSPF: vrf default: message-digest-keys keys: 3, encrypted: 3','pass','OSPF Keycrypt status')
luCommand('r2','vtysh -c "show k s"', 'passwords: 6, encrypted: 6','pass','BGP Keycrypt status')

luCommand('r3','vtysh -c "show k s"', 'RIP: authentication strings: 3, encrypted: 3','pass','RIP Keycrypt status')
luCommand('r3','vtysh -c "show k s"', 'OSPF: vrf default: message-digest-keys keys: 2, encrypted: 2','pass','OSPF Keycrypt status')
luCommand('r3','vtysh -c "show k s"', 'passwords: 4, encrypted: 4','pass','BGP Keycrypt status')
luCommand('r3','vtysh -c "show k s"', 'LDP: neighbor passwords: 1, encrypted: 1','pass','LDP Keycrypt status')

luCommand('r4','vtysh -c "show k s"', 'RIP: authentication strings: 3, encrypted: 3','pass','RIP Keycrypt status')
luCommand('r4','vtysh -c "show k s"', 'OSPF: vrf default: message-digest-keys keys: 1, encrypted: 1','pass','OSPF Keycrypt status')
luCommand('r4','vtysh -c "show k s"', 'passwords: 6, encrypted: 6','pass','BGP Keycrypt status')
