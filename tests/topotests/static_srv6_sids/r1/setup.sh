ip link add sr0 type dummy
ip link set sr0 up

ip link add Vrf10 type vrf table 10
ip link set Vrf10 up

ip link add Vrf20 type vrf table 20
ip link set Vrf20 up

ip link add Vrf30 type vrf table 30
ip link set Vrf30 up

sysctl -w net.vrf.strict_mode=1
