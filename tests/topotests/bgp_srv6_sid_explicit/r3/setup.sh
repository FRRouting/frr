ip link add sr0 type dummy
ip link set sr0 up

sysctl -w net.vrf.strict_mode=1

ip link add Vrf10 type vrf table 10
ip link set Vrf10 up
ip link add Vrf20 type vrf table 20
ip link set Vrf20 up

ip link set eth1 master Vrf10
ip link set eth2 master Vrf20
