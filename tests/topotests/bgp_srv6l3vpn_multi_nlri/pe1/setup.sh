sysctl net.vrf.strict_mode=1
ip link add Vrf1 type vrf table 10
ip link set Vrf1 up
ip link set eth1 master Vrf1
