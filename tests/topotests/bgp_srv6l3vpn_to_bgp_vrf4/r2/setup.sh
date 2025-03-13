sysctl net.vrf.strict_mode=1
ip link add vrf10 type vrf table 10
ip link set vrf10 up
ip link set eth1 master vrf10
