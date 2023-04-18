ip link add vrf10 type vrf table 10
ip link set vrf10 up
ip link add dum0 type dummy
ip link set dum0 up
sysctl -w net.ipv6.conf.dum0.disable_ipv6=0
