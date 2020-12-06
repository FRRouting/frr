ip link add dum0 type dummy
ip link set dum0 up
sysctl -w net.ipv6.conf.dum0.disable_ipv6=0
