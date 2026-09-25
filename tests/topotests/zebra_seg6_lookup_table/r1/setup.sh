ip link add eth0 type dummy
ip link set eth0 up

ip link add vrfA type vrf table 1001
ip link set dev vrfA up

ip link add eth1 type dummy
ip link set dev eth1 master vrfA
ip link set eth1 up

ip r a 1.1.1.0/24 encap seg6 mode encap segs fec0::ff dev eth0
ip r a 2.2.2.0/24 encap seg6 mode encap segs fec0::ff lookup 254 dev eth0
ip r a 3.3.3.0/24 encap seg6 mode encap segs fec1::ff lookup 1001 dev eth1

ip -6 r a 2001:db8:1::/48 encap seg6 mode encap segs fec0::ff dev eth0
ip -6 r a 2001:db8:2::/48 encap seg6 mode encap segs fec0::ff lookup 254 dev eth0
ip -6 r a 2001:db8:3::/48 encap seg6 mode encap segs fec1::ff lookup 1001 dev eth1
