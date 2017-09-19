# Useful Sysctl Settings
Sysctl on Linux systems can tweak many useful behaviors. When it comes to a routing protocol suite like FRRouting there are numerous values depending on your use case that make sense to optimize.

The below sysctl values provide a logical set of defaults which can be further optimized.


```
# /etc/sysctl.d/99frr_defaults.conf
# Place this file at the location above and reload the device.
# or run the sysctl -p /etc/sysctl.d/99frr_defaults.conf
  
# Enables IPv4/IPv6 Routing
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding=1

# Routing
net.ipv6.route.max_size=131072
net.ipv4.conf.all.ignore_routes_with_linkdown=1
net.ipv6.conf.all.ignore_routes_with_linkdown=1

# Best Settings for Peering w/ BGP Unnumbered
#    and OSPF Neighbors
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.rp_filter = 0
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.default.arp_notify = 1
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_notify = 1
net.ipv4.conf.all.arp_ignore=1
net.ipv4.icmp_errors_use_inbound_ifaddr=1

# Miscellaneous Settings

#   Keep ipv6 permanent addresses on an admin down
net.ipv6.conf.all.keep_addr_on_down=1

# igmp
net.ipv4.igmp_max_memberships=1000
net.ipv4.neigh.default.mcast_solicit = 10

# MLD
net.ipv6.mld_max_msf=512

# Garbage Collection Settings for ARP and Neighbors
net.ipv4.neigh.default.gc_thresh2=7168
net.ipv4.neigh.default.gc_thresh3=8192
net.ipv4.neigh.default.base_reachable_time_ms=14400000
net.ipv6.neigh.default.gc_thresh2=3584
net.ipv6.neigh.default.gc_thresh3=4096
net.ipv6.neigh.default.base_reachable_time_ms=14400000

# Use neigh information on selection of nexthop for multipath hops
net.ipv4.fib_multipath_use_neigh=1

# Allows Apps to Work with VRF
net.ipv4.tcp_l3mdev_accept=1
```
