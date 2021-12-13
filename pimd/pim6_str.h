
#ifndef PIM6_STR_H
#define PIM6_STR_H

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <prefix.h>

#define PIM_ADDR in6_addr
#define PIM_SG_PFX(sg) (sg).src.ipaddr_v6
#define PIM_IPADDR_PFX(ip) (ip).ipaddr_v6
#define PIM_UN_PFX(p) (p).u.prefix6
#define pim_inet_dump prefix_mcast_inet6_dump

void pim_inet4_dump(const char *onfail, struct in_addr addr, char *buf,
		    int buf_size);

