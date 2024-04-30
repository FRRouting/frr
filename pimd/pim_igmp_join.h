// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_IGMP_JOIN_H
#define PIM_IGMP_JOIN_H

#include "pim_addr.h"

/* required headers #include'd by caller */

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef MCAST_JOIN_GROUP
#define MCAST_JOIN_GROUP 42
#endif

#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
struct group_source_req {
	uint32_t gsr_interface;
	struct sockaddr_storage gsr_group;
	struct sockaddr_storage gsr_source;
};
#endif

#if PIM_IPV == 4
static inline int pim_gm_join_source(int fd, ifindex_t ifindex,
				     pim_addr group_addr, pim_addr source_addr)
{
	struct group_source_req req;
	struct sockaddr_in group = {};
	struct sockaddr_in source = {};

	memset(&req, 0, sizeof(req));

	group.sin_family = PIM_AF;
	group.sin_addr = group_addr;
	group.sin_port = htons(0);
	memcpy(&req.gsr_group, &group, sizeof(group));

	source.sin_family = PIM_AF;
	source.sin_addr = source_addr;
	source.sin_port = htons(0);
	memcpy(&req.gsr_source, &source, sizeof(source));

	req.gsr_interface = ifindex;

	if (pim_addr_is_any(source_addr))
		return setsockopt(fd, SOL_IP, MCAST_JOIN_GROUP, &req,
				  sizeof(req));
	else
		return setsockopt(fd, SOL_IP, MCAST_JOIN_SOURCE_GROUP, &req,
				  sizeof(req));
}
#else  /* PIM_IPV != 4*/
static inline int pim_gm_join_source(int fd, ifindex_t ifindex,
				     pim_addr group_addr, pim_addr source_addr)
{
	struct group_source_req req;
	struct sockaddr_in6 group = {};
	struct sockaddr_in6 source = {};

	memset(&req, 0, sizeof(req));

	group.sin6_family = PIM_AF;
	group.sin6_addr = group_addr;
	group.sin6_port = htons(0);
	memcpy(&req.gsr_group, &group, sizeof(group));

	source.sin6_family = PIM_AF;
	source.sin6_addr = source_addr;
	source.sin6_port = htons(0);
	memcpy(&req.gsr_source, &source, sizeof(source));

	req.gsr_interface = ifindex;

	if (pim_addr_is_any(source_addr))
		return setsockopt(fd, SOL_IPV6, MCAST_JOIN_GROUP, &req,
				  sizeof(req));
	else
		return setsockopt(fd, SOL_IPV6, MCAST_JOIN_SOURCE_GROUP, &req,
				  sizeof(req));
}
#endif /* PIM_IPV != 4*/

#endif /* PIM_IGMP_JOIN_H */
