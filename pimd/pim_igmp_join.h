// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_IGMP_JOIN_H
#define PIM_IGMP_JOIN_H

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

static inline int pim_igmp_join_source(int fd, ifindex_t ifindex,
				       struct in_addr group_addr,
				       struct in_addr source_addr)
{
	struct group_source_req req;
	struct sockaddr_in group;
	struct sockaddr_in source;

	memset(&req, 0, sizeof(req));
	memset(&group, 0, sizeof(group));
	group.sin_family = AF_INET;
	group.sin_addr = group_addr;
	group.sin_port = htons(0);
	memcpy(&req.gsr_group, &group, sizeof(struct sockaddr_in));

	memset(&source, 0, sizeof(source));
	source.sin_family = AF_INET;
	source.sin_addr = source_addr;
	source.sin_port = htons(0);
	memcpy(&req.gsr_source, &source, sizeof(struct sockaddr_in));

	req.gsr_interface = ifindex;

	if (source_addr.s_addr == INADDR_ANY)
		return setsockopt(fd, SOL_IP, MCAST_JOIN_GROUP, &req,
				  sizeof(req));
	else
		return setsockopt(fd, SOL_IP, MCAST_JOIN_SOURCE_GROUP, &req,
				  sizeof(req));
}

#endif /* PIM_IGMP_JOIN_H */
