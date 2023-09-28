// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Daniel Walton
 */

#ifndef PIM_IGMPV2_H
#define PIM_IGMPV2_H

void igmp_v2_send_query(struct gm_group *group, int fd, const char *ifname,
			char *query_buf, struct in_addr dst_addr,
			struct in_addr group_addr,
			int query_max_response_time_dsec);

int igmp_v2_recv_report(struct gm_sock *igmp, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len);

int igmp_v2_recv_leave(struct gm_sock *igmp, struct ip *ip_hdr,
		       const char *from_str, char *igmp_msg, int igmp_msg_len);

#endif /* PIM_IGMPV2_H */
