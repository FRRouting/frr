/*
 * PIM for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Daniel Walton
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PIM_IGMPV2_H
#define PIM_IGMPV2_H

void igmp_v2_send_query(struct igmp_group *group, int fd, const char *ifname,
			char *query_buf, struct in_addr dst_addr,
			struct in_addr group_addr,
			int query_max_response_time_dsec);

int igmp_v2_recv_report(struct igmp_sock *igmp, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len);

int igmp_v2_recv_leave(struct igmp_sock *igmp, struct in_addr from,
		       const char *from_str, char *igmp_msg, int igmp_msg_len);

#endif /* PIM_IGMPV2_H */
