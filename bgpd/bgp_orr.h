/*
 * BGP Optimal Route Reflection
 * Copyright (C) 2021  Samsung R&D Institute India - Bangalore.
 *			Madhurilatha Kuruganti
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_BGP_ORR_H
#define _FRR_BGP_ORR_H
#include <zebra.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Macro to log debug message */
#define bgp_orr_debug(...)                                                     \
	do {                                                                   \
		if (BGP_DEBUG(optimal_route_reflection, ORR))                  \
			zlog_debug("[BGP-ORR] " __VA_ARGS__);                  \
	} while (0)


/* BGP ORR Message Type */
enum bgp_orr_msg_type {
	BGP_ORR_IMSG_INVALID = 0,

	/* ORR group update */
	BGP_ORR_IMSG_GROUP_CREATE = 1,
	BGP_ORR_IMSG_GROUP_DELETE,
	BGP_ORR_IMSG_GROUP_UPDATE,

	/* ORR group update on a BGP RR Client */
	BGP_ORR_IMSG_SET_ORR_ON_PEER = 4,
	BGP_ORR_IMSG_UNSET_ORR_ON_PEER,

	/* ORR IGP Metric Update from IGP from requested Location */
	BGP_ORR_IMSG_IGP_METRIC_UPDATE = 6,

	/* ORR Group Related Information display */
	BGP_ORR_IMSG_SHOW_ORR = 7,
	BGP_ORR_IMSG_SHOW_ORR_GROUP,

	/* Invalid Message Type*/
	BGP_ORR_IMSG_MAX
};

extern struct zclient *zclient;

extern void bgp_config_write_orr(struct vty *vty, struct bgp *bgp, afi_t afi,
				 safi_t safi);

extern int bgp_afi_safi_orr_group_set_vty(struct vty *vty, afi_t afi,
					  safi_t safi, const char *name,
					  const char *primary_str,
					  const char *secondary_str,
					  const char *tertiary_str, bool unset);
extern int peer_orr_group_unset(struct peer *peer, afi_t afi, safi_t safi,
				const char *orr_group_name);
extern int peer_orr_group_set_vty(struct vty *vty, const char *ip_str,
				  afi_t afi, safi_t safi,
				  const char *orr_group_name, bool unset);
extern bool peer_orr_rrclient_check(struct peer *peer, afi_t afi, safi_t safi);

extern int bgp_show_orr(struct vty *vty, struct bgp *bgp, afi_t afi,
			safi_t safi, const char *orr_group_name,
			uint8_t show_flags);

extern int bgp_afi_safi_orr_group_set(struct bgp *bgp, afi_t afi, safi_t safi,
				      const char *name, struct peer *primary,
				      struct peer *secondary,
				      struct peer *tertiary);
extern int bgp_afi_safi_orr_group_unset(struct bgp *bgp, afi_t afi, safi_t safi,
					const char *name);

extern void bgp_peer_update_orr_active_roots(struct peer *peer);

extern int bgg_orr_message_process(enum bgp_orr_msg_type msg_type, void *msg);

extern struct bgp_orr_group *bgp_orr_group_lookup_by_name(struct bgp *bgp,
							  afi_t afi,
							  safi_t safi,
							  const char *name);
extern void bgp_orr_cleanup(struct bgp *bgp);
#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_ORR_H */
