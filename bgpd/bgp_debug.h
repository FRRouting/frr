// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP message debug header.
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_DEBUG_H
#define _QUAGGA_BGP_DEBUG_H

#include "hook.h"
#include "vty.h"

#include "bgp_attr.h"
#include "bgp_updgrp.h"

DECLARE_HOOK(bgp_hook_config_write_debug, (struct vty *vty, bool running),
	     (vty, running));

/* sort of packet direction */
#define DUMP_ON        1
#define DUMP_SEND      2
#define DUMP_RECV      4

/* for dump_update */
#define DUMP_WITHDRAW  8
#define DUMP_NLRI     16

/* dump detail */
#define DUMP_DETAIL   32

/* RD + Prefix + Path-Id */
#define BGP_PRD_PATH_STRLEN                                                    \
	(PREFIX_STRLEN + RD_ADDRSTRLEN + INET6_ADDRSTRLEN + 34)

extern int dump_open;
extern int dump_update;
extern int dump_keepalive;
extern int dump_notify;

extern int Debug_Event;
extern int Debug_Keepalive;
extern int Debug_Update;
extern int Debug_Radix;

#define	NLRI	 1
#define	WITHDRAW 2
#define	NO_OPT	 3
#define	SEND	 4
#define	RECV	 5
#define	DETAIL	 6

/* Prototypes. */
extern void bgp_debug_init(void);
extern void bgp_packet_dump(struct stream *);

extern int debug(unsigned int option);

extern unsigned long conf_bgp_debug_as4;
extern unsigned long conf_bgp_debug_neighbor_events;
extern unsigned long conf_bgp_debug_packet;
extern unsigned long conf_bgp_debug_keepalive;
extern unsigned long conf_bgp_debug_update;
extern unsigned long conf_bgp_debug_bestpath;
extern unsigned long conf_bgp_debug_zebra;
extern unsigned long conf_bgp_debug_nht;
extern unsigned long conf_bgp_debug_update_groups;
extern unsigned long conf_bgp_debug_vpn;
extern unsigned long conf_bgp_debug_flowspec;
extern unsigned long conf_bgp_debug_labelpool;
extern unsigned long conf_bgp_debug_pbr;
extern unsigned long conf_bgp_debug_graceful_restart;
extern unsigned long conf_bgp_debug_evpn_mh;
extern unsigned long conf_bgp_debug_bfd;
extern unsigned long conf_bgp_debug_cond_adv;

extern unsigned long term_bgp_debug_as4;
extern unsigned long term_bgp_debug_neighbor_events;
extern unsigned long term_bgp_debug_packet;
extern unsigned long term_bgp_debug_keepalive;
extern unsigned long term_bgp_debug_update;
extern unsigned long term_bgp_debug_bestpath;
extern unsigned long term_bgp_debug_zebra;
extern unsigned long term_bgp_debug_nht;
extern unsigned long term_bgp_debug_update_groups;
extern unsigned long term_bgp_debug_vpn;
extern unsigned long term_bgp_debug_flowspec;
extern unsigned long term_bgp_debug_labelpool;
extern unsigned long term_bgp_debug_pbr;
extern unsigned long term_bgp_debug_graceful_restart;
extern unsigned long term_bgp_debug_evpn_mh;
extern unsigned long term_bgp_debug_bfd;
extern unsigned long term_bgp_debug_cond_adv;

extern struct list *bgp_debug_neighbor_events_peers;
extern struct list *bgp_debug_keepalive_peers;
extern struct list *bgp_debug_update_in_peers;
extern struct list *bgp_debug_update_out_peers;
extern struct list *bgp_debug_update_prefixes;
extern struct list *bgp_debug_bestpath_prefixes;
extern struct list *bgp_debug_zebra_prefixes;

struct bgp_debug_filter {
	char *host;
	char *plist_name;
	struct prefix_list *plist_v4;
	struct prefix_list *plist_v6;
	struct prefix *p;
};

#define BGP_DEBUG_AS4                 0x01
#define BGP_DEBUG_AS4_SEGMENT         0x02

#define BGP_DEBUG_BESTPATH            0x01
#define BGP_DEBUG_NEIGHBOR_EVENTS     0x01
#define BGP_DEBUG_PACKET              0x01
#define BGP_DEBUG_KEEPALIVE           0x01
#define BGP_DEBUG_UPDATE_IN           0x01
#define BGP_DEBUG_UPDATE_OUT          0x02
#define BGP_DEBUG_UPDATE_PREFIX       0x04
#define BGP_DEBUG_UPDATE_DETAIL       0x08
#define BGP_DEBUG_ZEBRA               0x01
#define BGP_DEBUG_NHT                 0x01
#define BGP_DEBUG_UPDATE_GROUPS       0x01
#define BGP_DEBUG_VPN_LEAK_FROM_VRF   0x01
#define BGP_DEBUG_VPN_LEAK_TO_VRF     0x02
#define BGP_DEBUG_VPN_LEAK_RMAP_EVENT 0x04
#define BGP_DEBUG_VPN_LEAK_LABEL      0x08
#define BGP_DEBUG_FLOWSPEC            0x01
#define BGP_DEBUG_LABELPOOL           0x01
#define BGP_DEBUG_PBR                 0x01
#define BGP_DEBUG_PBR_ERROR           0x02
#define BGP_DEBUG_EVPN_MH_ES          0x01
#define BGP_DEBUG_EVPN_MH_RT          0x02

#define BGP_DEBUG_GRACEFUL_RESTART     0x01

#define BGP_DEBUG_BFD_LIB             0x01
#define BGP_DEBUG_COND_ADV 0x01

#define CONF_DEBUG_ON(a, b)	(conf_bgp_debug_ ## a |= (BGP_DEBUG_ ## b))
#define CONF_DEBUG_OFF(a, b)	(conf_bgp_debug_ ## a &= ~(BGP_DEBUG_ ## b))

#define TERM_DEBUG_ON(a, b)	(term_bgp_debug_ ## a |= (BGP_DEBUG_ ## b))
#define TERM_DEBUG_OFF(a, b)	(term_bgp_debug_ ## a &= ~(BGP_DEBUG_ ## b))

#define DEBUG_ON(a, b)                                                         \
	do {                                                                   \
		CONF_DEBUG_ON(a, b);                                           \
		TERM_DEBUG_ON(a, b);                                           \
	} while (0)
#define DEBUG_OFF(a, b)                                                        \
	do {                                                                   \
		CONF_DEBUG_OFF(a, b);                                          \
		TERM_DEBUG_OFF(a, b);                                          \
	} while (0)

#define BGP_DEBUG(a, b)	     (unlikely(term_bgp_debug_##a & BGP_DEBUG_##b))
#define CONF_BGP_DEBUG(a, b) (unlikely(conf_bgp_debug_##a & BGP_DEBUG_##b))

extern const char *const bgp_type_str[];

extern bool bgp_dump_attr(struct attr *attr, char *buf, size_t size);
extern bool bgp_debug_peer_updout_enabled(char *host);
extern const char *bgp_notify_code_str(char code);
extern const char *bgp_notify_subcode_str(char code, char subcode);
extern void bgp_notify_print(struct peer *peer, struct bgp_notify *bgp_notify,
			     const char *direct, bool hard_reset);

extern const struct message bgp_status_msg[];
extern bool bgp_debug_neighbor_events(const struct peer *peer);
extern bool bgp_debug_keepalive(const struct peer *peer);
extern bool bgp_debug_update(const struct peer *peer, const struct prefix *p,
			     struct update_group *updgrp, unsigned int inbound);
extern bool bgp_debug_bestpath(struct bgp_dest *dest);
extern bool bgp_debug_zebra(const struct prefix *p);

extern const char *bgp_debug_rdpfxpath2str(
	afi_t afi, safi_t safi, const struct prefix_rd *prd,
	union prefixconstptr pu, mpls_label_t *label, uint8_t num_labels,
	int addpath_valid, uint32_t addpath_id,
	struct bgp_route_evpn *overlay_index, char *str, int size);
const char *bgp_notify_admin_message(char *buf, size_t bufsz, uint8_t *data,
				     size_t datalen);

#endif /* _QUAGGA_BGP_DEBUG_H */
