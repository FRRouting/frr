// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_autorp.h: PIM Auto RP handling related
 *
 * Copyright (C) 20224 ATCorp.
 * Nathan Bahr
 */

#ifndef __PIM_AUTORP_H__
#define __PIM_AUTORP_H__

#include <typesafe.h>

#define AUTORP_VERSION		 1
#define AUTORP_ANNOUNCEMENT_TYPE 1
#define AUTORP_DISCOVERY_TYPE	 2
#define AUTORP_PIM_VUNKNOWN	 0
#define AUTORP_PIM_V1		 1
#define AUTORP_PIM_V2		 2
#define AUTORP_PIM_V1_2		 3

#define DEFAULT_AUTORP_ANNOUNCE_INTERVAL 60
#define DEFAULT_AUTORP_ANNOUNCE_SCOPE	 31
#define DEFAULT_AUTORP_ANNOUNCE_HOLDTIME -1

#define DEFAULT_AUTORP_DISCOVERY_INTERVAL 60
#define DEFAULT_AUTORP_DISCOVERY_SCOPE	  31
#define DEFAULT_AUTORP_DISCOVERY_HOLDTIME 180

PREDECL_SORTLIST_UNIQ(pim_autorp_rp);
PREDECL_SORTLIST_UNIQ(pim_autorp_grppfix);

struct autorp_pkt_grp {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t negprefix : 1;
	uint8_t reserved : 7;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t reserved : 7;
	uint8_t negprefix : 1;
#else
#error "Please fix <bits/endian.h>"
#endif
	uint8_t masklen;
	uint32_t addr;
} __attribute__((__packed__));

struct autorp_pkt_rp {
	uint32_t addr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t pimver : 2;
	uint8_t reserved : 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t reserved : 6;
	uint8_t pimver : 2;
#else
#error "Please fix <bits/endian.h>"
#endif
	uint8_t grpcnt;
} __attribute__((__packed__));

struct autorp_pkt_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t type : 4;
	uint8_t version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version : 4;
	uint8_t type : 4;
#else
#error "Please fix <bits/endian.h>"
#endif
	uint8_t rpcnt;
	uint16_t holdtime;
	uint32_t reserved;
} __attribute__((__packed__));

#define MIN_AUTORP_PKT_SZ                                                      \
	(sizeof(struct autorp_pkt_hdr) + sizeof(struct autorp_pkt_rp) +        \
	 sizeof(struct autorp_pkt_grp))

struct pim_autorp_rp {
	struct pim_autorp *autorp;
	struct in_addr addr;
	uint16_t holdtime;
	struct event *hold_timer;
	struct prefix grp;
	char grplist[32];
	struct pim_autorp_grppfix_head grp_pfix_list;
	struct pim_autorp_rp_item item;
};

struct pim_autorp_grppfix {
	struct prefix grp;
	struct in_addr rp;
	bool negative;
	struct pim_autorp_grppfix_item item;
};

struct pim_autorp {
	/* backpointer to pim instance */
	struct pim_instance *pim;

	/* UDP socket bound to AutoRP port, used for sending and receiving all AutoRP packets */
	int sock;

	/* Event for reading AutoRP packets */
	struct event *read_event;

	/* Event for sending announcement packets */
	struct event *announce_timer;

	/* Event for sending discovery packets*/
	struct event *send_discovery_timer;

	/* Flag enabling reading discovery packets */
	bool do_discovery;

	/* Flag enabling mapping agent (reading announcements and sending discovery)*/
	bool send_rp_discovery;

	/* Flag indicating if we are sending discovery messages (true) or if a higher IP mapping
	 * agent preemptied our sending (false)
	 */
	bool mapping_agent_active;

	/* List of RP's in received discovery packets */
	struct pim_autorp_rp_head discovery_rp_list;

	/* List of configured candidate RP's to send in announcement packets */
	struct pim_autorp_rp_head candidate_rp_list;

	/* List of announced RP's to send in discovery packets */
	struct pim_autorp_rp_head mapping_rp_list;

	/* List of the last advertised RP's, via mapping agent discovery
	 * This is only filled if a discovery message was sent
	 */
	struct pim_autorp_rp_head advertised_rp_list;

	/* Packet parameters for sending announcement packets */
	uint8_t announce_scope;
	uint16_t announce_interval;
	int32_t announce_holdtime;

	/* Pre-built announcement packet, only changes when configured RP's or packet parameters change */
	uint8_t *announce_pkt;
	uint16_t announce_pkt_sz;

	/* Packet parameters for sending discovery packets */
	uint8_t discovery_scope;
	uint16_t discovery_interval;
	uint16_t discovery_holdtime;
	struct cand_addrsel mapping_agent_addrsel;
};

#define AUTORP_GRPLEN 6
#define AUTORP_RPLEN  6
#define AUTORP_HDRLEN 8

void pim_autorp_prefix_list_update(struct pim_instance *pim, struct prefix_list *plist);
bool pim_autorp_rm_candidate_rp(struct pim_instance *pim, pim_addr rpaddr);
void pim_autorp_add_candidate_rp_group(struct pim_instance *pim, pim_addr rpaddr,
				       struct prefix group);
bool pim_autorp_rm_candidate_rp_group(struct pim_instance *pim, pim_addr rpaddr,
				      struct prefix group);
void pim_autorp_add_candidate_rp_plist(struct pim_instance *pim, pim_addr rpaddr, const char *plist);
bool pim_autorp_rm_candidate_rp_plist(struct pim_instance *pim, pim_addr rpaddr, const char *plist);
void pim_autorp_announce_scope(struct pim_instance *pim, uint8_t scope);
void pim_autorp_announce_interval(struct pim_instance *pim, uint16_t interval);
void pim_autorp_announce_holdtime(struct pim_instance *pim, int32_t holdtime);
void pim_autorp_send_discovery_apply(struct pim_autorp *autorp);
void pim_autorp_add_ifp(struct interface *ifp);
void pim_autorp_rm_ifp(struct interface *ifp);
void pim_autorp_start_discovery(struct pim_instance *pim);
void pim_autorp_stop_discovery(struct pim_instance *pim);
void pim_autorp_init(struct pim_instance *pim);
void pim_autorp_finish(struct pim_instance *pim);
int pim_autorp_config_write(struct pim_instance *pim, struct vty *vty);
void pim_autorp_show_autorp(struct vty *vty, struct pim_instance *pim, const char *component,
			    json_object *json);

#endif
