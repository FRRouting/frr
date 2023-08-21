// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

#ifndef _QUAGGA_VNC_VNC_EXPORT_TABLE_H_
#define _QUAGGA_VNC_VNC_EXPORT_TABLE_H_

#include "lib/table.h"
#include "frrevent.h"
#include "lib/vty.h"

#include "bgpd/bgpd.h"

#define VNC_EXPORT_TYPE_BGP	1
#define VNC_EXPORT_TYPE_ZEBRA	2

typedef enum vnc_export_type {
	EXPORT_TYPE_BGP,
	EXPORT_TYPE_ZEBRA
} vnc_export_type_t;

struct vnc_export_info {
	struct vnc_export_info *next;
	struct agg_node *node;
	struct peer *peer;
	uint8_t type;
	uint8_t subtype;
	uint32_t lifetime;
	struct event *timer;
};

extern struct agg_node *vnc_etn_get(struct bgp *bgp, vnc_export_type_t type,
				    const struct prefix *p);

extern struct agg_node *vnc_etn_lookup(struct bgp *bgp, vnc_export_type_t type,
				       const struct prefix *p);

extern struct vnc_export_info *
vnc_eti_get(struct bgp *bgp, vnc_export_type_t etype, const struct prefix *p,
	    struct peer *peer, uint8_t type, uint8_t subtype);

extern void vnc_eti_delete(struct vnc_export_info *goner);

extern struct vnc_export_info *
vnc_eti_checktimer(struct bgp *bgp, vnc_export_type_t etype,
		   const struct prefix *p, struct peer *peer, uint8_t type,
		   uint8_t subtype);


#endif /* _QUAGGA_VNC_VNC_EXPORT_TABLE_H_ */
