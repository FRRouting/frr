// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */


#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/agg_table.h"
#include "lib/memory.h"
#include "lib/vty.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

#include "bgpd/rfapi/vnc_export_table.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/vnc_debug.h"

struct agg_node *vnc_etn_get(struct bgp *bgp, vnc_export_type_t type,
			     const struct prefix *p)
{
	struct agg_table *t = NULL;
	struct agg_node *rn = NULL;
	afi_t afi;

	if (!bgp || !bgp->rfapi)
		return NULL;

	afi = family2afi(p->family);
	assert(afi == AFI_IP || afi == AFI_IP6);

	switch (type) {
	case EXPORT_TYPE_BGP:
		if (!bgp->rfapi->rt_export_bgp[afi])
			bgp->rfapi->rt_export_bgp[afi] = agg_table_init();
		t = bgp->rfapi->rt_export_bgp[afi];
		break;

	case EXPORT_TYPE_ZEBRA:
		if (!bgp->rfapi->rt_export_zebra[afi])
			bgp->rfapi->rt_export_zebra[afi] = agg_table_init();
		t = bgp->rfapi->rt_export_zebra[afi];
		break;
	}

	if (t)
		rn = agg_node_get(t, p);
	return rn;
}

struct agg_node *vnc_etn_lookup(struct bgp *bgp, vnc_export_type_t type,
				const struct prefix *p)
{
	struct agg_table *t = NULL;
	struct agg_node *rn = NULL;
	afi_t afi;

	if (!bgp || !bgp->rfapi)
		return NULL;

	afi = family2afi(p->family);
	assert(afi == AFI_IP || afi == AFI_IP6);

	switch (type) {
	case EXPORT_TYPE_BGP:
		if (!bgp->rfapi->rt_export_bgp[afi])
			bgp->rfapi->rt_export_bgp[afi] = agg_table_init();
		t = bgp->rfapi->rt_export_bgp[afi];
		break;

	case EXPORT_TYPE_ZEBRA:
		if (!bgp->rfapi->rt_export_zebra[afi])
			bgp->rfapi->rt_export_zebra[afi] = agg_table_init();
		t = bgp->rfapi->rt_export_zebra[afi];
		break;
	}

	if (t)
		rn = agg_node_lookup(t, p);
	return rn;
}

struct vnc_export_info *vnc_eti_get(struct bgp *bgp, vnc_export_type_t etype,
				    const struct prefix *p, struct peer *peer,
				    uint8_t type, uint8_t subtype)
{
	struct agg_node *etn;
	struct vnc_export_info *eti;

	etn = vnc_etn_get(bgp, etype, p);
	assert(etn);

	for (eti = etn->info; eti; eti = eti->next) {
		if (peer == eti->peer && type == eti->type
		    && subtype == eti->subtype) {

			break;
		}
	}

	if (eti) {
		agg_unlock_node(etn);
	} else {
		eti = XCALLOC(MTYPE_RFAPI_ETI, sizeof(struct vnc_export_info));
		eti->node = etn;
		eti->peer = peer;
		peer_lock(peer);
		eti->type = type;
		eti->subtype = subtype;
		eti->next = etn->info;
		etn->info = eti;
	}

	return eti;
}

void vnc_eti_delete(struct vnc_export_info *goner)
{
	struct agg_node *etn;
	struct vnc_export_info *eti;
	struct vnc_export_info *eti_prev = NULL;

	etn = goner->node;

	for (eti = etn->info; eti; eti_prev = eti, eti = eti->next) {
		if (eti == goner)
			break;
	}

	if (!eti) {
		vnc_zlog_debug_verbose("%s: COULDN'T FIND ETI", __func__);
		return;
	}

	if (eti_prev) {
		eti_prev->next = goner->next;
	} else {
		etn->info = goner->next;
	}

	peer_unlock(eti->peer);
	goner->node = NULL;
	XFREE(MTYPE_RFAPI_ETI, goner);

	agg_unlock_node(etn);
}

struct vnc_export_info *vnc_eti_checktimer(struct bgp *bgp,
					   vnc_export_type_t etype,
					   const struct prefix *p,
					   struct peer *peer, uint8_t type,
					   uint8_t subtype)
{
	struct agg_node *etn;
	struct vnc_export_info *eti;

	etn = vnc_etn_lookup(bgp, etype, p);
	if (!etn)
		return NULL;

	for (eti = etn->info; eti; eti = eti->next) {
		if (peer == eti->peer && type == eti->type
		    && subtype == eti->subtype) {

			break;
		}
	}

	agg_unlock_node(etn);

	if (eti && eti->timer)
		return eti;

	return NULL;
}
