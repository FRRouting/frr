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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_orr.h"
#include "bgpd/bgp_vty.h"
#include "zclient.h"

extern struct zclient *zclient;
static void bgp_orr_igp_metric_register(struct peer *active_root, safi_t safi,
					bool reg);

static struct bgp_orr_group *bgp_orr_group_new(struct bgp *bgp, afi_t afi,
					       safi_t safi, const char *name)
{
	int ret;
	struct list *orr_group_list = NULL;
	struct bgp_orr_group *orr_group = NULL;

	if (!bgp->orr_group[afi][safi])
		bgp->orr_group[afi][safi] = list_new();

	orr_group_list = bgp->orr_group[afi][safi];
	orr_group = XCALLOC(MTYPE_BGP_ORR_GROUP, sizeof(struct bgp_orr_group));
	if (!orr_group)
		return NULL;

	listnode_add(orr_group_list, orr_group);

	orr_group->name = XSTRDUP(MTYPE_BGP_ORR_GROUP_NAME, name);
	orr_group->afi = afi;
	orr_group->safi = safi;
	orr_group->primary = orr_group->secondary = orr_group->tertiary = NULL;

	/* Register for opaque messages from IGPs when first ORR group is
	 * configured. */
	if (!bgp->orr_group_count) {
		ret = zclient_register_opaque(zclient, ORR_IGP_METRIC_UPDATE);
		if (ret != ZCLIENT_SEND_SUCCESS)
			zlog_debug(
				"%s: zclient_register_opaque failed with ret = %d",
				__func__, ret);
	}

	bgp->orr_group_count++;

	return orr_group;
}

static struct bgp_orr_group *bgp_orr_group_lookup(struct bgp *bgp, afi_t afi,
						  safi_t safi, const char *name)
{
	struct list *orr_group_list = NULL;
	struct bgp_orr_group *group = NULL;
	struct listnode *node;

	assert(bgp);

	orr_group_list = bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, group))
		if (strcmp(group->name, name) == 0)
			return group;

	bgp_orr_debug("%s: For %s, ORR Group '%s' Not Found.", __func__,
		      get_afi_safi_str(afi, safi, false), name);

	return NULL;
}

static char *bgp_orr_group_rrclient_lookup(struct bgp_orr_group *orr_group,
					   const char *rr_client_host)
{
	char *rrclient = NULL;
	struct list *orr_group_rrclient_list = NULL;
	struct listnode *node;

	orr_group_rrclient_list = orr_group->rr_client_list;
	if (!orr_group_rrclient_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(orr_group_rrclient_list, node, rrclient))
		if (strcmp(rrclient, rr_client_host) == 0)
			return rrclient;

	bgp_orr_debug(
		"%s: For %s, %s Not Found in ORR Group '%s' RR Client list",
		__func__,
		get_afi_safi_str(orr_group->afi, orr_group->safi, false),
		rr_client_host, orr_group->name);

	return NULL;
}

static void bgp_orr_group_rrclient_update(struct peer *peer, afi_t afi,
					  safi_t safi,
					  const char *orr_group_name, bool add)
{
	char *rr_client = NULL;
	struct bgp_orr_group *orr_group = NULL;
	struct list *rr_client_list = NULL;

	assert(peer && peer->bgp && orr_group_name);

	/* Get BGP ORR entry for the given address-family */
	orr_group = bgp_orr_group_lookup(peer->bgp, afi, safi, orr_group_name);
	if (!orr_group) {
		bgp_orr_debug("%s: For %s, ORR Group '%s' Not Found.", __func__,
			      get_afi_safi_str(afi, safi, false),
			      orr_group_name);
		return;
	}

	/* Get BGP ORR client entry for the given RR client */
	rr_client = bgp_orr_group_rrclient_lookup(orr_group, peer->host);

	/* Nothing to do */
	if ((rr_client && add) || (!rr_client && !add))
		return;

	if (add) {
		/* Create BGP ORR RR client entry to the ORR Group */
		if (!orr_group->rr_client_list)
			orr_group->rr_client_list = list_new();
		rr_client_list = orr_group->rr_client_list;
		rr_client = XSTRDUP(MTYPE_BGP_PEER_HOST, peer->host);

		listnode_add(rr_client_list, rr_client);

		bgp_orr_debug(
			"%s: For %s, %s is Added to ORR Group '%s' RR Client list.",
			__func__, get_afi_safi_str(afi, safi, false),
			peer->host, orr_group_name);
	} else {
		/* Delete BGP ORR RR client entry from the ORR Group */
		listnode_delete(orr_group->rr_client_list, rr_client);
		XFREE(MTYPE_BGP_PEER_HOST, rr_client);
		if (!orr_group->rr_client_list->count)
			list_delete(&orr_group->rr_client_list);

		bgp_orr_debug(
			"%s: For %s, %s is Removed from ORR Group '%s' RR Client list.",
			__func__, get_afi_safi_str(afi, safi, false),
			peer->host, orr_group_name);
	}
}

/* Create/Update BGP Optimal Route Reflection Group */
int bgp_afi_safi_orr_group_set(struct bgp *bgp, afi_t afi, safi_t safi,
			       const char *name, struct peer *primary,
			       struct peer *secondary, struct peer *tertiary)
{
	bool primary_reachable = false;
	bool secondary_reachable = false;
	bool tertiary_reachable = false;
	struct bgp_orr_group *orr_group = NULL;

	bgp_orr_debug(
		"%s: For %s, ORR Group '%s' Primary %s Secondary %s Tertiary %s",
		__func__, get_afi_safi_str(afi, safi, false), name,
		primary ? primary->host : "NULL",
		secondary ? secondary->host : "NULL",
		tertiary ? tertiary->host : "NULL");

	/* Get BGP ORR entry for the given address-family */
	orr_group = bgp_orr_group_lookup(bgp, afi, safi, name);
	if (!orr_group) {
		/* Create BGP ORR entry for the given address-family */
		orr_group = bgp_orr_group_new(bgp, afi, safi, name);
		if (!orr_group) {
			bgp_orr_debug(
				"%s: For %s, Failed to create ORR Group '%s'.",
				__func__, get_afi_safi_str(afi, safi, false),
				name);
			return CMD_WARNING;
		}
	}

	/* Compare and update Primary Root Address */
	if (primary) {
		if (!orr_group->primary
		    || strcmp(orr_group->primary->host, primary->host))
			orr_group->primary = primary;
		else
			bgp_orr_debug("%s: No Change in Primary Root",
				      __func__);

		/* Update Active Root if there is a change and primary is
		 * reachable. */
		if (primary->afc_nego[afi][safi]
		    && (primary->status == Established)) {
			primary_reachable = true;
			if (!orr_group->active) {
				orr_group->active = primary;
				bgp_orr_igp_metric_register(primary, safi,
							    true);
			} else if (orr_group->primary
				   && strcmp(orr_group->active->host,
					     orr_group->primary->host)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(primary, safi,
							    true);
				orr_group->active = primary;
			} else
				bgp_orr_debug(
					"%s: %s", __func__,
					orr_group->primary->host
						? "No Change in Active Root"
						: "Primary Root is NULL");
		}
	} else {
		if (orr_group->primary) {
			if (orr_group->active
			    && !strcmp(orr_group->active->host,
				       orr_group->primary->host)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				orr_group->active = NULL;
			}
			orr_group->primary = NULL;
		}
	}

	/* Compare and update Secondary Root Address */
	if (secondary) {
		if (!orr_group->secondary
		    || strcmp(orr_group->secondary->host, secondary->host))
			orr_group->secondary = secondary;
		else
			bgp_orr_debug("%s: No Change in Secondary Root",
				      __func__);

		/* Update Active Root if Primary is not reachable */
		if (secondary->afc_nego[afi][safi]
		    && (secondary->status == Established)) {
			secondary_reachable = true;
			if (!orr_group->active) {
				orr_group->active = secondary;
				bgp_orr_igp_metric_register(secondary, safi,
							    true);
			} else if (!primary_reachable && orr_group->secondary
				   && strcmp(orr_group->active->host,
					     orr_group->secondary->host)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(secondary, safi,
							    true);
				orr_group->active = secondary;
			} else
				bgp_orr_debug(
					"%s: %s", __func__,
					primary_reachable
						? "Primary is Active Root"
						: orr_group->secondary->host
							  ? "No Change in Active Root"
							  : "Secondary Root is NULL");
		}
	} else {
		if (orr_group->secondary) {
			if (orr_group->active
			    && !strcmp(orr_group->active->host,
				       orr_group->secondary->host)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				orr_group->active = NULL;
			}
			orr_group->secondary = NULL;
		}
	}

	/* Compare and update Tertiary Root Address */
	if (tertiary) {
		if (!orr_group->tertiary
		    || strcmp(orr_group->tertiary->host, tertiary->host))
			orr_group->tertiary = tertiary;
		else
			bgp_orr_debug("%s: No Change in Tertiay Root",
				      __func__);

		/* Update Active Root if Primary & Secondary are not reachable
		 */
		if (tertiary->afc_nego[afi][safi]
		    && (tertiary->status == Established)) {
			tertiary_reachable = true;
			if (!orr_group->active) {
				orr_group->active = tertiary;
				bgp_orr_igp_metric_register(tertiary, safi,
							    true);
			} else if (!primary_reachable && !secondary_reachable
				   && orr_group->tertiary
				   && strcmp(orr_group->active->host,
					     orr_group->tertiary->host)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(tertiary, safi,
							    true);
				orr_group->active = tertiary;
			} else
				bgp_orr_debug(
					"%s: %s", __func__,
					primary_reachable
						? "Primary is Active Root"
						: secondary_reachable
							  ? "Secondary is Active Root"
							  : !orr_group->tertiary
								    ? "Tertiary Root is NULL"
								    : "No Change in Active Root");
		}
	} else {
		if (orr_group->tertiary) {
			if (orr_group->active
			    && !strcmp(orr_group->active->host,
				       orr_group->tertiary)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				orr_group->active = NULL;
			}
			orr_group->tertiary = NULL;
		}
	}

	if (orr_group->active && !primary_reachable && !secondary_reachable
	    && !tertiary_reachable) {
		bgp_orr_igp_metric_register(orr_group->active, safi, false);
		orr_group->active = NULL;
	}

	bgp_orr_debug("%s: For %s, ORR Group '%s' Active Root is %s", __func__,
		      get_afi_safi_str(afi, safi, false), name,
		      orr_group->active ? orr_group->active->host : "NULL");

	return CMD_SUCCESS;
}

/* Delete BGP Optimal Route Reflection Group */
int bgp_afi_safi_orr_group_unset(struct bgp *bgp, afi_t afi, safi_t safi,
				 const char *name)
{
	struct bgp_orr_group *orr_group;
	orr_group = bgp_orr_group_lookup(bgp, afi, safi, name);
	if (!orr_group)
		return CMD_WARNING;

	/* Check if there are any neighbors configured with this ORR Group */
	if (orr_group->rr_client_list) {
		bgp_orr_debug(
			"%s: For %s, ORR Group '%s' not Removed as '%s' is configured on neighbor(s)",
			__func__,
			get_afi_safi_str(orr_group->afi, orr_group->safi,
					 false),
			name, name);
		return CMD_WARNING;
	}

	/* Unset ORR Group parameters */
	XFREE(MTYPE_BGP_ORR_GROUP_NAME, orr_group->name);

	/* Unregister with IGP for Metric Calculation from specified location */
	bgp_orr_igp_metric_register(orr_group->active, safi, false);

	orr_group->primary = orr_group->secondary = orr_group->tertiary =
		orr_group->active = NULL;

	listnode_delete(bgp->orr_group[afi][safi], orr_group);
	XFREE(MTYPE_BGP_ORR_GROUP, orr_group);

	bgp->orr_group_count--;

	if (!bgp->orr_group[afi][safi]->count)
		list_delete(&bgp->orr_group[afi][safi]);
	return CMD_SUCCESS;
}

/* Set optimal route reflection group to the peer */
static int peer_orr_group_set(struct peer *peer, afi_t afi, safi_t safi,
			      const char *orr_group_name)
{
	struct bgp_orr_group *orr_group = NULL;
	if (!peer)
		return CMD_WARNING;

	/* Get BGP ORR entry for the given address-family */
	orr_group = bgp_orr_group_lookup(peer->bgp, afi, safi, orr_group_name);
	if (!orr_group) {
		/* Create BGP ORR entry for the given address-family */
		orr_group =
			bgp_orr_group_new(peer->bgp, afi, safi, orr_group_name);
		if (!orr_group) {
			bgp_orr_debug(
				"%s: For %s, Failed to create ORR Group '%s'.",
				__func__, get_afi_safi_str(afi, safi, false),
				orr_group_name);
			return CMD_WARNING;
		}
	}

	/* Skip processing if there is no change in ORR Group */
	if (peer_af_flag_check(peer, afi, safi, PEER_FLAG_ORR_GROUP)) {
		if (!strcmp(peer->orr_group_name[afi][safi], orr_group_name)) {
			bgp_orr_debug(
				"%s: For %s, ORR Group '%s' is Already Configured on %s",
				__func__, get_afi_safi_str(afi, safi, false),
				orr_group_name, peer->host);
			return CMD_SUCCESS;
		} else {
			/* Remove the peer from ORR Group's peer list */
			bgp_orr_group_rrclient_update(
				peer, afi, safi,
				peer->orr_group_name[afi][safi], false);
			XFREE(MTYPE_BGP_ORR_GROUP_NAME,
			      peer->orr_group_name[afi][safi]);
		}
	}

	peer->orr_group_name[afi][safi] =
		XSTRDUP(MTYPE_BGP_ORR_GROUP_NAME, orr_group_name);
	SET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ORR_GROUP);

	/* Add the peer to ORR Group's client list */
	bgp_orr_group_rrclient_update(peer, afi, safi, orr_group_name, true);

	return CMD_SUCCESS;
}

/* Unset optimal route reflection group from the peer*/
static int peer_orr_group_unset(struct peer *peer, afi_t afi, safi_t safi,
				const char *orr_group_name)
{
	struct bgp_orr_group *orr_group = NULL;
	assert(peer && peer->bgp && orr_group_name);

	if (!peer_af_flag_check(peer, afi, safi, PEER_FLAG_ORR_GROUP)
	    || strcmp(peer->orr_group_name[afi][safi], orr_group_name)) {
		bgp_orr_debug(
			"%s: For %s, ORR Group '%s' is Not Configured on %s",
			__func__, get_afi_safi_str(afi, safi, false),
			orr_group_name, peer->host);
		return CMD_ERR_NO_MATCH;
	}

	/* Check if this RR Client is one the Root nodes */
	orr_group = bgp_orr_group_lookup(peer->bgp, afi, safi, orr_group_name);

	/* Should not be Null when orr-group is enabled on peer */
	assert(orr_group);

	if ((orr_group->primary
	     && !strcmp(orr_group->primary->host, peer->host))
	    || (orr_group->secondary
		&& !strcmp(orr_group->secondary->host, peer->host))
	    || (orr_group->tertiary
		&& !strcmp(orr_group->tertiary->host, peer->host))) {
		bgp_orr_debug(
			"%s: For %s, %s is one of the Root nodes of ORR Group '%s'",
			__func__, get_afi_safi_str(afi, safi, false),
			peer->host, orr_group_name);
		return CMD_WARNING;
	}

	UNSET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ORR_GROUP);
	XFREE(MTYPE_BGP_ORR_GROUP_NAME, peer->orr_group_name[afi][safi]);

	/* Remove the peer from ORR Group's client list */
	bgp_orr_group_rrclient_update(peer, afi, safi, orr_group_name, false);

	return CMD_SUCCESS;
}

int bgp_afi_safi_orr_group_set_vty(struct vty *vty, afi_t afi, safi_t safi,
				   const char *name, const char *primary_str,
				   const char *secondary_str,
				   const char *tertiary_str, bool set)
{
	int ret = CMD_WARNING_CONFIG_FAILED;
	struct bgp *bgp;
	struct peer *primary = NULL, *secondary = NULL, *tertiary = NULL;

	bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "%% No BGP process is configured\n");
		return ret;
	}

	if (!set) {
		ret = bgp_afi_safi_orr_group_unset(bgp, afi, safi, name);
		if (ret != CMD_SUCCESS)
			vty_out(vty,
				"%% ORR Group %s not Removed as '%s' is Not Found OR configured on neighbor(s)\n",
				name, name);
		return ret;
	}

	primary = peer_and_group_lookup_vty(vty, primary_str);
	if (!primary
	    || !peer_af_flag_check(primary, afi, safi,
				   PEER_FLAG_REFLECTOR_CLIENT)) {
		vty_out(vty,
			"%% Primary Root is not a Route Reflector Client\n");
		return ret;
	}

	if (secondary_str) {
		secondary = peer_and_group_lookup_vty(vty, secondary_str);
		if (!secondary
		    || !peer_af_flag_check(secondary, afi, safi,
					   PEER_FLAG_REFLECTOR_CLIENT)) {
			vty_out(vty,
				"%% Secondary Root is not a Route Reflector Client\n");
			return ret;
		}
	}

	if (tertiary_str) {
		tertiary = peer_and_group_lookup_vty(vty, tertiary_str);
		if (!tertiary
		    || !peer_af_flag_check(tertiary, afi, safi,
					   PEER_FLAG_REFLECTOR_CLIENT)) {
			vty_out(vty,
				"%% Tertiary Root is not a Route Reflector Client\n");
			return ret;
		}
	}
	return bgp_afi_safi_orr_group_set(bgp, afi, safi, name, primary,
					  secondary, tertiary);
}

/* Set optimal route reflection group name to the peer. */
int peer_orr_group_set_vty(struct vty *vty, const char *ip_str, afi_t afi,
			   safi_t safi, const char *orr_group_name, bool set)
{
	int ret = CMD_WARNING_CONFIG_FAILED;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return ret;

	if (!peer_af_flag_check(peer, afi, safi, PEER_FLAG_REFLECTOR_CLIENT)) {
		vty_out(vty, "%% Neighbor %s is not a Route Reflector Client\n",
			peer->host);
		return ret;
	}

	if (set) {
		ret = peer_orr_group_set(peer, afi, safi, orr_group_name);
		if (ret != CMD_SUCCESS)
			vty_out(vty, "%% ORR Group '%s' is Not Configured\n",
				orr_group_name);
	} else {
		ret = peer_orr_group_unset(peer, afi, safi, orr_group_name);
		if (ret == CMD_ERR_NO_MATCH)
			vty_out(vty,
				"%% ORR Group '%s' is Not Configured on %s\n",
				orr_group_name, peer->host);
		else if (ret == CMD_WARNING)
			vty_out(vty,
				"%% %s is one of the Root Nodes of ORR Group '%s'.\n",
				peer->host, orr_group_name);
	}
	return bgp_vty_return(vty, ret);
}

void bgp_config_write_orr(struct vty *vty, struct bgp *bgp, afi_t afi,
			  safi_t safi)
{
	struct list *orr_group_list;
	struct listnode *node;
	struct bgp_orr_group *orr_group;

	orr_group_list = bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, orr_group)) {
		/* optimal route reflection configuration */
		vty_out(vty, "  optimal-route-reflection %s", orr_group->name);
		if (orr_group->primary)
			vty_out(vty, " %s", orr_group->primary->host);
		if (orr_group->secondary)
			vty_out(vty, " %s", orr_group->secondary->host);
		if (orr_group->tertiary)
			vty_out(vty, " %s", orr_group->tertiary->host);
		vty_out(vty, "\n");
	}
}

static void bgp_show_orr_group(struct vty *vty, struct bgp_orr_group *orr_group,
			       afi_t afi, safi_t safi)
{
	char *rrclient = NULL;
	struct listnode *node;
	struct list *orr_group_rrclient_list = NULL;

	if (!orr_group)
		return;

	vty_out(vty, "\nORR policy: %s, %s\n", orr_group->name,
		get_afi_safi_str(afi, safi, false));
	vty_out(vty, "Configured root:");
	vty_out(vty, " primary: %s,",
		orr_group->primary ? orr_group->primary->host : "NULL");
	vty_out(vty, " secondary: %s,",
		orr_group->secondary ? orr_group->secondary->host : "NULL");
	vty_out(vty, " tertiary: %s\n",
		orr_group->tertiary ? orr_group->tertiary->host : "NULL");
	vty_out(vty, "Active Root: %s\n",
		orr_group->active ? orr_group->active->host : "NULL");

	orr_group_rrclient_list = orr_group->rr_client_list;
	if (!orr_group_rrclient_list)
		return;

	vty_out(vty, "\nRR Clients mapped:\n");

	for (ALL_LIST_ELEMENTS_RO(orr_group_rrclient_list, node, rrclient))
		vty_out(vty, "%s\n", rrclient);

	vty_out(vty, "\nNumber of mapping entries: %d\n\n",
		orr_group->rr_client_list->count);
}

int bgp_show_orr(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		 const char *orr_group_name, uint8_t show_flags)
{
	struct listnode *node;
	struct bgp_orr_group *orr_group = NULL;
	struct list *orr_group_list = NULL;

	assert(bgp);

	/* Display the matching entries for the given ORR Group */
	if (orr_group_name) {
		orr_group =
			bgp_orr_group_lookup(bgp, afi, safi, orr_group_name);
		if (!orr_group) {
			vty_out(vty, "%% ORR Group %s Not Found\n",
				orr_group_name);
			return 0;
		}
		bgp_show_orr_group(vty, orr_group, afi, safi);
		return 0;
	}
	orr_group_list = bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, orr_group))
		bgp_show_orr_group(vty, orr_group, afi, safi);

	return 0;
}

/* Check if the Reflector Client belongs to any ORR Group */
bool peer_orr_rrclient_check(struct peer *peer, afi_t afi, safi_t safi)
{
	char *rrclient = NULL;
	struct listnode *node;
	struct list *orr_group_list = NULL;
	struct list *orr_group_rrclient_list = NULL;
	struct bgp_orr_group *orr_group = NULL;

	assert(peer && peer->bgp);

	orr_group_list = peer->bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return false;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, orr_group)) {
		/*Check if peer configured as primary/secondary/tertiary root */
		if (orr_group->primary
		    && !strcmp(peer->host, orr_group->primary->host))
			return true;
		else if (orr_group->secondary
			 && !strcmp(peer->host, orr_group->secondary->host))
			return true;
		else if (orr_group->tertiary
			 && !strcmp(peer->host, orr_group->tertiary->host))
			return true;
		else {
			/* Check if peer is mapped to any ORR Group in this
			 * Address Family */
			orr_group_rrclient_list = orr_group->rr_client_list;
			if (!orr_group_rrclient_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(orr_group_rrclient_list, node,
						  rrclient))
				if (!strcmp(rrclient, peer->host))
					return true;
		}
	}
	return false;
}

void bgp_orr_update_active_root(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	struct bgp_orr_group *orr_group = NULL;

	assert(peer && peer->bgp);

	FOREACH_AFI_SAFI (afi, safi) {
		if (!peer->orr_group_name[afi][safi])
			continue;

		/* Get BGP ORR entry for the given address-family */
		orr_group = bgp_orr_group_lookup(
			peer->bgp, afi, safi, peer->orr_group_name[afi][safi]);
		assert(orr_group);

		/* Peer is reachable, update Active Root if needed */
		if (peer->afc_nego[afi][safi] && peer->status == Established) {
			/* If this peer is not one of the Root nodes */
			if (!is_orr_root_node(orr_group, peer->host))
				continue;

			/* If Active is null, Update this node as Active Root */
			if (!orr_group->active) {
				orr_group->active = peer;
				bgp_orr_igp_metric_register(peer, safi, true);
				continue;
			}

			/* Nothing to do, if this is the current Active Root */
			if (is_orr_active_root(orr_group, peer->host))
				continue;

			/* If this is Primary and current Active is not Primary
			 */
			if (is_orr_primary_root(orr_group, peer->host)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(peer, safi, true);
				orr_group->active = peer;
				continue;
			}

			/* If this is Secondary and current Active is not
			 * Primary/Secondary */
			if (is_orr_secondary_root(orr_group, peer->host)) {
				if (is_orr_active_root(
					    orr_group,
					    orr_group->primary->host))
					continue;

				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(peer, safi, true);
				orr_group->active = peer;
				continue;
			}
		}
		/* Non Active Root is unreachable, so nothing to do */
		if (!is_orr_active_root(orr_group, peer->host))
			continue;

		if (is_orr_primary_root(orr_group, peer->host)) {
			/* If secondary is reachable, update it as Active */
			if (is_orr_secondary_reachable(orr_group)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(
					orr_group->secondary, safi, true);
				orr_group->active = orr_group->secondary;
				continue;
			}

			/* If tertiary is reachable, update it as Active */
			if (is_orr_tertiary_reachable(orr_group)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(orr_group->tertiary,
							    safi, true);
				orr_group->active = orr_group->tertiary;
				continue;
			}
		} else if (is_orr_secondary_root(orr_group, peer->host)) {
			/* If tertiary is reachable, update it as Active */
			if (is_orr_tertiary_reachable(orr_group)) {
				bgp_orr_igp_metric_register(orr_group->active,
							    safi, false);
				bgp_orr_igp_metric_register(orr_group->tertiary,
							    safi, true);
				orr_group->active = orr_group->tertiary;
				continue;
			}
		}
		/* Assign Active as null */
		bgp_orr_igp_metric_register(orr_group->active, safi, false);
		orr_group->active = NULL;

		bgp_orr_debug("%s: For %s, ORR Group '%s' currently no active",
			      __func__, get_afi_safi_str(afi, safi, false),
			      peer->orr_group_name[afi][safi]);
	}
}

static int bgp_orr_igp_metric_update(struct orr_igp_metric_info *table)
{
	afi_t afi;
	safi_t safi;
	uint32_t instId = 0;
	uint32_t numEntries = 0;
	uint32_t entry = 0;
	uint8_t proto = ZEBRA_ROUTE_MAX;
	struct bgp *bgp = NULL;
	struct prefix root = {0};
	char buf[PREFIX2STR_BUFFER];

	bgp = bgp_get_default();
	assert(bgp && table);

	proto = table->proto;
	afi = family2afi(table->root.family);
	safi = table->safi;
	instId = table->instId;
	numEntries = table->num_entries;
	prefix_copy(&root, &table->root);

	if ((proto != ZEBRA_ROUTE_OSPF) && (proto != ZEBRA_ROUTE_OSPF6)
	    && (proto != ZEBRA_ROUTE_ISIS)) {
		bgp_orr_debug("%s: Message received from unsupported protocol",
			      __func__);
		return -1;
	}

	if (BGP_DEBUG(optimal_route_reflection, ORR)) {
		zlog_debug(
			"[BGP-ORR] %s: Received metric update from protocol %s instance %d",
			__func__,
			proto == ZEBRA_ROUTE_ISIS
				? "ISIS"
				: (proto == ZEBRA_ROUTE_OSPF ? "OSPF"
							     : "OSPF6"),
			instId);
		zlog_debug("[BGP-ORR] %s: Address family %s", __func__,
			   get_afi_safi_str(afi, safi, false));
		zlog_debug("[BGP-ORR] %s: Root %s", __func__,
			   prefix2str(&root, buf, sizeof(buf)));
		zlog_debug("[BGP-ORR] %s: Number of entries %d", __func__,
			   numEntries);
		zlog_debug("[BGP-ORR] %s: Prefix Table :", __func__);
		for (entry = 0; entry < numEntries; entry++)
			zlog_debug("[BGP-ORR] %s: %s\t\t\t\t\t\t%d", __func__,
				   prefix2str(&table->nexthop[entry].prefix,
					      buf, sizeof(buf)),
				   table->nexthop[entry].metric);
		/* TODO: Update 'igp_metric_info' of orr-group */
	}
}

static void bgp_orr_igp_metric_register(struct peer *active_root, safi_t safi,
					bool reg)
{
	struct orr_igp_metric_reg msg;
	struct prefix p;
	char buf[PREFIX2STR_BUFFER];

	if (!active_root)
		return;

	memset(&msg, 0, sizeof(msg));
	if (str2prefix(active_root->host, &p) == 0) {
		bgp_orr_debug("%s: Malformed prefix for %s", __func__,
			      active_root->host);
		return;
	}

	msg.reg = reg;
	msg.proto = ZEBRA_ROUTE_BGP;
	msg.safi = safi;
	prefix_copy(&msg.prefix, &p);

	bgp_orr_debug(
		"%s: %s with IGP Protocol for Metric Calculation from loacation %s",
		__func__, reg ? "Register" : "Unregister",
		prefix2str(&msg.prefix, buf, sizeof(buf)));

	if (zclient_send_opaque(zclient, ORR_IGP_METRIC_REGISTER,
				(uint8_t *)&msg, sizeof(msg))
	    == ZCLIENT_SEND_FAILURE)
		zlog_warn("[BGP-ORR] %s: Failed to send message to IGP.",
			  __func__);
}

/* BGP ORR message processing */
int bgg_orr_message_process(bgp_orr_msg_type_t msg_type, void *msg)
{
	int ret = 0;

	bgp_orr_debug("%s: Start", __func__);

	assert(msg && msg_type > BGP_ORR_IMSG_INVALID
	       && msg_type < BGP_ORR_IMSG_MAX);
	switch (msg_type) {
	case BGP_ORR_IMSG_GROUP_CREATE:
		break;
	case BGP_ORR_IMSG_GROUP_DELETE:
		break;
	case BGP_ORR_IMSG_GROUP_UPDATE:
		break;
	case BGP_ORR_IMSG_SET_ORR_ON_PEER:
		break;
	case BGP_ORR_IMSG_UNSET_ORR_ON_PEER:
		break;
	case BGP_ORR_IMSG_IGP_METRIC_UPDATE:
		ret = bgp_orr_igp_metric_update(
			(struct orr_igp_metric_info *)msg);
		break;
	case BGP_ORR_IMSG_SHOW_ORR:
		/* bgp_show_orr */
		break;
	case BGP_ORR_IMSG_SHOW_ORR_GROUP:
		/* bgp_show_orr_group */
		break;
	default:
		break;
	}

	bgp_orr_debug("%s: End", __func__);

	/* Free Memory */
	return ret;
}
