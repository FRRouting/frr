/*
 * PIM for Quagga
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
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
#include <zebra.h>
#include "network.h"
#include "zclient.h"
#include "stream.h"
#include "nexthop.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"

#include "pimd.h"
#include "pimd/pim_nht.h"
#include "log.h"
#include "pim_time.h"
#include "pim_oil.h"
#include "pim_ifchannel.h"
#include "pim_mroute.h"
#include "pim_zebra.h"
#include "pim_upstream.h"
#include "pim_join.h"
#include "pim_jp_agg.h"
#include "pim_zebra.h"
#include "pim_zlookup.h"

/**
 * pim_sendmsg_zebra_rnh -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 */
void pim_sendmsg_zebra_rnh(struct pim_instance *pim, struct zclient *zclient,
			   struct pim_nexthop_cache *pnc, int command)
{
	struct prefix *p;
	int ret;

	p = &(pnc->rpf.rpf_addr);
	ret = zclient_send_rnh(zclient, command, p, false, pim->vrf_id);
	if (ret < 0)
		zlog_warn("sendmsg_nexthop: zclient_send_message() failed");

	if (PIM_DEBUG_PIM_NHT) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(p, buf, sizeof(buf));
		zlog_debug(
			"%s: NHT %sregistered addr %s(%s) with Zebra ret:%d ",
			__PRETTY_FUNCTION__,
			(command == ZEBRA_NEXTHOP_REGISTER) ? " " : "de", buf,
			pim->vrf->name, ret);
	}

	return;
}

struct pim_nexthop_cache *pim_nexthop_cache_find(struct pim_instance *pim,
						 struct pim_rpf *rpf)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	lookup.rpf.rpf_addr.family = rpf->rpf_addr.family;
	lookup.rpf.rpf_addr.prefixlen = rpf->rpf_addr.prefixlen;
	lookup.rpf.rpf_addr.u.prefix4.s_addr = rpf->rpf_addr.u.prefix4.s_addr;

	pnc = hash_lookup(pim->rpf_hash, &lookup);

	return pnc;
}

static struct pim_nexthop_cache *pim_nexthop_cache_add(struct pim_instance *pim,
						       struct pim_rpf *rpf_addr)
{
	struct pim_nexthop_cache *pnc;
	char hash_name[64];
	char buf1[64];

	pnc = XCALLOC(MTYPE_PIM_NEXTHOP_CACHE,
		      sizeof(struct pim_nexthop_cache));
	if (!pnc) {
		zlog_err("%s: NHT PIM XCALLOC failure ", __PRETTY_FUNCTION__);
		return NULL;
	}
	pnc->rpf.rpf_addr.family = rpf_addr->rpf_addr.family;
	pnc->rpf.rpf_addr.prefixlen = rpf_addr->rpf_addr.prefixlen;
	pnc->rpf.rpf_addr.u.prefix4.s_addr =
		rpf_addr->rpf_addr.u.prefix4.s_addr;

	pnc = hash_get(pim->rpf_hash, pnc, hash_alloc_intern);

	pnc->rp_list = list_new();
	pnc->rp_list->cmp = pim_rp_list_cmp;

	snprintf(hash_name, 64, "PNC %s(%s) Upstream Hash",
		 prefix2str(&pnc->rpf.rpf_addr, buf1, 64), pim->vrf->name);
	pnc->upstream_hash = hash_create_size(8192, pim_upstream_hash_key,
					      pim_upstream_equal, hash_name);

	return pnc;
}

/*
 * pim_find_or_track_nexthop
 *
 * This API is used to Register an address with Zebra
 *
 * 1 -> Success
 * 0 -> Failure
 */
int pim_find_or_track_nexthop(struct pim_instance *pim, struct prefix *addr,
			      struct pim_upstream *up, struct rp_info *rp,
			      struct pim_nexthop_cache *out_pnc)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_rpf rpf;
	struct listnode *ch_node = NULL;
	struct zclient *zclient = NULL;

	zclient = pim_zebra_zclient_get();
	memset(&rpf, 0, sizeof(struct pim_rpf));
	rpf.rpf_addr.family = addr->family;
	rpf.rpf_addr.prefixlen = addr->prefixlen;
	rpf.rpf_addr.u.prefix4 = addr->u.prefix4;

	pnc = pim_nexthop_cache_find(pim, &rpf);
	if (!pnc) {
		pnc = pim_nexthop_cache_add(pim, &rpf);
		if (!pnc) {
			char rpf_str[PREFIX_STRLEN];
			pim_addr_dump("<nht-pnc?>", addr, rpf_str,
				      sizeof(rpf_str));
			zlog_warn("%s: pnc node allocation failed. addr %s ",
				  __PRETTY_FUNCTION__, rpf_str);
			return 0;
		}
		pim_sendmsg_zebra_rnh(pim, zclient, pnc,
				      ZEBRA_NEXTHOP_REGISTER);
		if (PIM_DEBUG_PIM_NHT) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(addr, buf, sizeof(buf));
			zlog_debug(
				"%s: NHT cache and zebra notification added for %s(%s)",
				__PRETTY_FUNCTION__, buf, pim->vrf->name);
		}
	}

	if (rp != NULL) {
		ch_node = listnode_lookup(pnc->rp_list, rp);
		if (ch_node == NULL)
			listnode_add_sort(pnc->rp_list, rp);
	}

	if (up != NULL)
		hash_get(pnc->upstream_hash, up, hash_alloc_intern);

	if (pnc && CHECK_FLAG(pnc->flags, PIM_NEXTHOP_VALID)) {
		memcpy(out_pnc, pnc, sizeof(struct pim_nexthop_cache));
		return 1;
	}

	return 0;
}

void pim_delete_tracked_nexthop(struct pim_instance *pim, struct prefix *addr,
				struct pim_upstream *up, struct rp_info *rp)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;
	struct zclient *zclient = NULL;

	zclient = pim_zebra_zclient_get();

	/* Remove from RPF hash if it is the last entry */
	lookup.rpf.rpf_addr = *addr;
	pnc = hash_lookup(pim->rpf_hash, &lookup);
	if (pnc) {
		if (rp)
			listnode_delete(pnc->rp_list, rp);
		if (up)
			hash_release(pnc->upstream_hash, up);

		if (PIM_DEBUG_PIM_NHT) {
			char buf[PREFIX_STRLEN];
			prefix2str(addr, buf, sizeof buf);
			zlog_debug(
				"%s: NHT %s(%s) rp_list count:%d upstream count:%ld",
				__PRETTY_FUNCTION__, buf, pim->vrf->name,
				pnc->rp_list->count, pnc->upstream_hash->count);
		}

		if (pnc->rp_list->count == 0
		    && pnc->upstream_hash->count == 0) {
			pim_sendmsg_zebra_rnh(pim, zclient, pnc,
					      ZEBRA_NEXTHOP_UNREGISTER);

			list_delete_and_null(&pnc->rp_list);
			hash_free(pnc->upstream_hash);

			hash_release(pim->rpf_hash, pnc);
			if (pnc->nexthop)
				nexthops_free(pnc->nexthop);
			XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
		}
	}
}

/* Update RP nexthop info based on Nexthop update received from Zebra.*/
static void pim_update_rp_nh(struct pim_instance *pim,
			     struct pim_nexthop_cache *pnc)
{
	struct listnode *node = NULL;
	struct rp_info *rp_info = NULL;

	/*Traverse RP list and update each RP Nexthop info */
	for (ALL_LIST_ELEMENTS_RO(pnc->rp_list, node, rp_info)) {
		if (rp_info->rp.rpf_addr.u.prefix4.s_addr == INADDR_NONE)
			continue;

		// Compute PIM RPF using cached nexthop
		pim_ecmp_nexthop_search(pim, pnc, &rp_info->rp.source_nexthop,
					&rp_info->rp.rpf_addr, &rp_info->group,
					1);
	}
}

/* This API is used to traverse nexthop cache of RPF addr
   of upstream entry whose IPv4 nexthop address is in
   unresolved state and due to event like pim neighbor
   UP event if it can be resolved.
*/
void pim_resolve_upstream_nh(struct pim_instance *pim, struct prefix *nht_p)
{
	struct nexthop *nh_node = NULL;
	struct pim_nexthop_cache pnc;
	struct pim_neighbor *nbr = NULL;

	memset(&pnc, 0, sizeof(struct pim_nexthop_cache));
	if (!pim_find_or_track_nexthop(pim, nht_p, NULL, NULL, &pnc))
		return;

	for (nh_node = pnc.nexthop; nh_node; nh_node = nh_node->next) {
		if (nh_node->gate.ipv4.s_addr != 0)
			continue;

		struct interface *ifp1 =
			if_lookup_by_index(nh_node->ifindex, pim->vrf_id);
		nbr = pim_neighbor_find_if(ifp1);
		if (!nbr)
			continue;

		nh_node->gate.ipv4 = nbr->source_addr;
		if (PIM_DEBUG_PIM_NHT) {
			char str[PREFIX_STRLEN];
			char str1[INET_ADDRSTRLEN];
			pim_inet4_dump("<nht_nbr?>", nbr->source_addr, str1,
				       sizeof(str1));
			pim_addr_dump("<nht_addr?>", nht_p, str, sizeof(str));
			zlog_debug(
				"%s: addr %s new nexthop addr %s interface %s",
				__PRETTY_FUNCTION__, str, str1, ifp1->name);
		}
	}
}

/* Update Upstream nexthop info based on Nexthop update received from Zebra.*/
static int pim_update_upstream_nh_helper(struct hash_backet *backet, void *arg)
{
	struct pim_instance *pim = (struct pim_instance *)arg;
	struct pim_upstream *up = (struct pim_upstream *)backet->data;
	int vif_index = 0;

	enum pim_rpf_result rpf_result;
	struct pim_rpf old;

	old.source_nexthop.interface = up->rpf.source_nexthop.interface;
	rpf_result = pim_rpf_update(pim, up, &old, 0);
	if (rpf_result == PIM_RPF_FAILURE) {
		pim_mroute_del(up->channel_oil, __PRETTY_FUNCTION__);
		return HASHWALK_CONTINUE;
	}

	/* update kernel multicast forwarding cache (MFC) */
	if (up->channel_oil) {
		ifindex_t ifindex = up->rpf.source_nexthop.interface->ifindex;

		vif_index = pim_if_find_vifindex_by_ifindex(pim, ifindex);
		/* Pass Current selected NH vif index to mroute download
		 */
		if (vif_index)
			pim_scan_individual_oil(up->channel_oil, vif_index);
		else {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: NHT upstream %s channel_oil IIF %s vif_index is not valid",
					__PRETTY_FUNCTION__, up->sg_str,
					up->rpf.source_nexthop.interface->name);
		}
	}

	if (rpf_result == PIM_RPF_CHANGED) {
		struct pim_neighbor *nbr;

		nbr = pim_neighbor_find(old.source_nexthop.interface,
					old.rpf_addr.u.prefix4);
		if (nbr)
			pim_jp_agg_remove_group(nbr->upstream_jp_agg, up);

		/*
		 * We have detected a case where we might need to rescan
		 * the inherited o_list so do it.
		 */
		if (up->channel_oil && up->channel_oil->oil_inherited_rescan) {
			pim_upstream_inherited_olist_decide(pim, up);
			up->channel_oil->oil_inherited_rescan = 0;
		}

		if (up->join_state == PIM_UPSTREAM_JOINED) {
			/*
			 * If we come up real fast we can be here
			 * where the mroute has not been installed
			 * so install it.
			 */
			if (up->channel_oil && !up->channel_oil->installed)
				pim_mroute_add(up->channel_oil,
					       __PRETTY_FUNCTION__);

			/*
			 * RFC 4601: 4.5.7.  Sending (S,G) Join/Prune Messages
			 *
			 * Transitions from Joined State
			 *
			 * RPF'(S,G) changes not due to an Assert
			 *
			 * The upstream (S,G) state machine remains in Joined
			 * state. Send Join(S,G) to the new upstream
			 * neighbor, which is the new value of RPF'(S,G).
			 * Send Prune(S,G) to the old upstream neighbor, which
			 * is the old value of RPF'(S,G).  Set the Join
			 * Timer (JT) to expire after t_periodic seconds.
			 */
			pim_jp_agg_switch_interface(&old, &up->rpf, up);

			pim_upstream_join_timer_restart(up, &old);
		} /* up->join_state == PIM_UPSTREAM_JOINED */

		/*
		 * FIXME can join_desired actually be changed by
		 * pim_rpf_update() returning PIM_RPF_CHANGED ?
		 */
		pim_upstream_update_join_desired(pim, up);

	} /* PIM_RPF_CHANGED */

	if (PIM_DEBUG_PIM_NHT) {
		zlog_debug("%s: NHT upstream %s(%s) old ifp %s new ifp %s",
			   __PRETTY_FUNCTION__, up->sg_str, pim->vrf->name,
			   old.source_nexthop.interface->name,
			   up->rpf.source_nexthop.interface->name);
	}

	return HASHWALK_CONTINUE;
}

static int pim_update_upstream_nh(struct pim_instance *pim,
				  struct pim_nexthop_cache *pnc)
{
	struct listnode *node;
	struct interface *ifp;

	hash_walk(pnc->upstream_hash, pim_update_upstream_nh_helper, pim);

	FOR_ALL_INTERFACES (pim->vrf, ifp)
		if (ifp->info) {
			struct pim_interface *pim_ifp = ifp->info;
			struct pim_iface_upstream_switch *us;

			for (ALL_LIST_ELEMENTS_RO(pim_ifp->upstream_switch_list,
						  node, us)) {
				struct pim_rpf rpf;
				rpf.source_nexthop.interface = ifp;
				rpf.rpf_addr.u.prefix4 = us->address;
				pim_joinprune_send(&rpf, us->us);
				pim_jp_agg_clear_group(us->us);
			}
		}

	return 0;
}

uint32_t pim_compute_ecmp_hash(struct prefix *src, struct prefix *grp)
{
	uint32_t hash_val;
	uint32_t s = 0, g = 0;

	if ((!src))
		return 0;

	switch (src->family) {
	case AF_INET: {
		s = src->u.prefix4.s_addr;
		s = s == 0 ? 1 : s;
		if (grp)
			g = grp->u.prefix4.s_addr;
	} break;
	default:
		break;
	}

	hash_val = jhash_2words(g, s, 101);
	return hash_val;
}

int pim_ecmp_nexthop_search(struct pim_instance *pim,
			    struct pim_nexthop_cache *pnc,
			    struct pim_nexthop *nexthop, struct prefix *src,
			    struct prefix *grp, int neighbor_needed)
{
	struct pim_neighbor *nbr = NULL;
	struct nexthop *nh_node = NULL;
	ifindex_t first_ifindex;
	struct interface *ifp = NULL;
	uint32_t hash_val = 0, mod_val = 0;
	uint8_t nh_iter = 0, found = 0;

	if (!pnc || !pnc->nexthop_num || !nexthop)
		return 0;

	// Current Nexthop is VALID, check to stay on the current path.
	if (nexthop->interface && nexthop->interface->info
	    && nexthop->mrib_nexthop_addr.u.prefix4.s_addr
		       != PIM_NET_INADDR_ANY) {
		/* User configured knob to explicitly switch
		   to new path is disabled or current path
		   metric is less than nexthop update.
		 */

		if (pim->ecmp_rebalance_enable == 0) {
			uint8_t curr_route_valid = 0;
			// Check if current nexthop is present in new updated
			// Nexthop list.
			// If the current nexthop is not valid, candidate to
			// choose new Nexthop.
			for (nh_node = pnc->nexthop; nh_node;
			     nh_node = nh_node->next) {
				curr_route_valid = (nexthop->interface->ifindex
						    == nh_node->ifindex);
				if (curr_route_valid)
					break;
			}

			if (curr_route_valid
			    && !pim_if_connected_to_source(nexthop->interface,
							   src->u.prefix4)) {
				nbr = pim_neighbor_find(
					nexthop->interface,
					nexthop->mrib_nexthop_addr.u.prefix4);
				if (!nbr
				    && !if_is_loopback(nexthop->interface)) {
					if (PIM_DEBUG_PIM_NHT)
						zlog_debug(
							"%s: current nexthop does not have nbr ",
							__PRETTY_FUNCTION__);
				} else {
					if (PIM_DEBUG_PIM_NHT) {
						char src_str[INET_ADDRSTRLEN];
						pim_inet4_dump("<addr?>",
							       src->u.prefix4,
							       src_str,
							       sizeof(src_str));
						char grp_str[INET_ADDRSTRLEN];
						pim_inet4_dump("<addr?>",
							       grp->u.prefix4,
							       grp_str,
							       sizeof(grp_str));
						zlog_debug(
							"%s: (%s,%s)(%s) current nexthop %s is valid, skipping new path selection",
							__PRETTY_FUNCTION__,
							src_str, grp_str,
							pim->vrf->name,
							nexthop->interface->name);
					}
					return 1;
				}
			}
		}
	}
	if (pim->ecmp_enable) {
		// PIM ECMP flag is enable then choose ECMP path.
		hash_val = pim_compute_ecmp_hash(src, grp);
		mod_val = hash_val % pnc->nexthop_num;
	}

	for (nh_node = pnc->nexthop; nh_node && (found == 0);
	     nh_node = nh_node->next) {
		first_ifindex = nh_node->ifindex;
		ifp = if_lookup_by_index(first_ifindex, pim->vrf_id);
		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", src->u.prefix4,
					       addr_str, sizeof(addr_str));
				zlog_debug(
					"%s %s: could not find interface for ifindex %d (address %s(%s))",
					__FILE__, __PRETTY_FUNCTION__,
					first_ifindex, addr_str,
					pim->vrf->name);
			}
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}
		if (!ifp->info) {
			if (PIM_DEBUG_PIM_NHT) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", src->u.prefix4,
					       addr_str, sizeof(addr_str));
				zlog_debug(
					"%s: multicast not enabled on input interface %s(%s) (ifindex=%d, RPF for source %s)",
					__PRETTY_FUNCTION__, ifp->name,
					pim->vrf->name, first_ifindex,
					addr_str);
			}
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}

		if (neighbor_needed
		    && !pim_if_connected_to_source(ifp, src->u.prefix4)) {
			nbr = pim_neighbor_find(ifp, nh_node->gate.ipv4);
			if (!nbr && !if_is_loopback(ifp)) {
				if (PIM_DEBUG_PIM_NHT)
					zlog_debug(
						"%s: pim nbr not found on input interface %s(%s)",
						__PRETTY_FUNCTION__, ifp->name,
						pim->vrf->name);
				if (nh_iter == mod_val)
					mod_val++; // Select nexthpath
				nh_iter++;
				continue;
			}
		}

		if (nh_iter == mod_val) {
			nexthop->interface = ifp;
			nexthop->mrib_nexthop_addr.family = AF_INET;
			nexthop->mrib_nexthop_addr.prefixlen = IPV4_MAX_BITLEN;
			nexthop->mrib_nexthop_addr.u.prefix4 =
				nh_node->gate.ipv4;
			nexthop->mrib_metric_preference = pnc->distance;
			nexthop->mrib_route_metric = pnc->metric;
			nexthop->last_lookup = src->u.prefix4;
			nexthop->last_lookup_time = pim_time_monotonic_usec();
			nexthop->nbr = nbr;
			found = 1;
			if (PIM_DEBUG_PIM_NHT) {
				char buf[INET_ADDRSTRLEN];
				char buf2[INET_ADDRSTRLEN];
				char buf3[INET_ADDRSTRLEN];
				pim_inet4_dump("<src?>", src->u.prefix4, buf2,
					       sizeof(buf2));
				pim_inet4_dump("<grp?>", grp->u.prefix4, buf3,
					       sizeof(buf3));
				pim_inet4_dump(
					"<rpf?>",
					nexthop->mrib_nexthop_addr.u.prefix4,
					buf, sizeof(buf));
				zlog_debug(
					"%s: (%s,%s)(%s) selected nhop interface %s addr %s mod_val %u iter %d ecmp %d",
					__PRETTY_FUNCTION__, buf2, buf3,
					pim->vrf->name, ifp->name, buf, mod_val,
					nh_iter, pim->ecmp_enable);
			}
		}
		nh_iter++;
	}

	if (found)
		return 1;
	else
		return 0;
}

/* This API is used to parse Registered address nexthop update coming from Zebra
 */
int pim_parse_nexthop_update(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
	struct nexthop *nexthop;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	int i;
	struct pim_rpf rpf;
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_neighbor *nbr = NULL;
	struct interface *ifp = NULL;
	struct interface *ifp1 = NULL;
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct pim_instance *pim;
	struct zapi_route nhr;

	if (!vrf)
		return 0;
	pim = vrf->info;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: Decode of nexthop update from zebra failed",
				__PRETTY_FUNCTION__);
		return 0;
	}

	if (command == ZEBRA_NEXTHOP_UPDATE) {
		prefix_copy(&rpf.rpf_addr, &nhr.prefix);
		pnc = pim_nexthop_cache_find(pim, &rpf);
		if (!pnc) {
			if (PIM_DEBUG_PIM_NHT) {
				char buf[PREFIX2STR_BUFFER];
				prefix2str(&rpf.rpf_addr, buf, sizeof(buf));
				zlog_debug(
					"%s: Skipping NHT update, addr %s is not in local cached DB.",
					__PRETTY_FUNCTION__, buf);
			}
			return 0;
		}
	} else {
		/*
		 * We do not currently handle ZEBRA_IMPORT_CHECK_UPDATE
		 */
		return 0;
	}

	pnc->last_update = pim_time_monotonic_usec();

	if (nhr.nexthop_num) {
		pnc->nexthop_num = 0; // Only increment for pim enabled rpf.

		for (i = 0; i < nhr.nexthop_num; i++) {
			nexthop = nexthop_from_zapi_nexthop(&nhr.nexthops[i]);
			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_BLACKHOLE:
				break;
			case NEXTHOP_TYPE_IFINDEX:
				/*
				 * Connected route (i.e. no nexthop), use
				 * RPF address from nexthop cache (i.e.
				 * destination) as PIM nexthop.
				 */
				nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				nexthop->gate.ipv4 =
					pnc->rpf.rpf_addr.u.prefix4;
				break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				ifp1 = if_lookup_by_index(nexthop->ifindex,
							  pim->vrf_id);
				nbr = pim_neighbor_find_if(ifp1);
				/* Overwrite with Nbr address as NH addr */
				if (nbr)
					nexthop->gate.ipv4 = nbr->source_addr;
				else {
					// Mark nexthop address to 0 until PIM
					// Nbr is resolved.
					nexthop->gate.ipv4.s_addr =
						PIM_NET_INADDR_ANY;
				}

				break;
			}

			ifp = if_lookup_by_index(nexthop->ifindex, pim->vrf_id);
			if (!ifp) {
				if (PIM_DEBUG_PIM_NHT) {
					char buf[NEXTHOP_STRLEN];
					zlog_debug(
						"%s: could not find interface for ifindex %d(%s) (addr %s)",
						__PRETTY_FUNCTION__,
						nexthop->ifindex,
						pim->vrf->name,
						nexthop2str(nexthop, buf,
							    sizeof(buf)));
				}
				nexthop_free(nexthop);
				continue;
			}

			if (PIM_DEBUG_PIM_NHT) {
				char p_str[PREFIX2STR_BUFFER];

				prefix2str(&nhr.prefix, p_str, sizeof(p_str));
				zlog_debug(
					"%s: NHT addr %s(%s) %d-nhop via %s(%s) type %d distance:%u metric:%u ",
					__PRETTY_FUNCTION__, p_str,
					pim->vrf->name, i + 1,
					inet_ntoa(nexthop->gate.ipv4),
					ifp->name, nexthop->type, nhr.distance,
					nhr.metric);
			}

			if (!ifp->info) {
				if (PIM_DEBUG_PIM_NHT) {
					char buf[NEXTHOP_STRLEN];

					zlog_debug(
						"%s: multicast not enabled on input interface %s(%s) (ifindex=%d, addr %s)",
						__PRETTY_FUNCTION__, ifp->name,
						pim->vrf->name,
						nexthop->ifindex,
						nexthop2str(nexthop, buf,
							    sizeof(buf)));
				}
				nexthop_free(nexthop);
				continue;
			}

			if (nhlist_tail) {
				nhlist_tail->next = nexthop;
				nhlist_tail = nexthop;
			} else {
				nhlist_tail = nexthop;
				nhlist_head = nexthop;
			}
			// Only keep track of nexthops which are PIM enabled.
			pnc->nexthop_num++;
		}
		/* Reset existing pnc->nexthop before assigning new list */
		nexthops_free(pnc->nexthop);
		pnc->nexthop = nhlist_head;
		if (pnc->nexthop_num) {
			pnc->flags |= PIM_NEXTHOP_VALID;
			pnc->distance = nhr.distance;
			pnc->metric = nhr.metric;
		}
	} else {
		pnc->flags &= ~PIM_NEXTHOP_VALID;
		pnc->nexthop_num = nhr.nexthop_num;
		nexthops_free(pnc->nexthop);
		pnc->nexthop = NULL;
	}

	if (PIM_DEBUG_PIM_NHT) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&nhr.prefix, buf, sizeof(buf));
		zlog_debug(
			"%s: NHT Update for %s(%s) num_nh %d num_pim_nh %d vrf:%u up %ld rp %d",
			__PRETTY_FUNCTION__, buf, pim->vrf->name,
			nhr.nexthop_num, pnc->nexthop_num, vrf_id,
			pnc->upstream_hash->count, listcount(pnc->rp_list));
	}

	pim_rpf_set_refresh_time(pim);

	if (listcount(pnc->rp_list))
		pim_update_rp_nh(pim, pnc);
	if (pnc->upstream_hash->count)
		pim_update_upstream_nh(pim, pnc);

	return 0;
}

int pim_ecmp_nexthop_lookup(struct pim_instance *pim,
			    struct pim_nexthop *nexthop, struct in_addr addr,
			    struct prefix *src, struct prefix *grp,
			    int neighbor_needed)
{
	struct pim_zlookup_nexthop nexthop_tab[MULTIPATH_NUM];
	struct pim_neighbor *nbr = NULL;
	int num_ifindex;
	struct interface *ifp;
	int first_ifindex;
	int found = 0;
	uint8_t i = 0;
	uint32_t hash_val = 0, mod_val = 0;

	if (PIM_DEBUG_PIM_NHT) {
		char addr_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<addr?>", addr, addr_str, sizeof(addr_str));
		zlog_debug("%s: Looking up: %s(%s), last lookup time: %lld",
			   __PRETTY_FUNCTION__, addr_str, pim->vrf->name,
			   nexthop->last_lookup_time);
	}

	memset(nexthop_tab, 0,
	       sizeof(struct pim_zlookup_nexthop) * MULTIPATH_NUM);
	num_ifindex = zclient_lookup_nexthop(pim, nexthop_tab, MULTIPATH_NUM,
					     addr, PIM_NEXTHOP_LOOKUP_MAX);
	if (num_ifindex < 1) {
		if (PIM_DEBUG_PIM_NHT) {
			char addr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<addr?>", addr, addr_str,
				       sizeof(addr_str));
			zlog_warn(
				"%s: could not find nexthop ifindex for address %s(%s)",
				__PRETTY_FUNCTION__, addr_str, pim->vrf->name);
		}
		return 0;
	}

	// If PIM ECMP enable then choose ECMP path.
	if (pim->ecmp_enable) {
		hash_val = pim_compute_ecmp_hash(src, grp);
		mod_val = hash_val % num_ifindex;
		if (PIM_DEBUG_PIM_NHT_DETAIL)
			zlog_debug("%s: hash_val %u mod_val %u",
				   __PRETTY_FUNCTION__, hash_val, mod_val);
	}

	while (!found && (i < num_ifindex)) {
		first_ifindex = nexthop_tab[i].ifindex;

		ifp = if_lookup_by_index(first_ifindex, pim->vrf_id);
		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", addr, addr_str,
					       sizeof(addr_str));
				zlog_debug(
					"%s %s: could not find interface for ifindex %d (address %s(%s))",
					__FILE__, __PRETTY_FUNCTION__,
					first_ifindex, addr_str,
					pim->vrf->name);
			}
			if (i == mod_val)
				mod_val++;
			i++;
			continue;
		}

		if (!ifp->info) {
			if (PIM_DEBUG_PIM_NHT) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", addr, addr_str,
					       sizeof(addr_str));
				zlog_debug(
					"%s: multicast not enabled on input interface %s(%s) (ifindex=%d, RPF for source %s)",
					__PRETTY_FUNCTION__, ifp->name,
					pim->vrf->name, first_ifindex,
					addr_str);
			}
			if (i == mod_val)
				mod_val++;
			i++;
			continue;
		}
		if (neighbor_needed && !pim_if_connected_to_source(ifp, addr)) {
			nbr = pim_neighbor_find(
				ifp, nexthop_tab[i].nexthop_addr.u.prefix4);
			if (PIM_DEBUG_PIM_NHT_DETAIL)
				zlog_debug("ifp name: %s(%s), pim nbr: %p",
					   ifp->name, pim->vrf->name, nbr);
			if (!nbr && !if_is_loopback(ifp)) {
				if (i == mod_val)
					mod_val++;
				i++;
				if (PIM_DEBUG_PIM_NHT) {
					char addr_str[INET_ADDRSTRLEN];
					pim_inet4_dump("<addr?>", addr,
						       addr_str,
						       sizeof(addr_str));
					zlog_debug(
						"%s: NBR not found on input interface %s(%s) (RPF for source %s)",
						__PRETTY_FUNCTION__, ifp->name,
						pim->vrf->name, addr_str);
				}
				continue;
			}
		}

		if (i == mod_val) {
			if (PIM_DEBUG_PIM_NHT) {
				char nexthop_str[PREFIX_STRLEN];
				char addr_str[INET_ADDRSTRLEN];
				pim_addr_dump("<nexthop?>",
					      &nexthop_tab[i].nexthop_addr,
					      nexthop_str, sizeof(nexthop_str));
				pim_inet4_dump("<addr?>", addr, addr_str,
					       sizeof(addr_str));
				zlog_debug(
					"%s: found nhop %s for addr %s interface %s(%s) metric %d dist %d",
					__PRETTY_FUNCTION__, nexthop_str,
					addr_str, ifp->name, pim->vrf->name,
					nexthop_tab[i].route_metric,
					nexthop_tab[i].protocol_distance);
			}
			/* update nexthop data */
			nexthop->interface = ifp;
			nexthop->mrib_nexthop_addr =
				nexthop_tab[i].nexthop_addr;
			nexthop->mrib_metric_preference =
				nexthop_tab[i].protocol_distance;
			nexthop->mrib_route_metric =
				nexthop_tab[i].route_metric;
			nexthop->last_lookup = addr;
			nexthop->last_lookup_time = pim_time_monotonic_usec();
			nexthop->nbr = nbr;
			found = 1;
		}
		i++;
	}

	if (found)
		return 1;
	else
		return 0;
}

int pim_ecmp_fib_lookup_if_vif_index(struct pim_instance *pim,
				     struct in_addr addr, struct prefix *src,
				     struct prefix *grp)
{
	struct pim_zlookup_nexthop nexthop_tab[MULTIPATH_NUM];
	int num_ifindex;
	int vif_index;
	ifindex_t first_ifindex;
	uint32_t hash_val = 0, mod_val = 0;

	memset(nexthop_tab, 0,
	       sizeof(struct pim_zlookup_nexthop) * MULTIPATH_NUM);
	num_ifindex = zclient_lookup_nexthop(pim, nexthop_tab, MULTIPATH_NUM,
					     addr, PIM_NEXTHOP_LOOKUP_MAX);
	if (num_ifindex < 1) {
		if (PIM_DEBUG_PIM_NHT) {
			char addr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<addr?>", addr, addr_str,
				       sizeof(addr_str));
			zlog_debug(
				"%s: could not find nexthop ifindex for address %s(%s)",
				__PRETTY_FUNCTION__, addr_str, pim->vrf->name);
		}
		return -1;
	}

	// If PIM ECMP enable then choose ECMP path.
	if (pim->ecmp_enable) {
		hash_val = pim_compute_ecmp_hash(src, grp);
		mod_val = hash_val % num_ifindex;
		if (PIM_DEBUG_PIM_NHT_DETAIL)
			zlog_debug("%s: hash_val %u mod_val %u",
				   __PRETTY_FUNCTION__, hash_val, mod_val);
	}

	first_ifindex = nexthop_tab[mod_val].ifindex;

	if (PIM_DEBUG_PIM_NHT) {
		char addr_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<ifaddr?>", addr, addr_str, sizeof(addr_str));
		zlog_debug(
			"%s: found nexthop ifindex=%d (interface %s(%s)) for address %s",
			__PRETTY_FUNCTION__, first_ifindex,
			ifindex2ifname(first_ifindex, pim->vrf_id),
			pim->vrf->name, addr_str);
	}

	vif_index = pim_if_find_vifindex_by_ifindex(pim, first_ifindex);

	if (vif_index < 0) {
		if (PIM_DEBUG_PIM_NHT) {
			char addr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<addr?>", addr, addr_str,
				       sizeof(addr_str));
			zlog_debug(
				"%s: low vif_index=%d(%s) < 1 nexthop for address %s",
				__PRETTY_FUNCTION__, vif_index, pim->vrf->name,
				addr_str);
		}
		return -2;
	}

	return vif_index;
}
