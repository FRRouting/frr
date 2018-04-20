/*
 * PBR-map Code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "vrf.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "memory.h"
#include "log.h"
#include "vty.h"

#include "pbr_nht.h"
#include "pbr_map.h"
#include "pbr_zebra.h"
#include "pbr_memory.h"
#include "pbr_debug.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_MAP, "PBR Map")
DEFINE_MTYPE_STATIC(PBRD, PBR_MAP_SEQNO, "PBR Map Sequence")
DEFINE_MTYPE_STATIC(PBRD, PBR_MAP_INTERFACE, "PBR Map Interface")

static uint32_t pbr_map_sequence_unique;

static inline int pbr_map_compare(const struct pbr_map *pbrmap1,
				  const struct pbr_map *pbrmap2);

RB_GENERATE(pbr_map_entry_head, pbr_map, pbr_map_entry, pbr_map_compare)

struct pbr_map_entry_head pbr_maps = RB_INITIALIZER(&pbr_maps);

DEFINE_QOBJ_TYPE(pbr_map_sequence)

static inline int pbr_map_compare(const struct pbr_map *pbrmap1,
				  const struct pbr_map *pbrmap2)
{
	return strcmp(pbrmap1->name, pbrmap2->name);
}

static int pbr_map_sequence_compare(const struct pbr_map_sequence *pbrms1,
				    const struct pbr_map_sequence *pbrms2)
{
	if (pbrms1->seqno == pbrms2->seqno)
		return 0;

	if (pbrms1->seqno < pbrms2->seqno)
		return -1;

	return 1;
}

static void pbr_map_sequence_delete(struct pbr_map_sequence *pbrms)
{
	if (pbrms->internal_nhg_name)
		XFREE(MTYPE_TMP, pbrms->internal_nhg_name);

	XFREE(MTYPE_PBR_MAP_SEQNO, pbrms);
}

static int pbr_map_interface_compare(const struct pbr_map_interface *pmi1,
				     const struct pbr_map_interface *pmi2)
{
	return strcmp(pmi1->ifp->name, pmi2->ifp->name);
}

static void pbr_map_interface_list_delete(struct pbr_map_interface *pmi)
{
	struct pbr_map_interface *pmi_int;
	struct listnode *node, *nnode;
	struct pbr_map *pbrm;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		for (ALL_LIST_ELEMENTS(pbrm->incoming, node, nnode, pmi_int)) {
			if (pmi == pmi_int) {
				pbr_map_policy_delete(pbrm, pmi);
				return;
			}
		}
	}
}

static const char *pbr_map_reason_str[] = {
	"Invalid NH-group",     "Invalid NH",	 "No Nexthops",
	"Both NH and NH-Group", "Invalid Src or Dst", "Deleting Sequence",
};

void pbr_map_reason_string(unsigned int reason, char *buf, int size)
{
	unsigned int bit;
	int len = 0;

	if (!buf)
		return;

	for (bit = 0; bit < array_size(pbr_map_reason_str); bit++) {
		if ((reason & (1 << bit)) && (len < size)) {
			len += snprintf((buf + len), (size - len), "%s%s",
					(len > 0) ? ", " : "",
					pbr_map_reason_str[bit]);
		}
	}
}


void pbr_map_interface_delete(struct pbr_map *pbrm, struct interface *ifp_del)
{

	struct listnode *node;
	struct pbr_map_interface *pmi;

	for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, node, pmi)) {
		if (ifp_del == pmi->ifp)
			break;
	}

	if (pmi)
		pbr_map_policy_delete(pbrm, pmi);
}

void pbr_map_add_interface(struct pbr_map *pbrm, struct interface *ifp_add)
{
	struct listnode *node;
	struct pbr_map_interface *pmi;

	for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, node, pmi)) {
		if (ifp_add == pmi->ifp)
			return;
	}

	pmi = XCALLOC(MTYPE_PBR_MAP_INTERFACE, sizeof(*pmi));
	pmi->ifp = ifp_add;
	pmi->pbrm = pbrm;
	listnode_add_sort(pbrm->incoming, pmi);

	bf_assign_index(pbrm->ifi_bitfield, pmi->install_bit);
	pbr_map_check_valid(pbrm->name);
	if (pbrm->valid)
		pbr_map_install(pbrm);
}

void pbr_map_write_interfaces(struct vty *vty, struct interface *ifp)
{
	struct pbr_interface *pbr_ifp = ifp->info;

	if (pbr_ifp
	    && strncmp(pbr_ifp->mapname, "", sizeof(pbr_ifp->mapname)) != 0)
		vty_out(vty, " pbr-policy %s\n", pbr_ifp->mapname);
}

struct pbr_map *pbrm_find(const char *name)
{
	struct pbr_map pbrm;

	strlcpy(pbrm.name, name, sizeof(pbrm.name));

	return RB_FIND(pbr_map_entry_head, &pbr_maps, &pbrm);
}

extern void pbr_map_delete(struct pbr_map_sequence *pbrms)
{
	struct pbr_map *pbrm;
	struct listnode *inode;
	struct pbr_map_interface *pmi;

	pbrm = pbrms->parent;

	for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, inode, pmi))
		pbr_send_pbr_map(pbrms, pmi, false);

	if (pbrms->nhg)
		pbr_nht_delete_individual_nexthop(pbrms);

	listnode_delete(pbrm->seqnumbers, pbrms);

	if (pbrm->seqnumbers->count == 0) {
		RB_REMOVE(pbr_map_entry_head, &pbr_maps, pbrm);

		bf_free(pbrm->ifi_bitfield);
		XFREE(MTYPE_PBR_MAP, pbrm);
	}
}

void pbr_map_delete_nexthop_group(struct pbr_map_sequence *pbrms)
{
	struct pbr_map *pbrm = pbrms->parent;
	struct listnode *node;
	struct pbr_map_interface *pmi;

	if (pbrm->valid && pbrms->nhs_installed && pbrm->incoming->count) {
		for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, node, pmi))
			pbr_send_pbr_map(pbrms, pmi, false);
	}

	pbrm->valid = false;
	pbrms->nhs_installed = false;
	pbrms->reason |= PBR_MAP_INVALID_NO_NEXTHOPS;
	pbrms->nhgrp_name = NULL;
}

struct pbr_map_sequence *pbrms_lookup_unique(uint32_t unique, ifindex_t ifindex,
					     struct pbr_map_interface **ppmi)
{
	struct pbr_map_sequence *pbrms;
	struct listnode *snode, *inode;
	struct pbr_map_interface *pmi;
	struct pbr_map *pbrm;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, inode, pmi)) {
			if (pmi->ifp->ifindex != ifindex)
				continue;

			if (ppmi)
				*ppmi = pmi;

			for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, snode,
						  pbrms)) {
				DEBUGD(&pbr_dbg_map, "%s: Comparing %u to %u",
				       __PRETTY_FUNCTION__, pbrms->unique,
				       unique);
				if (pbrms->unique == unique)
					return pbrms;
			}
		}
	}

	return NULL;
}

static void pbr_map_add_interfaces(struct pbr_map *pbrm)
{
	struct interface *ifp;
	struct pbr_interface *pbr_ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifp->info) {
				pbr_ifp = ifp->info;
				if (strcmp(pbrm->name, pbr_ifp->mapname) == 0)
					pbr_map_add_interface(pbrm, ifp);
			}
		}
	}
}

struct pbr_map_sequence *pbrms_get(const char *name, uint32_t seqno)
{
	struct pbr_map *pbrm;
	struct pbr_map_sequence *pbrms;
	struct listnode *node;

	pbrm = pbrm_find(name);
	if (!pbrm) {
		pbrm = XCALLOC(MTYPE_PBR_MAP, sizeof(*pbrm));
		snprintf(pbrm->name, sizeof(pbrm->name), "%s", name);

		pbrm->seqnumbers = list_new();
		pbrm->seqnumbers->cmp =
			(int (*)(void *, void *))pbr_map_sequence_compare;
		pbrm->seqnumbers->del =
			 (void (*)(void *))pbr_map_sequence_delete;

		pbrm->incoming = list_new();
		pbrm->incoming->cmp =
			(int (*)(void *, void *))pbr_map_interface_compare;
		pbrm->incoming->del =
			(void (*)(void *))pbr_map_interface_list_delete;

		RB_INSERT(pbr_map_entry_head, &pbr_maps, pbrm);

		bf_init(pbrm->ifi_bitfield, 64);
		pbr_map_add_interfaces(pbrm);
	}

	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
		if (pbrms->seqno == seqno)
			break;

	}

	if (!pbrms) {
		pbrms = XCALLOC(MTYPE_PBR_MAP_SEQNO, sizeof(*pbrms));
		pbrms->unique = pbr_map_sequence_unique++;
		pbrms->seqno = seqno;
		pbrms->ruleno = pbr_nht_get_next_rule(seqno);
		pbrms->parent = pbrm;
		pbrms->reason =
			PBR_MAP_INVALID_SRCDST |
			PBR_MAP_INVALID_NO_NEXTHOPS;

		QOBJ_REG(pbrms, pbr_map_sequence);
		listnode_add_sort(pbrm->seqnumbers, pbrms);
	}

	return pbrms;
}

static void
pbr_map_sequence_check_nexthops_valid(struct pbr_map_sequence *pbrms)
{
	/*
	 * Check validness of the nexthop or nexthop-group
	 */
	if (!pbrms->nhg && !pbrms->nhgrp_name)
		pbrms->reason |= PBR_MAP_INVALID_NO_NEXTHOPS;

	if (pbrms->nhg && pbrms->nhgrp_name)
		pbrms->reason |= PBR_MAP_INVALID_BOTH_NHANDGRP;

	if (pbrms->nhg &&
	    !pbr_nht_nexthop_group_valid(pbrms->internal_nhg_name))
		pbrms->reason |= PBR_MAP_INVALID_NEXTHOP;

	if (pbrms->nhgrp_name) {
		if (!pbr_nht_nexthop_group_valid(pbrms->nhgrp_name))
			pbrms->reason |= PBR_MAP_INVALID_NEXTHOP_GROUP;
		else
			pbrms->nhs_installed = true;
	}
}

static void pbr_map_sequence_check_src_dst_valid(struct pbr_map_sequence *pbrms)
{
	if (!pbrms->src && !pbrms->dst)
		pbrms->reason |= PBR_MAP_INVALID_SRCDST;
}

/*
 * Checks to see if we think that the pbmrs is valid.  If we think
 * the config is valid return true.
 */
static void pbr_map_sequence_check_valid(struct pbr_map_sequence *pbrms)
{
	pbr_map_sequence_check_nexthops_valid(pbrms);

	pbr_map_sequence_check_src_dst_valid(pbrms);
}

static bool pbr_map_check_valid_internal(struct pbr_map *pbrm)
{
	struct pbr_map_sequence *pbrms;
	struct listnode *node;

	pbrm->valid = true;
	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
		pbrms->reason = 0;
		pbr_map_sequence_check_valid(pbrms);
		/*
		 * A pbr_map_sequence that is invalid causes
		 * the whole shebang to be invalid
		 */
		if (pbrms->reason != 0)
			pbrm->valid = false;
	}

	return pbrm->valid;
}

/*
 * For a given PBR-MAP check to see if we think it is a
 * valid config or not.  If so note that it is and return
 * that we are valid.
 */
bool pbr_map_check_valid(const char *name)
{
	struct pbr_map *pbrm;

	pbrm = pbrm_find(name);
	if (!pbrm) {
		DEBUGD(&pbr_dbg_map,
		       "%s: Specified PBR-MAP(%s) does not exist?",
		       __PRETTY_FUNCTION__, name);
		return false;
	}

	pbr_map_check_valid_internal(pbrm);
	return pbrm->valid;
}

void pbr_map_schedule_policy_from_nhg(const char *nh_group)
{
	struct pbr_map_sequence *pbrms;
	struct pbr_map *pbrm;
	struct listnode *node;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		DEBUGD(&pbr_dbg_map, "%s: Looking at %s", __PRETTY_FUNCTION__,
		       pbrm->name);
		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
			DEBUGD(&pbr_dbg_map, "\tNH Grp name: %s",
			       pbrms->nhgrp_name ? pbrms->nhgrp_name : "NULL");

			if (pbrms->nhgrp_name
			    && (strcmp(nh_group, pbrms->nhgrp_name) == 0)) {
				pbrms->nhs_installed = true;

				pbr_map_check(pbrms);
			}

			if (pbrms->nhg
			    && (strcmp(nh_group, pbrms->internal_nhg_name)
				== 0)) {
				pbrms->nhs_installed = true;

				pbr_map_check(pbrms);
			}
		}
	}
}

void pbr_map_policy_install(const char *name)
{
	struct pbr_map_sequence *pbrms;
	struct pbr_map *pbrm;
	struct listnode *node, *inode;
	struct pbr_map_interface *pmi;

	DEBUGD(&pbr_dbg_map, "%s: for %s", __PRETTY_FUNCTION__, name);
	pbrm = pbrm_find(name);
	if (!pbrm)
		return;

	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
		DEBUGD(&pbr_dbg_map,
		       "%s: Looking at what to install %s(%u) %d %d",
		       __PRETTY_FUNCTION__, name, pbrms->seqno, pbrm->valid,
		       pbrms->nhs_installed);

		if (pbrm->valid && pbrms->nhs_installed && pbrm->incoming->count) {
			DEBUGD(&pbr_dbg_map, "\tInstalling %s %u",
			       pbrm->name, pbrms->seqno);
			for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, inode, pmi))
				pbr_send_pbr_map(pbrms, pmi, true);
		}
	}
}

void pbr_map_policy_delete(struct pbr_map *pbrm, struct pbr_map_interface *pmi)
{
	struct listnode *node;
	struct pbr_map_sequence *pbrms;


	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms))
		pbr_send_pbr_map(pbrms, pmi, false);

	listnode_delete(pbrm->incoming, pmi);
	pmi->pbrm = NULL;

	bf_release_index(pbrm->ifi_bitfield, pmi->install_bit);
	XFREE(MTYPE_PBR_MAP_INTERFACE, pmi);
}

/*
 * For a nexthop group specified, see if any of the pbr-maps
 * are using it and if so, check to see that we are still
 * valid for usage.  If we are valid then schedule the installation/deletion
 * of the pbr-policy.
 */
void pbr_map_check_nh_group_change(const char *nh_group)
{
	struct pbr_map_sequence *pbrms;
	struct pbr_map *pbrm;
	struct listnode *node, *inode;
	struct pbr_map_interface *pmi;
	bool found_name;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
			found_name = false;
			if (pbrms->nhgrp_name)
				found_name =
					!strcmp(nh_group, pbrms->nhgrp_name);
			else if (pbrms->nhg)
				found_name = !strcmp(nh_group,
						     pbrms->internal_nhg_name);

			if (found_name) {
				bool original = pbrm->valid;

				pbr_map_check_valid_internal(pbrm);

				if (pbrm->valid && (original != pbrm->valid))
					pbr_map_install(pbrm);

				if (pbrm->valid == false)
					for (ALL_LIST_ELEMENTS_RO(
						     pbrm->incoming, inode,
						     pmi))
						pbr_send_pbr_map(pbrms, pmi,
								 false);
			}
		}
	}
}

void pbr_map_check(struct pbr_map_sequence *pbrms)
{
	struct pbr_map *pbrm;
	struct listnode *inode;
	struct pbr_map_interface *pmi;
	bool install;

	pbrm = pbrms->parent;
	DEBUGD(&pbr_dbg_map, "%s: for %s(%u)", __PRETTY_FUNCTION__,
	       pbrm->name, pbrms->seqno);
	if (pbr_map_check_valid(pbrm->name))
		DEBUGD(&pbr_dbg_map, "We are totally valid %s\n",
		       pbrm->name);

	DEBUGD(&pbr_dbg_map, "%s: Installing %s(%u) reason: %" PRIu64,
	       __PRETTY_FUNCTION__, pbrm->name, pbrms->seqno, pbrms->reason);

	if (pbrms->reason == PBR_MAP_VALID_SEQUENCE_NUMBER) {
		install = true;
		DEBUGD(&pbr_dbg_map, "%s: Installing %s(%u) reason: %" PRIu64,
		       __PRETTY_FUNCTION__, pbrm->name, pbrms->seqno,
		       pbrms->reason);
		DEBUGD(&pbr_dbg_map,
		       "\tSending PBR_MAP_POLICY_INSTALL event");
	} else {
		install = false;
		DEBUGD(&pbr_dbg_map,
		       "%s: Removing %s(%u) reason: %" PRIu64,
		       __PRETTY_FUNCTION__, pbrm->name,
		       pbrms->seqno, pbrms->reason);
	}

	for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, inode, pmi)) {
		pbr_send_pbr_map(pbrms, pmi, install);
	}
}

void pbr_map_install(struct pbr_map *pbrm)
{
	struct listnode *node, *inode;
	struct pbr_map_sequence *pbrms;
	struct pbr_map_interface *pmi;

	if (!pbrm->incoming->count)
		return;

	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms))
		for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, inode, pmi))
			pbr_send_pbr_map(pbrms, pmi, true);
}

void pbr_map_init(void)
{
	RB_INIT(pbr_map_entry_head, &pbr_maps);

	pbr_map_sequence_unique = 1;
}
