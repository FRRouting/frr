// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_autorp.c: PIM AutoRP handling routines
 *
 * Copyright (C) 2024 ATCorp
 * Nathan Bahr
 */

#include <zebra.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "lib/plist.h"
#include "lib/plist_int.h"
#include "lib/sockopt.h"
#include "lib/network.h"
#include "lib/termtable.h"
#include "lib/json.h"

#include "pimd.h"
#include "pim_util.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_sock.h"
#include "pim_instance.h"
#include "pim_autorp.h"

DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP, "PIM AutoRP info");
DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP_RP, "PIM AutoRP discovered RP info");
DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP_ANNOUNCE, "PIM AutoRP announcement packet");
DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP_GRPPFIX, "PIM AutoRP group prefix list");

static const char *PIM_AUTORP_ANNOUNCEMENT_GRP = "224.0.1.39";
static const char *PIM_AUTORP_DISCOVERY_GRP = "224.0.1.40";
static const in_port_t PIM_AUTORP_PORT = 496;

static int pim_autorp_rp_cmp(const struct pim_autorp_rp *l, const struct pim_autorp_rp *r)
{
	return pim_addr_cmp(l->addr, r->addr);
}

DECLARE_SORTLIST_UNIQ(pim_autorp_rp, struct pim_autorp_rp, item, pim_autorp_rp_cmp);

static int pim_autorp_grppfix_cmp(const struct pim_autorp_grppfix *l,
				  const struct pim_autorp_grppfix *r)
{
	return prefix_cmp(&l->grp, &r->grp);
}

DECLARE_SORTLIST_UNIQ(pim_autorp_grppfix, struct pim_autorp_grppfix, item, pim_autorp_grppfix_cmp);

static void pim_autorp_grppfix_free(struct pim_autorp_grppfix_head *head)
{
	struct pim_autorp_grppfix *grp;

	while ((grp = pim_autorp_grppfix_pop(head)))
		XFREE(MTYPE_PIM_AUTORP_GRPPFIX, grp);
}

static void pim_autorp_rp_free(struct pim_autorp_rp *rp, bool installed)
{
	event_cancel(&rp->hold_timer);

	/* Clean up installed RP info */
	if (installed) {
		if (pim_rp_del(rp->autorp->pim, rp->addr, rp->grp,
			       (strlen(rp->grplist) ? rp->grplist : NULL), RP_SRC_AUTORP)) {
			zlog_warn("%s: Failed to delete RP %pI4", __func__, &rp->addr);
		}

		if (strlen(rp->grplist)) {
			struct prefix_list *pl;

			pl = prefix_list_lookup(AFI_IP, rp->grplist);
			if (pl)
				prefix_list_delete(pl);
		}
	}

	pim_autorp_grppfix_free(&rp->grp_pfix_list);
	pim_autorp_grppfix_fini(&rp->grp_pfix_list);

	XFREE(MTYPE_PIM_AUTORP_RP, rp);
}

static void pim_autorp_rplist_free(struct pim_autorp_rp_head *head, bool installed)
{
	struct pim_autorp_rp *rp;

	while ((rp = pim_autorp_rp_pop(head)))
		pim_autorp_rp_free(rp, installed);
}

static void pim_autorp_free(struct pim_autorp *autorp)
{
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Freeing PIM AutoRP", __func__);

	pim_autorp_rplist_free(&(autorp->discovery_rp_list), true);
	pim_autorp_rp_fini(&(autorp->discovery_rp_list));

	pim_autorp_rplist_free(&(autorp->candidate_rp_list), false);
	pim_autorp_rp_fini(&(autorp->candidate_rp_list));

	pim_autorp_rplist_free(&(autorp->mapping_rp_list), false);
	pim_autorp_rp_fini(&(autorp->mapping_rp_list));

	pim_autorp_rplist_free(&(autorp->advertised_rp_list), false);
	pim_autorp_rp_fini(&(autorp->advertised_rp_list));

	if (autorp->announce_pkt)
		XFREE(MTYPE_PIM_AUTORP_ANNOUNCE, autorp->announce_pkt);
}

static bool pim_autorp_join_groups(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct pim_autorp *autorp;
	pim_addr grp;

	pim_ifp = ifp->info;
	pim = pim_ifp->pim;
	autorp = pim->autorp;

	inet_pton(PIM_AF, PIM_AUTORP_DISCOVERY_GRP, &grp);
	if (pim_socket_join(autorp->sock, grp, pim_ifp->primary_address,
			    ifp->ifindex, pim_ifp)) {
		zlog_warn("Failed to join group %pI4 on interface %s", &grp, ifp->name);
		return false;
	}

	zlog_info("%s: Joined AutoRP discovery group %pPA on interface %s", __func__, &grp,
		  ifp->name);

	inet_pton(PIM_AF, PIM_AUTORP_ANNOUNCEMENT_GRP, &grp);
	if (pim_socket_join(pim->autorp->sock, grp, pim_ifp->primary_address, ifp->ifindex,
			    pim_ifp)) {
		zlog_warn("Failed to join group %pI4 on interface %s", &grp, ifp->name);
		return errno;
	}

	zlog_info("%s: Joined AutoRP announcement group %pPA on interface %s", __func__, &grp,
		  ifp->name);

	return true;
}

static bool pim_autorp_leave_groups(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct pim_autorp *autorp;
	pim_addr grp;

	pim_ifp = ifp->info;
	pim = pim_ifp->pim;
	autorp = pim->autorp;

	inet_pton(PIM_AF, PIM_AUTORP_DISCOVERY_GRP, &grp);
	if (pim_socket_leave(autorp->sock, grp, pim_ifp->primary_address,
			     ifp->ifindex, pim_ifp)) {
		zlog_warn("Failed to leave group %pI4 on interface %s", &grp, ifp->name);
		return false;
	}

	zlog_info("%s: Left AutoRP discovery group %pPA on interface %s", __func__, &grp, ifp->name);

	inet_pton(PIM_AF, PIM_AUTORP_ANNOUNCEMENT_GRP, &grp);
	if (pim_socket_leave(pim->autorp->sock, grp, pim_ifp->primary_address, ifp->ifindex,
			     pim_ifp)) {
		zlog_warn("Failed to leave group %pI4 on interface %s", &grp, ifp->name);
		return errno;
	}

	zlog_info("%s: Left AutoRP announcement group %pPA on interface %s", __func__, &grp,
		  ifp->name);

	return true;
}

static bool pim_autorp_setup(int fd)
{
#if defined(HAVE_IP_PKTINFO)
	int data;
	socklen_t data_len = sizeof(data);
#endif

	struct sockaddr_in autorp_addr = { .sin_family = AF_INET,
					   .sin_addr = { .s_addr = INADDR_ANY },
					   .sin_port = htons(PIM_AUTORP_PORT) };

	setsockopt_so_recvbuf(fd, 1024 * 1024 * 8);

#if defined(HAVE_IP_PKTINFO)
	/* Linux and Solaris IP_PKTINFO */
	data = 1;
	if (setsockopt(fd, PIM_IPPROTO, IP_PKTINFO, &data, data_len)) {
		zlog_warn("%s: Could not set IP_PKTINFO on socket fd=%d: errno=%d: %s", __func__,
			  fd, errno, safe_strerror(errno));
		return false;
	}
#endif

	if (set_nonblocking(fd) < 0) {
		zlog_warn("%s: Could not set non blocking on socket fd=%d: errno=%d: %s", __func__,
			  fd, errno, safe_strerror(errno));
		return false;
	}

	if (sockopt_reuseaddr(fd)) {
		zlog_warn("%s: Could not set reuse addr on socket fd=%d: errno=%d: %s", __func__,
			  fd, errno, safe_strerror(errno));
		return false;
	}

	if (setsockopt_ipv4_multicast_loop(fd, 1) < 0) {
		zlog_warn("%s: Could not enable multicast loopback on socket fd=%d: errno=%d: %s",
			  __func__, fd, errno, safe_strerror(errno));
		return false;
	}

	if (bind(fd, (const struct sockaddr *)&autorp_addr, sizeof(autorp_addr)) < 0) {
		zlog_warn("%s: Could not bind socket: %pSUp, fd=%d, errno=%d, %s", __func__,
			  (union sockunion *)&autorp_addr, fd, errno, safe_strerror(errno));
		return false;
	}

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP finished setup", __func__);

	return true;
}

static void autorp_ma_rp_holdtime(struct event *evt)
{
	/* Mapping agent RP hold time expired, remove the RP */
	struct pim_autorp_rp *rp = EVENT_ARG(evt);

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP hold time expired, RP removed from mapping agent: addr=%pI4, grp=%pFX, grplist=%s",
			   __func__, &rp->addr, &rp->grp,
			   (strlen(rp->grplist) ? rp->grplist : "NONE"));

	pim_autorp_rp_del(&(rp->autorp->mapping_rp_list), rp);
	pim_autorp_rp_free(rp, false);
}

static bool autorp_recv_announcement(struct pim_autorp *autorp, uint8_t rpcnt, uint16_t holdtime,
				     char *buf, size_t buf_size)
{
	int i, j;
	struct autorp_pkt_rp *rp;
	struct autorp_pkt_grp *grp;
	size_t offset = 0;
	pim_addr rp_addr;
	struct pim_autorp_rp *ma_rp;
	struct pim_autorp_rp *trp;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Processing AutoRP Announcement (rpcnt=%u, holdtime=%u)", __func__,
			   rpcnt, holdtime);

	for (i = 0; i < rpcnt; ++i) {
		if ((buf_size - offset) < AUTORP_RPLEN) {
			zlog_warn("%s: Failed to parse AutoRP Announcement RP, invalid buffer size (%u < %u)",
				  __func__, (uint32_t)(buf_size - offset), AUTORP_RPLEN);
			return false;
		}

		rp = (struct autorp_pkt_rp *)(buf + offset);
		offset += AUTORP_RPLEN;

		rp_addr.s_addr = rp->addr;

		/* Ignore RP's limited to PIM version 1 or with an unknown version */
		if (rp->pimver == AUTORP_PIM_V1 || rp->pimver == AUTORP_PIM_VUNKNOWN) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Ignoring unsupported PIM version (%u) in AutoRP Announcement for RP %pI4",
					   __func__, rp->pimver, (in_addr_t *)&(rp->addr));
			/* Update the offset to skip past the groups advertised for this RP */
			offset += (AUTORP_GRPLEN * rp->grpcnt);
			continue;
		}

		if (rp->grpcnt == 0) {
			/* No groups?? */
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Announcement message has no groups for RP %pI4",
					   __func__, (in_addr_t *)&(rp->addr));
			continue;
		}

		if ((buf_size - offset) < AUTORP_GRPLEN) {
			zlog_warn("%s: Buffer underrun parsing groups for RP %pI4", __func__,
				  (in_addr_t *)&(rp->addr));
			return false;
		}

		/* Store all announced RP's, calculate what to send in discovery when discovery is sent. */
		ma_rp = XCALLOC(MTYPE_PIM_AUTORP_RP, sizeof(struct pim_autorp_rp));
		memcpy(&(ma_rp->addr), &rp_addr, sizeof(pim_addr));
		trp = pim_autorp_rp_add(&(autorp->mapping_rp_list), ma_rp);
		if (trp == NULL) {
			/* RP was brand new, finish initializing */
			ma_rp->autorp = autorp;
			ma_rp->holdtime = holdtime;
			ma_rp->hold_timer = NULL;
			ma_rp->grplist[0] = '\0';
			memset(&(ma_rp->grp), 0, sizeof(ma_rp->grp));
			pim_autorp_grppfix_init(&ma_rp->grp_pfix_list);
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: New candidate RP learned (%pPA)", __func__,
					   &rp_addr);
		} else {
			/* Returned an existing entry, free allocated RP */
			XFREE(MTYPE_PIM_AUTORP_RP, ma_rp);
			ma_rp = trp;
			/* Free the existing group prefix list, in case the advertised groups changed */
			pim_autorp_grppfix_free(&ma_rp->grp_pfix_list);
		}

		/* Cancel any existing timer and restart it */
		event_cancel(&ma_rp->hold_timer);
		if (holdtime > 0)
			event_add_timer(router->master, autorp_ma_rp_holdtime, ma_rp,
					ma_rp->holdtime, &(ma_rp->hold_timer));

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: Parsing %u group(s) for candidate RP %pPA", __func__,
				   rp->grpcnt, &rp_addr);

		for (j = 0; j < rp->grpcnt; ++j) {
			/* grp is already pointing at the first group in the buffer */
			struct pim_autorp_grppfix *lgrp;
			struct pim_autorp_grppfix *tgrp;

			if ((buf_size - offset) < AUTORP_GRPLEN) {
				zlog_warn("%s: Failed parsing AutoRP announcement, RP(%pI4), invalid buffer size (%u < %u)",
					  __func__, &rp_addr, (uint32_t)(buf_size - offset),
					  AUTORP_GRPLEN);
				return false;
			}

			grp = (struct autorp_pkt_grp *)(buf + offset);
			offset += AUTORP_GRPLEN;

			lgrp = XCALLOC(MTYPE_PIM_AUTORP_GRPPFIX, sizeof(struct pim_autorp_grppfix));
			lgrp->grp.family = AF_INET;
			lgrp->grp.prefixlen = grp->masklen;
			lgrp->grp.u.prefix4.s_addr = grp->addr;
			lgrp->negative = grp->negprefix;

			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: %s%pFX added to candidate RP %pPA", __func__,
					   (lgrp->negative ? "!" : ""), &lgrp->grp, &rp_addr);

			tgrp = pim_autorp_grppfix_add(&ma_rp->grp_pfix_list, lgrp);
			if (tgrp != NULL) {
				/* This should never happen but if there was an existing entry just free the
				 * allocated group prefix
				 */
				if (PIM_DEBUG_AUTORP)
					zlog_debug("%s: %pFX was duplicated in AutoRP announcement",
						   __func__, &lgrp->grp);
				XFREE(MTYPE_PIM_AUTORP_GRPPFIX, lgrp);
			}
		}
	}

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP processed announcement message", __func__);
	return true;
}

static void autorp_cand_rp_holdtime(struct event *evt)
{
	/* RP hold time expired, remove the RP */
	struct pim_autorp_rp *rp = EVENT_ARG(evt);

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP hold time expired, RP removed: addr=%pI4, grp=%pFX, grplist=%s",
			   __func__, &rp->addr, &rp->grp,
			   (strlen(rp->grplist) ? rp->grplist : "NONE"));

	pim_autorp_rp_del(&(rp->autorp->discovery_rp_list), rp);
	pim_autorp_rp_free(rp, true);
}

static bool pim_autorp_add_rp(struct pim_autorp *autorp, pim_addr rpaddr, struct prefix grp,
			      char *listname, uint16_t holdtime)
{
	struct pim_autorp_rp *rp;
	struct pim_autorp_rp *trp = NULL;
	int ret;

	ret = pim_rp_new(autorp->pim, rpaddr, grp, listname, RP_SRC_AUTORP);

	/* There may not be a path to the RP right now, but that doesn't mean it failed to add the RP */
	if (ret != PIM_SUCCESS && ret != PIM_RP_NO_PATH) {
		zlog_warn("%s: Failed to add active RP addr=%pI4, grp=%pFX, grplist=%s", __func__,
			  &rpaddr, &grp, (listname ? listname : "NONE"));
		return false;
	}

	rp = XCALLOC(MTYPE_PIM_AUTORP_RP, sizeof(*rp));
	rp->autorp = autorp;
	memcpy(&(rp->addr), &rpaddr, sizeof(pim_addr));
	trp = pim_autorp_rp_add(&(autorp->discovery_rp_list), rp);
	if (trp == NULL) {
		/* RP was brand new */
		trp = pim_autorp_rp_find(&(autorp->discovery_rp_list),
					 (const struct pim_autorp_rp *)rp);
		/* Make sure the timer is NULL so the cancel below doesn't mess up */
		trp->hold_timer = NULL;
		zlog_info("%s: Added new AutoRP learned RP addr=%pI4, grp=%pFX, grplist=%s",
			  __func__, &rpaddr, &grp, (listname ? listname : "NONE"));
	} else {
		/* RP already existed, free the temp one */
		XFREE(MTYPE_PIM_AUTORP_RP, rp);
	}

	/* Cancel any existing timer before restarting it */
	event_cancel(&trp->hold_timer);
	trp->holdtime = holdtime;
	prefix_copy(&(trp->grp), &grp);
	if (listname)
		snprintf(trp->grplist, sizeof(trp->grplist), "%s", listname);
	else
		trp->grplist[0] = '\0';

	if (holdtime > 0) {
		event_add_timer(router->master, autorp_cand_rp_holdtime, trp, holdtime,
				&(trp->hold_timer));
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: Started %u second hold timer for RP %pI4", __func__,
				   holdtime, &trp->addr);
	}

	return true;
}

static size_t autorp_build_disc_rps(struct pim_autorp *autorp, uint8_t *buf, size_t buf_sz,
				    size_t *sz)
{
	/* Header has already been added, fill in starting with the address of RP1
	 *  buf_sz is the max size of the buf
	 *  sz is the current size of the packet, update as buf is filled
	 *  return the total number of RP's added
	 *
	 *
	 * We need to resolve the announced RP's following these rules:
	 *  1) Co-existence of longer and shorter group prefixes, from different RPs. E.g. when RP1
	 *     announces 224.2.*.*, and RP2 announces 224.2.2.*, both are accepted;
	 *  2) For announcements for identical group prefixes from two different RPs, the one from the
	 *     RP with the higher IP address is accepted;
	 *  3) No duplicates are sent to the AUTORP-DISCOVERY address. E.g. if an RP announces both
	 *     224.2.2.* and 224.2.*.*, the former group-prefix is not sent and only 224.2.*.* is sent
	 *     to the AUTORP-DISCOVERY address.
	 *
	 *
	 * The approach to resolution, first loop the stored RP's and extract the group prefixes, stored
	 * in a sorted list, sorted from least specific to most 0.0.0.0/0 -> 239.255.255.255/32. Each
	 * group prefix will then store the RP advertising that group prefix, this will resolve 2.
	 * The next step is to then loop the group prefix list and store them back into a list sorted by
	 * RP address, where the least specific group address will be stored, resolving 3. 1 is more
	 * about what is allowed, and in the example above the different prefixes will be unique in the
	 * list of group prefixes, and when they go back into RP's, they are also from different RP's
	 * and will therefore be sent.
	 */

	struct pim_autorp_rp *rp;
	struct pim_autorp_rp *trp;
	struct pim_autorp_grppfix *grp;
	struct pim_autorp_grppfix *grp2;
	struct pim_autorp_grppfix *tgrp;
	struct pim_autorp_grppfix_head grplist;
	bool skip = false;
	size_t rpcnt = 0;
	size_t bsz = 0;

	/* Initialize the lists, grplist is temporary, disc rp list is stored long term for
	 * show output, so make sure it's empty
	 */
	pim_autorp_grppfix_init(&grplist);
	pim_autorp_rplist_free(&autorp->advertised_rp_list, false);

	/* Loop the advertised RP's and their group prefixes and make a unique list of group prefixes,
	 * keeping just the highest IP RP for each group prefix
	 */
	frr_each (pim_autorp_rp, &autorp->mapping_rp_list, rp) {
		frr_each (pim_autorp_grppfix, &rp->grp_pfix_list, grp) {
			grp2 = XCALLOC(MTYPE_PIM_AUTORP_GRPPFIX, sizeof(struct pim_autorp_grppfix));
			prefix_copy(&grp2->grp, &grp->grp);
			grp2->negative = grp->negative;
			grp2->rp = rp->addr;
			tgrp = pim_autorp_grppfix_add(&grplist, grp2);
			if (tgrp != NULL) {
				/* Returned an existing entry. Use the highest RP addr and free allocated object */
				if (IPV4_ADDR_CMP(&tgrp->rp, &grp2->rp))
					tgrp->rp = grp2->rp;
				XFREE(MTYPE_PIM_AUTORP_GRPPFIX, grp2);
			}
		}
	}

	/* Now loop the unique group prefixes and put it back into an RP list */
	frr_each (pim_autorp_grppfix, &grplist, grp) {
		rp = XCALLOC(MTYPE_PIM_AUTORP_RP, sizeof(struct pim_autorp_rp));
		rp->addr = grp->rp;
		trp = pim_autorp_rp_add(&autorp->advertised_rp_list, rp);
		if (trp == NULL) {
			/* RP was brand new, finish initializing */
			rp->autorp = NULL;
			rp->holdtime = 0;
			rp->hold_timer = NULL;
			rp->grplist[0] = '\0';
			memset(&(rp->grp), 0, sizeof(rp->grp));
			pim_autorp_grppfix_init(&rp->grp_pfix_list);
		} else {
			/* Returned an existing entry, free allocated RP */
			XFREE(MTYPE_PIM_AUTORP_RP, rp);
			rp = trp;
		}

		/* Groups are in order from least specific to most, so go through the existing
		 * groups for this RP and see if the current group is within the prefix of one that
		 * is already in the list, if so, skip it, if not, add it
		 * If one is a positive match and the other is negative, then still include it.
		 */
		skip = false;
		frr_each (pim_autorp_grppfix, &rp->grp_pfix_list, grp2) {
			if (prefix_match(&grp2->grp, &grp->grp) && grp->negative == grp2->negative) {
				skip = true;
				break;
			}
		}

		if (skip)
			continue;

		/* add the group to the RP's group list */
		grp2 = XCALLOC(MTYPE_PIM_AUTORP_GRPPFIX, sizeof(struct pim_autorp_grppfix));
		prefix_copy(&grp2->grp, &grp->grp);
		grp2->negative = grp->negative;
		tgrp = pim_autorp_grppfix_add(&rp->grp_pfix_list, grp2);
		assert(tgrp == NULL);
	}

	/* Done with temporary group prefix list, so free and finish */
	pim_autorp_grppfix_free(&grplist);
	pim_autorp_grppfix_fini(&grplist);

	/* Now finally we can loop the disc rp list and build the packet */
	frr_each (pim_autorp_rp, &autorp->advertised_rp_list, rp) {
		struct autorp_pkt_rp *brp;
		struct autorp_pkt_grp *bgrp;
		size_t rp_sz;
		size_t grpcnt;

		grpcnt = pim_autorp_grppfix_count(&rp->grp_pfix_list);
		rp_sz = sizeof(struct autorp_pkt_rp) + (grpcnt * sizeof(struct autorp_pkt_grp));
		if (buf_sz < *sz + rp_sz) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Failed to pack AutoRP discovery packet, buffer overrun, (%u < %u)",
					   __func__, (uint32_t)buf_sz, (uint32_t)(*sz + rp_sz));
			break;
		}

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: Add RP %pI4 (grpcnt=%u) to discovery message", __func__,
				   &rp->addr, (uint32_t)grpcnt);

		rpcnt++;

		brp = (struct autorp_pkt_rp *)(buf + bsz);
		bsz += sizeof(struct autorp_pkt_rp);

		/* Since this is an in_addr, assume it's already the right byte order */
		brp->addr = rp->addr.s_addr;
		brp->pimver = AUTORP_PIM_V2;
		brp->reserved = 0;
		brp->grpcnt = grpcnt;

		frr_each (pim_autorp_grppfix, &rp->grp_pfix_list, grp) {
			bgrp = (struct autorp_pkt_grp *)(buf + bsz);
			bsz += sizeof(struct autorp_pkt_grp);

			bgrp->addr = grp->grp.u.prefix4.s_addr;
			bgrp->masklen = grp->grp.prefixlen;
			bgrp->negprefix = grp->negative;

			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Add group %s%pFX for RP %pI4 to discovery message",
					   __func__, (grp->negative ? "!" : ""), &grp->grp,
					   &rp->addr);
		}

		/* Update the size with this RP now that it is packed */
		*sz += bsz;
	}

	return rpcnt;
}

static size_t autorp_build_disc_packet(struct pim_autorp *autorp, uint8_t *buf, size_t buf_sz)
{
	size_t sz = 0;
	struct autorp_pkt_hdr *hdr;

	if (buf_sz >= AUTORP_HDRLEN) {
		hdr = (struct autorp_pkt_hdr *)buf;
		hdr->version = AUTORP_VERSION;
		hdr->type = AUTORP_DISCOVERY_TYPE;
		hdr->holdtime = htons(autorp->discovery_holdtime);
		hdr->reserved = 0;
		sz += AUTORP_HDRLEN;
		hdr->rpcnt = autorp_build_disc_rps(autorp, buf + sizeof(struct autorp_pkt_hdr),
						   (buf_sz - AUTORP_HDRLEN), &sz);
		if (hdr->rpcnt == 0)
			sz = 0;
	}
	return sz;
}

static void autorp_send_discovery(struct event *evt)
{
	struct pim_autorp *autorp = EVENT_ARG(evt);
	struct sockaddr_in discGrp;
	size_t disc_sz;
	size_t buf_sz = 65535;
	uint8_t buf[65535] = { 0 };

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP sending discovery info", __func__);

	/* Mark true, even if nothing is sent */
	autorp->mapping_agent_active = true;
	disc_sz = autorp_build_disc_packet(autorp, buf, buf_sz);

	if (disc_sz > 0) {
		discGrp.sin_family = AF_INET;
		discGrp.sin_port = htons(PIM_AUTORP_PORT);
		inet_pton(PIM_AF, PIM_AUTORP_DISCOVERY_GRP, &discGrp.sin_addr);

		if (setsockopt(autorp->sock, IPPROTO_IP, IP_MULTICAST_TTL,
			       &(autorp->discovery_scope), sizeof(autorp->discovery_scope)) == 0) {
			if (setsockopt(autorp->sock, IPPROTO_IP, IP_MULTICAST_IF,
				       &(autorp->mapping_agent_addrsel.run_addr),
				       sizeof(autorp->mapping_agent_addrsel.run_addr)) == 0) {
				if (sendto(autorp->sock, buf, disc_sz, 0,
					   (struct sockaddr *)&discGrp, sizeof(discGrp)) > 0) {
					if (PIM_DEBUG_AUTORP)
						zlog_debug("%s: AutoRP discovery message sent",
							   __func__);
				} else if (PIM_DEBUG_AUTORP)
					zlog_warn("%s: Failed to send AutoRP discovery message, errno=%d, %s",
						  __func__, errno, safe_strerror(errno));
			} else if (PIM_DEBUG_AUTORP)
				zlog_warn("%s: Failed to set Multicast Interface for sending AutoRP discovery message, errno=%d, %s",
					  __func__, errno, safe_strerror(errno));
		} else if (PIM_DEBUG_AUTORP)
			zlog_warn("%s: Failed to set Multicast TTL for sending AutoRP discovery message, errno=%d, %s",
				  __func__, errno, safe_strerror(errno));
	}

	/* Start the new timer for the entire send discovery interval */
	event_add_timer(router->master, autorp_send_discovery, autorp, autorp->discovery_interval,
			&(autorp->send_discovery_timer));
}

static void autorp_send_discovery_on(struct pim_autorp *autorp)
{
	int interval = 5;

	/* Send the first discovery shortly after being enabled.
	 * If the configured interval is less than 5 seconds, then just use that.
	 */
	if (interval > autorp->discovery_interval)
		interval = autorp->discovery_interval;

	if (autorp->send_discovery_timer)
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP discovery sending enabled in %u seconds", __func__,
				   interval);

	event_add_timer(router->master, autorp_send_discovery, autorp, interval,
			&(autorp->send_discovery_timer));
}

static void autorp_send_discovery_off(struct pim_autorp *autorp)
{
	if (autorp->send_discovery_timer)
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP discovery sending disabled", __func__);
	event_cancel(&(autorp->send_discovery_timer));
}

static bool autorp_recv_discovery(struct pim_autorp *autorp, uint8_t rpcnt, uint16_t holdtime,
				  char *buf, size_t buf_size, pim_addr src)
{
	int i, j;
	struct autorp_pkt_rp *rp;
	struct autorp_pkt_grp *grp;
	size_t offset = 0;
	pim_addr rp_addr;
	struct prefix grppfix = {};
	char plname[32];
	struct prefix_list *pl;
	struct prefix_list_entry *ple;
	int64_t seq = 1;
	bool success = true;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Received AutoRP discovery message (src=%pI4, rpcnt=%u, holdtime=%u)",
			   __func__, &src, rpcnt, holdtime);

	if (autorp->send_rp_discovery &&
	    (pim_addr_cmp(autorp->mapping_agent_addrsel.run_addr, src) < 0)) {
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP send discovery suppressed -- Discovery received with higher IP address",
				   __func__);

		/* Cancel the existing send timer and restart for 3X the send discovery interval */
		event_cancel(&(autorp->send_discovery_timer));
		event_add_timer(router->master, autorp_send_discovery, autorp,
				(autorp->discovery_interval * 3), &(autorp->send_discovery_timer));

		/* Clear the last sent discovery RP's, since it is no longer valid */
		pim_autorp_rplist_free(&autorp->advertised_rp_list, false);
		/* Unset flag indicating we are active */
		autorp->mapping_agent_active = false;
	}

	for (i = 0; i < rpcnt; ++i) {
		if ((buf_size - offset) < AUTORP_RPLEN) {
			zlog_warn("%s: Failed to parse AutoRP discovery message, invalid buffer size (%u < %u)",
				  __func__, (uint32_t)(buf_size - offset), AUTORP_RPLEN);
			return false;
		}

		rp = (struct autorp_pkt_rp *)(buf + offset);
		offset += AUTORP_RPLEN;

		rp_addr.s_addr = rp->addr;

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: Parsing RP %pI4 (grpcnt=%u)", __func__,
				   (in_addr_t *)&rp->addr, rp->grpcnt);

		/* Ignore RP's limited to PIM version 1 or with an unknown version */
		if (rp->pimver == AUTORP_PIM_V1 || rp->pimver == AUTORP_PIM_VUNKNOWN) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Ignoring unsupported PIM version in AutoRP Discovery for RP %pI4",
					   __func__, (in_addr_t *)&(rp->addr));
			/* Update the offset to skip past the groups advertised for this RP */
			offset += (AUTORP_GRPLEN * rp->grpcnt);
			continue;
		}

		if (rp->grpcnt == 0) {
			/* No groups?? */
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Discovery message has no groups for RP %pI4",
					   __func__, (in_addr_t *)&(rp->addr));
			continue;
		}

		/* Make sure there is enough buffer to parse all the groups */
		if ((buf_size - offset) < (AUTORP_GRPLEN * rp->grpcnt)) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Buffer underrun parsing groups for RP %pI4 (%u < %u)",
					   __func__, (in_addr_t *)&(rp->addr),
					   (uint32_t)(buf_size - offset),
					   (uint32_t)(AUTORP_GRPLEN * rp->grpcnt));
			return false;
		}

		/* Get the first group so we can check for a negative prefix */
		/* Don't add to offset yet to make the multiple group loop easier */
		grp = (struct autorp_pkt_grp *)(buf + offset);

		if (rp->grpcnt == 1 && grp->negprefix == 0) {
			/* Only one group with positive prefix, we can use the standard RP API */
			offset += AUTORP_GRPLEN;
			grppfix.family = AF_INET;
			grppfix.prefixlen = grp->masklen;
			grppfix.u.prefix4.s_addr = grp->addr;

			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Parsing group %s%pFX for RP %pI4", __func__,
					   (grp->negprefix ? "!" : ""), &grppfix,
					   (in_addr_t *)&rp->addr);

			if (!pim_autorp_add_rp(autorp, rp_addr, grppfix, NULL, holdtime))
				success = false;
		} else {
			/* More than one grp, or the only group is a negative prefix.
			 * Need to make a prefix list for this RP
			 */
			snprintfrr(plname, sizeof(plname), "__AUTORP_%pI4__", &rp_addr);
			pl = prefix_list_lookup(AFI_IP, plname);

			if (pl) {
				/* Existing prefix list found, delete it first */
				/* TODO: Instead of deleting completely, maybe we can just clear it and re-add entries */
				if (PIM_DEBUG_AUTORP)
					zlog_debug("%s: Found existing prefix list %s, replacing it",
						   __func__, plname);
				prefix_list_delete(pl);
			}

			/* Now get a new prefix list */
			pl = prefix_list_get(AFI_IP, 0, plname);

			for (j = 0; j < rp->grpcnt; ++j) {
				/* This will just set grp to the same pointer on the first loop, but offset will
				 * be updated correctly while parsing
				 */
				grp = (struct autorp_pkt_grp *)(buf + offset);
				offset += AUTORP_GRPLEN;

				ple = prefix_list_entry_new();
				ple->pl = pl;
				ple->seq = seq;
				seq += 5;
				memset(&ple->prefix, 0, sizeof(ple->prefix));
				prefix_list_entry_update_start(ple);
				ple->type = (grp->negprefix ? PREFIX_DENY : PREFIX_PERMIT);
				ple->prefix.family = AF_INET;
				ple->prefix.prefixlen = grp->masklen;
				ple->prefix.u.prefix4.s_addr = grp->addr;
				ple->any = false;
				ple->ge = 0;
				ple->le = 32;
				prefix_list_entry_update_finish(ple);

				if (PIM_DEBUG_AUTORP)
					zlog_debug("%s: Parsing group %s%pFX for RP %pI4", __func__,
						   (grp->negprefix ? "!" : ""), &ple->prefix,
						   (in_addr_t *)&rp->addr);
			}

			if (!pim_autorp_add_rp(autorp, rp_addr, grppfix, plname, holdtime))
				success = false;
		}
	}

	return success;
}

static bool autorp_recv_msg(struct pim_autorp *autorp, char *buf, size_t buf_size, pim_addr src)
{
	struct autorp_pkt_hdr *h;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Received AutoRP message", __func__);

	if (buf_size < AUTORP_HDRLEN) {
		zlog_warn("%s: Invalid AutoRP Header size (%u < %u)", __func__, (uint32_t)buf_size,
			  AUTORP_HDRLEN);
		return false;
	}

	h = (struct autorp_pkt_hdr *)buf;

	if (h->version != AUTORP_VERSION) {
		zlog_warn("%s: Unsupported AutoRP version (%u != %u)", __func__, h->version,
			  AUTORP_VERSION);
		return false;
	}

	if (h->type == AUTORP_ANNOUNCEMENT_TYPE)
		return autorp_recv_announcement(autorp, h->rpcnt, htons(h->holdtime),
						buf + AUTORP_HDRLEN, buf_size - AUTORP_HDRLEN);

	if (h->type == AUTORP_DISCOVERY_TYPE)
		return autorp_recv_discovery(autorp, h->rpcnt, htons(h->holdtime),
					     buf + AUTORP_HDRLEN, buf_size - AUTORP_HDRLEN, src);

	zlog_warn("%s: Unknown AutoRP message type (%u)", __func__, h->type);

	return false;
}

static void autorp_read(struct event *t);

static void autorp_read_on(struct pim_autorp *autorp)
{
	event_add_read(router->master, autorp_read, autorp, autorp->sock, &(autorp->read_event));
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket read enabled", __func__);
}

static void autorp_read_off(struct pim_autorp *autorp)
{
	event_cancel(&(autorp->read_event));
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket read disabled", __func__);
}

static void autorp_read(struct event *evt)
{
	struct pim_autorp *autorp = evt->arg;
	int fd = evt->u.fd;
	char buf[10000];
	int rd;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	pim_addr src;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Reading from AutoRP socket", __func__);

	while (1) {
		rd = pim_socket_recvfromto(fd, (uint8_t *)buf, sizeof(buf), &from, &fromlen, NULL,
					   NULL, NULL);
		if (rd <= 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;
			zlog_warn("%s: Failure reading rd=%d: fd=%d: errno=%d: %s", __func__, rd,
				  fd, errno, safe_strerror(errno));
			goto err;
		}

		if (from.ss_family == AF_INET)
			src.s_addr = ((struct sockaddr_in *)&from)->sin_addr.s_addr;
		else {
			zlog_warn("%s: AutoRP message is not IPV4", __func__);
			goto err;
		}

		if (!autorp_recv_msg(autorp, buf, rd, src))
			zlog_warn("%s: Failure parsing AutoRP message", __func__);
		/* Keep reading until would block */
	}

	/* No error, enable read again */
	autorp_read_on(autorp);

err:
	return;
}

static bool pim_autorp_socket_enable(struct pim_autorp *autorp)
{
	int fd;

	frr_with_privs (&pimd_privs) {
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		if (fd < 0) {
			zlog_warn("Could not create autorp socket: errno=%d: %s", errno,
				  safe_strerror(errno));
			return false;
		}

		if (!pim_autorp_setup(fd)) {
			zlog_warn("Could not setup autorp socket fd=%d: errno=%d: %s", fd, errno,
				  safe_strerror(errno));
			close(fd);
			return false;
		}
	}

	autorp->sock = fd;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket enabled (fd=%u)", __func__, fd);

	return true;
}

static bool pim_autorp_socket_disable(struct pim_autorp *autorp)
{
	if (close(autorp->sock)) {
		zlog_warn("Failure closing autorp socket: fd=%d errno=%d: %s", autorp->sock, errno,
			  safe_strerror(errno));
		return false;
	}

	autorp_read_off(autorp);
	autorp->sock = -1;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket disabled", __func__);

	return true;
}

static void autorp_send_announcement(struct event *evt)
{
	struct pim_autorp *autorp = EVENT_ARG(evt);
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct sockaddr_in announceGrp;

	announceGrp.sin_family = AF_INET;
	announceGrp.sin_port = htons(PIM_AUTORP_PORT);
	inet_pton(PIM_AF, PIM_AUTORP_ANNOUNCEMENT_GRP, &announceGrp.sin_addr);

	if (autorp->announce_pkt_sz >= MIN_AUTORP_PKT_SZ) {
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: Sending AutoRP announcement", __func__);

		if (setsockopt(autorp->sock, IPPROTO_IP, IP_MULTICAST_TTL,
			       &(autorp->announce_scope), sizeof(autorp->announce_scope)) < 0) {
			zlog_warn("%s: Failed to set Multicast TTL for sending AutoRP announcement message, errno=%d, %s",
				  __func__, errno, safe_strerror(errno));
			return;
		}

		FOR_ALL_INTERFACES (autorp->pim->vrf, ifp) {
			pim_ifp = ifp->info;
			/* Only send on active interfaces with full pim enabled, non-passive
			 * and have a primary address set.
			 */
			if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) && pim_ifp &&
			    pim_ifp->pim_enable && !pim_ifp->pim_passive_enable &&
			    !pim_addr_is_any(pim_ifp->primary_address)) {
				if (setsockopt(autorp->sock, IPPROTO_IP, IP_MULTICAST_IF,
					       &(pim_ifp->primary_address),
					       sizeof(pim_ifp->primary_address)) < 0) {
					zlog_warn("%s: Failed to set Multicast Interface for sending AutoRP announcement message, errno=%d, %s",
						  __func__, errno, safe_strerror(errno));
					continue;
				}

				if (sendto(autorp->sock, autorp->announce_pkt,
					   autorp->announce_pkt_sz, 0,
					   (struct sockaddr *)&announceGrp,
					   sizeof(announceGrp)) <= 0)
					zlog_warn("%s: Failed to send AutoRP announcement message, errno=%d, %s",
						  __func__, errno, safe_strerror(errno));
			}
		}
	}

	/* Start the new timer for the entire announce interval */
	event_add_timer(router->master, autorp_send_announcement, autorp, autorp->announce_interval,
			&(autorp->announce_timer));
}

static void autorp_announcement_on(struct pim_autorp *autorp)
{
	int interval = 5;

	/* Send the first announcement shortly after being enabled.
	 * If the configured interval is less than 5 seconds, then just use that.
	 */
	if (interval > autorp->announce_interval)
		interval = autorp->announce_interval;

	if (autorp->announce_timer == NULL)
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP announcement sending enabled", __func__);

	event_add_timer(router->master, autorp_send_announcement, autorp, interval,
			&(autorp->announce_timer));
}

static void autorp_announcement_off(struct pim_autorp *autorp)
{
	if (autorp->announce_timer != NULL)
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP announcement sending disabled", __func__);
	event_cancel(&(autorp->announce_timer));
}

/* Pack the groups of the RP
 *   rp - Pointer to the RP
 *   buf - Pointer to the buffer where to start packing groups
 *   returns - Total group count packed
 */
static uint8_t pim_autorp_new_announcement_rp_grps(struct pim_autorp_rp *rp, uint8_t *buf)
{
	struct autorp_pkt_grp *grpp = (struct autorp_pkt_grp *)buf;
	uint8_t cnt = 0;

	if (is_default_prefix(&(rp->grp))) {
		/* No group so pack from the prefix list
		 * The grplist should be set and the prefix list exist with at least one group address
		 */
		struct prefix_list *plist;
		struct prefix_list_entry *ple;

		plist = prefix_list_lookup(AFI_IP, rp->grplist);
		for (ple = plist->head; ple; ple = ple->next) {
			if (pim_addr_is_multicast(ple->prefix.u.prefix4) &&
			    ple->prefix.prefixlen >= 4) {
				grpp->addr = ple->prefix.u.prefix4.s_addr;
				grpp->masklen = ple->prefix.prefixlen;
				grpp->negprefix = (ple->type == PREFIX_PERMIT ? 0 : 1);
				grpp->reserved = 0;

				++cnt;
				grpp = (struct autorp_pkt_grp *)(buf +
								 (sizeof(struct autorp_pkt_grp) *
								  cnt));
			}
		}

		return cnt;
	}

	/* Only one of group or prefix list should be defined */
	grpp->addr = rp->grp.u.prefix4.s_addr;
	grpp->masklen = rp->grp.prefixlen;
	grpp->negprefix = 0;
	grpp->reserved = 0;
	return 1;
}

/* Pack a single candidate RP
 *   rp - Pointer to the RP to pack
 *   buf - Pointer to the buffer where to start packing the RP
 *   returns - Buffer pointer pointing to the start of the next RP
 */
static uint8_t *pim_autorp_new_announcement_rp(struct pim_autorp_rp *rp, uint8_t *buf)
{
	struct autorp_pkt_rp *brp = (struct autorp_pkt_rp *)buf;

	/* Since this is an in_addr, assume it's already the right byte order */
	brp->addr = rp->addr.s_addr;
	brp->pimver = AUTORP_PIM_V2;
	brp->reserved = 0;
	brp->grpcnt = pim_autorp_new_announcement_rp_grps(rp, buf + sizeof(struct autorp_pkt_rp));
	return buf + sizeof(struct autorp_pkt_rp) + (brp->grpcnt * sizeof(struct autorp_pkt_grp));
}

/* Pack the candidate RP's on the announcement packet
 *   autorp - Pointer to the AutoRP instance
 *   buf - Pointer to the buffer where to start packing the first RP
 *   bufsz - Output parameter to track size of packed bytes
 *   returns - Total count of RP's packed
 */
static int pim_autorp_new_announcement_rps(struct pim_autorp *autorp, uint8_t *buf, uint16_t *bufsz)
{
	int cnt = 0;
	struct pim_autorp_rp *rp;
	/* Keep the original buffer pointer to calculate final size after packing */
	uint8_t *obuf = buf;

	frr_each_safe (pim_autorp_rp, &(autorp->candidate_rp_list), rp) {
		/* We must have an rp address and either group or list in order to pack this RP,
		 * so skip this one
		 */
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: Evaluating AutoRP candidate %pI4, group range %pFX, group list %s",
				   __func__, &rp->addr, &rp->grp, rp->grplist);

		if (pim_addr_is_any(rp->addr) ||
		    (is_default_prefix(&rp->grp) && strlen(rp->grplist) == 0))
			continue;

		/* Make sure that either group prefix is set, or that the prefix list exists and has at
		 * least one valid multicast prefix in it. Only multicast prefixes will be used.
		 */
		if (is_default_prefix(&rp->grp)) {
			struct prefix_list *plist;
			struct prefix_list_entry *ple;

			plist = prefix_list_lookup(AFI_IP, rp->grplist);
			if (plist == NULL)
				continue;
			plist = prefix_list_lookup(AFI_IP, rp->grplist);
			for (ple = plist->head; ple; ple = ple->next) {
				if (pim_addr_is_multicast(ple->prefix.u.prefix4) &&
				    ple->prefix.prefixlen >= 4)
					break;
			}

			/* If we went through the entire list without finding a multicast prefix,
			 * then skip this RP
			 */
			if (ple == NULL)
				continue;
		}

		/* Now we know for sure we will pack this RP, so count it */
		++cnt;
		/* This will return the buffer pointer at the location to start packing the next RP */
		buf = pim_autorp_new_announcement_rp(rp, buf);

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP candidate %pI4 added to announcement", __func__,
				   &rp->addr);
	}

	if (cnt > 0)
		*bufsz = buf - obuf;

	return cnt;
}

/* Build the new announcement packet. If there is a packet to send, restart the send timer
 * with a short wait
 */
static void pim_autorp_new_announcement(struct pim_instance *pim)
{
	struct pim_autorp *autorp = pim->autorp;
	struct autorp_pkt_hdr *hdr;
	int32_t holdtime;

	/* First disable any existing send timer */
	autorp_announcement_off(autorp);

	/*
	 * First time building, allocate the space
	 * Allocate the max packet size of 65536 so we don't need to resize later.
	 * This should be ok since we are only allocating the memory once for a single packet
	 * (potentially per vrf)
	 */
	if (!autorp->announce_pkt)
		autorp->announce_pkt = XCALLOC(MTYPE_PIM_AUTORP_ANNOUNCE, 65536);

	autorp->announce_pkt_sz = 0;

	holdtime = autorp->announce_holdtime;
	if (holdtime == DEFAULT_AUTORP_ANNOUNCE_HOLDTIME)
		holdtime = autorp->announce_interval * 3;
	if (holdtime > UINT16_MAX)
		holdtime = UINT16_MAX;

	hdr = (struct autorp_pkt_hdr *)autorp->announce_pkt;
	hdr->version = AUTORP_VERSION;
	hdr->type = AUTORP_ANNOUNCEMENT_TYPE;
	hdr->holdtime = htons((uint16_t)holdtime);
	hdr->reserved = 0;
	hdr->rpcnt = pim_autorp_new_announcement_rps(autorp,
						     autorp->announce_pkt +
							     sizeof(struct autorp_pkt_hdr),
						     &(autorp->announce_pkt_sz));

	/* Still need to add on the size of the header */
	autorp->announce_pkt_sz += sizeof(struct autorp_pkt_hdr);

	/* Only turn on the announcement timer if we have a packet to send */
	if (autorp->announce_pkt_sz >= MIN_AUTORP_PKT_SZ)
		autorp_announcement_on(autorp);
}

void pim_autorp_prefix_list_update(struct pim_instance *pim, struct prefix_list *plist)
{
	struct pim_autorp_rp *rp = NULL;
	struct pim_autorp *autorp = NULL;

	autorp = pim->autorp;
	if (autorp == NULL)
		return;

	/* Search for a candidate RP using this prefix list */
	frr_each_safe (pim_autorp_rp, &(autorp->candidate_rp_list), rp) {
		if (strmatch(rp->grplist, plist->name))
			break;
	}

	/* If we broke out of the loop early because we found a match, then rebuild the announcement */
	if (rp != NULL)
		pim_autorp_new_announcement(pim);
}

bool pim_autorp_rm_candidate_rp(struct pim_instance *pim, pim_addr rpaddr)
{
	struct pim_autorp *autorp = pim->autorp;
	struct pim_autorp_rp *rp;
	struct pim_autorp_rp find = { .addr = rpaddr };

	rp = pim_autorp_rp_find(&(autorp->candidate_rp_list), (const struct pim_autorp_rp *)&find);
	if (!rp)
		return false;

	pim_autorp_rp_del(&(autorp->candidate_rp_list), rp);
	pim_autorp_rp_free(rp, false);
	pim_autorp_new_announcement(pim);
	return true;
}

void pim_autorp_add_candidate_rp_group(struct pim_instance *pim, pim_addr rpaddr,
				       struct prefix group)
{
	struct pim_autorp *autorp = pim->autorp;
	struct pim_autorp_rp *rp;
	struct pim_autorp_rp find = { .addr = rpaddr };

	rp = pim_autorp_rp_find(&(autorp->candidate_rp_list), (const struct pim_autorp_rp *)&find);
	if (!rp) {
		rp = XCALLOC(MTYPE_PIM_AUTORP_RP, sizeof(*rp));
		memset(rp, 0, sizeof(struct pim_autorp_rp));
		rp->autorp = autorp;
		memcpy(&(rp->addr), &rpaddr, sizeof(pim_addr));
		pim_autorp_rp_add(&(autorp->candidate_rp_list), rp);
	}

	apply_mask(&group);
	prefix_copy(&(rp->grp), &group);
	/* A new group prefix implies that any previous prefix list is now invalid */
	rp->grplist[0] = '\0';

	pim_autorp_new_announcement(pim);
}

bool pim_autorp_rm_candidate_rp_group(struct pim_instance *pim, pim_addr rpaddr, struct prefix group)
{
	struct pim_autorp *autorp = pim->autorp;
	struct pim_autorp_rp *rp;
	struct pim_autorp_rp find = { .addr = rpaddr };

	rp = pim_autorp_rp_find(&(autorp->candidate_rp_list), (const struct pim_autorp_rp *)&find);
	if (!rp)
		return false;

	memset(&(rp->grp), 0, sizeof(rp->grp));
	pim_autorp_new_announcement(pim);
	return true;
}

void pim_autorp_add_candidate_rp_plist(struct pim_instance *pim, pim_addr rpaddr, const char *plist)
{
	struct pim_autorp *autorp = pim->autorp;
	struct pim_autorp_rp *rp;
	struct pim_autorp_rp find = { .addr = rpaddr };

	rp = pim_autorp_rp_find(&(autorp->candidate_rp_list), (const struct pim_autorp_rp *)&find);
	if (!rp) {
		rp = XCALLOC(MTYPE_PIM_AUTORP_RP, sizeof(*rp));
		memset(rp, 0, sizeof(struct pim_autorp_rp));
		rp->autorp = autorp;
		memcpy(&(rp->addr), &rpaddr, sizeof(pim_addr));
		pim_autorp_rp_add(&(autorp->candidate_rp_list), rp);
	}

	snprintf(rp->grplist, sizeof(rp->grplist), "%s", plist);
	/* A new group prefix list implies that any previous group prefix is now invalid */
	memset(&(rp->grp), 0, sizeof(rp->grp));
	rp->grp.family = AF_INET;

	pim_autorp_new_announcement(pim);
}

bool pim_autorp_rm_candidate_rp_plist(struct pim_instance *pim, pim_addr rpaddr, const char *plist)
{
	struct pim_autorp *autorp = pim->autorp;
	struct pim_autorp_rp *rp;
	struct pim_autorp_rp find = { .addr = rpaddr };

	rp = pim_autorp_rp_find(&(autorp->candidate_rp_list), (const struct pim_autorp_rp *)&find);
	if (!rp)
		return false;

	rp->grplist[0] = '\0';
	pim_autorp_new_announcement(pim);
	return true;
}

void pim_autorp_announce_scope(struct pim_instance *pim, uint8_t scope)
{
	struct pim_autorp *autorp = pim->autorp;

	scope = (scope == 0 ? DEFAULT_AUTORP_ANNOUNCE_SCOPE : scope);
	if (autorp->announce_scope != scope) {
		autorp->announce_scope = scope;
		pim_autorp_new_announcement(pim);
	}
}

void pim_autorp_announce_interval(struct pim_instance *pim, uint16_t interval)
{
	struct pim_autorp *autorp = pim->autorp;

	interval = (interval == 0 ? DEFAULT_AUTORP_ANNOUNCE_INTERVAL : interval);
	if (autorp->announce_interval != interval) {
		autorp->announce_interval = interval;
		pim_autorp_new_announcement(pim);
	}
}

void pim_autorp_announce_holdtime(struct pim_instance *pim, int32_t holdtime)
{
	struct pim_autorp *autorp = pim->autorp;

	if (autorp->announce_holdtime != holdtime) {
		autorp->announce_holdtime = holdtime;
		pim_autorp_new_announcement(pim);
	}
}

void pim_autorp_send_discovery_apply(struct pim_autorp *autorp)
{
	if (!autorp->mapping_agent_addrsel.run || !autorp->send_rp_discovery) {
		autorp_send_discovery_off(autorp);
		return;
	}

	autorp_send_discovery_on(autorp);
}

void pim_autorp_add_ifp(struct interface *ifp)
{
	/* Add a new interface for autorp
	 *   When autorp is enabled, we must join the autorp groups on all
	 *   pim/multicast interfaces. When autorp first starts, if finds all
	 *   current multicast interfaces and joins on them. If a new interface
	 *   comes up or is configured for multicast after autorp is running, then
	 *   this method will add it for autorp->
	 * This is called even when adding a new pim interface that is not yet
	 * active, so make sure the check, it'll call in again once the interface is up.
	 */
	struct pim_instance *pim;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) && pim_ifp && pim_ifp->pim_enable) {
		pim = pim_ifp->pim;
		if (pim && pim->autorp && pim->autorp->do_discovery) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Adding interface %s to AutoRP, joining AutoRP groups",
					   __func__, ifp->name);
			if (!pim_autorp_join_groups(ifp))
				zlog_warn("Could not join AutoRP groups, errno=%d, %s", errno,
					  safe_strerror(errno));
		}
	}
}

void pim_autorp_rm_ifp(struct interface *ifp)
{
	/* Remove interface for autorp
	 *   When an interface is no longer enabled for multicast, or at all, then
	 *   we should leave the AutoRP groups on this interface.
	 */
	struct pim_instance *pim;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) && pim_ifp) {
		pim = pim_ifp->pim;
		if (pim && pim->autorp) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Removing interface %s from AutoRP, leaving AutoRP groups",
					   __func__, ifp->name);
			if (!pim_autorp_leave_groups(ifp))
				zlog_warn("Could not leave AutoRP groups, errno=%d, %s", errno,
					  safe_strerror(errno));
		}
	}
}

void pim_autorp_start_discovery(struct pim_instance *pim)
{
	struct interface *ifp;
	struct pim_autorp *autorp = pim->autorp;

	if (!autorp->do_discovery) {
		autorp->do_discovery = true;
		autorp_read_on(autorp);

		FOR_ALL_INTERFACES (autorp->pim->vrf, ifp) {
			pim_autorp_add_ifp(ifp);
		}

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP Discovery started", __func__);
	}
}

void pim_autorp_stop_discovery(struct pim_instance *pim)
{
	struct interface *ifp;
	struct pim_autorp *autorp = pim->autorp;

	if (autorp->do_discovery) {
		FOR_ALL_INTERFACES (autorp->pim->vrf, ifp) {
			pim_autorp_rm_ifp(ifp);
		}

		autorp->do_discovery = false;
		autorp_read_off(autorp);

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP Discovery stopped", __func__);
	}
}

void pim_autorp_init(struct pim_instance *pim)
{
	struct pim_autorp *autorp;

	autorp = XCALLOC(MTYPE_PIM_AUTORP, sizeof(*autorp));
	autorp->pim = pim;
	autorp->sock = -1;
	autorp->read_event = NULL;
	autorp->announce_timer = NULL;
	autorp->do_discovery = false;
	autorp->send_discovery_timer = NULL;
	autorp->send_rp_discovery = false;
	pim_autorp_rp_init(&(autorp->discovery_rp_list));
	pim_autorp_rp_init(&(autorp->candidate_rp_list));
	pim_autorp_rp_init(&(autorp->mapping_rp_list));
	pim_autorp_rp_init(&autorp->advertised_rp_list);
	autorp->announce_scope = DEFAULT_AUTORP_ANNOUNCE_SCOPE;
	autorp->announce_interval = DEFAULT_AUTORP_ANNOUNCE_INTERVAL;
	autorp->announce_holdtime = DEFAULT_AUTORP_ANNOUNCE_HOLDTIME;
	autorp->discovery_scope = DEFAULT_AUTORP_DISCOVERY_SCOPE;
	autorp->discovery_interval = DEFAULT_AUTORP_DISCOVERY_INTERVAL;
	autorp->discovery_holdtime = DEFAULT_AUTORP_DISCOVERY_HOLDTIME;
	cand_addrsel_clear(&(autorp->mapping_agent_addrsel));

	if (!pim_autorp_socket_enable(autorp)) {
		zlog_warn("%s: AutoRP failed to initialize", __func__);
		return;
	}

	pim->autorp = autorp;
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP Initialized", __func__);

	/* Start AutoRP discovery by default on startup */
	pim_autorp_start_discovery(pim);
}

void pim_autorp_finish(struct pim_instance *pim)
{
	struct pim_autorp *autorp = pim->autorp;

	autorp_read_off(autorp);
	autorp_announcement_off(autorp);
	autorp_send_discovery_off(autorp);
	pim_autorp_free(autorp);
	pim_autorp_socket_disable(autorp);
	XFREE(MTYPE_PIM_AUTORP, pim->autorp);

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP Finished", __func__);
}

int pim_autorp_config_write(struct pim_instance *pim, struct vty *vty)
{
	struct pim_autorp_rp *rp;
	struct pim_autorp *autorp = pim->autorp;
	int writes = 0;

	if (!autorp->do_discovery) {
		vty_out(vty, " no autorp discovery\n");
		++writes;
	}

	if (autorp->announce_interval != DEFAULT_AUTORP_ANNOUNCE_INTERVAL ||
	    autorp->announce_scope != DEFAULT_AUTORP_ANNOUNCE_SCOPE ||
	    autorp->announce_holdtime != DEFAULT_AUTORP_ANNOUNCE_HOLDTIME) {
		vty_out(vty, " autorp announce");
		if (autorp->announce_interval != DEFAULT_AUTORP_ANNOUNCE_INTERVAL)
			vty_out(vty, " interval %u", autorp->announce_interval);
		if (autorp->announce_scope != DEFAULT_AUTORP_ANNOUNCE_SCOPE)
			vty_out(vty, " scope %u", autorp->announce_scope);
		if (autorp->announce_holdtime != DEFAULT_AUTORP_ANNOUNCE_HOLDTIME)
			vty_out(vty, " holdtime %u", autorp->announce_holdtime);
		vty_out(vty, "\n");
		++writes;
	}

	frr_each_safe (pim_autorp_rp, &(autorp->candidate_rp_list), rp) {
		/* Only print candidate RP's that have all the information needed to be announced */
		if (pim_addr_is_any(rp->addr) ||
		    (is_default_prefix(&(rp->grp)) && strlen(rp->grplist) == 0))
			continue;

		vty_out(vty, " autorp announce %pI4", &(rp->addr));
		if (!is_default_prefix(&(rp->grp)))
			vty_out(vty, " %pFX", &(rp->grp));
		else
			vty_out(vty, " group-list %s", rp->grplist);
		vty_out(vty, "\n");
		++writes;
	}

	if (autorp->send_rp_discovery) {
		if (autorp->mapping_agent_addrsel.cfg_enable) {
			vty_out(vty, " autorp send-rp-discovery");
			switch (autorp->mapping_agent_addrsel.cfg_mode) {
			case CAND_ADDR_LO:
				break;
			case CAND_ADDR_ANY:
				vty_out(vty, " source any");
				break;
			case CAND_ADDR_IFACE:
				vty_out(vty, " source interface %s",
					autorp->mapping_agent_addrsel.cfg_ifname);
				break;
			case CAND_ADDR_EXPLICIT:
				vty_out(vty, " source address %pPA",
					&autorp->mapping_agent_addrsel.cfg_addr);
				break;
			}
			vty_out(vty, "\n");
			++writes;
		}

		if (autorp->discovery_interval != DEFAULT_AUTORP_DISCOVERY_INTERVAL ||
		    autorp->discovery_scope != DEFAULT_AUTORP_DISCOVERY_SCOPE ||
		    autorp->discovery_holdtime != DEFAULT_AUTORP_DISCOVERY_HOLDTIME) {
			vty_out(vty, " autorp send-rp-discovery");
			if (autorp->discovery_interval != DEFAULT_AUTORP_DISCOVERY_INTERVAL)
				vty_out(vty, " interval %u", autorp->discovery_interval);
			if (autorp->discovery_scope != DEFAULT_AUTORP_DISCOVERY_SCOPE)
				vty_out(vty, " scope %u", autorp->discovery_scope);
			if (autorp->discovery_holdtime != DEFAULT_AUTORP_DISCOVERY_HOLDTIME)
				vty_out(vty, " holdtime %u", autorp->discovery_holdtime);
			vty_out(vty, "\n");
			++writes;
		}
	}

	return writes;
}

static void pim_autorp_show_autorp_json(struct pim_autorp *autorp, const char *component,
					json_object *json, struct ttable *cand_table)
{
	struct pim_autorp_rp *rp;

	if (!component || strmatch(component, "discovery")) {
		json_object *disc_obj;

		disc_obj = json_object_new_object();
		json_object_boolean_add(disc_obj, "enabled", autorp->do_discovery);
		if (autorp->do_discovery) {
			json_object *rplist_obj;

			rplist_obj = json_object_new_object();
			frr_each (pim_autorp_rp, &(autorp->discovery_rp_list), rp) {
				json_object *rp_obj;
				json_object *grp_arr;

				rp_obj = json_object_new_object();
				json_object_string_addf(rp_obj, "rpAddress", "%pI4", &rp->addr);
				json_object_int_add(rp_obj, "holdtime", rp->holdtime);
				grp_arr = json_object_new_array();

				if (strlen(rp->grplist)) {
					struct prefix_list *pl;
					struct prefix_list_entry *ple;

					pl = prefix_list_lookup(AFI_IP, rp->grplist);
					if (pl == NULL)
						continue;

					for (ple = pl->head; ple != NULL; ple = ple->next) {
						json_object *grp_obj;

						grp_obj = json_object_new_object();
						json_object_boolean_add(grp_obj, "negative",
									ple->type == PREFIX_DENY);
						json_object_string_addf(grp_obj, "prefix", "%pFX",
									&ple->prefix);
						json_object_array_add(grp_arr, grp_obj);
					}
				} else {
					json_object *grp_obj;

					grp_obj = json_object_new_object();
					json_object_boolean_add(grp_obj, "negative", false);
					json_object_string_addf(grp_obj, "prefix", "%pFX", &rp->grp);
					json_object_array_add(grp_arr, grp_obj);
				}

				json_object_object_add(rp_obj, "groupRanges", grp_arr);
				json_object_object_addf(rplist_obj, rp_obj, "%pI4", &rp->addr);
			}
			json_object_object_add(disc_obj, "rpList", rplist_obj);
		}
		json_object_object_add(json, "discovery", disc_obj);
	}

	if (!component || strmatch(component, "candidate")) {
		json_object *announce_obj;

		announce_obj = json_object_new_object();
		json_object_boolean_add(announce_obj, "enabled",
					pim_autorp_rp_count(&autorp->candidate_rp_list) > 0);
		if (pim_autorp_rp_count(&autorp->candidate_rp_list) > 0) {
			json_object_int_add(announce_obj, "scope", autorp->announce_scope);
			json_object_int_add(announce_obj, "interval", autorp->announce_interval);
			json_object_int_add(announce_obj, "holdtime",
					    (autorp->announce_holdtime ==
							     DEFAULT_AUTORP_ANNOUNCE_HOLDTIME
						     ? (autorp->announce_interval * 3)
						     : autorp->announce_holdtime));
			json_object_object_add(announce_obj, "rpList",
					       ttable_json_with_json_text(cand_table, "sss",
									  "rpAddress|groupRange|prefixList"));
		}
		json_object_object_add(json, "announce", announce_obj);
	}

	if (!component || strmatch(component, "mapping-agent")) {
		json_object *adv_obj;

		adv_obj = json_object_new_object();
		json_object_boolean_add(adv_obj, "enabled", autorp->send_rp_discovery);
		if (autorp->send_rp_discovery) {
			json_object *rplist_obj;

			json_object_boolean_add(adv_obj, "active", autorp->mapping_agent_active);
			json_object_int_add(adv_obj, "scope", autorp->discovery_scope);
			json_object_int_add(adv_obj, "interval", autorp->discovery_interval);
			json_object_int_add(adv_obj, "holdtime", autorp->discovery_holdtime);
			switch (autorp->mapping_agent_addrsel.cfg_mode) {
			case CAND_ADDR_LO:
				json_object_string_add(adv_obj, "source", "loopback");
				break;
			case CAND_ADDR_ANY:
				json_object_string_add(adv_obj, "source", "any");
				break;
			case CAND_ADDR_IFACE:
				json_object_string_add(adv_obj, "source", "interface");
				json_object_string_add(adv_obj, "interface",
						       autorp->mapping_agent_addrsel.cfg_ifname);
				break;
			case CAND_ADDR_EXPLICIT:
				json_object_string_add(adv_obj, "source", "address");
				break;
			}
			json_object_string_addf(adv_obj, "address", "%pPA",
						&autorp->mapping_agent_addrsel.run_addr);

			rplist_obj = json_object_new_object();
			frr_each (pim_autorp_rp, &(autorp->advertised_rp_list), rp) {
				json_object *rp_obj;
				json_object *grp_arr;
				struct pim_autorp_grppfix *grppfix;

				rp_obj = json_object_new_object();
				json_object_string_addf(rp_obj, "rpAddress", "%pI4", &rp->addr);
				grp_arr = json_object_new_array();
				frr_each (pim_autorp_grppfix, &rp->grp_pfix_list, grppfix) {
					json_object *grp_obj;

					grp_obj = json_object_new_object();
					json_object_boolean_add(grp_obj, "negative",
								grppfix->negative);
					json_object_string_addf(grp_obj, "prefix", "%pFX",
								&grppfix->grp);
					json_object_array_add(grp_arr, grp_obj);
				}
				json_object_object_add(rp_obj, "groupRanges", grp_arr);
				json_object_object_addf(rplist_obj, rp_obj, "%pI4", &rp->addr);
			}
			json_object_object_add(adv_obj, "rpList", rplist_obj);
		}
		json_object_object_add(json, "mapping-agent", adv_obj);
	}
}

void pim_autorp_show_autorp(struct vty *vty, struct pim_instance *pim, const char *component,
			    json_object *json)
{
	struct pim_autorp *autorp = pim->autorp;
	struct pim_autorp_rp *rp;
	struct ttable *cand_table = NULL;
	struct ttable *adv_table = NULL;
	struct ttable *disc_table = NULL;
	char *tmp;

	if (autorp == NULL)
		return;

	/* We may use the candidate table in the json output, so prepare it first. */
	if (!component || strmatch(component, "candidate")) {
		cand_table = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(cand_table, "RP address|Group Range|Prefix-List");
		cand_table->style.cell.rpad = 2;
		cand_table->style.corner = '+';
		ttable_restyle(cand_table);

		frr_each (pim_autorp_rp, &(autorp->candidate_rp_list), rp) {
			if (strlen(rp->grplist))
				ttable_add_row(cand_table, "%pI4|%s|%s", &(rp->addr), "-",
					       rp->grplist);
			else
				ttable_add_row(cand_table, "%pI4|%pFX|%s", &(rp->addr), &(rp->grp),
					       "-");
		}
	}

	if (json) {
		pim_autorp_show_autorp_json(autorp, component, json, cand_table);
		if (cand_table)
			ttable_del(cand_table);
		return;
	}

	/* Prepare discovered RP's table. */
	if (!component || strmatch(component, "discovery")) {
		disc_table = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(disc_table, "RP address|Group Range");
		disc_table->style.cell.rpad = 2;
		disc_table->style.corner = '+';
		ttable_restyle(disc_table);

		frr_each (pim_autorp_rp, &(autorp->discovery_rp_list), rp) {
			if (strlen(rp->grplist)) {
				struct prefix_list *pl;
				struct prefix_list_entry *ple;
				bool first = true;

				pl = prefix_list_lookup(AFI_IP, rp->grplist);

				if (pl == NULL) {
					ttable_add_row(disc_table,
						       "%pI4|failed to find prefix list %s",
						       &(rp->addr), rp->grplist);
					continue;
				}

				for (ple = pl->head; ple != NULL; ple = ple->next) {
					if (first)
						ttable_add_row(disc_table, "%pI4|%s%pFX",
							       &(rp->addr),
							       (ple->type == PREFIX_DENY ? "!"
											 : " "),
							       &ple->prefix);
					else
						ttable_add_row(disc_table, "%s|%s%pFX", " ",
							       (ple->type == PREFIX_DENY ? "!"
											 : " "),
							       &ple->prefix);
					first = false;
				}
			} else
				ttable_add_row(disc_table, "%pI4| %pFX", &(rp->addr), &(rp->grp));
		}
	}

	/* Prepare discovery RP's table (mapping-agent). */
	if (!component || strmatch(component, "mapping-agent")) {
		adv_table = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(adv_table, "RP address|Group Range");
		adv_table->style.cell.rpad = 2;
		adv_table->style.corner = '+';
		ttable_restyle(adv_table);

		frr_each (pim_autorp_rp, &(autorp->advertised_rp_list), rp) {
			struct pim_autorp_grppfix *grppfix;
			bool first = true;

			frr_each (pim_autorp_grppfix, &rp->grp_pfix_list, grppfix) {
				if (first)
					ttable_add_row(adv_table, "%pI4|%s%pFX", &rp->addr,
						       grppfix->negative ? "!" : " ", &grppfix->grp);
				else
					ttable_add_row(adv_table, "%s|%s%pFX", " ",
						       grppfix->negative ? "!" : " ", &grppfix->grp);
				first = false;
			}
		}
	}

	if (!component || strmatch(component, "discovery")) {
		vty_out(vty, "AutoRP Discovery is %sabled\n", (autorp->do_discovery ? "en" : "dis"));
		if (autorp->do_discovery) {
			tmp = ttable_dump(disc_table, "\n");
			vty_out(vty, "\n");
			vty_out(vty, "Discovered RP's (count=%u)\n",
				(uint32_t)pim_autorp_rp_count(&autorp->discovery_rp_list));
			vty_out(vty, "%s\n", tmp);
			XFREE(MTYPE_TMP_TTABLE, tmp);
		} else
			vty_out(vty, "\n");
	}

	if (!component || strmatch(component, "candidate")) {
		vty_out(vty, "AutoRP Announcement is %sabled\n",
			(pim_autorp_rp_count(&autorp->candidate_rp_list) > 0 ? "en" : "dis"));
		if (pim_autorp_rp_count(&autorp->candidate_rp_list) > 0) {
			tmp = ttable_dump(cand_table, "\n");
			vty_out(vty, "  interval %us scope %u holdtime %us\n",
				autorp->announce_interval, autorp->announce_scope,
				(autorp->announce_holdtime == DEFAULT_AUTORP_ANNOUNCE_HOLDTIME
					 ? (autorp->announce_interval * 3)
					 : autorp->announce_holdtime));
			vty_out(vty, "\n");
			vty_out(vty, "Candidate RP's (count=%u)\n",
				(uint32_t)pim_autorp_rp_count(&autorp->candidate_rp_list));
			vty_out(vty, "%s\n", tmp);
			XFREE(MTYPE_TMP_TTABLE, tmp);
		} else
			vty_out(vty, "\n");
	}

	if (!component || strmatch(component, "mapping-agent")) {
		vty_out(vty, "AutoRP Mapping-Agent is %sabled\n",
			(autorp->send_rp_discovery ? "en" : "dis"));
		if (autorp->send_rp_discovery) {
			vty_out(vty, "  interval %us scope %u holdtime %us\n",
				autorp->discovery_interval, autorp->discovery_scope,
				autorp->discovery_holdtime);
			vty_out(vty, "  source %pPA", &autorp->mapping_agent_addrsel.run_addr);
			switch (autorp->mapping_agent_addrsel.cfg_mode) {
			case CAND_ADDR_LO:
				vty_out(vty, " (loopback)");
				break;
			case CAND_ADDR_ANY:
				vty_out(vty, " (any)");
				break;
			case CAND_ADDR_IFACE:
				vty_out(vty, " (interface %s)",
					autorp->mapping_agent_addrsel.cfg_ifname);
				break;
			case CAND_ADDR_EXPLICIT:
				vty_out(vty, " (explicit address)");
				break;
			}
			vty_out(vty, "\n");

			if (autorp->mapping_agent_active) {
				tmp = ttable_dump(adv_table, "\n");
				vty_out(vty, "\n");
				vty_out(vty, "Advertised RP's (count=%u)\n",
					(uint32_t)pim_autorp_rp_count(&autorp->advertised_rp_list));
				vty_out(vty, "%s\n", tmp);
				XFREE(MTYPE_TMP_TTABLE, tmp);
			} else
				vty_out(vty, "  Mapping agent is inactive\n");
		} else
			vty_out(vty, "\n");
	}

	if (cand_table)
		ttable_del(cand_table);
	if (adv_table)
		ttable_del(adv_table);
	if (disc_table)
		ttable_del(disc_table);
}
