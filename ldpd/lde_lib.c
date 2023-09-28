// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "log.h"
#include "rlfa.h"

#include "mpls.h"

static __inline int	 fec_compare(const struct fec *, const struct fec *);
static int	 lde_nbr_is_nexthop(struct fec_node *, struct lde_nbr *);
static void	 fec_free(void *);
static struct fec_node	 *fec_add(struct fec *fec);
static struct fec_nh	 *fec_nh_add(struct fec_node *, int, union ldpd_addr *,
			    ifindex_t, uint8_t, unsigned short);
static void	 fec_nh_del(struct fec_nh *);

RB_GENERATE(fec_tree, fec, entry, fec_compare)

struct fec_tree	 ft = RB_INITIALIZER(&ft);
struct event *gc_timer;

/* FEC tree functions */
void
fec_init(struct fec_tree *fh)
{
	RB_INIT(fec_tree, fh);
}

static __inline int
fec_compare(const struct fec *a, const struct fec *b)
{
	if (a->type < b->type)
		return (-1);
	if (a->type > b->type)
		return (1);

	switch (a->type) {
	case FEC_TYPE_IPV4:
		if (ntohl(a->u.ipv4.prefix.s_addr) < ntohl(b->u.ipv4.prefix.s_addr))
			return (-1);
		if (ntohl(a->u.ipv4.prefix.s_addr) > ntohl(b->u.ipv4.prefix.s_addr))
			return (1);
		if (a->u.ipv4.prefixlen < b->u.ipv4.prefixlen)
			return (-1);
		if (a->u.ipv4.prefixlen > b->u.ipv4.prefixlen)
			return (1);
		return (0);
	case FEC_TYPE_IPV6:
		if (memcmp(&a->u.ipv6.prefix, &b->u.ipv6.prefix,
		    sizeof(struct in6_addr)) < 0)
			return (-1);
		if (memcmp(&a->u.ipv6.prefix, &b->u.ipv6.prefix,
		    sizeof(struct in6_addr)) > 0)
			return (1);
		if (a->u.ipv6.prefixlen < b->u.ipv6.prefixlen)
			return (-1);
		if (a->u.ipv6.prefixlen > b->u.ipv6.prefixlen)
			return (1);
		return (0);
	case FEC_TYPE_PWID:
		if (a->u.pwid.type < b->u.pwid.type)
			return (-1);
		if (a->u.pwid.type > b->u.pwid.type)
			return (1);
		if (a->u.pwid.pwid < b->u.pwid.pwid)
			return (-1);
		if (a->u.pwid.pwid > b->u.pwid.pwid)
			return (1);
		if (ntohl(a->u.pwid.lsr_id.s_addr) < ntohl(b->u.pwid.lsr_id.s_addr))
			return (-1);
		if (ntohl(a->u.pwid.lsr_id.s_addr) > ntohl(b->u.pwid.lsr_id.s_addr))
			return (1);
		return (0);
	}

	return (-1);
}

struct fec *
fec_find(struct fec_tree *fh, struct fec *f)
{
	return (RB_FIND(fec_tree, fh, f));
}

int
fec_insert(struct fec_tree *fh, struct fec *f)
{
	if (RB_INSERT(fec_tree, fh, f) != NULL)
		return (-1);
	return (0);
}

int
fec_remove(struct fec_tree *fh, struct fec *f)
{
	if (RB_REMOVE(fec_tree, fh, f) == NULL) {
		log_warnx("%s failed for %s", __func__, log_fec(f));
		return (-1);
	}
	return (0);
}

void
fec_clear(struct fec_tree *fh, void (*free_cb)(void *))
{
	struct fec	*f;

	while (!RB_EMPTY(fec_tree, fh)) {
		f = RB_ROOT(fec_tree, fh);

		fec_remove(fh, f);
		free_cb(f);
	}
}

/* routing table functions */
static int
lde_nbr_is_nexthop(struct fec_node *fn, struct lde_nbr *ln)
{
	struct fec_nh		*fnh;

	LIST_FOREACH(fnh, &fn->nexthops, entry)
		if (lde_address_find(ln, fnh->af, &fnh->nexthop))
			return (1);

	return (0);
}

void
rt_dump(pid_t pid)
{
	struct fec		*f;
	struct fec_node		*fn;
	struct lde_map		*me;
	static struct ctl_rt	 rtctl;

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		if (fn->local_label == NO_LABEL &&
		    RB_EMPTY(lde_map_head, &fn->downstream))
			continue;

		memset(&rtctl, 0, sizeof(rtctl));
		switch (fn->fec.type) {
		case FEC_TYPE_IPV4:
			rtctl.af = AF_INET;
			rtctl.prefix.v4 = fn->fec.u.ipv4.prefix;
			rtctl.prefixlen = fn->fec.u.ipv4.prefixlen;
			break;
		case FEC_TYPE_IPV6:
			rtctl.af = AF_INET6;
			rtctl.prefix.v6 = fn->fec.u.ipv6.prefix;
			rtctl.prefixlen = fn->fec.u.ipv6.prefixlen;
			break;
		case FEC_TYPE_PWID:
			continue;
		}

		rtctl.local_label = fn->local_label;
		if (RB_EMPTY(lde_map_head, &fn->downstream)) {
			rtctl.in_use = 0;
			rtctl.nexthop.s_addr = INADDR_ANY;
			rtctl.remote_label = NO_LABEL;
			rtctl.no_downstream = 1;
		}
		lde_imsg_compose_ldpe(IMSG_CTL_SHOW_LIB_BEGIN, 0, pid, &rtctl,
		    sizeof(rtctl));

		RB_FOREACH(me, lde_map_head, &fn->upstream) {
			rtctl.nexthop = me->nexthop->id;
			lde_imsg_compose_ldpe(IMSG_CTL_SHOW_LIB_SENT, 0, pid,
			    &rtctl, sizeof(rtctl));
		}

		RB_FOREACH(me, lde_map_head, &fn->downstream) {
			rtctl.in_use = lde_nbr_is_nexthop(fn, me->nexthop);
			rtctl.nexthop = me->nexthop->id;
			rtctl.remote_label = me->map.label;
			lde_imsg_compose_ldpe(IMSG_CTL_SHOW_LIB_RCVD, 0, pid,
			    &rtctl, sizeof(rtctl));
		}
		lde_imsg_compose_ldpe(IMSG_CTL_SHOW_LIB_END, 0, pid, &rtctl,
		    sizeof(rtctl));
	}
}

void
fec_snap(struct lde_nbr *ln)
{
	struct fec	*f;
	struct fec_node	*fn;

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		if (fn->local_label == NO_LABEL)
			continue;

		lde_send_labelmapping(ln, fn, 0);
	}

	lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid, 0, NULL, 0);
}

static void
fec_free(void *arg)
{
	struct fec_node	*fn = arg;
	struct fec_nh	*fnh;

	while ((fnh = LIST_FIRST(&fn->nexthops))) {
		fec_nh_del(fnh);
		assert(fnh != LIST_FIRST(&fn->nexthops));
	}
	if (!RB_EMPTY(lde_map_head, &fn->downstream))
		log_warnx("%s: fec %s downstream list not empty", __func__,
		    log_fec(&fn->fec));
	if (!RB_EMPTY(lde_map_head, &fn->upstream))
		log_warnx("%s: fec %s upstream list not empty", __func__,
		    log_fec(&fn->fec));

	free(fn);
}

void
fec_tree_clear(void)
{
	fec_clear(&ft, fec_free);
}

static struct fec_node *
fec_add(struct fec *fec)
{
	struct fec_node	*fn;

	fn = calloc(1, sizeof(*fn));
	if (fn == NULL)
		fatal(__func__);

	fn->fec = *fec;
	fn->local_label = NO_LABEL;
	RB_INIT(lde_map_head, &fn->upstream);
	RB_INIT(lde_map_head, &fn->downstream);
	LIST_INIT(&fn->nexthops);

	if (fec->type == FEC_TYPE_PWID)
		fn->pw_remote_status = PW_FORWARDING;

	if (fec_insert(&ft, &fn->fec))
		log_warnx("failed to add %s to ft tree", log_fec(&fn->fec));

	return (fn);
}

struct fec_nh *
fec_nh_find(struct fec_node *fn, int af, union ldpd_addr *nexthop,
    ifindex_t ifindex, uint8_t route_type, unsigned short route_instance)
{
	struct fec_nh	*fnh;

	LIST_FOREACH(fnh, &fn->nexthops, entry)
		if (fnh->af == af &&
		    ldp_addrcmp(af, &fnh->nexthop, nexthop) == 0 &&
		    fnh->ifindex == ifindex &&
		    fnh->route_type == route_type &&
		    fnh->route_instance == route_instance)
			return (fnh);

	return (NULL);
}

static struct fec_nh *
fec_nh_add(struct fec_node *fn, int af, union ldpd_addr *nexthop,
    ifindex_t ifindex, uint8_t route_type, unsigned short route_instance)
{
	struct fec_nh	*fnh;

	fnh = calloc(1, sizeof(*fnh));
	if (fnh == NULL)
		fatal(__func__);

	fnh->af = af;
	fnh->nexthop = *nexthop;
	fnh->ifindex = ifindex;
	fnh->remote_label = NO_LABEL;
	fnh->route_type = route_type;
	fnh->route_instance = route_instance;
	LIST_INSERT_HEAD(&fn->nexthops, fnh, entry);

	return (fnh);
}

static void
fec_nh_del(struct fec_nh *fnh)
{
	LIST_REMOVE(fnh, entry);
	free(fnh);
}

void
lde_kernel_insert(struct fec *fec, int af, union ldpd_addr *nexthop,
    ifindex_t ifindex, uint8_t route_type, unsigned short route_instance,
    int connected, void *data)
{
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct iface		*iface;

	fn = (struct fec_node *)fec_find(&ft, fec);
	if (fn == NULL)
		fn = fec_add(fec);
	if (data)
		fn->data = data;

	fnh = fec_nh_find(fn, af, nexthop, ifindex, route_type, route_instance);
	if (fnh == NULL) {
		fnh = fec_nh_add(fn, af, nexthop, ifindex, route_type,
		    route_instance);
		/*
		 * Ordered Control: if not a connected route and not a route
		 * learned over an interface not running LDP and not a PW
		 * then mark to wait until we receive labelmap msg before
		 * installing in kernel and sending to peer
		 */
		iface = if_lookup(ldeconf, ifindex);
		if (CHECK_FLAG(ldeconf->flags, F_LDPD_ORDERED_CONTROL) &&
		    !connected && iface != NULL && fec->type != FEC_TYPE_PWID)
			SET_FLAG(fnh->flags, F_FEC_NH_DEFER);
	}

	SET_FLAG(fnh->flags, F_FEC_NH_NEW);
	if (connected)
		SET_FLAG(fnh->flags, F_FEC_NH_CONNECTED);
}

void
lde_kernel_remove(struct fec *fec, int af, union ldpd_addr *nexthop,
    ifindex_t ifindex, uint8_t route_type, unsigned short route_instance)
{
	struct fec_node		*fn;
	struct fec_nh		*fnh;

	fn = (struct fec_node *)fec_find(&ft, fec);
	if (fn == NULL)
		/* route lost */
		return;
	fnh = fec_nh_find(fn, af, nexthop, ifindex, route_type, route_instance);
	if (fnh == NULL)
		/* route lost */
		return;

	lde_send_delete_klabel(fn, fnh);
	fec_nh_del(fnh);
}

/*
 * Whenever a route is changed, zebra advertises its new version without
 * withdrawing the old one. So, after processing a ZEBRA_REDISTRIBUTE_IPV[46]_ADD
 * message, we need to check for nexthops that were removed and, for each of
 * them (if any), withdraw the associated labels from zebra.
 */
void
lde_kernel_update(struct fec *fec)
{
	struct fec_node		*fn;
	struct fec_nh		*fnh, *safe;
	struct lde_nbr		*ln;
	struct lde_map		*me;
	struct iface		*iface;

	fn = (struct fec_node *)fec_find(&ft, fec);
	if (fn == NULL)
		return;

	LIST_FOREACH_SAFE(fnh, &fn->nexthops, entry, safe) {
		if (CHECK_FLAG(fnh->flags, F_FEC_NH_NEW)) {
			UNSET_FLAG(fnh->flags, F_FEC_NH_NEW);
			/*
			 * if LDP configured on interface or a static route
			 * clear flag else treat fec as a connected route
			 */
			if (CHECK_FLAG(ldeconf->flags, F_LDPD_ENABLED)) {
				iface = if_lookup(ldeconf,fnh->ifindex);
				if (CHECK_FLAG(fnh->flags, F_FEC_NH_CONNECTED) ||
				    iface ||
				    fnh->route_type == ZEBRA_ROUTE_STATIC)
					UNSET_FLAG(fnh->flags, F_FEC_NH_NO_LDP);
				else
					SET_FLAG(fnh->flags, F_FEC_NH_NO_LDP);
			} else
				SET_FLAG(fnh->flags, F_FEC_NH_NO_LDP);
		} else {
			lde_send_delete_klabel(fn, fnh);
			fec_nh_del(fnh);
		}
	}

	if (LIST_EMPTY(&fn->nexthops)) {
		RB_FOREACH(ln, nbr_tree, &lde_nbrs)
			lde_send_labelwithdraw(ln, fn, NULL, NULL);
		fn->data = NULL;

		/*
		 * Do not deallocate the local label now, do that only in the
		 * LIB garbage collector. This will prevent ldpd from changing
		 * the input label of some prefixes too often when running on
		 * an unstable network. Also, restart the garbage collector
		 * timer so that labels are deallocated only when the network
		 * is stabilized.
		 */
		lde_gc_start_timer();
	} else {
		fn->local_label = lde_update_label(fn);
		if (fn->local_label != NO_LABEL)
			/* FEC.1: perform lsr label distribution procedure */
			RB_FOREACH(ln, nbr_tree, &lde_nbrs)
				lde_send_labelmapping(ln, fn, 1);
	}

	/* if no label created yet then don't try to program labeled route */
	if (fn->local_label == NO_LABEL)
		return;

	LIST_FOREACH(fnh, &fn->nexthops, entry) {
		lde_send_change_klabel(fn, fnh);

		switch (fn->fec.type) {
		case FEC_TYPE_IPV4:
		case FEC_TYPE_IPV6:
			ln = lde_nbr_find_by_addr(fnh->af, &fnh->nexthop);
			break;
		case FEC_TYPE_PWID:
			ln = lde_nbr_find_by_lsrid(fn->fec.u.pwid.lsr_id);
			break;
		default:
			ln = NULL;
			break;
		}

		if (ln) {
			/* FEC.2  */
			me = (struct lde_map *)fec_find(&ln->recv_map, &fn->fec);
			if (me)
				/* FEC.5 */
				lde_check_mapping(&me->map, ln, 0);
		}
	}
}

void
lde_check_mapping(struct map *map, struct lde_nbr *ln, int rcvd_label_mapping)
{
	struct fec		 fec;
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct lde_req		*lre;
	struct lde_map		*me;
	struct l2vpn_pw		*pw;
	bool			 send_map = false;

	lde_map2fec(map, ln->id, &fec);

	switch (fec.type) {
	case FEC_TYPE_IPV4:
		if (lde_acl_check(ldeconf->ipv4.acl_label_accept_from,
		    AF_INET, (union ldpd_addr *)&ln->id, 32) != FILTER_PERMIT)
			return;
		if (lde_acl_check(ldeconf->ipv4.acl_label_accept_for,
		    AF_INET, (union ldpd_addr *)&fec.u.ipv4.prefix,
		    fec.u.ipv4.prefixlen) != FILTER_PERMIT)
			return;
		break;
	case FEC_TYPE_IPV6:
		if (lde_acl_check(ldeconf->ipv6.acl_label_accept_from,
		    AF_INET, (union ldpd_addr *)&ln->id, 32) != FILTER_PERMIT)
			return;
		if (lde_acl_check(ldeconf->ipv6.acl_label_accept_for,
		    AF_INET6, (union ldpd_addr *)&fec.u.ipv6.prefix,
		    fec.u.ipv6.prefixlen) != FILTER_PERMIT)
			return;
		break;
	case FEC_TYPE_PWID:
		break;
	}

	fn = (struct fec_node *)fec_find(&ft, &fec);
	if (fn == NULL)
		fn = fec_add(&fec);

	/* LMp.1: first check if we have a pending request running */
	lre = (struct lde_req *)fec_find(&ln->sent_req, &fn->fec);
	if (lre)
		/* LMp.2: delete record of outstanding label request */
		lde_req_del(ln, lre, 1);

	/* RFC 4447 control word and status tlv negotiation */
	if (map->type == MAP_TYPE_PWID && l2vpn_pw_negotiate(ln, fn, map)) {
		if (rcvd_label_mapping && CHECK_FLAG(map->flags, F_MAP_PW_STATUS))
			fn->pw_remote_status = map->pw_status;

		return;
	}

	/*
	 * LMp.3 - LMp.8: loop detection - unnecessary for frame-mode
	 * mpls networks.
	 */

	/* LMp.9 */
	me = (struct lde_map *)fec_find(&ln->recv_map, &fn->fec);
	if (me) {
		/* LMp.10 */
		if (me->map.label != map->label && lre == NULL) {
			/* LMp.10a */
			lde_send_labelrelease(ln, fn, NULL, me->map.label);

			/*
			 * Can not use lde_nbr_find_by_addr() because there's
			 * the possibility of multipath.
			 */
			LIST_FOREACH(fnh, &fn->nexthops, entry) {
				if (lde_address_find(ln, fnh->af, &fnh->nexthop) == NULL)
					continue;

				lde_send_delete_klabel(fn, fnh);
				fnh->remote_label = NO_LABEL;
			}
		}
	}

	/*
	 * LMp.11 - 12: consider multiple nexthops in order to
	 * support multipath
	 */
	LIST_FOREACH(fnh, &fn->nexthops, entry) {
		/* LMp.15: install FEC in FIB */
		switch (fec.type) {
		case FEC_TYPE_IPV4:
		case FEC_TYPE_IPV6:
			if (!lde_address_find(ln, fnh->af, &fnh->nexthop))
				continue;

			/*
			 * Ordered Control: labelmap msg received from
			 * NH so clear flag and send labelmap msg to
			 * peer
			 */
			if (CHECK_FLAG(ldeconf->flags, F_LDPD_ORDERED_CONTROL)) {
				send_map = true;
				UNSET_FLAG(fnh->flags, F_FEC_NH_DEFER);
			}
			fnh->remote_label = map->label;
			if (fn->local_label != NO_LABEL)
				lde_send_change_klabel(fn, fnh);
			break;
		case FEC_TYPE_PWID:
			pw = (struct l2vpn_pw *) fn->data;
			if (pw == NULL)
				continue;

			pw->remote_group = map->fec.pwid.group_id;
			if (CHECK_FLAG(map->flags, F_MAP_PW_IFMTU))
				pw->remote_mtu = map->fec.pwid.ifmtu;
			if (rcvd_label_mapping && CHECK_FLAG(map->flags, F_MAP_PW_STATUS)) {
				pw->remote_status = map->pw_status;
				fn->pw_remote_status = map->pw_status;
			}
			else
				pw->remote_status = PW_FORWARDING;
			fnh->remote_label = map->label;
			if (l2vpn_pw_ok(pw, fnh))
				lde_send_change_klabel(fn, fnh);
			break;
		default:
			break;
		}
	}

	/* Update RLFA clients. */
	lde_rlfa_update_clients(&fec, ln, map->label);

	/* LMp.13 & LMp.16: Record the mapping from this peer */
	if (me == NULL)
		me = lde_map_add(ln, fn, 0);
	me->map = *map;

	/*
	 * LMp.17 - LMp.27 are unnecessary since we don't need to implement
	 * loop detection. LMp.28 - LMp.30 are unnecessary because we are
	 * merging capable.
	 */

	/*
	 * Ordered Control: just received a labelmap for this fec from NH so
	 * need to send labelmap to all peers
	 * LMp.20 - LMp21 Execute procedure to send Label Mapping
	 */
	if (send_map && fn->local_label != NO_LABEL)
		RB_FOREACH(ln, nbr_tree, &lde_nbrs)
			lde_send_labelmapping(ln, fn, 1);
}

void
lde_check_request(struct map *map, struct lde_nbr *ln)
{
	struct fec	 fec;
	struct lde_req	*lre;
	struct fec_node	*fn;
	struct fec_nh	*fnh;

	/* wildcard label request */
	if (map->type == MAP_TYPE_TYPED_WCARD) {
		lde_check_request_wcard(map, ln);
		return;
	}

	/* LRq.1: skip loop detection (not necessary) */

	/* LRq.2: is there a next hop for fec? */
	lde_map2fec(map, ln->id, &fec);
	fn = (struct fec_node *)fec_find(&ft, &fec);
	if (fn == NULL || LIST_EMPTY(&fn->nexthops)) {
		/* LRq.5: send No Route notification */
		lde_send_notification(ln, S_NO_ROUTE, map->msg_id,
		    htons(MSG_TYPE_LABELREQUEST));
		return;
	}

	/* LRq.3: is MsgSource the next hop? */
	LIST_FOREACH(fnh, &fn->nexthops, entry) {
		switch (fec.type) {
		case FEC_TYPE_IPV4:
		case FEC_TYPE_IPV6:
			if (!lde_address_find(ln, fnh->af, &fnh->nexthop))
				continue;

			/* LRq.4: send Loop Detected notification */
			lde_send_notification(ln, S_LOOP_DETECTED, map->msg_id,
			    htons(MSG_TYPE_LABELREQUEST));
			return;
		case FEC_TYPE_PWID:
			break;
		}
	}

	/* LRq.6: first check if we have a pending request running */
	lre = (struct lde_req *)fec_find(&ln->recv_req, &fn->fec);
	if (lre != NULL)
		/* LRq.7: duplicate request */
		return;

	/* LRq.8: record label request */
	lre = lde_req_add(ln, &fn->fec, 0);
	if (lre != NULL)
		lre->msg_id = ntohl(map->msg_id);

	/* LRq.9: perform LSR label distribution */
	lde_send_labelmapping(ln, fn, 1);

	/*
	 * LRq.10: do nothing (Request Never) since we use liberal
	 * label retention.
	 * LRq.11 - 12 are unnecessary since we are merging capable.
	 */
}

void
lde_check_request_wcard(struct map *map, struct lde_nbr *ln)
{
	struct fec	*f;
	struct fec_node	*fn;
	struct lde_req	*lre;

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;

		/* only a typed wildcard is possible here */
		if (lde_wildcard_apply(map, &fn->fec, NULL) == 0)
			continue;

		/* LRq.2: is there a next hop for fec? */
		if (LIST_EMPTY(&fn->nexthops))
			continue;

		/* LRq.6: first check if we have a pending request running */
		lre = (struct lde_req *)fec_find(&ln->recv_req, &fn->fec);
		if (lre != NULL)
			/* LRq.7: duplicate request */
			continue;

		/* LRq.8: record label request */
		lre = lde_req_add(ln, &fn->fec, 0);
		if (lre != NULL)
			lre->msg_id = ntohl(map->msg_id);

		/* LRq.9: perform LSR label distribution */
		lde_send_labelmapping(ln, fn, 1);
	}
}

void
lde_check_release(struct map *map, struct lde_nbr *ln)
{
	struct fec		 fec;
	struct fec_node		*fn;
	struct lde_wdraw	*lw;
	struct lde_map		*me;
	struct fec		*pending_map;

	/* wildcard label release */
	if (map->type == MAP_TYPE_WILDCARD ||
	    map->type == MAP_TYPE_TYPED_WCARD ||
	    (map->type == MAP_TYPE_PWID && !CHECK_FLAG(map->flags, F_MAP_PW_ID))) {
		lde_check_release_wcard(map, ln);
		return;
	}

	lde_map2fec(map, ln->id, &fec);
	fn = (struct fec_node *)fec_find(&ft, &fec);
	/* LRl.1: does FEC match a known FEC? */
	if (fn == NULL)
		return;

	/* LRl.6: check sent map list and remove it if available */
	me = (struct lde_map *)fec_find(&ln->sent_map, &fn->fec);
	if (me && (map->label == NO_LABEL || map->label == me->map.label))
		lde_map_del(ln, me, 1);

	/* LRl.3: first check if we have a pending withdraw running */
	lw = (struct lde_wdraw *)fec_find(&ln->sent_wdraw, &fn->fec);
	if (lw && (map->label == NO_LABEL || map->label == lw->label)) {
		/* LRl.4: delete record of outstanding label withdraw */
		lde_wdraw_del(ln, lw);

		/* send pending label mapping if any */
		pending_map = fec_find(&ln->sent_map_pending, &fn->fec);
		if (pending_map) {
			lde_send_labelmapping(ln, fn, 1);
			lde_map_pending_del(ln, pending_map);
		}
	}

	/*
	 * LRl.11 - 13 are unnecessary since we remove the label from
	 * forwarding/switching as soon as the FEC is unreachable.
	 */
}

void
lde_check_release_wcard(struct map *map, struct lde_nbr *ln)
{
	struct fec		*f;
	struct fec_node		*fn;
	struct lde_wdraw	*lw;
	struct lde_map		*me;
	struct fec		*pending_map;

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		me = (struct lde_map *)fec_find(&ln->sent_map, &fn->fec);

		/* LRl.1: does FEC match a known FEC? */
		if (lde_wildcard_apply(map, &fn->fec, me) == 0)
			continue;

		/* LRl.6: check sent map list and remove it if available */
		if (me &&
		    (map->label == NO_LABEL || map->label == me->map.label))
			lde_map_del(ln, me, 1);

		/* LRl.3: first check if we have a pending withdraw running */
		lw = (struct lde_wdraw *)fec_find(&ln->sent_wdraw, &fn->fec);
		if (lw && (map->label == NO_LABEL || map->label == lw->label)) {
			/* LRl.4: delete record of outstanding lbl withdraw */
			lde_wdraw_del(ln, lw);

			/* send pending label mapping if any */
			pending_map = fec_find(&ln->sent_map_pending, &fn->fec);
			if (pending_map) {
				lde_send_labelmapping(ln, fn, 1);
				lde_map_pending_del(ln, pending_map);
			}
		}

		/*
		 * LRl.11 - 13 are unnecessary since we remove the label from
		 * forwarding/switching as soon as the FEC is unreachable.
		 */
	}
}

void
lde_check_withdraw(struct map *map, struct lde_nbr *ln)
{
	struct fec		 fec;
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct lde_map		*me;
	struct l2vpn_pw		*pw;
	struct lde_nbr		*lnbr;

	/* wildcard label withdraw */
	if (map->type == MAP_TYPE_WILDCARD ||
	    map->type == MAP_TYPE_TYPED_WCARD ||
	    (map->type == MAP_TYPE_PWID && !CHECK_FLAG(map->flags, F_MAP_PW_ID))) {
		lde_check_withdraw_wcard(map, ln);
		return;
	}

	lde_map2fec(map, ln->id, &fec);
	fn = (struct fec_node *)fec_find(&ft, &fec);
	if (fn == NULL)
		fn = fec_add(&fec);

	/* LWd.1: remove label from forwarding/switching use */
	LIST_FOREACH(fnh, &fn->nexthops, entry) {
		switch (fec.type) {
		case FEC_TYPE_IPV4:
		case FEC_TYPE_IPV6:
			if (!lde_address_find(ln, fnh->af, &fnh->nexthop))
				continue;
			break;
		case FEC_TYPE_PWID:
			pw = (struct l2vpn_pw *) fn->data;
			if (pw == NULL)
				continue;
			pw->remote_status = PW_NOT_FORWARDING;
			break;
		default:
			break;
		}
		if (map->label != NO_LABEL && map->label != fnh->remote_label)
			continue;

		lde_send_delete_klabel(fn, fnh);
		fnh->remote_label = NO_LABEL;
	}

	/* Update RLFA clients. */
	lde_rlfa_update_clients(&fec, ln, MPLS_INVALID_LABEL);

	/* LWd.2: send label release */
	lde_send_labelrelease(ln, fn, NULL, map->label);

	/* LWd.3: check previously received label mapping */
	me = (struct lde_map *)fec_find(&ln->recv_map, &fn->fec);
	if (me && (map->label == NO_LABEL || map->label == me->map.label))
		/* LWd.4: remove record of previously received lbl mapping */
		lde_map_del(ln, me, 0);
	else
		/* LWd.13 done */
		return;

	/* Ordered Control: additional withdraw steps */
	if (CHECK_FLAG(ldeconf->flags, F_LDPD_ORDERED_CONTROL)) {
		/* LWd.8: for each neighbor other that src of withdraw msg */
		RB_FOREACH(lnbr, nbr_tree, &lde_nbrs) {
			if (ln->peerid == lnbr->peerid)
				continue;

			/* LWd.9: check if previously sent a label mapping */
			me = (struct lde_map *)fec_find(&lnbr->sent_map, &fn->fec);

			/*
			 * LWd.10: does label sent to peer "map" to withdraw
			 * label
			 */
			if (me && lde_nbr_is_nexthop(fn, lnbr))
				/* LWd.11: send label withdraw */
				lde_send_labelwithdraw(lnbr, fn, NULL, NULL);
		}
	}

}

void
lde_check_withdraw_wcard(struct map *map, struct lde_nbr *ln)
{
	struct fec	*f;
	struct fec_node	*fn;
	struct fec_nh	*fnh;
	struct lde_map	*me;
	struct l2vpn_pw	*pw;
	struct lde_nbr  *lnbr;

	/* LWd.2: send label release */
	lde_send_labelrelease(ln, NULL, map, map->label);

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		me = (struct lde_map *)fec_find(&ln->recv_map, &fn->fec);

		if (lde_wildcard_apply(map, &fn->fec, me) == 0)
			continue;

		/* LWd.1: remove label from forwarding/switching use */
		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			switch (f->type) {
			case FEC_TYPE_IPV4:
			case FEC_TYPE_IPV6:
				if (!lde_address_find(ln, fnh->af, &fnh->nexthop))
					continue;
				break;
			case FEC_TYPE_PWID:
				if (f->u.pwid.lsr_id.s_addr != ln->id.s_addr)
					continue;
				pw = (struct l2vpn_pw *) fn->data;
				if (pw)
					pw->remote_status = PW_NOT_FORWARDING;
				break;
			default:
				break;
			}
			if (map->label != NO_LABEL && map->label != fnh->remote_label)
				continue;

			lde_send_delete_klabel(fn, fnh);
			fnh->remote_label = NO_LABEL;
		}

		/* Update RLFA clients. */
		lde_rlfa_update_clients(f, ln, MPLS_INVALID_LABEL);

		/* LWd.3: check previously received label mapping */
		if (me && (map->label == NO_LABEL || map->label == me->map.label))
			/*
			 * LWd.4: remove record of previously received
			 * label mapping
			 */
			lde_map_del(ln, me, 0);
		else
			/* LWd.13 done */
			continue;

		/* Ordered Control: additional withdraw steps */
		if (CHECK_FLAG(ldeconf->flags, F_LDPD_ORDERED_CONTROL)) {
			/*
			 * LWd.8: for each neighbor other that src of
			 *  withdraw msg
			 */
			RB_FOREACH(lnbr, nbr_tree, &lde_nbrs) {
				if (ln->peerid == lnbr->peerid)
					continue;

				/* LWd.9: check if previously sent a label
				 * mapping
				 */
				me = (struct lde_map *)fec_find(&lnbr->sent_map, &fn->fec);
				/*
				 * LWd.10: does label sent to peer "map" to
				 *  withdraw label
				 */
				if (me && lde_nbr_is_nexthop(fn, lnbr))
					/* LWd.11: send label withdraw */
					lde_send_labelwithdraw(lnbr, fn, NULL, NULL);
			}
		}
	}
}

int
lde_wildcard_apply(struct map *wcard, struct fec *fec, struct lde_map *me)
{
	switch (wcard->type) {
	case MAP_TYPE_WILDCARD:
		/* full wildcard */
		return (1);
	case MAP_TYPE_TYPED_WCARD:
		switch (wcard->fec.twcard.type) {
		case MAP_TYPE_PREFIX:
			if (wcard->fec.twcard.u.prefix_af == AF_INET &&
			    fec->type != FEC_TYPE_IPV4)
				return (0);
			if (wcard->fec.twcard.u.prefix_af == AF_INET6 &&
			    fec->type != FEC_TYPE_IPV6)
				return (0);
			return (1);
		case MAP_TYPE_PWID:
			if (fec->type != FEC_TYPE_PWID)
				return (0);
			if (wcard->fec.twcard.u.pw_type != PW_TYPE_WILDCARD &&
			    wcard->fec.twcard.u.pw_type != fec->u.pwid.type)
				return (0);
			return (1);
		default:
			fatalx("lde_wildcard_apply: unexpected fec type");
		}
		break;
	case MAP_TYPE_PWID:
		/* RFC4447 pw-id group wildcard */
		if (fec->type != FEC_TYPE_PWID)
			return (0);
		if (fec->u.pwid.type != wcard->fec.pwid.type)
			return (0);
		if (me == NULL || (me->map.fec.pwid.group_id !=
		    wcard->fec.pwid.group_id))
			return (0);
		return (1);
	default:
		fatalx("lde_wildcard_apply: unexpected fec type");
	}
}

/* gabage collector timer: timer to remove dead entries from the LIB */

/* ARGSUSED */
void lde_gc_timer(struct event *thread)
{
	struct fec	*fec, *safe;
	struct fec_node	*fn;
	int		 count = 0;

	RB_FOREACH_SAFE(fec, fec_tree, &ft, safe) {
		fn = (struct fec_node *) fec;

		if (!LIST_EMPTY(&fn->nexthops) ||
		    !RB_EMPTY(lde_map_head, &fn->downstream) ||
		    !RB_EMPTY(lde_map_head, &fn->upstream))
			continue;

		if (fn->local_label != NO_LABEL)
			lde_free_label(fn->local_label);

		fec_remove(&ft, &fn->fec);
		free(fn);
		count++;
	}

	if (count > 0)
		log_debug("%s: %u entries removed", __func__, count);

	lde_gc_start_timer();
}

void
lde_gc_start_timer(void)
{
	EVENT_OFF(gc_timer);
	event_add_timer(master, lde_gc_timer, NULL, LDE_GC_INTERVAL, &gc_timer);
}

void
lde_gc_stop_timer(void)
{
	EVENT_OFF(gc_timer);
}
