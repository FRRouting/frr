// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2015 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005, 2008 Esben Norby <norby@openbsd.org>
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "log.h"

static void		 l2vpn_pw_fec(struct l2vpn_pw *, struct fec *);
static __inline int	 l2vpn_compare(const struct l2vpn *, const struct l2vpn *);
static __inline int	 l2vpn_if_compare(const struct l2vpn_if *, const struct l2vpn_if *);
static __inline int	 l2vpn_pw_compare(const struct l2vpn_pw *, const struct l2vpn_pw *);

RB_GENERATE(l2vpn_head, l2vpn, entry, l2vpn_compare)
RB_GENERATE(l2vpn_if_head, l2vpn_if, entry, l2vpn_if_compare)
RB_GENERATE(l2vpn_pw_head, l2vpn_pw, entry, l2vpn_pw_compare)

static __inline int
l2vpn_compare(const struct l2vpn *a, const struct l2vpn *b)
{
	return (strcmp(a->name, b->name));
}

struct l2vpn *
l2vpn_new(const char *name)
{
	struct l2vpn	*l2vpn;

	if ((l2vpn = calloc(1, sizeof(*l2vpn))) == NULL)
		fatal("l2vpn_new: calloc");

	strlcpy(l2vpn->name, name, sizeof(l2vpn->name));

	/* set default values */
	l2vpn->mtu = DEFAULT_L2VPN_MTU;
	l2vpn->pw_type = DEFAULT_PW_TYPE;

	RB_INIT(l2vpn_if_head, &l2vpn->if_tree);
	RB_INIT(l2vpn_pw_head, &l2vpn->pw_tree);
	RB_INIT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

	return (l2vpn);
}

struct l2vpn *
l2vpn_find(struct ldpd_conf *xconf, const char *name)
{
	struct l2vpn	 l2vpn;
	strlcpy(l2vpn.name, name, sizeof(l2vpn.name));
	return (RB_FIND(l2vpn_head, &xconf->l2vpn_tree, &l2vpn));
}

void
l2vpn_del(struct l2vpn *l2vpn)
{
	struct l2vpn_if		*lif;
	struct l2vpn_pw		*pw;

	while (!RB_EMPTY(l2vpn_if_head, &l2vpn->if_tree)) {
		lif = RB_ROOT(l2vpn_if_head, &l2vpn->if_tree);

		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		free(lif);
	}
	while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_tree)) {
		pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_tree);

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
		free(pw);
	}
	while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_inactive_tree)) {
		pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		free(pw);
	}

	free(l2vpn);
}

void
l2vpn_init(struct l2vpn *l2vpn)
{
	struct l2vpn_pw	*pw;

	RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree)
		l2vpn_pw_init(pw);
}

void
l2vpn_exit(struct l2vpn *l2vpn)
{
	struct l2vpn_pw		*pw;

	RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree)
		l2vpn_pw_exit(pw);
}

static __inline int
l2vpn_if_compare(const struct l2vpn_if *a, const struct l2vpn_if *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

struct l2vpn_if *
l2vpn_if_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if	*lif;

	if ((lif = calloc(1, sizeof(*lif))) == NULL)
		fatal("l2vpn_if_new: calloc");

	lif->l2vpn = l2vpn;
	strlcpy(lif->ifname, ifname, sizeof(lif->ifname));

	return (lif);
}

struct l2vpn_if *
l2vpn_if_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if	 lif;
	strlcpy(lif.ifname, ifname, sizeof(lif.ifname));
	return (RB_FIND(l2vpn_if_head, &l2vpn->if_tree, &lif));
}

void
l2vpn_if_update_info(struct l2vpn_if *lif, struct kif *kif)
{
	lif->ifindex = kif->ifindex;
	lif->operative = kif->operative;
	memcpy(lif->mac, kif->mac, sizeof(lif->mac));
}

void
l2vpn_if_update(struct l2vpn_if *lif)
{
	struct l2vpn	*l2vpn = lif->l2vpn;
	struct l2vpn_pw	*pw;
	struct map	 fec;
	struct nbr	*nbr;

	if (lif->operative)
		return;

	RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree) {
		nbr = nbr_find_ldpid(pw->lsr_id.s_addr);
		if (nbr == NULL)
			continue;

		memset(&fec, 0, sizeof(fec));
		fec.type = MAP_TYPE_PWID;
		fec.fec.pwid.type = l2vpn->pw_type;
		fec.fec.pwid.group_id = 0;
		SET_FLAG(fec.flags, F_MAP_PW_ID);
		fec.fec.pwid.pwid = pw->pwid;

		send_mac_withdrawal(nbr, &fec, lif->mac);
	}
}

static __inline int
l2vpn_pw_compare(const struct l2vpn_pw *a, const struct l2vpn_pw *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

struct l2vpn_pw *
l2vpn_pw_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw	*pw;

	if ((pw = calloc(1, sizeof(*pw))) == NULL)
		fatal("l2vpn_pw_new: calloc");

	pw->l2vpn = l2vpn;
	strlcpy(pw->ifname, ifname, sizeof(pw->ifname));

	return (pw);
}

struct l2vpn_pw *
l2vpn_pw_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw	*pw;
	struct l2vpn_pw	 s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	pw = RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, &s);
	if (pw)
		return (pw);
	return (RB_FIND(l2vpn_pw_head, &l2vpn->pw_inactive_tree, &s));
}

struct l2vpn_pw *
l2vpn_pw_find_active(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw	 s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return (RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, &s));
}

struct l2vpn_pw *
l2vpn_pw_find_inactive(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw	 s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return (RB_FIND(l2vpn_pw_head, &l2vpn->pw_inactive_tree, &s));
}

void
l2vpn_pw_update_info(struct l2vpn_pw *pw, struct kif *kif)
{
	pw->ifindex = kif->ifindex;
}

void
l2vpn_pw_init(struct l2vpn_pw *pw)
{
	struct fec	 fec;
	struct zapi_pw	 zpw;

	l2vpn_pw_reset(pw);

	pw2zpw(pw, &zpw);
	lde_imsg_compose_parent(IMSG_KPW_ADD, 0, &zpw, sizeof(zpw));

	l2vpn_pw_fec(pw, &fec);
	lde_kernel_insert(&fec, AF_INET, (union ldpd_addr*)&pw->lsr_id, 0, 0,
	    0, 0, (void *)pw);
	lde_kernel_update(&fec);
}

void
l2vpn_pw_exit(struct l2vpn_pw *pw)
{
	struct fec	 fec;
	struct zapi_pw	 zpw;

	l2vpn_pw_fec(pw, &fec);
	lde_kernel_remove(&fec, AF_INET, (union ldpd_addr*)&pw->lsr_id, 0, 0, 0);
	lde_kernel_update(&fec);

	pw2zpw(pw, &zpw);
	lde_imsg_compose_parent(IMSG_KPW_DELETE, 0, &zpw, sizeof(zpw));
}

static void
l2vpn_pw_fec(struct l2vpn_pw *pw, struct fec *fec)
{
	memset(fec, 0, sizeof(*fec));
	fec->type = FEC_TYPE_PWID;
	fec->u.pwid.type = pw->l2vpn->pw_type;
	fec->u.pwid.pwid = pw->pwid;
	fec->u.pwid.lsr_id = pw->lsr_id;
}

void
l2vpn_pw_reset(struct l2vpn_pw *pw)
{
	pw->remote_group = 0;
	pw->remote_mtu = 0;
	pw->local_status = PW_FORWARDING;
	pw->remote_status = PW_NOT_FORWARDING;

	if (CHECK_FLAG(pw->flags, F_PW_CWORD_CONF))
		SET_FLAG(pw->flags, F_PW_CWORD);
	else
		UNSET_FLAG(pw->flags, F_PW_CWORD);

	if (CHECK_FLAG(pw->flags, F_PW_STATUSTLV_CONF))
		SET_FLAG(pw->flags, F_PW_STATUSTLV);
	else
		UNSET_FLAG(pw->flags, F_PW_STATUSTLV);

	if (CHECK_FLAG(pw->flags, F_PW_STATUSTLV_CONF)) {
		struct fec_node         *fn;
		struct fec fec;
		l2vpn_pw_fec(pw, &fec);
		fn = (struct fec_node *)fec_find(&ft, &fec);
		if (fn)
			pw->remote_status = fn->pw_remote_status;
	}

}

int
l2vpn_pw_ok(struct l2vpn_pw *pw, struct fec_nh *fnh)
{
	/* check for a remote label */
	if (fnh->remote_label == NO_LABEL) {
		log_warnx("%s: pseudowire %s: no remote label", __func__, pw->ifname);
		pw->reason = F_PW_NO_REMOTE_LABEL;
		return (0);
	}

	/* MTUs must match */
	if (pw->l2vpn->mtu != pw->remote_mtu) {
		log_warnx("%s: pseudowire %s: MTU mismatch detected", __func__,
			  pw->ifname);
		pw->reason = F_PW_MTU_MISMATCH;
		return (0);
	}

	/* check pw status if applicable */
	if (CHECK_FLAG(pw->flags, F_PW_STATUSTLV) &&
	    pw->remote_status != PW_FORWARDING) {
		log_warnx("%s: pseudowire %s: remote end is down", __func__, pw->ifname);
		pw->reason = F_PW_REMOTE_NOT_FWD;
		return (0);
	}

	pw->reason = F_PW_NO_ERR;
	return (1);
}

int
l2vpn_pw_negotiate(struct lde_nbr *ln, struct fec_node *fn, struct map *map)
{
	struct l2vpn_pw		*pw;
	struct status_tlv	 st;

	/* NOTE: thanks martini & friends for all this mess */

	pw = (struct l2vpn_pw *) fn->data;
	if (pw == NULL)
		/*
		 * pseudowire not configured, return and record
		 * the mapping later
		 */
		return (0);

	/* RFC4447 - Section 6.2: control word negotiation */
	if (fec_find(&ln->sent_map, &fn->fec)) {
		if (CHECK_FLAG(map->flags, F_MAP_PW_CWORD) &&
		    !CHECK_FLAG(pw->flags, F_PW_CWORD_CONF)) {
			/* ignore the received label mapping */
			return (1);
		} else if (!CHECK_FLAG(map->flags, F_MAP_PW_CWORD) &&
		    CHECK_FLAG(pw->flags, F_PW_CWORD_CONF)) {
			/* append a "Wrong C-bit" status code */
			st.status_code = S_WRONG_CBIT;
			st.msg_id = map->msg_id;
			st.msg_type = htons(MSG_TYPE_LABELMAPPING);
			lde_send_labelwithdraw(ln, fn, NULL, &st);

			UNSET_FLAG(pw->flags, F_PW_CWORD);
			lde_send_labelmapping(ln, fn, 1);
		}
	} else if (CHECK_FLAG(map->flags, F_MAP_PW_CWORD)) {
		if (CHECK_FLAG(pw->flags, F_PW_CWORD_CONF))
			SET_FLAG(pw->flags, F_PW_CWORD);
		else
			/* act as if no label mapping had been received */
			return (1);
	} else
		UNSET_FLAG(pw->flags, F_PW_CWORD);

	/* RFC4447 - Section 5.4.3: pseudowire status negotiation */
	if (fec_find(&ln->recv_map, &fn->fec) == NULL &&
	    !CHECK_FLAG(map->flags, F_MAP_PW_STATUS))
		UNSET_FLAG(pw->flags, F_PW_STATUSTLV);

	return (0);
}

void
l2vpn_send_pw_status(struct lde_nbr *ln, uint32_t status, struct fec *fec)
{
	struct notify_msg	 nm;

	memset(&nm, 0, sizeof(nm));
	nm.status_code = S_PW_STATUS;
	nm.pw_status = status;
	SET_FLAG(nm.flags, F_NOTIF_PW_STATUS);
	lde_fec2map(fec, &nm.fec);
	SET_FLAG(nm.flags, F_NOTIF_FEC);

	lde_imsg_compose_ldpe(IMSG_NOTIFICATION_SEND, ln->peerid, 0, &nm, sizeof(nm));
}

void
l2vpn_send_pw_status_wcard(struct lde_nbr *ln, uint32_t status,
    uint16_t pw_type, uint32_t group_id)
{
	struct notify_msg	 nm;

	memset(&nm, 0, sizeof(nm));
	nm.status_code = S_PW_STATUS;
	nm.pw_status = status;
	SET_FLAG(nm.flags, F_NOTIF_PW_STATUS);
	nm.fec.type = MAP_TYPE_PWID;
	nm.fec.fec.pwid.type = pw_type;
	nm.fec.fec.pwid.group_id = group_id;
	SET_FLAG(nm.flags, F_NOTIF_FEC);

	lde_imsg_compose_ldpe(IMSG_NOTIFICATION_SEND, ln->peerid, 0, &nm, sizeof(nm));
}

void
l2vpn_recv_pw_status(struct lde_nbr *ln, struct notify_msg *nm)
{
	struct fec		 fec;
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct l2vpn_pw		*pw;

	if (nm->fec.type == MAP_TYPE_TYPED_WCARD ||
	    !CHECK_FLAG(nm->fec.flags, F_MAP_PW_ID)) {
		l2vpn_recv_pw_status_wcard(ln, nm);
		return;
	}

	lde_map2fec(&nm->fec, ln->id, &fec);
	fn = (struct fec_node *)fec_find(&ft, &fec);
	if (fn == NULL)
		/* unknown fec */
		return;

	fn->pw_remote_status = nm->pw_status;

	pw = (struct l2vpn_pw *) fn->data;
	if (pw == NULL)
		return;

	fnh = fec_nh_find(fn, AF_INET, (union ldpd_addr *)&ln->id, 0, 0, 0);
	if (fnh == NULL)
		return;

	/* remote status didn't change */
	if (pw->remote_status == nm->pw_status)
		return;
	pw->remote_status = nm->pw_status;

	if (l2vpn_pw_ok(pw, fnh))
		lde_send_change_klabel(fn, fnh);
	else
		lde_send_delete_klabel(fn, fnh);
}

/* RFC4447 PWid group wildcard */
void
l2vpn_recv_pw_status_wcard(struct lde_nbr *ln, struct notify_msg *nm)
{
	struct fec		*f;
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct l2vpn_pw		*pw;
	struct map		*wcard = &nm->fec;

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		if (fn->fec.type != FEC_TYPE_PWID)
			continue;

		pw = (struct l2vpn_pw *) fn->data;
		if (pw == NULL)
			continue;

		switch (wcard->type) {
		case MAP_TYPE_TYPED_WCARD:
			if (wcard->fec.twcard.u.pw_type != PW_TYPE_WILDCARD &&
			    wcard->fec.twcard.u.pw_type != fn->fec.u.pwid.type)
				continue;
			break;
		case MAP_TYPE_PWID:
			if (wcard->fec.pwid.type != fn->fec.u.pwid.type)
				continue;
			if (wcard->fec.pwid.group_id != pw->remote_group)
				continue;
			break;
		}

		fnh = fec_nh_find(fn, AF_INET, (union ldpd_addr *)&ln->id,
		    0, 0, 0);
		if (fnh == NULL)
			continue;

		/* remote status didn't change */
		if (pw->remote_status == nm->pw_status)
			continue;
		pw->remote_status = nm->pw_status;

		if (l2vpn_pw_ok(pw, fnh))
			lde_send_change_klabel(fn, fnh);
		else
			lde_send_delete_klabel(fn, fnh);
	}
}

int
l2vpn_pw_status_update(struct zapi_pw_status *zpw)
{
	struct l2vpn		*l2vpn;
	struct l2vpn_pw		*pw = NULL;
	struct lde_nbr		*ln;
	struct fec		 fec;
	uint32_t		 local_status;

	RB_FOREACH(l2vpn, l2vpn_head, &ldeconf->l2vpn_tree) {
		pw = l2vpn_pw_find(l2vpn, zpw->ifname);
		if (pw)
			break;
	}
	if (!pw) {
		log_warnx("%s: pseudowire %s not found", __func__, zpw->ifname);
		return (1);
	}

	if (zpw->status == PW_FORWARDING) {
		local_status = PW_FORWARDING;
		pw->reason = F_PW_NO_ERR;
	} else {
		local_status = zpw->status;
		pw->reason = F_PW_LOCAL_NOT_FWD;
	}

	/* local status didn't change */
	if (pw->local_status == local_status)
		return (0);
	pw->local_status = local_status;

	/* notify remote peer about the status update */
	ln = lde_nbr_find_by_lsrid(pw->lsr_id);
	if (ln == NULL)
		return (0);
	l2vpn_pw_fec(pw, &fec);
	if (CHECK_FLAG(pw->flags, F_PW_STATUSTLV))
		l2vpn_send_pw_status(ln, local_status, &fec);
	else {
		struct fec_node *fn;
		fn = (struct fec_node *)fec_find(&ft, &fec);
		if (fn) {
			if (pw->local_status == PW_FORWARDING)
				lde_send_labelmapping(ln, fn, 1);
			else
				lde_send_labelwithdraw(ln, fn, NULL, NULL);
		}
	}

	return (0);
}

void
l2vpn_pw_ctl(pid_t pid)
{
	struct l2vpn		*l2vpn;
	struct l2vpn_pw		*pw;
	static struct ctl_pw	 pwctl;

	RB_FOREACH(l2vpn, l2vpn_head, &ldeconf->l2vpn_tree)
		RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree) {
			memset(&pwctl, 0, sizeof(pwctl));
			strlcpy(pwctl.l2vpn_name, pw->l2vpn->name,
			    sizeof(pwctl.l2vpn_name));
			strlcpy(pwctl.ifname, pw->ifname,
			    sizeof(pwctl.ifname));
			pwctl.pwid = pw->pwid;
			pwctl.lsr_id = pw->lsr_id;
			pwctl.status = PW_NOT_FORWARDING;
			if (pw->enabled &&
			    pw->local_status == PW_FORWARDING &&
			    pw->remote_status == PW_FORWARDING)
				pwctl.status = PW_FORWARDING;

			lde_imsg_compose_ldpe(IMSG_CTL_SHOW_L2VPN_PW, 0,
			    pid, &pwctl, sizeof(pwctl));
		}
}

void
l2vpn_binding_ctl(pid_t pid)
{
	struct fec		*f;
	struct fec_node		*fn;
	struct lde_map		*me;
	struct l2vpn_pw		*pw;
	static struct ctl_pw	 pwctl;

	RB_FOREACH(f, fec_tree, &ft) {
		if (f->type != FEC_TYPE_PWID)
			continue;

		fn = (struct fec_node *)f;
		if (fn->local_label == NO_LABEL &&
		    RB_EMPTY(lde_map_head, &fn->downstream))
			continue;

		memset(&pwctl, 0, sizeof(pwctl));
		pwctl.type = f->u.pwid.type;
		pwctl.pwid = f->u.pwid.pwid;
		pwctl.lsr_id = f->u.pwid.lsr_id;

		pw = (struct l2vpn_pw *) fn->data;
		if (pw) {
			pwctl.local_label = fn->local_label;
			pwctl.local_gid = 0;
			pwctl.local_ifmtu = pw->l2vpn->mtu;
			pwctl.local_cword = CHECK_FLAG(pw->flags, F_PW_CWORD_CONF) ? 1 : 0;
			pwctl.reason = pw->reason;
		} else
			pwctl.local_label = NO_LABEL;

		RB_FOREACH(me, lde_map_head, &fn->downstream)
			if (f->u.pwid.lsr_id.s_addr == me->nexthop->id.s_addr)
				break;

		if (me) {
			pwctl.remote_label = me->map.label;
			pwctl.remote_gid = me->map.fec.pwid.group_id;
			if (CHECK_FLAG(me->map.flags, F_MAP_PW_IFMTU))
				pwctl.remote_ifmtu = me->map.fec.pwid.ifmtu;
			if (pw)
				pwctl.remote_cword = CHECK_FLAG(pw->flags, F_PW_CWORD) ? 1 : 0;

			lde_imsg_compose_ldpe(IMSG_CTL_SHOW_L2VPN_BINDING,
			    0, pid, &pwctl, sizeof(pwctl));
		} else if (pw) {
			pwctl.remote_label = NO_LABEL;

			lde_imsg_compose_ldpe(IMSG_CTL_SHOW_L2VPN_BINDING,
			    0, pid, &pwctl, sizeof(pwctl));
		}
	}
}

/* ldpe */

void
ldpe_l2vpn_init(struct l2vpn *l2vpn)
{
	struct l2vpn_pw		*pw;

	RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree)
		ldpe_l2vpn_pw_init(pw);
}

void
ldpe_l2vpn_exit(struct l2vpn *l2vpn)
{
	struct l2vpn_pw		*pw;

	RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree)
		ldpe_l2vpn_pw_exit(pw);
}

void
ldpe_l2vpn_pw_init(struct l2vpn_pw *pw)
{
	struct tnbr		*tnbr;

	tnbr = tnbr_find(leconf, pw->af, &pw->addr);
	if (tnbr == NULL) {
		tnbr = tnbr_new(pw->af, &pw->addr);
		tnbr_update(tnbr);
		RB_INSERT(tnbr_head, &leconf->tnbr_tree, tnbr);
	}

	tnbr->pw_count++;
}

void
ldpe_l2vpn_pw_exit(struct l2vpn_pw *pw)
{
	struct tnbr		*tnbr;

	tnbr = tnbr_find(leconf, pw->af, &pw->addr);
	if (tnbr) {
		tnbr->pw_count--;
		tnbr_check(leconf, tnbr);
	}
}
