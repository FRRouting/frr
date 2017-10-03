/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2015 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005, 2008 Esben Norby <norby@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "log.h"

static __inline int adj_compare(const struct adj *, const struct adj *);
static int	 adj_itimer(struct thread *);
static __inline int tnbr_compare(const struct tnbr *, const struct tnbr *);
static void	 tnbr_del(struct ldpd_conf *, struct tnbr *);
static void	 tnbr_start(struct tnbr *);
static void	 tnbr_stop(struct tnbr *);
static int	 tnbr_hello_timer(struct thread *);
static void	 tnbr_start_hello_timer(struct tnbr *);
static void	 tnbr_stop_hello_timer(struct tnbr *);

RB_GENERATE(global_adj_head, adj, global_entry, adj_compare)
RB_GENERATE(nbr_adj_head, adj, nbr_entry, adj_compare)
RB_GENERATE(ia_adj_head, adj, ia_entry, adj_compare)
RB_GENERATE(tnbr_head, tnbr, entry, tnbr_compare)

static __inline int
adj_compare(const struct adj *a, const struct adj *b)
{
	if (adj_get_af(a) < adj_get_af(b))
		return (-1);
	if (adj_get_af(a) > adj_get_af(b))
		return (1);

	if (ntohl(a->lsr_id.s_addr) < ntohl(b->lsr_id.s_addr))
		return (-1);
	if (ntohl(a->lsr_id.s_addr) > ntohl(b->lsr_id.s_addr))
		return (1);

	if (a->source.type < b->source.type)
		return (-1);
	if (a->source.type > b->source.type)
		return (1);

	switch (a->source.type) {
	case HELLO_LINK:
		if (if_cmp_name_func((char *)a->source.link.ia->iface->name,
		    (char *)b->source.link.ia->iface->name) < 0)
			return (-1);
		if (if_cmp_name_func((char *)a->source.link.ia->iface->name,
		    (char *)b->source.link.ia->iface->name) > 0)
			return (1);
		return (ldp_addrcmp(a->source.link.ia->af,
		    &a->source.link.src_addr, &b->source.link.src_addr));
	case HELLO_TARGETED:
		return (ldp_addrcmp(a->source.target->af,
		    &a->source.target->addr, &b->source.target->addr));
	default:
		fatalx("adj_compare: unknown hello type");
	}

	return (0);
}

struct adj *
adj_new(struct in_addr lsr_id, struct hello_source *source,
    union ldpd_addr *addr)
{
	struct adj	*adj;

	log_debug("%s: lsr-id %s, %s", __func__, inet_ntoa(lsr_id),
	    log_hello_src(source));

	if ((adj = calloc(1, sizeof(*adj))) == NULL)
		fatal(__func__);

	adj->lsr_id = lsr_id;
	adj->nbr = NULL;
	adj->source = *source;
	adj->trans_addr = *addr;

	RB_INSERT(global_adj_head, &global.adj_tree, adj);

	switch (source->type) {
	case HELLO_LINK:
		RB_INSERT(ia_adj_head, &source->link.ia->adj_tree, adj);
		break;
	case HELLO_TARGETED:
		source->target->adj = adj;
		break;
	}

	return (adj);
}

void
adj_del(struct adj *adj, uint32_t notif_status)
{
	struct nbr	*nbr = adj->nbr;

	log_debug("%s: lsr-id %s, %s (%s)", __func__, inet_ntoa(adj->lsr_id),
	    log_hello_src(&adj->source), af_name(adj_get_af(adj)));

	adj_stop_itimer(adj);

	RB_REMOVE(global_adj_head, &global.adj_tree, adj);
	if (nbr)
		RB_REMOVE(nbr_adj_head, &nbr->adj_tree, adj);
	switch (adj->source.type) {
	case HELLO_LINK:
		RB_REMOVE(ia_adj_head, &adj->source.link.ia->adj_tree, adj);
		break;
	case HELLO_TARGETED:
		adj->source.target->adj = NULL;
		break;
	}

	free(adj);

	/*
	 * If the neighbor still exists but none of its remaining
	 * adjacencies (if any) are from the preferred address-family,
	 * then delete it.
	 */
	if (nbr && nbr_adj_count(nbr, nbr->af) == 0) {
		session_shutdown(nbr, notif_status, 0, 0);
		nbr_del(nbr);
	}
}

struct adj *
adj_find(struct in_addr lsr_id, struct hello_source *source)
{
	struct adj	 adj;
	adj.lsr_id = lsr_id;
	adj.source = *source;
	return (RB_FIND(global_adj_head, &global.adj_tree, &adj));
}

int
adj_get_af(const struct adj *adj)
{
	switch (adj->source.type) {
	case HELLO_LINK:
		return (adj->source.link.ia->af);
	case HELLO_TARGETED:
		return (adj->source.target->af);
	default:
		fatalx("adj_get_af: unknown hello type");
	}
}

/* adjacency timers */

/* ARGSUSED */
static int
adj_itimer(struct thread *thread)
{
	struct adj *adj = THREAD_ARG(thread);

	adj->inactivity_timer = NULL;

	log_debug("%s: lsr-id %s", __func__, inet_ntoa(adj->lsr_id));

	if (adj->source.type == HELLO_TARGETED) {
		if (!(adj->source.target->flags & F_TNBR_CONFIGURED) &&
		    adj->source.target->pw_count == 0) {
			/* remove dynamic targeted neighbor */
			tnbr_del(leconf, adj->source.target);
			return (0);
		}
	}

	adj_del(adj, S_HOLDTIME_EXP);

	return (0);
}

void
adj_start_itimer(struct adj *adj)
{
	THREAD_TIMER_OFF(adj->inactivity_timer);
	adj->inactivity_timer = NULL;
	thread_add_timer(master, adj_itimer, adj, adj->holdtime,
			 &adj->inactivity_timer);
}

void
adj_stop_itimer(struct adj *adj)
{
	THREAD_TIMER_OFF(adj->inactivity_timer);
}

/* targeted neighbors */

static __inline int
tnbr_compare(const struct tnbr *a, const struct tnbr *b)
{
	if (a->af < b->af)
		return (-1);
	if (a->af > b->af)
		return (1);

	return (ldp_addrcmp(a->af, &a->addr, &b->addr));
}

struct tnbr *
tnbr_new(int af, union ldpd_addr *addr)
{
	struct tnbr		*tnbr;

	if ((tnbr = calloc(1, sizeof(*tnbr))) == NULL)
		fatal(__func__);

	tnbr->af = af;
	tnbr->addr = *addr;
	tnbr->state = TNBR_STA_DOWN;

	return (tnbr);
}

static void
tnbr_del(struct ldpd_conf *xconf, struct tnbr *tnbr)
{
	tnbr_stop(tnbr);
	RB_REMOVE(tnbr_head, &xconf->tnbr_tree, tnbr);
	free(tnbr);
}

struct tnbr *
tnbr_find(struct ldpd_conf *xconf, int af, union ldpd_addr *addr)
{
	struct tnbr	 tnbr;
	tnbr.af = af;
	tnbr.addr = *addr;
	return (RB_FIND(tnbr_head, &xconf->tnbr_tree, &tnbr));
}

struct tnbr *
tnbr_check(struct ldpd_conf *xconf, struct tnbr *tnbr)
{
	if (!(tnbr->flags & (F_TNBR_CONFIGURED|F_TNBR_DYNAMIC)) &&
	    tnbr->pw_count == 0) {
		tnbr_del(xconf, tnbr);
		return (NULL);
	}

	return (tnbr);
}

static void
tnbr_start(struct tnbr *tnbr)
{
	send_hello(HELLO_TARGETED, NULL, tnbr);
	tnbr_start_hello_timer(tnbr);
	tnbr->state = TNBR_STA_ACTIVE;
}

static void
tnbr_stop(struct tnbr *tnbr)
{
	tnbr_stop_hello_timer(tnbr);
	if (tnbr->adj)
		adj_del(tnbr->adj, S_SHUTDOWN);
	tnbr->state = TNBR_STA_DOWN;
}

void
tnbr_update(struct tnbr *tnbr)
{
	int			 socket_ok, rtr_id_ok;

	if ((ldp_af_global_get(&global, tnbr->af))->ldp_edisc_socket != -1)
		socket_ok = 1;
	else
		socket_ok = 0;

	if (ldp_rtr_id_get(leconf) != INADDR_ANY)
		rtr_id_ok = 1;
	else
		rtr_id_ok = 0;

	if (tnbr->state == TNBR_STA_DOWN) {
		if (!socket_ok || !rtr_id_ok)
			return;

		tnbr_start(tnbr);
	} else if (tnbr->state == TNBR_STA_ACTIVE) {
		if (socket_ok && rtr_id_ok)
			return;

		tnbr_stop(tnbr);
	}
}

void
tnbr_update_all(int af)
{
	struct tnbr		*tnbr;

	/* update targeted neighbors */
	RB_FOREACH(tnbr, tnbr_head, &leconf->tnbr_tree)
		if (tnbr->af == af || af == AF_UNSPEC)
			tnbr_update(tnbr);
}

uint16_t
tnbr_get_hello_holdtime(struct tnbr *tnbr)
{
	if ((ldp_af_conf_get(leconf, tnbr->af))->thello_holdtime != 0)
		return ((ldp_af_conf_get(leconf, tnbr->af))->thello_holdtime);

	return (leconf->thello_holdtime);
}

uint16_t
tnbr_get_hello_interval(struct tnbr *tnbr)
{
	if ((ldp_af_conf_get(leconf, tnbr->af))->thello_interval != 0)
		return ((ldp_af_conf_get(leconf, tnbr->af))->thello_interval);

	return (leconf->thello_interval);
}

/* target neighbors timers */

/* ARGSUSED */
static int
tnbr_hello_timer(struct thread *thread)
{
	struct tnbr	*tnbr = THREAD_ARG(thread);

	tnbr->hello_timer = NULL;
	send_hello(HELLO_TARGETED, NULL, tnbr);
	tnbr_start_hello_timer(tnbr);

	return (0);
}

static void
tnbr_start_hello_timer(struct tnbr *tnbr)
{
	THREAD_TIMER_OFF(tnbr->hello_timer);
	tnbr->hello_timer = NULL;
	thread_add_timer(master, tnbr_hello_timer, tnbr, tnbr_get_hello_interval(tnbr),
			 &tnbr->hello_timer);
}

static void
tnbr_stop_hello_timer(struct tnbr *tnbr)
{
	THREAD_TIMER_OFF(tnbr->hello_timer);
}

struct ctl_adj *
adj_to_ctl(struct adj *adj)
{
	static struct ctl_adj	 actl;

	actl.af = adj_get_af(adj);
	actl.id = adj->lsr_id;
	actl.type = adj->source.type;
	switch (adj->source.type) {
	case HELLO_LINK:
		memcpy(actl.ifname, adj->source.link.ia->iface->name,
		    sizeof(actl.ifname));
		actl.src_addr = adj->source.link.src_addr;
		break;
	case HELLO_TARGETED:
		actl.src_addr = adj->source.target->addr;
		break;
	}
	actl.holdtime = adj->holdtime;
	actl.holdtime_remaining =
	    thread_timer_remain_second(adj->inactivity_timer);
	actl.trans_addr = adj->trans_addr;
	actl.ds_tlv = adj->ds_tlv;

	return (&actl);
}
