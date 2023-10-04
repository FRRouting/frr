// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2004, 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <zebra.h>

#include "ldp.h"
#include "ldpd.h"
#include "ldpe.h"
#include "log.h"
#include "lde.h"
#include "ldp_debug.h"
#include "rlfa.h"

#include <lib/log.h>
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "mpls.h"
#include <lib/linklist.h>
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "libfrr.h"

static void		 lde_shutdown(void);
static void lde_dispatch_imsg(struct event *thread);
static void lde_dispatch_parent(struct event *thread);
static __inline	int	 lde_nbr_compare(const struct lde_nbr *,
			    const struct lde_nbr *);
static struct lde_nbr	*lde_nbr_new(uint32_t, struct lde_nbr *);
static void		 lde_nbr_del(struct lde_nbr *);
static struct lde_nbr	*lde_nbr_find(uint32_t);
static void		 lde_nbr_clear(void);
static void		 lde_nbr_addr_update(struct lde_nbr *,
			    struct lde_addr *, int);
static __inline int	 lde_map_compare(const struct lde_map *,
			    const struct lde_map *);
static void		 lde_map_free(void *);
static int		 lde_address_add(struct lde_nbr *, struct lde_addr *);
static int		 lde_address_del(struct lde_nbr *, struct lde_addr *);
static void		 lde_address_list_free(struct lde_nbr *);
static void              zclient_sync_init(void);
static void		 lde_label_list_init(void);
static int		 lde_get_label_chunk(void);
static void		 on_get_label_chunk_response(uint32_t start, uint32_t end);
static uint32_t		 lde_get_next_label(void);
static bool		 lde_fec_connected(const struct fec_node *);
static bool		 lde_fec_outside_mpls_network(const struct fec_node *);
static void		 lde_check_filter_af(int, struct ldpd_af_conf *,
			     const char *);

RB_GENERATE(nbr_tree, lde_nbr, entry, lde_nbr_compare)
RB_GENERATE(lde_map_head, lde_map, entry, lde_map_compare)

struct ldpd_conf	*ldeconf;
struct nbr_tree		 lde_nbrs = RB_INITIALIZER(&lde_nbrs);

static struct imsgev	*iev_ldpe;
static struct imsgev    iev_main_sync_data;
static struct imsgev	*iev_main, *iev_main_sync;

/* lde privileges */
static zebra_capabilities_t _caps_p [] =
{
	ZCAP_NET_ADMIN
};

static struct zebra_privs_t lde_privs =
{
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};

/* List of chunks of labels externally assigned by Zebra */
static struct list *label_chunk_list;
static struct listnode *current_label_chunk;

/* Synchronous zclient to request labels */
struct zclient *zclient_sync;

/* SIGINT / SIGTERM handler. */
static void
sigint(void)
{
	lde_shutdown();
}

static struct frr_signal_t lde_signals[] =
{
	{
		.signal = SIGHUP,
		/* ignore */
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigint,
	},
};

/* label decision engine */
void
lde(void)
{
#ifdef HAVE_SETPROCTITLE
	setproctitle("label decision engine");
#endif
	ldpd_process = PROC_LDE_ENGINE;
	log_procname = log_procnames[PROC_LDE_ENGINE];

	master = frr_init();
	/* no frr_config_fork() here, allow frr_pthread to create threads */
	frr_is_after_fork = true;

	/* setup signal handler */
	signal_init(master, array_size(lde_signals), lde_signals);

	/* setup pipes and event handlers to the parent process */
	if ((iev_main = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_main->ibuf, LDPD_FD_ASYNC);
	iev_main->handler_read = lde_dispatch_parent;
	event_add_read(master, iev_main->handler_read, iev_main,
		       iev_main->ibuf.fd, &iev_main->ev_read);
	iev_main->handler_write = ldp_write_handler;

	memset(&iev_main_sync_data, 0, sizeof(iev_main_sync_data));
	iev_main_sync = &iev_main_sync_data;
	imsg_init(&iev_main_sync->ibuf, LDPD_FD_SYNC);

	/* create base configuration */
	ldeconf = config_new_empty();

	struct event thread;
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* NOTREACHED */
	return;
}

void
lde_init(struct ldpd_init *init)
{
	/* drop privileges */
	lde_privs.user = init->user;
	lde_privs.group = init->group;
	zprivs_preinit(&lde_privs);
	zprivs_init(&lde_privs);

	/* start the LIB garbage collector */
	lde_gc_start_timer();

	/* Init synchronous zclient and label list */
	frr_zclient_addr(&zclient_addr, &zclient_addr_len,
			 init->zclient_serv_path);
	zclient_sync_init();
}

static void
lde_shutdown(void)
{
	/* close pipes */
	if (iev_ldpe) {
		msgbuf_clear(&iev_ldpe->ibuf.w);
		close(iev_ldpe->ibuf.fd);
		iev_ldpe->ibuf.fd = -1;
	}
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);
	iev_main->ibuf.fd = -1;
	msgbuf_clear(&iev_main_sync->ibuf.w);
	close(iev_main_sync->ibuf.fd);
	iev_main_sync->ibuf.fd = -1;

	lde_gc_stop_timer();
	lde_nbr_clear();
	fec_tree_clear();

	config_clear(ldeconf);

	if (iev_ldpe)
		free(iev_ldpe);
	free(iev_main);

	log_info("label decision engine exiting");

	zlog_fini();
	exit(0);
}

/* imesg */
int
lde_imsg_compose_parent(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (iev_main->ibuf.fd == -1)
		return (0);
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data, datalen));
}

void
lde_imsg_compose_parent_sync(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (iev_main_sync->ibuf.fd == -1)
		return;
	imsg_compose_event(iev_main_sync, type, 0, pid, -1, data, datalen);
	imsg_flush(&iev_main_sync->ibuf);
}

int
lde_imsg_compose_ldpe(int type, uint32_t peerid, pid_t pid, void *data,
    uint16_t datalen)
{
	if (iev_ldpe->ibuf.fd == -1)
		return (0);
	return (imsg_compose_event(iev_ldpe, type, peerid, pid,
	     -1, data, datalen));
}

/* ARGSUSED */
static void lde_dispatch_imsg(struct event *thread)
{
	struct imsgev *iev = EVENT_ARG(thread);
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct lde_nbr		*ln;
	struct map		*map;
	struct lde_addr		*lde_addr;
	struct notify_msg	*nm;
	ssize_t			 n;
	int			 shut = 0;

	iev->ev_read = NULL;

	if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
		fatal("imsg_read error");
	if (n == 0)	/* connection closed */
		shut = 1;

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lde_dispatch_imsg: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_LABEL_MAPPING_FULL:
			ln = lde_nbr_find(imsg.hdr.peerid);
			if (ln == NULL) {
				log_debug("%s: cannot find lde neighbor", __func__);
				break;
			}

			fec_snap(ln);
			break;
		case IMSG_LABEL_MAPPING:
		case IMSG_LABEL_REQUEST:
		case IMSG_LABEL_RELEASE:
		case IMSG_LABEL_WITHDRAW:
		case IMSG_LABEL_ABORT:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(struct map))
				fatalx("lde_dispatch_imsg: wrong imsg len");
			map = imsg.data;

			ln = lde_nbr_find(imsg.hdr.peerid);
			if (ln == NULL) {
				log_debug("%s: cannot find lde neighbor", __func__);
				break;
			}

			switch (imsg.hdr.type) {
			case IMSG_LABEL_MAPPING:
				lde_check_mapping(map, ln, 1);
				break;
			case IMSG_LABEL_REQUEST:
				lde_check_request(map, ln);
				break;
			case IMSG_LABEL_RELEASE:
				lde_check_release(map, ln);
				break;
			case IMSG_LABEL_WITHDRAW:
				lde_check_withdraw(map, ln);
				break;
			case IMSG_LABEL_ABORT:
				/* not necessary */
				break;
			}
			break;
		case IMSG_ADDRESS_ADD:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(struct lde_addr))
				fatalx("lde_dispatch_imsg: wrong imsg len");
			lde_addr = imsg.data;

			ln = lde_nbr_find(imsg.hdr.peerid);
			if (ln == NULL) {
				log_debug("%s: cannot find lde neighbor", __func__);
				break;
			}

			if (lde_address_add(ln, lde_addr) < 0) {
				log_debug("%s: cannot add address %s, it already exists", __func__,
				    log_addr(lde_addr->af, &lde_addr->addr));
			}
			break;
		case IMSG_ADDRESS_DEL:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(struct lde_addr))
				fatalx("lde_dispatch_imsg: wrong imsg len");
			lde_addr = imsg.data;

			ln = lde_nbr_find(imsg.hdr.peerid);
			if (ln == NULL) {
				log_debug("%s: cannot find lde neighbor", __func__);
				break;
			}

			if (lde_address_del(ln, lde_addr) < 0) {
				log_debug("%s: cannot delete address %s, it does not exist", __func__,
				    log_addr(lde_addr->af, &lde_addr->addr));
			}
			break;
		case IMSG_NOTIFICATION:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(struct notify_msg))
				fatalx("lde_dispatch_imsg: wrong imsg len");
			nm = imsg.data;

			ln = lde_nbr_find(imsg.hdr.peerid);
			if (ln == NULL) {
				log_debug("%s: cannot find lde neighbor", __func__);
				break;
			}

			switch (nm->status_code) {
			case S_PW_STATUS:
				l2vpn_recv_pw_status(ln, nm);
				break;
			case S_ENDOFLIB:
				/*
				 * Do nothing for now. Should be useful in
				 * the future when we implement LDP-IGP
				 * Synchronization (RFC 5443) and Graceful
				 * Restart (RFC 3478).
				 */
			default:
				break;
			}
			break;
		case IMSG_NEIGHBOR_UP:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(struct lde_nbr))
				fatalx("lde_dispatch_imsg: wrong imsg len");

			if (lde_nbr_find(imsg.hdr.peerid))
				fatalx("lde_dispatch_imsg: neighbor already exists");
			lde_nbr_new(imsg.hdr.peerid, imsg.data);
			break;
		case IMSG_NEIGHBOR_DOWN:
			lde_nbr_del(lde_nbr_find(imsg.hdr.peerid));
			break;
		case IMSG_CTL_SHOW_LIB:
			rt_dump(imsg.hdr.pid);

			lde_imsg_compose_ldpe(IMSG_CTL_END, 0,
			    imsg.hdr.pid, NULL, 0);
			break;
		case IMSG_CTL_SHOW_L2VPN_PW:
			l2vpn_pw_ctl(imsg.hdr.pid);

			lde_imsg_compose_ldpe(IMSG_CTL_END, 0, imsg.hdr.pid, NULL, 0);
			break;
		case IMSG_CTL_SHOW_L2VPN_BINDING:
			l2vpn_binding_ctl(imsg.hdr.pid);

			lde_imsg_compose_ldpe(IMSG_CTL_END, 0, imsg.hdr.pid, NULL, 0);
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__, imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handlers and exit */
		EVENT_OFF(iev->ev_read);
		EVENT_OFF(iev->ev_write);
		lde_shutdown();
	}
}

/* ARGSUSED */
static void lde_dispatch_parent(struct event *thread)
{
	static struct ldpd_conf	*nconf;
	struct iface		*iface, *niface;
	struct tnbr		*ntnbr;
	struct nbr_params	*nnbrp;
	static struct l2vpn	*l2vpn, *nl2vpn;
	struct l2vpn_if		*lif, *nlif;
	struct l2vpn_pw		*pw, *npw;
	struct imsg		 imsg;
	struct kif		*kif;
	struct kroute		*kr;
	int			 fd;
	struct imsgev *iev = EVENT_ARG(thread);
	struct imsgbuf		*ibuf = &iev->ibuf;
	ssize_t			 n;
	int			 shut = 0;
	struct fec		 fec;
	struct ldp_access	*laccess;
	struct ldp_rlfa_node	 *rnode, *rntmp;
	struct ldp_rlfa_client	 *rclient;
	struct zapi_rlfa_request *rlfa_req;
	struct zapi_rlfa_igp	 *rlfa_igp;

	iev->ev_read = NULL;

	if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
		fatal("imsg_read error");
	if (n == 0)	/* connection closed */
		shut = 1;

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("lde_dispatch_parent: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_IFSTATUS:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct kif))
				fatalx("IFSTATUS imsg with wrong len");
			kif = imsg.data;

			iface = if_lookup_name(ldeconf, kif->ifname);
			if (iface) {
				if_update_info(iface, kif);

				/* if up see if any labels need to be updated */
				if (kif->operative)
					lde_route_update(iface, AF_UNSPEC);
				break;
			}

			RB_FOREACH(l2vpn, l2vpn_head, &ldeconf->l2vpn_tree) {
				lif = l2vpn_if_find(l2vpn, kif->ifname);
				if (lif) {
					l2vpn_if_update_info(lif, kif);
					break;
				}
				pw = l2vpn_pw_find(l2vpn, kif->ifname);
				if (pw) {
					l2vpn_pw_update_info(pw, kif);
					break;
				}
			}
			break;
		case IMSG_PW_UPDATE:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct zapi_pw_status))
				fatalx("PW_UPDATE imsg with wrong len");

			if (l2vpn_pw_status_update(imsg.data) != 0)
				log_warnx("%s: error updating PW status", __func__);
			break;
		case IMSG_NETWORK_ADD:
		case IMSG_NETWORK_UPDATE:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct kroute)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			kr = imsg.data;

			switch (kr->af) {
			case AF_INET:
				fec.type = FEC_TYPE_IPV4;
				fec.u.ipv4.prefix = kr->prefix.v4;
				fec.u.ipv4.prefixlen = kr->prefixlen;
				break;
			case AF_INET6:
				fec.type = FEC_TYPE_IPV6;
				fec.u.ipv6.prefix = kr->prefix.v6;
				fec.u.ipv6.prefixlen = kr->prefixlen;
				break;
			default:
				fatalx("lde_dispatch_parent: unknown af");
			}

			switch (imsg.hdr.type) {
			case IMSG_NETWORK_ADD:
				lde_kernel_insert(&fec, kr->af, &kr->nexthop,
				    kr->ifindex, kr->route_type, kr->route_instance,
				    CHECK_FLAG(kr->flags, F_CONNECTED), NULL);
				break;
			case IMSG_NETWORK_UPDATE:
				lde_kernel_update(&fec);
				break;
			}
			break;
		case IMSG_SOCKET_IPC:
			if (iev_ldpe) {
				log_warnx("%s: received unexpected imsg fd to ldpe", __func__);
				break;
			}
			if ((fd = imsg.fd) == -1) {
				log_warnx("%s: expected to receive imsg fd to ldpe but didn't receive any", __func__);
				break;
			}

			if ((iev_ldpe = malloc(sizeof(struct imsgev))) == NULL)
				fatal(NULL);
			imsg_init(&iev_ldpe->ibuf, fd);
			iev_ldpe->handler_read = lde_dispatch_imsg;
			event_add_read(master, iev_ldpe->handler_read, iev_ldpe,
				       iev_ldpe->ibuf.fd, &iev_ldpe->ev_read);
			iev_ldpe->handler_write = ldp_write_handler;
			iev_ldpe->ev_write = NULL;
			break;
		case IMSG_INIT:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct ldpd_init))
				fatalx("INIT imsg with wrong len");

			memcpy(&init, imsg.data, sizeof(init));
			lde_init(&init);
			break;
		case IMSG_AGENTX_ENABLED:
			ldp_agentx_enabled();
			break;
		case IMSG_RECONF_CONF:
			if ((nconf = malloc(sizeof(struct ldpd_conf))) == NULL)
				fatal(NULL);
			memcpy(nconf, imsg.data, sizeof(struct ldpd_conf));

			RB_INIT(iface_head, &nconf->iface_tree);
			RB_INIT(tnbr_head, &nconf->tnbr_tree);
			RB_INIT(nbrp_head, &nconf->nbrp_tree);
			RB_INIT(l2vpn_head, &nconf->l2vpn_tree);
			break;
		case IMSG_RECONF_IFACE:
			if ((niface = malloc(sizeof(struct iface))) == NULL)
				fatal(NULL);
			memcpy(niface, imsg.data, sizeof(struct iface));

			RB_INSERT(iface_head, &nconf->iface_tree, niface);
			break;
		case IMSG_RECONF_TNBR:
			if ((ntnbr = malloc(sizeof(struct tnbr))) == NULL)
				fatal(NULL);
			memcpy(ntnbr, imsg.data, sizeof(struct tnbr));

			RB_INSERT(tnbr_head, &nconf->tnbr_tree, ntnbr);
			break;
		case IMSG_RECONF_NBRP:
			if ((nnbrp = malloc(sizeof(struct nbr_params))) == NULL)
				fatal(NULL);
			memcpy(nnbrp, imsg.data, sizeof(struct nbr_params));

			RB_INSERT(nbrp_head, &nconf->nbrp_tree, nnbrp);
			break;
		case IMSG_RECONF_L2VPN:
			if ((nl2vpn = malloc(sizeof(struct l2vpn))) == NULL)
				fatal(NULL);
			memcpy(nl2vpn, imsg.data, sizeof(struct l2vpn));

			RB_INIT(l2vpn_if_head, &nl2vpn->if_tree);
			RB_INIT(l2vpn_pw_head, &nl2vpn->pw_tree);
			RB_INIT(l2vpn_pw_head, &nl2vpn->pw_inactive_tree);

			RB_INSERT(l2vpn_head, &nconf->l2vpn_tree, nl2vpn);
			break;
		case IMSG_RECONF_L2VPN_IF:
			if ((nlif = malloc(sizeof(struct l2vpn_if))) == NULL)
				fatal(NULL);
			memcpy(nlif, imsg.data, sizeof(struct l2vpn_if));

			RB_INSERT(l2vpn_if_head, &nl2vpn->if_tree, nlif);
			break;
		case IMSG_RECONF_L2VPN_PW:
			if ((npw = malloc(sizeof(struct l2vpn_pw))) == NULL)
				fatal(NULL);
			memcpy(npw, imsg.data, sizeof(struct l2vpn_pw));

			RB_INSERT(l2vpn_pw_head, &nl2vpn->pw_tree, npw);
			break;
		case IMSG_RECONF_L2VPN_IPW:
			if ((npw = malloc(sizeof(struct l2vpn_pw))) == NULL)
				fatal(NULL);
			memcpy(npw, imsg.data, sizeof(struct l2vpn_pw));

			RB_INSERT(l2vpn_pw_head, &nl2vpn->pw_inactive_tree, npw);
			break;
		case IMSG_RECONF_END:
			merge_config(ldeconf, nconf);
			ldp_clear_config(nconf);
			nconf = NULL;
			break;
		case IMSG_DEBUG_UPDATE:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(ldp_debug)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			memcpy(&ldp_debug, imsg.data, sizeof(ldp_debug));
			break;
		case IMSG_FILTER_UPDATE:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct ldp_access)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			laccess = imsg.data;
			lde_check_filter_af(AF_INET, &ldeconf->ipv4,
				laccess->name);
			lde_check_filter_af(AF_INET6, &ldeconf->ipv6,
				laccess->name);
			break;
		case IMSG_RLFA_REG:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct zapi_rlfa_request)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			rlfa_req = imsg.data;
			rnode = rlfa_node_find(&rlfa_req->destination,
					       rlfa_req->pq_address);
			if (!rnode)
				rnode = rlfa_node_new(&rlfa_req->destination,
						      rlfa_req->pq_address);
			rclient = rlfa_client_find(rnode, &rlfa_req->igp);
			if (rclient)
				/* RLFA already registered - do nothing */
				break;
			rclient = rlfa_client_new(rnode, &rlfa_req->igp);
			lde_rlfa_check(rclient);
			break;
		case IMSG_RLFA_UNREG_ALL:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct zapi_rlfa_igp)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			rlfa_igp = imsg.data;

			RB_FOREACH_SAFE (rnode, ldp_rlfa_node_head,
					 &rlfa_node_tree, rntmp) {
				rclient = rlfa_client_find(rnode, rlfa_igp);
				if (!rclient)
					continue;

				rlfa_client_del(rclient);
			}
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__, imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handlers and exit */
		EVENT_OFF(iev->ev_read);
		EVENT_OFF(iev->ev_write);
		lde_shutdown();
	}
}

int
lde_acl_check(char *acl_name, int af, union ldpd_addr *addr, uint8_t prefixlen)
{
	return ldp_acl_request(iev_main_sync, acl_name, af, addr, prefixlen);
}

static bool lde_fec_connected(const struct fec_node *fn)
{
	struct fec_nh *fnh;

	LIST_FOREACH(fnh, &fn->nexthops, entry)
		if (CHECK_FLAG(fnh->flags, F_FEC_NH_CONNECTED))
			return true;

	return false;
}

static bool lde_fec_outside_mpls_network(const struct fec_node *fn)
{
	struct fec_nh *fnh;

	LIST_FOREACH(fnh, &fn->nexthops, entry)
		if (!CHECK_FLAG(fnh->flags, F_FEC_NH_NO_LDP))
			return false;

	return true;
}

uint32_t
lde_update_label(struct fec_node *fn)
{

	/* should we allocate a label for this fec? */
	switch (fn->fec.type) {
	case FEC_TYPE_IPV4:
		if (CHECK_FLAG(ldeconf->ipv4.flags, F_LDPD_AF_ALLOCHOSTONLY)
		    && fn->fec.u.ipv4.prefixlen != IPV4_MAX_BITLEN)
			return (NO_LABEL);

		if (lde_acl_check(ldeconf->ipv4.acl_label_allocate_for,
		    AF_INET, (union ldpd_addr *)&fn->fec.u.ipv4.prefix,
		    fn->fec.u.ipv4.prefixlen) != FILTER_PERMIT)
			return (NO_LABEL);
		break;
	case FEC_TYPE_IPV6:
		if (CHECK_FLAG(ldeconf->ipv6.flags, F_LDPD_AF_ALLOCHOSTONLY)
		    && fn->fec.u.ipv6.prefixlen != IPV6_MAX_BITLEN)
			return (NO_LABEL);

		if (lde_acl_check(ldeconf->ipv6.acl_label_allocate_for,
		    AF_INET6, (union ldpd_addr *)&fn->fec.u.ipv6.prefix,
		    fn->fec.u.ipv6.prefixlen) != FILTER_PERMIT)
			return (NO_LABEL);
		break;
	case FEC_TYPE_PWID:
		break;
	}

	/*
	 * If connected interface act as egress for fec.
	 * If LDP is not configured on an interface but there
	 * are other NHs with interfaces configured with LDP
	 * then don't act as an egress for the fec, otherwise
	 * act as an egress for the fec
	 */
	if (lde_fec_connected(fn) || lde_fec_outside_mpls_network(fn)) {
		/* choose implicit or explicit-null depending on configuration */
		switch (fn->fec.type) {
		case FEC_TYPE_IPV4:
			if (!CHECK_FLAG(ldeconf->ipv4.flags, F_LDPD_AF_EXPNULL))
				return (MPLS_LABEL_IMPLICIT_NULL);

			if (lde_acl_check(ldeconf->ipv4.acl_label_expnull_for,
			    AF_INET, (union ldpd_addr *)&fn->fec.u.ipv4.prefix,
			    fn->fec.u.ipv4.prefixlen) != FILTER_PERMIT)
				return (MPLS_LABEL_IMPLICIT_NULL);
			return MPLS_LABEL_IPV4_EXPLICIT_NULL;
		case FEC_TYPE_IPV6:
			if (!CHECK_FLAG(ldeconf->ipv6.flags, F_LDPD_AF_EXPNULL))
				return (MPLS_LABEL_IMPLICIT_NULL);

			if (lde_acl_check(ldeconf->ipv6.acl_label_expnull_for,
			    AF_INET6, (union ldpd_addr *)&fn->fec.u.ipv6.prefix,
			    fn->fec.u.ipv6.prefixlen) != FILTER_PERMIT)
				return (MPLS_LABEL_IMPLICIT_NULL);
			return MPLS_LABEL_IPV6_EXPLICIT_NULL;
		case FEC_TYPE_PWID:
			break;
		}
	}

	/* preserve current label if there's no need to update it */
	if (fn->local_label != NO_LABEL &&
	    fn->local_label > MPLS_LABEL_RESERVED_MAX)
		return (fn->local_label);

	return (lde_get_next_label());
}

void
lde_send_change_klabel(struct fec_node *fn, struct fec_nh *fnh)
{
	struct kroute	 kr;
	struct zapi_pw	 zpw;
	struct l2vpn_pw	*pw;

	/*
	 * Ordered Control: don't program label into HW until a
	 * labelmap msg has been received from upstream router
	 */
	if (CHECK_FLAG(fnh->flags, F_FEC_NH_DEFER))
		return;

	switch (fn->fec.type) {
	case FEC_TYPE_IPV4:
		memset(&kr, 0, sizeof(kr));
		kr.af = AF_INET;
		kr.prefix.v4 = fn->fec.u.ipv4.prefix;
		kr.prefixlen = fn->fec.u.ipv4.prefixlen;
		kr.nexthop.v4 = fnh->nexthop.v4;
		kr.ifindex = fnh->ifindex;
		kr.local_label = fn->local_label;
		kr.remote_label = fnh->remote_label;
		kr.route_type = fnh->route_type;
		kr.route_instance = fnh->route_instance;
		lde_imsg_compose_parent(IMSG_KLABEL_CHANGE, 0, &kr, sizeof(kr));
		break;
	case FEC_TYPE_IPV6:
		memset(&kr, 0, sizeof(kr));
		kr.af = AF_INET6;
		kr.prefix.v6 = fn->fec.u.ipv6.prefix;
		kr.prefixlen = fn->fec.u.ipv6.prefixlen;
		kr.nexthop.v6 = fnh->nexthop.v6;
		kr.ifindex = fnh->ifindex;
		kr.local_label = fn->local_label;
		kr.remote_label = fnh->remote_label;
		kr.route_type = fnh->route_type;
		kr.route_instance = fnh->route_instance;

		lde_imsg_compose_parent(IMSG_KLABEL_CHANGE, 0, &kr, sizeof(kr));
		break;
	case FEC_TYPE_PWID:
		pw = (struct l2vpn_pw *) fn->data;
		if (!pw || fn->local_label == NO_LABEL ||
		    fnh->remote_label == NO_LABEL)
			return;

		pw->enabled = true;
		pw2zpw(pw, &zpw);
		zpw.local_label = fn->local_label;
		zpw.remote_label = fnh->remote_label;
		lde_imsg_compose_parent(IMSG_KPW_SET, 0, &zpw, sizeof(zpw));
		break;
	}
}

void
lde_send_delete_klabel(struct fec_node *fn, struct fec_nh *fnh)
{
	struct kroute	 kr;
	struct zapi_pw	 zpw;
	struct l2vpn_pw	*pw;

	switch (fn->fec.type) {
	case FEC_TYPE_IPV4:
		memset(&kr, 0, sizeof(kr));
		kr.af = AF_INET;
		kr.prefix.v4 = fn->fec.u.ipv4.prefix;
		kr.prefixlen = fn->fec.u.ipv4.prefixlen;
		kr.nexthop.v4 = fnh->nexthop.v4;
		kr.ifindex = fnh->ifindex;
		kr.local_label = fn->local_label;
		kr.remote_label = fnh->remote_label;
		kr.route_type = fnh->route_type;
		kr.route_instance = fnh->route_instance;

		lde_imsg_compose_parent(IMSG_KLABEL_DELETE, 0, &kr, sizeof(kr));
		break;
	case FEC_TYPE_IPV6:
		memset(&kr, 0, sizeof(kr));
		kr.af = AF_INET6;
		kr.prefix.v6 = fn->fec.u.ipv6.prefix;
		kr.prefixlen = fn->fec.u.ipv6.prefixlen;
		kr.nexthop.v6 = fnh->nexthop.v6;
		kr.ifindex = fnh->ifindex;
		kr.local_label = fn->local_label;
		kr.remote_label = fnh->remote_label;
		kr.route_type = fnh->route_type;
		kr.route_instance = fnh->route_instance;

		lde_imsg_compose_parent(IMSG_KLABEL_DELETE, 0, &kr, sizeof(kr));
		break;
	case FEC_TYPE_PWID:
		pw = (struct l2vpn_pw *) fn->data;
		if (!pw)
			return;

		pw->enabled = false;
		pw2zpw(pw, &zpw);
		zpw.local_label = fn->local_label;
		zpw.remote_label = fnh->remote_label;
		lde_imsg_compose_parent(IMSG_KPW_UNSET, 0, &zpw, sizeof(zpw));
		break;
	}
}

void
lde_fec2prefix(const struct fec *fec, struct prefix *prefix)
{
	memset(prefix, 0, sizeof(*prefix));
	switch (fec->type) {
	case FEC_TYPE_IPV4:
		prefix->family = AF_INET;
		prefix->u.prefix4 = fec->u.ipv4.prefix;
		prefix->prefixlen = fec->u.ipv4.prefixlen;
		break;
	case FEC_TYPE_IPV6:
		prefix->family = AF_INET6;
		prefix->u.prefix6 = fec->u.ipv6.prefix;
		prefix->prefixlen = fec->u.ipv6.prefixlen;
		break;
	case FEC_TYPE_PWID:
		prefix->family = AF_UNSPEC;
		break;
	}
}

void
lde_prefix2fec(const struct prefix *prefix, struct fec *fec)
{
	memset(fec, 0, sizeof(*fec));
	switch (prefix->family) {
	case AF_INET:
		fec->type = FEC_TYPE_IPV4;
		fec->u.ipv4.prefix = prefix->u.prefix4;
		fec->u.ipv4.prefixlen = prefix->prefixlen;
		break;
	case AF_INET6:
		fec->type = FEC_TYPE_IPV6;
		fec->u.ipv6.prefix = prefix->u.prefix6;
		fec->u.ipv6.prefixlen = prefix->prefixlen;
		break;
	default:
		fatalx("lde_prefix2fec: unknown af");
		break;
	}
}

void
lde_fec2map(struct fec *fec, struct map *map)
{
	memset(map, 0, sizeof(*map));

	switch (fec->type) {
	case FEC_TYPE_IPV4:
		map->type = MAP_TYPE_PREFIX;
		map->fec.prefix.af = AF_INET;
		map->fec.prefix.prefix.v4 = fec->u.ipv4.prefix;
		map->fec.prefix.prefixlen = fec->u.ipv4.prefixlen;
		break;
	case FEC_TYPE_IPV6:
		map->type = MAP_TYPE_PREFIX;
		map->fec.prefix.af = AF_INET6;
		map->fec.prefix.prefix.v6 = fec->u.ipv6.prefix;
		map->fec.prefix.prefixlen = fec->u.ipv6.prefixlen;
		break;
	case FEC_TYPE_PWID:
		map->type = MAP_TYPE_PWID;
		map->fec.pwid.type = fec->u.pwid.type;
		map->fec.pwid.group_id = 0;
		SET_FLAG(map->flags, F_MAP_PW_ID);
		map->fec.pwid.pwid = fec->u.pwid.pwid;
		break;
	}
}

void
lde_map2fec(struct map *map, struct in_addr lsr_id, struct fec *fec)
{
	memset(fec, 0, sizeof(*fec));

	switch (map->type) {
	case MAP_TYPE_PREFIX:
		switch (map->fec.prefix.af) {
		case AF_INET:
			fec->type = FEC_TYPE_IPV4;
			fec->u.ipv4.prefix = map->fec.prefix.prefix.v4;
			fec->u.ipv4.prefixlen = map->fec.prefix.prefixlen;
			break;
		case AF_INET6:
			fec->type = FEC_TYPE_IPV6;
			fec->u.ipv6.prefix = map->fec.prefix.prefix.v6;
			fec->u.ipv6.prefixlen = map->fec.prefix.prefixlen;
			break;
		default:
			fatalx("lde_map2fec: unknown af");
			break;
		}
		break;
	case MAP_TYPE_PWID:
		fec->type = FEC_TYPE_PWID;
		fec->u.pwid.type = map->fec.pwid.type;
		fec->u.pwid.pwid = map->fec.pwid.pwid;
		fec->u.pwid.lsr_id = lsr_id;
		break;
	}
}

void
lde_send_labelmapping(struct lde_nbr *ln, struct fec_node *fn, int single)
{
	struct lde_wdraw	*lw;
	struct lde_map		*me;
	struct lde_req		*lre;
	struct map		 map;
	struct l2vpn_pw		*pw;
	struct fec_nh		*fnh;
	bool			 allow = false;

	/*
	 * Ordered Control: do not send a labelmap msg until
	 * a labelmap message is received from downstream router
	 * and don't send labelmap back to downstream router
	 */
	if (CHECK_FLAG(ldeconf->flags, F_LDPD_ORDERED_CONTROL)) {
		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			if (CHECK_FLAG(fnh->flags, F_FEC_NH_DEFER))
				continue;

			if (lde_address_find(ln, fnh->af, &fnh->nexthop))
				return;
			allow = true;
			break;
		}
		if (!allow)
			return;
	}

	/*
	 * We shouldn't send a new label mapping if we have a pending
	 * label release to receive. In this case, schedule to send a
	 * label mapping as soon as a label release is received.
	 */
	lw = (struct lde_wdraw *)fec_find(&ln->sent_wdraw, &fn->fec);
	if (lw) {
		if (!fec_find(&ln->sent_map_pending, &fn->fec)) {
			debug_evt("%s: FEC %s: scheduling to send label mapping later (waiting for pending label release)",
			    __func__, log_fec(&fn->fec));
			lde_map_pending_add(ln, fn);
		}
		return;
	}

	/*
	 * This function skips SL.1 - 3 and SL.9 - 14 because the label
	 * allocation is done way earlier (because of the merging nature of
	 * ldpd).
	 */

	lde_fec2map(&fn->fec, &map);
	switch (fn->fec.type) {
	case FEC_TYPE_IPV4:
		if (!ln->v4_enabled)
			return;

		if (lde_acl_check(ldeconf->ipv4.acl_label_advertise_to,
		    AF_INET, (union ldpd_addr *)&ln->id, 32) != FILTER_PERMIT)
			return;

		if (lde_acl_check(ldeconf->ipv4.acl_label_advertise_for,
		    AF_INET, (union ldpd_addr *)&fn->fec.u.ipv4.prefix,
		    fn->fec.u.ipv4.prefixlen) != FILTER_PERMIT)
			return;
		break;
	case FEC_TYPE_IPV6:
		if (!ln->v6_enabled)
			return;

		if (lde_acl_check(ldeconf->ipv6.acl_label_advertise_to,
		    AF_INET, (union ldpd_addr *)&ln->id, 32) != FILTER_PERMIT)
			return;

		if (lde_acl_check(ldeconf->ipv6.acl_label_advertise_for,
		    AF_INET6, (union ldpd_addr *)&fn->fec.u.ipv6.prefix,
		    fn->fec.u.ipv6.prefixlen) != FILTER_PERMIT)
			return;
		break;
	case FEC_TYPE_PWID:
		pw = (struct l2vpn_pw *) fn->data;
		if (pw == NULL || pw->lsr_id.s_addr != ln->id.s_addr)
			/* not the remote end of the pseudowire */
			return;

		SET_FLAG(map.flags, F_MAP_PW_IFMTU);
		map.fec.pwid.ifmtu = pw->l2vpn->mtu;

		if (CHECK_FLAG(pw->flags, F_PW_CWORD))
			SET_FLAG(map.flags, F_MAP_PW_CWORD);

		if (CHECK_FLAG(pw->flags, F_PW_STATUSTLV)) {
			SET_FLAG(map.flags, F_MAP_PW_STATUS);
			map.pw_status = pw->local_status;
		}
		break;
	}
	map.label = fn->local_label;

	/* SL.6: is there a pending request for this mapping? */
	lre = (struct lde_req *)fec_find(&ln->recv_req, &fn->fec);
	if (lre) {
		/* set label request msg id in the mapping response. */
		map.requestid = lre->msg_id;
		map.flags = F_MAP_REQ_ID;

		/* SL.7: delete record of pending request */
		lde_req_del(ln, lre, 0);
	}

	/* SL.4: send label mapping */
	lde_imsg_compose_ldpe(IMSG_MAPPING_ADD, ln->peerid, 0,
	    &map, sizeof(map));
	if (single)
		lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid, 0,
		    NULL, 0);

	/* SL.5: record sent label mapping */
	me = (struct lde_map *)fec_find(&ln->sent_map, &fn->fec);
	if (me == NULL)
		me = lde_map_add(ln, fn, 1);
	me->map = map;
}

void
lde_send_labelwithdraw(struct lde_nbr *ln, struct fec_node *fn,
    struct map *wcard, struct status_tlv *st)
{
	struct lde_wdraw	*lw;
	struct map		 map;
	struct fec		*f;
	struct l2vpn_pw		*pw;

	if (fn) {
		lde_fec2map(&fn->fec, &map);
		switch (fn->fec.type) {
		case FEC_TYPE_IPV4:
			if (!ln->v4_enabled)
				return;
			break;
		case FEC_TYPE_IPV6:
			if (!ln->v6_enabled)
				return;
			break;
		case FEC_TYPE_PWID:
			pw = (struct l2vpn_pw *) fn->data;
			if (pw == NULL || pw->lsr_id.s_addr != ln->id.s_addr)
				/* not the remote end of the pseudowire */
				return;

			if (CHECK_FLAG(pw->flags, F_PW_CWORD))
				SET_FLAG(map.flags, F_MAP_PW_CWORD);
			break;
		}
		map.label = fn->local_label;
	} else
		memcpy(&map, wcard, sizeof(map));

	if (st) {
		map.st.status_code = st->status_code;
		map.st.msg_id = st->msg_id;
		map.st.msg_type = st->msg_type;
		SET_FLAG(map.flags, F_MAP_STATUS);
	}

	/* SWd.1: send label withdraw. */
	lde_imsg_compose_ldpe(IMSG_WITHDRAW_ADD, ln->peerid, 0,
 	    &map, sizeof(map));
	lde_imsg_compose_ldpe(IMSG_WITHDRAW_ADD_END, ln->peerid, 0, NULL, 0);

	/* SWd.2: record label withdraw. */
	if (fn) {
		lw = (struct lde_wdraw *)fec_find(&ln->sent_wdraw, &fn->fec);
		if (lw == NULL)
			lw = lde_wdraw_add(ln, fn);
		lw->label = map.label;
	} else {
		struct lde_map *me;

		RB_FOREACH(f, fec_tree, &ft) {
			fn = (struct fec_node *)f;
			me = (struct lde_map *)fec_find(&ln->sent_map, &fn->fec);
			if (lde_wildcard_apply(wcard, &fn->fec, me) == 0)
				continue;

			lw = (struct lde_wdraw *)fec_find(&ln->sent_wdraw, &fn->fec);
			if (lw == NULL)
				lw = lde_wdraw_add(ln, fn);

			lw->label = map.label;
		}
	}
}

void
lde_send_labelwithdraw_wcard(struct lde_nbr *ln, uint32_t label)
{
	struct map	 wcard;

	memset(&wcard, 0, sizeof(wcard));
	wcard.type = MAP_TYPE_WILDCARD;
	wcard.label = label;
	lde_send_labelwithdraw(ln, NULL, &wcard, NULL);
}

void
lde_send_labelwithdraw_twcard_prefix(struct lde_nbr *ln, uint16_t af,
    uint32_t label)
{
	struct map	 wcard;

	memset(&wcard, 0, sizeof(wcard));
	wcard.type = MAP_TYPE_TYPED_WCARD;
	wcard.fec.twcard.type = MAP_TYPE_PREFIX;
	wcard.fec.twcard.u.prefix_af = af;
	wcard.label = label;
	lde_send_labelwithdraw(ln, NULL, &wcard, NULL);
}

void
lde_send_labelwithdraw_twcard_pwid(struct lde_nbr *ln, uint16_t pw_type,
    uint32_t label)
{
	struct map	 wcard;

	memset(&wcard, 0, sizeof(wcard));
	wcard.type = MAP_TYPE_TYPED_WCARD;
	wcard.fec.twcard.type = MAP_TYPE_PWID;
	wcard.fec.twcard.u.pw_type = pw_type;
	wcard.label = label;
	lde_send_labelwithdraw(ln, NULL, &wcard, NULL);
}

void
lde_send_labelwithdraw_pwid_wcard(struct lde_nbr *ln, uint16_t pw_type,
    uint32_t group_id)
{
	struct map	 wcard;

	memset(&wcard, 0, sizeof(wcard));
	wcard.type = MAP_TYPE_PWID;
	wcard.fec.pwid.type = pw_type;
	wcard.fec.pwid.group_id = group_id;
	/* we can not append a Label TLV when using PWid group wildcards. */
	wcard.label = NO_LABEL;
	lde_send_labelwithdraw(ln, NULL, &wcard, NULL);
}

void
lde_send_labelrelease(struct lde_nbr *ln, struct fec_node *fn,
    struct map *wcard, uint32_t label)
{
	struct map		 map;
	struct l2vpn_pw		*pw;

	if (fn) {
		lde_fec2map(&fn->fec, &map);
		switch (fn->fec.type) {
		case FEC_TYPE_IPV4:
			if (!ln->v4_enabled)
				return;
			break;
		case FEC_TYPE_IPV6:
			if (!ln->v6_enabled)
				return;
			break;
		case FEC_TYPE_PWID:
			pw = (struct l2vpn_pw *) fn->data;
			if (pw == NULL || pw->lsr_id.s_addr != ln->id.s_addr)
				/* not the remote end of the pseudowire */
				return;

			if (CHECK_FLAG(pw->flags, F_PW_CWORD))
				SET_FLAG(map.flags, F_MAP_PW_CWORD);
			break;
		}
	} else
		memcpy(&map, wcard, sizeof(map));
	map.label = label;

	lde_imsg_compose_ldpe(IMSG_RELEASE_ADD, ln->peerid, 0,
	    &map, sizeof(map));
	lde_imsg_compose_ldpe(IMSG_RELEASE_ADD_END, ln->peerid, 0, NULL, 0);
}

void
lde_send_labelrequest(struct lde_nbr *ln, struct fec_node *fn,
		      struct map *wcard, int single)
{
	struct map		 map;
	struct fec		*f;
	struct lde_req		*lre;

	if (fn) {
		lde_fec2map(&fn->fec, &map);
		switch (fn->fec.type) {
		case FEC_TYPE_IPV4:
			if (!ln->v4_enabled)
				return;
			break;
		case FEC_TYPE_IPV6:
			if (!ln->v6_enabled)
				return;
			break;
		case FEC_TYPE_PWID:
			fatalx("lde_send_labelrequest: unknown af");
		}
	} else
		memcpy(&map, wcard, sizeof(map));

	map.label = NO_LABEL;

	if (fn) {
		/* SLR1.1: has label request for FEC been previously sent
		 * and still outstanding just return,
		 */
		lre = (struct  lde_req *)fec_find(&ln->sent_req, &fn->fec);
		if (lre == NULL) {
			/* SLRq.3: send label request */
			lde_imsg_compose_ldpe(IMSG_REQUEST_ADD, ln->peerid, 0,
			    &map, sizeof(map));
			if (single)
				lde_imsg_compose_ldpe(IMSG_REQUEST_ADD_END,
				    ln->peerid, 0, NULL, 0);

			/* SLRq.4: record sent request */
			lde_req_add(ln, &fn->fec, 1);
		}
	} else {
		/* if Wilcard just send label request */
		/* SLRq.3: send label request */
		lde_imsg_compose_ldpe(IMSG_REQUEST_ADD,
		    ln->peerid, 0, &map, sizeof(map));
		if (single)
			lde_imsg_compose_ldpe(IMSG_REQUEST_ADD_END, ln->peerid, 0, NULL, 0);

		/* SLRq.4: record sent request */
		RB_FOREACH(f, fec_tree, &ft) {
			fn = (struct fec_node *)f;
			lre = (struct lde_req *)fec_find(&ln->sent_req, &fn->fec);
			if (lde_wildcard_apply(wcard, &fn->fec, NULL) == 0)
				continue;
			if (lre == NULL)
				lde_req_add(ln, f, 1);
		}
	}
}

void
lde_send_labelrequest_wcard(struct lde_nbr *ln, uint16_t af)
{
	struct map	 wcard;

	memset(&wcard, 0, sizeof(wcard));
	wcard.type = MAP_TYPE_TYPED_WCARD;
	wcard.fec.twcard.type = MAP_TYPE_PREFIX;
	wcard.fec.twcard.u.prefix_af = af;
	lde_send_labelrequest(ln, NULL, &wcard, 1);
}

void
lde_send_notification(struct lde_nbr *ln, uint32_t status_code, uint32_t msg_id,
    uint16_t msg_type)
{
	struct notify_msg nm;

	memset(&nm, 0, sizeof(nm));
	nm.status_code = status_code;
	/* 'msg_id' and 'msg_type' should be in network byte order */
	nm.msg_id = msg_id;
	nm.msg_type = msg_type;

	lde_imsg_compose_ldpe(IMSG_NOTIFICATION_SEND, ln->peerid, 0,
	    &nm, sizeof(nm));
}

void
lde_send_notification_eol_prefix(struct lde_nbr *ln, int af)
{
	struct notify_msg nm;

	memset(&nm, 0, sizeof(nm));
	nm.status_code = S_ENDOFLIB;
	nm.fec.type = MAP_TYPE_TYPED_WCARD;
	nm.fec.fec.twcard.type = MAP_TYPE_PREFIX;
	nm.fec.fec.twcard.u.prefix_af = af;
	SET_FLAG(nm.flags, F_NOTIF_FEC);

	lde_imsg_compose_ldpe(IMSG_NOTIFICATION_SEND, ln->peerid, 0,
	    &nm, sizeof(nm));
}

void
lde_send_notification_eol_pwid(struct lde_nbr *ln, uint16_t pw_type)
{
	struct notify_msg nm;

	memset(&nm, 0, sizeof(nm));
	nm.status_code = S_ENDOFLIB;
	nm.fec.type = MAP_TYPE_TYPED_WCARD;
	nm.fec.fec.twcard.type = MAP_TYPE_PWID;
	nm.fec.fec.twcard.u.pw_type = pw_type;
	SET_FLAG(nm.flags, F_NOTIF_FEC);

	lde_imsg_compose_ldpe(IMSG_NOTIFICATION_SEND, ln->peerid, 0,
	    &nm, sizeof(nm));
}

static __inline int
lde_nbr_compare(const struct lde_nbr *a, const struct lde_nbr *b)
{
	return (a->peerid - b->peerid);
}

static struct lde_nbr *
lde_nbr_new(uint32_t peerid, struct lde_nbr *new)
{
	struct lde_nbr	*ln;

	if ((ln = calloc(1, sizeof(*ln))) == NULL)
		fatal(__func__);

	ln->id = new->id;
	ln->v4_enabled = new->v4_enabled;
	ln->v6_enabled = new->v6_enabled;
	ln->flags = new->flags;
	ln->peerid = peerid;
	fec_init(&ln->recv_map);
	fec_init(&ln->sent_map);
	fec_init(&ln->sent_map_pending);
	fec_init(&ln->recv_req);
	fec_init(&ln->sent_req);
	fec_init(&ln->sent_wdraw);

	TAILQ_INIT(&ln->addr_list);

	if (RB_INSERT(nbr_tree, &lde_nbrs, ln) != NULL)
		fatalx("lde_nbr_new: RB_INSERT failed");

	return (ln);
}

static void
lde_nbr_del(struct lde_nbr *ln)
{
	struct fec		*f;
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct l2vpn_pw		*pw;
	struct lde_nbr		*lnbr;

	if (ln == NULL)
		return;

	/* uninstall received mappings */
	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;

		/* Update RLFA clients. */
		lde_rlfa_update_clients(f, ln, MPLS_INVALID_LABEL);

		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			switch (f->type) {
			case FEC_TYPE_IPV4:
			case FEC_TYPE_IPV6:
				if (!lde_address_find(ln, fnh->af, &fnh->nexthop))
					continue;

				/*
				 * Ordered Control: must mark any non-connected
				 * NH to wait until we receive a labelmap msg
				 * before installing in kernel and sending to
				 * peer, must do this as NHs are not removed
				 * when lsps go down.  Also send label withdraw
				 * to other neighbors for all fecs from neighbor
				 * going down
				 */
				if (CHECK_FLAG(ldeconf->flags, F_LDPD_ORDERED_CONTROL)) {
					SET_FLAG(fnh->flags, F_FEC_NH_DEFER);

					RB_FOREACH(lnbr, nbr_tree, &lde_nbrs) {
						if (ln->peerid == lnbr->peerid)
							continue;
						lde_send_labelwithdraw(lnbr, fn, NULL, NULL);
					}
				}
				break;
			case FEC_TYPE_PWID:
				if (f->u.pwid.lsr_id.s_addr != ln->id.s_addr)
					continue;
				pw = (struct l2vpn_pw *) fn->data;
				if (pw) {
					pw->reason = F_PW_NO_REMOTE_LABEL;
					l2vpn_pw_reset(pw);
				}
				break;
			default:
				break;
			}

			lde_send_delete_klabel(fn, fnh);
			fnh->remote_label = NO_LABEL;
		}
	}

	lde_address_list_free(ln);

	fec_clear(&ln->recv_map, lde_map_free);
	fec_clear(&ln->sent_map, lde_map_free);
	fec_clear(&ln->sent_map_pending, free);
	fec_clear(&ln->recv_req, free);
	fec_clear(&ln->sent_req, free);
	fec_clear(&ln->sent_wdraw, free);

	RB_REMOVE(nbr_tree, &lde_nbrs, ln);

	free(ln);
}

static struct lde_nbr *
lde_nbr_find(uint32_t peerid)
{
	struct lde_nbr		 ln;

	ln.peerid = peerid;

	return (RB_FIND(nbr_tree, &lde_nbrs, &ln));
}

struct lde_nbr *
lde_nbr_find_by_lsrid(struct in_addr addr)
{
	struct lde_nbr		*ln;

	RB_FOREACH(ln, nbr_tree, &lde_nbrs)
		if (ln->id.s_addr == addr.s_addr)
			return (ln);

	return (NULL);
}

struct lde_nbr *
lde_nbr_find_by_addr(int af, union ldpd_addr *addr)
{
	struct lde_nbr		*ln;

	RB_FOREACH(ln, nbr_tree, &lde_nbrs)
		if (lde_address_find(ln, af, addr) != NULL)
			return (ln);

	return (NULL);
}

static void
lde_nbr_clear(void)
{
	struct lde_nbr	*ln;

	while (!RB_EMPTY(nbr_tree, &lde_nbrs)) {
		ln = RB_ROOT(nbr_tree, &lde_nbrs);

		lde_nbr_del(ln);
	}
}

static void
lde_nbr_addr_update(struct lde_nbr *ln, struct lde_addr *lde_addr, int removed)
{
	struct fec		*fec;
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct lde_map		*me;

	RB_FOREACH(fec, fec_tree, &ln->recv_map) {
		switch (fec->type) {
		case FEC_TYPE_IPV4:
			if (lde_addr->af != AF_INET)
				continue;
			break;
		case FEC_TYPE_IPV6:
			if (lde_addr->af != AF_INET6)
				continue;
			break;
		case FEC_TYPE_PWID:
			continue;
		}

		fn = (struct fec_node *)fec_find(&ft, fec);
		if (fn == NULL)
			/* shouldn't happen */
			continue;

		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			if (ldp_addrcmp(fnh->af, &fnh->nexthop, &lde_addr->addr))
				continue;

			if (removed) {
				lde_send_delete_klabel(fn, fnh);
				fnh->remote_label = NO_LABEL;
			} else {
				me = (struct lde_map *)fec;
				fnh->remote_label = me->map.label;
				lde_send_change_klabel(fn, fnh);
			}
			break;
		}
	}
}

void
lde_allow_broken_lsp_update(int new_config)
{
	struct fec_node		*fn;
	struct fec_nh		*fnh;
	struct fec		*f;

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;

		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			/* allow-broken-lsp config is changing so
			 * we need to reprogram labeled routes to
			 * have proper top-level label
			 */
			if (!(new_config & F_LDPD_ALLOW_BROKEN_LSP))
				lde_send_delete_klabel(fn, fnh);

			if (fn->local_label != NO_LABEL)
				lde_send_change_klabel(fn, fnh);
		}
	}
}

static __inline int
lde_map_compare(const struct lde_map *a, const struct lde_map *b)
{
	return (ldp_addrcmp(AF_INET, (union ldpd_addr *)&a->nexthop->id,
	    (union ldpd_addr *)&b->nexthop->id));
}

struct lde_map *
lde_map_add(struct lde_nbr *ln, struct fec_node *fn, int sent)
{
	struct lde_map  *me;

	me = calloc(1, sizeof(*me));
	if (me == NULL)
		fatal(__func__);

	me->fec = fn->fec;
	me->nexthop = ln;

	if (sent) {
		RB_INSERT(lde_map_head, &fn->upstream, me);
		me->head = &fn->upstream;
		if (fec_insert(&ln->sent_map, &me->fec))
			log_warnx("failed to add %s to sent map", log_fec(&me->fec));
			/* XXX on failure more cleanup is needed */
	} else {
		RB_INSERT(lde_map_head, &fn->downstream, me);
		me->head = &fn->downstream;
		if (fec_insert(&ln->recv_map, &me->fec))
			log_warnx("failed to add %s to recv map", log_fec(&me->fec));
	}

	return (me);
}

void
lde_map_del(struct lde_nbr *ln, struct lde_map *me, int sent)
{
	if (sent)
		fec_remove(&ln->sent_map, &me->fec);
	else
		fec_remove(&ln->recv_map, &me->fec);

	lde_map_free(me);
}

static void
lde_map_free(void *ptr)
{
	struct lde_map	*map = ptr;

	RB_REMOVE(lde_map_head, map->head, map);
	free(map);
}

struct fec *
lde_map_pending_add(struct lde_nbr *ln, struct fec_node *fn)
{
	struct fec	*map;

	map = calloc(1, sizeof(*map));
	if (map == NULL)
		fatal(__func__);

	*map = fn->fec;
	if (fec_insert(&ln->sent_map_pending, map))
		log_warnx("failed to add %s to sent map (pending)", log_fec(map));

	return (map);
}

void
lde_map_pending_del(struct lde_nbr *ln, struct fec *map)
{
	fec_remove(&ln->sent_map_pending, map);
	free(map);
}

struct lde_req *
lde_req_add(struct lde_nbr *ln, struct fec *fec, int sent)
{
	struct fec_tree	*t;
	struct lde_req	*lre;

	t = sent ? &ln->sent_req : &ln->recv_req;

	lre = calloc(1, sizeof(*lre));
	if (lre != NULL) {
		lre->fec = *fec;

		if (fec_insert(t, &lre->fec)) {
			log_warnx("failed to add %s to %s req",
			    log_fec(&lre->fec), sent ? "sent" : "recv");
			free(lre);
			return (NULL);
		}
	}

	return (lre);
}

void
lde_req_del(struct lde_nbr *ln, struct lde_req *lre, int sent)
{
	if (sent)
		fec_remove(&ln->sent_req, &lre->fec);
	else
		fec_remove(&ln->recv_req, &lre->fec);

	free(lre);
}

struct lde_wdraw *
lde_wdraw_add(struct lde_nbr *ln, struct fec_node *fn)
{
	struct lde_wdraw  *lw;

	lw = calloc(1, sizeof(*lw));
	if (lw == NULL)
		fatal(__func__);

	lw->fec = fn->fec;

	if (fec_insert(&ln->sent_wdraw, &lw->fec))
		log_warnx("failed to add %s to sent wdraw", log_fec(&lw->fec));

	return (lw);
}

void
lde_wdraw_del(struct lde_nbr *ln, struct lde_wdraw *lw)
{
	fec_remove(&ln->sent_wdraw, &lw->fec);
	free(lw);
}

void
lde_change_egress_label(int af)
{
	struct lde_nbr	*ln;
	struct fec	*f;
	struct fec_node	*fn;

	/* explicitly withdraw all null labels */
	RB_FOREACH(ln, nbr_tree, &lde_nbrs) {
		lde_send_labelwithdraw_wcard(ln, MPLS_LABEL_IMPLICIT_NULL);
		if (ln->v4_enabled)
			lde_send_labelwithdraw_wcard(ln, MPLS_LABEL_IPV4_EXPLICIT_NULL);
		if (ln->v6_enabled)
			lde_send_labelwithdraw_wcard(ln, MPLS_LABEL_IPV6_EXPLICIT_NULL);
	}

	/* update label of connected routes */
	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		if (fn->local_label > MPLS_LABEL_RESERVED_MAX)
			continue;

		switch (af) {
		case AF_INET:
			if (fn->fec.type != FEC_TYPE_IPV4)
				continue;
			break;
		case AF_INET6:
			if (fn->fec.type != FEC_TYPE_IPV6)
				continue;
			break;
		default:
			fatalx("lde_change_egress_label: unknown af");
		}

		fn->local_label = lde_update_label(fn);
		if (fn->local_label != NO_LABEL)
			RB_FOREACH(ln, nbr_tree, &lde_nbrs)
				lde_send_labelmapping(ln, fn, 0);
	}
	RB_FOREACH(ln, nbr_tree, &lde_nbrs)
		lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid, 0, NULL, 0);
}

void
lde_change_allocate_filter(int af)
{
	struct lde_nbr  *ln;
	struct fec      *f;
	struct fec_node *fn;
	uint32_t         new_label;

	/* reallocate labels for fecs that match this filter */
	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;

		switch (af) {
		case AF_INET:
			if (fn->fec.type != FEC_TYPE_IPV4)
				continue;
			break;
		case AF_INET6:
			if (fn->fec.type != FEC_TYPE_IPV6)
				continue;
			break;
		default:
			fatalx("lde_change_allocate_filter: unknown af");
		}

		/*
		 * If the local label has changed to NO_LABEL, send a label
		 * withdraw to all peers.
		 * If the local label has changed and it's different from
		 * NO_LABEL, send a label mapping to all peers advertising
		 * the new label.
		 * If the local label hasn't changed, do nothing
		 */
		new_label = lde_update_label(fn);
		if (fn->local_label != new_label) {
			if (new_label == NO_LABEL)
				RB_FOREACH(ln, nbr_tree, &lde_nbrs)
					lde_send_labelwithdraw(ln, fn, NULL, NULL);

			fn->local_label = new_label;
			if (fn->local_label != NO_LABEL)
				RB_FOREACH(ln, nbr_tree, &lde_nbrs)
					lde_send_labelmapping(ln, fn, 0);
		}
	}

	RB_FOREACH(ln, nbr_tree, &lde_nbrs)
		lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid, 0,
		    NULL, 0);
}

void
lde_change_advertise_filter(int af)
{
	struct lde_nbr  *ln;
	struct fec      *f;
	struct fec_node *fn;
	char            *acl_to_filter;
	char            *acl_for_filter;
	union ldpd_addr *prefix;
	uint8_t          plen;
	struct lde_map  *me;

	/* advertise label for fecs to neighbors if matches advertise filters */
	switch (af) {
	case AF_INET:
		acl_to_filter = ldeconf->ipv4.acl_label_advertise_to;
		acl_for_filter = ldeconf->ipv4.acl_label_advertise_for;
		break;
	case AF_INET6:
		acl_to_filter = ldeconf->ipv6.acl_label_advertise_to;
		acl_for_filter = ldeconf->ipv6.acl_label_advertise_for;
		break;
	default:
		fatalx("lde_change_advertise_filter: unknown af");
	}

	RB_FOREACH(ln, nbr_tree, &lde_nbrs) {
		if (lde_acl_check(acl_to_filter, af, (union ldpd_addr *)&ln->id,
		    IPV4_MAX_BITLEN) != FILTER_PERMIT)
			lde_send_labelwithdraw_wcard(ln, NO_LABEL);
		else {
			/* This neighbor is allowed in to_filter, so
			 * send labels if fec also matches for_filter
			 */
			RB_FOREACH(f, fec_tree, &ft) {
				fn = (struct fec_node *)f;
				switch (af) {
				case AF_INET:
					if (fn->fec.type != FEC_TYPE_IPV4)
						continue;
					prefix = (union ldpd_addr *)&fn->fec.u.ipv4.prefix;
					plen = fn->fec.u.ipv4.prefixlen;
					break;
				case FEC_TYPE_IPV6:
					if (fn->fec.type != FEC_TYPE_IPV6)
						continue;
					prefix = (union ldpd_addr *)&fn->fec.u.ipv6.prefix;
					plen = fn->fec.u.ipv6.prefixlen;
					break;
				default:
					continue;
				}

				if (lde_acl_check(acl_for_filter, af,
				    prefix, plen) != FILTER_PERMIT) {
					me = (struct lde_map *)fec_find(&ln->sent_map, &fn->fec);
					if (me)
						/* fec filtered withdraw */
						lde_send_labelwithdraw(ln, fn, NULL, NULL);
				} else
					/* fec allowed send map */
					lde_send_labelmapping(ln, fn, 0);
			}
			lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid, 0, NULL, 0);
		}
	}
}


void
lde_change_accept_filter(int af)
{
	struct lde_nbr  *ln;
	struct fec      *f;
	struct fec_node *fn;
	char            *acl_for_filter;
	char            *acl_from_filter;
	union ldpd_addr *prefix;
	uint8_t          plen;
	struct lde_map  *me;
	enum fec_type    type;

	/* accept labels from neighbors specified in the from_filter and for
	 * fecs defined in the for_filter
	 */
	switch (af) {
	case AF_INET:
		acl_for_filter = ldeconf->ipv4.acl_label_accept_for;
		acl_from_filter = ldeconf->ipv4.acl_label_accept_from;
		type = FEC_TYPE_IPV4;
		break;
	case AF_INET6:
		acl_for_filter = ldeconf->ipv6.acl_label_accept_for;
		acl_from_filter = ldeconf->ipv6.acl_label_accept_from;
		type = FEC_TYPE_IPV6;
		break;
	default:
		fatalx("lde_change_accept_filter: unknown af");
	}

	RB_FOREACH(ln, nbr_tree, &lde_nbrs) {
		if (lde_acl_check(acl_from_filter, AF_INET, (union ldpd_addr *)
		    &ln->id, IPV4_MAX_BITLEN) != FILTER_PERMIT) {
			/* This neighbor is now filtered so remove fecs from
			 * recv list
			 */
			RB_FOREACH(f, fec_tree, &ft) {
				fn = (struct fec_node *)f;
				if (fn->fec.type == type) {
					me = (struct lde_map *)fec_find(&ln->recv_map, &fn->fec);
					if (me)
						lde_map_del(ln, me, 0);
				}
			}
		} else if (CHECK_FLAG(ln->flags, F_NBR_CAP_TWCARD)) {
			/* This neighbor is allowed and supports type
			 * wildcard so send a labelrequest
			 * to get any new labels from neighbor
			 * and make sure any fecs we currently have
			 * match for_filter.
			 */
			RB_FOREACH(f, fec_tree, &ft) {
				fn = (struct fec_node *)f;
				switch (af) {
				case AF_INET:
					if (fn->fec.type != FEC_TYPE_IPV4)
						continue;
					prefix = (union ldpd_addr *)&fn->fec.u.ipv4.prefix;
					plen = fn->fec.u.ipv4.prefixlen;
					break;
				case AF_INET6:
					if (fn->fec.type != FEC_TYPE_IPV6)
						continue;
					prefix = (union ldpd_addr *)&fn->fec.u.ipv6.prefix;
					plen = fn->fec.u.ipv6.prefixlen;
					break;
				default:
					continue;
				}
				if (lde_acl_check(acl_for_filter, af,
				    prefix, plen) != FILTER_PERMIT) {
					me = (struct lde_map *)fec_find(&ln->recv_map, &fn->fec);
					if (me)
						lde_map_del(ln, me, 0);
				}
			}
			lde_send_labelrequest_wcard(ln, af);
		} else
			/* Type Wildcard is not supported so restart session */
			lde_imsg_compose_ldpe(IMSG_NBR_SHUTDOWN, ln->peerid, 0, NULL, 0);
	}
}

void
lde_change_expnull_for_filter(int af)
{
	struct lde_nbr  *ln;
	struct fec      *f;
	struct fec_node *fn;
	char            *acl_name;
	uint32_t         exp_label;
	union ldpd_addr *prefix;
	uint8_t          plen;

	/* Configure explicit-null advertisement for all fecs in this filter */
	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;

		switch (af) {
		case AF_INET:
			if (fn->fec.type != FEC_TYPE_IPV4)
				continue;
			acl_name = ldeconf->ipv4.acl_label_expnull_for;
			prefix = (union ldpd_addr *)&fn->fec.u.ipv4.prefix;
			plen = fn->fec.u.ipv4.prefixlen;
			exp_label = MPLS_LABEL_IPV4_EXPLICIT_NULL;
			break;
		case AF_INET6:
			if (fn->fec.type != FEC_TYPE_IPV6)
				continue;
			acl_name = ldeconf->ipv6.acl_label_expnull_for;
			prefix = (union ldpd_addr *)&fn->fec.u.ipv6.prefix;
			plen = fn->fec.u.ipv6.prefixlen;
			exp_label = MPLS_LABEL_IPV6_EXPLICIT_NULL;
			break;
		default:
			fatalx("lde_change_expnull_for_filter: unknown af");
		}

		if (lde_acl_check(acl_name, af, prefix, plen) == FILTER_PERMIT) {
			/* for this fec change any imp-null to exp-null */
			if (fn->local_label == MPLS_LABEL_IMPLICIT_NULL) {
				fn->local_label= lde_update_label(fn);
				RB_FOREACH(ln, nbr_tree, &lde_nbrs)
					lde_send_labelmapping(ln, fn, 0);
			}
		} else {
			/* for this fec change any exp-null back to imp-null */
			if (fn->local_label == exp_label) {
				fn->local_label = lde_update_label(fn);
				RB_FOREACH(ln, nbr_tree, &lde_nbrs)
					lde_send_labelmapping(ln, fn, 0);
			}
		}
	}
	RB_FOREACH(ln, nbr_tree, &lde_nbrs)
		lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid, 0,
		    NULL, 0);
}

static int
lde_address_add(struct lde_nbr *ln, struct lde_addr *lde_addr)
{
	struct lde_addr		*new;

	if (lde_address_find(ln, lde_addr->af, &lde_addr->addr) != NULL)
		return (-1);

	if ((new = calloc(1, sizeof(*new))) == NULL)
		fatal(__func__);

	new->af = lde_addr->af;
	new->addr = lde_addr->addr;
	TAILQ_INSERT_TAIL(&ln->addr_list, new, entry);

	/* reevaluate the previously received mappings from this neighbor */
	lde_nbr_addr_update(ln, lde_addr, 0);

	return (0);
}

static int
lde_address_del(struct lde_nbr *ln, struct lde_addr *lde_addr)
{
	lde_addr = lde_address_find(ln, lde_addr->af, &lde_addr->addr);
	if (lde_addr == NULL)
		return (-1);

	/* reevaluate the previously received mappings from this neighbor */
	lde_nbr_addr_update(ln, lde_addr, 1);

	TAILQ_REMOVE(&ln->addr_list, lde_addr, entry);
	free(lde_addr);

	return (0);
}

struct lde_addr *
lde_address_find(struct lde_nbr *ln, int af, union ldpd_addr *addr)
{
	struct lde_addr		*lde_addr;

	TAILQ_FOREACH(lde_addr, &ln->addr_list, entry)
		if (lde_addr->af == af &&
		    ldp_addrcmp(af, &lde_addr->addr, addr) == 0)
			return (lde_addr);

	return (NULL);
}

static void
lde_address_list_free(struct lde_nbr *ln)
{
	struct lde_addr		*lde_addr;

	while ((lde_addr = TAILQ_POP_FIRST(&ln->addr_list, entry)) != NULL)
		free(lde_addr);
}

/*
 * Event callback used to retry the label-manager sync zapi session.
 */
static void zclient_sync_retry(struct event *thread)
{
	zclient_sync_init();
}

/*
 * Initialize and open a synchronous zapi session. This is used by label chunk
 * management code, which acquires and releases blocks of labels from the
 * zebra label-manager module.
 */
static void zclient_sync_init(void)
{
	struct zclient_options options = zclient_options_default;

	options.synchronous = true;

	/* Initialize special zclient for synchronous message exchanges. */
	zclient_sync = zclient_new(master, &options, NULL, 0);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_LDP;
	zclient_sync->session_id = 1; /* Distinguish from main session */
	zclient_sync->privs = &lde_privs;

	if (zclient_socket_connect(zclient_sync) < 0) {
		log_warnx("Error connecting synchronous zclient!");
		goto retry;
	}
	/* make socket non-blocking */
	sock_set_nonblock(zclient_sync->sock);

	/* Send hello to notify zebra this is a synchronous client */
	if (zclient_send_hello(zclient_sync) == ZCLIENT_SEND_FAILURE) {
		log_warnx("Error sending hello for synchronous zclient!");
		goto retry;
	}

	/* Connect to label manager */
	if (lm_label_manager_connect(zclient_sync, 0) != 0) {
		log_warnx("Error connecting to label manager!");
		goto retry;
	}

	/* Finish label-manager init once the LM session is running */
	lde_label_list_init();

	return;

retry:

	/* Discard failed zclient object */
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
	zclient_sync = NULL;

	/* Retry using a timer */
	event_add_timer(master, zclient_sync_retry, NULL, 1, NULL);
}

static void
lde_del_label_chunk(void *val)
{
	free(val);
}

static int
lde_release_label_chunk(uint32_t start, uint32_t end)
{
	int		ret;

	ret = lm_release_label_chunk(zclient_sync, start, end);
	if (ret < 0) {
		log_warnx("Error releasing label chunk!");
		return (-1);
	}
	return (0);
}

static int
lde_get_label_chunk(void)
{
	int		 ret;
	uint32_t	 start, end;

	debug_labels("getting label chunk (size %u)", CHUNK_SIZE);
	ret = lm_get_label_chunk(zclient_sync, 0, MPLS_LABEL_BASE_ANY,
				 CHUNK_SIZE, &start, &end);
	if (ret < 0) {
		log_warnx("Error getting label chunk!");
		return -1;
	}

	on_get_label_chunk_response(start, end);

	return (0);
}

static void
lde_label_list_init(void)
{
	label_chunk_list = list_new();
	label_chunk_list->del = lde_del_label_chunk;

	/* get first chunk */
	while (lde_get_label_chunk () != 0) {
		log_warnx("Error getting first label chunk!");
		sleep(1);
	}
}

static void
on_get_label_chunk_response(uint32_t start, uint32_t end)
{
	struct label_chunk *new_label_chunk;

	debug_labels("label chunk assign: %u - %u", start, end);

	new_label_chunk = calloc(1, sizeof(struct label_chunk));
	if (!new_label_chunk) {
		log_warn("Error trying to allocate label chunk %u - %u", start, end);
		return;
	}

	new_label_chunk->start = start;
	new_label_chunk->end = end;
	new_label_chunk->used_mask = 0;

	listnode_add(label_chunk_list, (void *)new_label_chunk);

	/* let's update current if needed */
	if (!current_label_chunk)
		current_label_chunk = listtail(label_chunk_list);
}

void
lde_free_label(uint32_t label)
{
	struct listnode	*node;
	struct label_chunk	*label_chunk;
	uint64_t		pos;

	for (ALL_LIST_ELEMENTS_RO(label_chunk_list, node, label_chunk)) {
		if (label <= label_chunk->end && label >= label_chunk->start) {
			pos = 1ULL << (label - label_chunk->start);
			UNSET_FLAG(label_chunk->used_mask, pos);
			/* if nobody is using this chunk and it's not current_label_chunk, then free it */
			if (!label_chunk->used_mask && (current_label_chunk != node)) {
				if (lde_release_label_chunk(label_chunk->start, label_chunk->end) != 0)
					log_warnx("%s: Error releasing label chunk!", __func__);
				else {
					listnode_delete(label_chunk_list, label_chunk);
					lde_del_label_chunk(label_chunk);
				}
			}
			break;
		}
	}

	return;
}

static uint32_t
lde_get_next_label(void)
{
	struct label_chunk	*label_chunk;
	uint32_t		 i, size;
	uint64_t		 pos;
	uint32_t		 label = NO_LABEL;

	while (current_label_chunk) {
		label_chunk = listgetdata(current_label_chunk);
		if (!label_chunk)
			goto end;

		/* try to get next free label in currently used label chunk */
		size = label_chunk->end - label_chunk->start + 1;
		for (i = 0, pos = 1; i < size; i++, pos <<= 1) {
			if (!(pos & label_chunk->used_mask)) {
				SET_FLAG(label_chunk->used_mask, pos);
				label = label_chunk->start + i;
				goto end;
			}
		}
		current_label_chunk = listnextnode(current_label_chunk);
	}

end:
	/* we moved till the last chunk, or were not able to find a label,
	   so let's ask for another one */
	if (!current_label_chunk ||
	    current_label_chunk == listtail(label_chunk_list) ||
	    label == NO_LABEL) {
		if (lde_get_label_chunk() != 0)
			log_warn("%s: Error getting label chunk!", __func__);

	}

	return (label);
}

static void
lde_check_filter_af(int af, struct ldpd_af_conf *af_conf,
    const char *filter_name)
{
	if (strcmp(af_conf->acl_label_allocate_for, filter_name) == 0)
		lde_change_allocate_filter(af);

	if ((strcmp(af_conf->acl_label_advertise_to, filter_name) == 0)
	    || (strcmp(af_conf->acl_label_advertise_for, filter_name) == 0))
		lde_change_advertise_filter(af);

	if ((strcmp(af_conf->acl_label_accept_for, filter_name) == 0)
	    || (strcmp(af_conf->acl_label_accept_from, filter_name) == 0))
		lde_change_accept_filter(af);

	if (strcmp(af_conf->acl_label_expnull_for, filter_name) == 0)
		lde_change_expnull_for_filter(af);
}

void lde_route_update(struct iface *iface, int af)
{
	struct fec	*f;
	struct fec_node	*fn;
	struct fec_nh	*fnh;
	struct lde_nbr  *ln;

	/* update label of non-connected routes */
	log_debug("update labels for interface %s", iface->name);

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		if (IS_MPLS_UNRESERVED_LABEL(fn->local_label))
			continue;

		switch (af) {
		case AF_INET:
			if (fn->fec.type != FEC_TYPE_IPV4)
				continue;
			break;
		case AF_INET6:
			if (fn->fec.type != FEC_TYPE_IPV6)
				continue;
			break;
		default:
			/* unspecified so process both address families */
			break;
		}

		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			/*
			 * If connected leave existing label. If LDP
			 * configured on interface or a static route
			 * may need new label. If no LDP configured
			 * treat fec as a connected route
			 */
			if (CHECK_FLAG(fnh->flags, F_FEC_NH_CONNECTED))
				break;

			if (fnh->ifindex != iface->ifindex)
				continue;

			UNSET_FLAG(fnh->flags, F_FEC_NH_NO_LDP);
			if (IS_MPLS_RESERVED_LABEL(fn->local_label)) {
				fn->local_label = NO_LABEL;
				fn->local_label = lde_update_label(fn);
				if (fn->local_label != NO_LABEL)
					RB_FOREACH(ln, nbr_tree, &lde_nbrs)
						lde_send_labelmapping(
						    ln, fn, 0);
			}
			break;
		}
	}

	RB_FOREACH(ln, nbr_tree, &lde_nbrs)
		lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid,
		    0, NULL, 0);
}

void lde_route_update_release(struct iface *iface, int af)
{
	struct lde_nbr	*ln;
	struct fec	*f;
	struct fec_node	*fn;
	struct fec_nh	*fnh;

	/* update label of interfaces no longer running LDP */
	log_debug("release all labels for interface %s af %s", iface->name,
	    af == AF_INET ? "ipv4" : "ipv6");

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;

		switch (af) {
		case AF_INET:
			if (fn->fec.type != FEC_TYPE_IPV4)
				continue;
			break;
		case AF_INET6:
			if (fn->fec.type != FEC_TYPE_IPV6)
				continue;
			break;
		default:
			fatalx("lde_route_update_release: unknown af");
		}

		if (fn->local_label == NO_LABEL)
			continue;

		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			/*
			 * If connected leave existing label. If LDP
			 * removed from interface may need new label
			 * and would be treated as a connected route
			 */
			if (CHECK_FLAG(fnh->flags, F_FEC_NH_CONNECTED))
				break;

			if (fnh->ifindex != iface->ifindex)
				continue;

			SET_FLAG(fnh->flags, F_FEC_NH_NO_LDP);
			RB_FOREACH(ln, nbr_tree, &lde_nbrs)
				lde_send_labelwithdraw(ln, fn, NULL, NULL);
			lde_free_label(fn->local_label);
			fn->local_label = NO_LABEL;
			fn->local_label = lde_update_label(fn);
			if (fn->local_label != NO_LABEL)
				RB_FOREACH(ln, nbr_tree, &lde_nbrs)
					lde_send_labelmapping(ln, fn, 0);
			break;
		}
	}

	RB_FOREACH(ln, nbr_tree, &lde_nbrs)
		lde_imsg_compose_ldpe(IMSG_MAPPING_ADD_END, ln->peerid,
		    0, NULL, 0);
}

void lde_route_update_release_all(int af)
{
	struct lde_nbr	*ln;
	struct fec	*f;
	struct fec_node	*fn;
	struct fec_nh	*fnh;

	/* remove labels from all interfaces as LDP is no longer running for
	 * this address family
	 */
	log_debug("release all labels for address family %s",
	    af == AF_INET ? "ipv4" : "ipv6");

	RB_FOREACH(f, fec_tree, &ft) {
		fn = (struct fec_node *)f;
		switch (af) {
		case AF_INET:
			if (fn->fec.type != FEC_TYPE_IPV4)
				continue;
			break;
		case AF_INET6:
			if (fn->fec.type != FEC_TYPE_IPV6)
				continue;
			break;
		default:
			fatalx("lde_route_update_release: unknown af");
		}

		RB_FOREACH(ln, nbr_tree, &lde_nbrs)
			lde_send_labelwithdraw(ln, fn, NULL, NULL);

		LIST_FOREACH(fnh, &fn->nexthops, entry) {
			SET_FLAG(fnh->flags, F_FEC_NH_NO_LDP);
			lde_send_delete_klabel(fn, fnh);
		}
	}
}
