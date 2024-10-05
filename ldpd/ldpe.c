// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2008 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "control.h"
#include "log.h"
#include "ldp_debug.h"
#include "rlfa.h"

#include <lib/log.h>
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "libfrr.h"
#include "zlog_live.h"

static void	 ldpe_shutdown(void);
static void ldpe_dispatch_main(struct event *thread);
static void ldpe_dispatch_lde(struct event *thread);
#ifdef __OpenBSD__
static void ldpe_dispatch_pfkey(struct event *thread);
#endif
static void	 ldpe_setup_sockets(int, int, int, int);
static void	 ldpe_close_sockets(int);
static void	 ldpe_iface_af_ctl(struct ctl_conn *c, int af, ifindex_t ifidx);
static void	 ldpe_check_filter_af(int, struct ldpd_af_conf *, const char *);

struct ldpd_conf	*leconf;
#ifdef __OpenBSD__
struct ldpd_sysdep	 sysdep;
#endif

static struct imsgev    iev_main_data;
static struct imsgev	*iev_main, *iev_main_sync;
static struct imsgev	*iev_lde;
#ifdef __OpenBSD__
static struct event *pfkey_ev;
#endif

/* ldpe privileges */
static zebra_capabilities_t _caps_p [] =
{
	ZCAP_BIND,
	ZCAP_NET_ADMIN
};

struct zebra_privs_t ldpe_privs =
{
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};

/* SIGINT / SIGTERM handler. */
static void
sigint(void)
{
	ldpe_shutdown();
}

static struct frr_signal_t ldpe_signals[] =
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

char *pkt_ptr; /* packet buffer */

/* label distribution protocol engine */
void
ldpe(void)
{
	static struct zlog_live_cfg child_log;

#ifdef HAVE_SETPROCTITLE
	setproctitle("ldp engine");
#endif
	ldpd_process = PROC_LDP_ENGINE;
	log_procname = log_procnames[ldpd_process];

	master = frr_init();
	zlog_live_open_fd(&child_log, LOG_DEBUG, LDPD_FD_LOG);

	/* no frr_config_fork() here, allow frr_pthread to create threads */
	frr_is_after_fork = true;

	/* setup signal handler */
	signal_init(master, array_size(ldpe_signals), ldpe_signals);

	/* setup pipes and event handlers to the parent process */
	if ((iev_main = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_main->ibuf, LDPD_FD_ASYNC);
	iev_main->handler_read = ldpe_dispatch_main;
	event_add_read(master, iev_main->handler_read, iev_main,
		       iev_main->ibuf.fd, &iev_main->ev_read);
	iev_main->handler_write = ldp_write_handler;

	memset(&iev_main_data, 0, sizeof(iev_main_data));
	iev_main_sync = &iev_main_data;
	imsg_init(&iev_main_sync->ibuf, LDPD_FD_SYNC);

	/* create base configuration */
	leconf = config_new_empty();

	struct event thread;
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* NOTREACHED */
	return;
}

void
ldpe_init(struct ldpd_init *init)
{
#ifdef __OpenBSD__
	/* This socket must be open before dropping privileges. */
	global.pfkeysock = pfkey_init();
	if (sysdep.no_pfkey == 0) {
		event_add_read(master, ldpe_dispatch_pfkey, NULL,
			       global.pfkeysock, &pfkey_ev);
	}
#endif

	/* drop privileges */
	ldpe_privs.user = init->user;
	ldpe_privs.group = init->group;
	zprivs_preinit(&ldpe_privs);
	zprivs_init(&ldpe_privs);

	/* listen on ldpd control socket */
	strlcpy(ctl_sock_path, init->ctl_sock_path, sizeof(ctl_sock_path));
	if (control_init(ctl_sock_path) == -1)
		fatalx("control socket setup failed");
	TAILQ_INIT(&ctl_conns);
	control_listen();

	LIST_INIT(&global.addr_list);
	RB_INIT(global_adj_head, &global.adj_tree);
	TAILQ_INIT(&global.pending_conns);
	if (inet_pton(AF_INET, AllRouters_v4, &global.mcast_addr_v4) != 1)
		fatal("inet_pton");
	if (inet_pton(AF_INET6, AllRouters_v6, &global.mcast_addr_v6) != 1)
		fatal("inet_pton");

	/* mark sockets as closed */
	global.ipv4.ldp_disc_socket = -1;
	global.ipv4.ldp_edisc_socket = -1;
	global.ipv4.ldp_session_socket = -1;
	global.ipv6.ldp_disc_socket = -1;
	global.ipv6.ldp_edisc_socket = -1;
	global.ipv6.ldp_session_socket = -1;

	if ((pkt_ptr = calloc(1, IBUF_READ_SIZE)) == NULL)
		fatal(__func__);

	accept_init();
}

static void
ldpe_shutdown(void)
{
	struct if_addr		*if_addr;
	struct adj		*adj;

	/* close pipes */
	if (iev_lde) {
		msgbuf_clear(&iev_lde->ibuf.w);
		close(iev_lde->ibuf.fd);
		iev_lde->ibuf.fd = -1;
	}
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);
	iev_main->ibuf.fd = -1;
	msgbuf_clear(&iev_main_sync->ibuf.w);
	close(iev_main_sync->ibuf.fd);
	iev_main_sync->ibuf.fd = -1;

	control_cleanup(ctl_sock_path);

#ifdef __OpenBSD__
	if (sysdep.no_pfkey == 0) {
		EVENT_OFF(pfkey_ev);
		close(global.pfkeysock);
	}
#endif
	ldpe_close_sockets(AF_INET);
	ldpe_close_sockets(AF_INET6);

	/* remove addresses from global list */
	while ((if_addr = LIST_FIRST(&global.addr_list)) != NULL) {
		LIST_REMOVE(if_addr, entry);
		assert(if_addr != LIST_FIRST(&global.addr_list));
		free(if_addr);
	}
	while (!RB_EMPTY(global_adj_head, &global.adj_tree)) {
		adj = RB_ROOT(global_adj_head, &global.adj_tree);

		adj_del(adj, S_SHUTDOWN);
	}

	config_clear(leconf);
	/* clean up */
	if (iev_lde)
		free(iev_lde);
	free(iev_main);
	free(pkt_ptr);

	log_info("ldp engine exiting");

	zlog_fini();

	exit(0);
}

/* imesg */
int
ldpe_imsg_compose_parent(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (iev_main->ibuf.fd == -1)
		return (0);
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data, datalen));
}

void
ldpe_imsg_compose_parent_sync(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (iev_main_sync->ibuf.fd == -1)
		return;
	imsg_compose_event(iev_main_sync, type, 0, pid, -1, data, datalen);
	imsg_flush(&iev_main_sync->ibuf);
}

int
ldpe_imsg_compose_lde(int type, uint32_t peerid, pid_t pid, void *data,
    uint16_t datalen)
{
	if (iev_lde->ibuf.fd == -1)
		return (0);
	return (imsg_compose_event(iev_lde, type, peerid, pid, -1, data, datalen));
}

/* ARGSUSED */
static void ldpe_dispatch_main(struct event *thread)
{
	static struct ldpd_conf	*nconf;
	struct iface		*niface;
	struct tnbr		*ntnbr;
	struct nbr_params	*nnbrp;
	static struct l2vpn	*l2vpn, *nl2vpn;
	struct l2vpn_if		*lif, *nlif;
	struct l2vpn_pw		*pw, *npw;
	struct imsg		 imsg;
	int			 fd;
	struct imsgev *iev = EVENT_ARG(thread);
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct iface		*iface = NULL;
	struct kif		*kif;
	int			 af;
	enum socket_type	*socket_type;
	static int		 disc_socket = -1;
	static int		 edisc_socket = -1;
	static int		 session_socket = -1;
	struct nbr		*nbr;
#ifdef __OpenBSD__
	struct nbr_params	*nbrp;
#endif
	int			 n, shut = 0;
	struct ldp_access       *laccess;
	struct ldp_igp_sync_if_state_req *ldp_sync_if_state_req;
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
			fatal("ldpe_dispatch_main: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_IFSTATUS:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct kif))
				fatalx("IFSTATUS imsg with wrong len");
			kif = imsg.data;

			iface = if_lookup_name(leconf, kif->ifname);
			if (iface) {
				if_update_info(iface, kif);
				ldp_if_update(iface, AF_UNSPEC);
				break;
			}

			RB_FOREACH(l2vpn, l2vpn_head, &leconf->l2vpn_tree) {
				lif = l2vpn_if_find(l2vpn, kif->ifname);
				if (lif) {
					l2vpn_if_update_info(lif, kif);
					l2vpn_if_update(lif);
					break;
				}
				pw = l2vpn_pw_find(l2vpn, kif->ifname);
				if (pw) {
					l2vpn_pw_update_info(pw, kif);
					break;
				}
			}
			break;
		case IMSG_NEWADDR:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct kaddr))
				fatalx("NEWADDR imsg with wrong len");

			if_addr_add(imsg.data);
			break;
		case IMSG_DELADDR:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct kaddr))
				fatalx("DELADDR imsg with wrong len");

			if_addr_del(imsg.data);
			break;
		case IMSG_SOCKET_IPC:
			if (iev_lde) {
				log_warnx("%s: received unexpected imsg fd to lde", __func__);
				break;
			}
			if ((fd = imsg.fd) == -1) {
				log_warnx("%s: expected to receive imsg fd to lde but didn't receive any", __func__);
				break;
			}

			if ((iev_lde = malloc(sizeof(struct imsgev))) == NULL)
				fatal(NULL);
			imsg_init(&iev_lde->ibuf, fd);
			iev_lde->handler_read = ldpe_dispatch_lde;
			event_add_read(master, iev_lde->handler_read, iev_lde,
				       iev_lde->ibuf.fd, &iev_lde->ev_read);
			iev_lde->handler_write = ldp_write_handler;
			iev_lde->ev_write = NULL;
			break;
		case IMSG_INIT:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct ldpd_init))
				fatalx("INIT imsg with wrong len");

			memcpy(&init, imsg.data, sizeof(init));
			ldpe_init(&init);
			break;
		case IMSG_AGENTX_ENABLED:
			ldp_agentx_enabled();
			break;
		case IMSG_CLOSE_SOCKETS:
			af = imsg.hdr.peerid;

			RB_FOREACH(nbr, nbr_id_head, &nbrs_by_id) {
				if (nbr->af != af)
					continue;
				session_shutdown(nbr, S_SHUTDOWN, 0, 0);
#ifdef __OpenBSD__
				pfkey_remove(nbr);
#endif
				nbr->auth.method = AUTH_NONE;
			}
			ldpe_close_sockets(af);
			if_update_all(af);
			tnbr_update_all(af);

			disc_socket = -1;
			edisc_socket = -1;
			session_socket = -1;
			if (CHECK_FLAG((ldp_af_conf_get(leconf, af))->flags, F_LDPD_AF_ENABLED))
				ldpe_imsg_compose_parent(IMSG_REQUEST_SOCKETS, af, NULL, 0);
			break;
		case IMSG_SOCKET_NET:
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(enum socket_type))
				fatalx("SOCKET_NET imsg with wrong len");
			socket_type = imsg.data;

			switch (*socket_type) {
			case LDP_SOCKET_DISC:
				disc_socket = imsg.fd;
				break;
			case LDP_SOCKET_EDISC:
				edisc_socket = imsg.fd;
				break;
			case LDP_SOCKET_SESSION:
				session_socket = imsg.fd;
				break;
			}
			break;
		case IMSG_SETUP_SOCKETS:
			af = imsg.hdr.peerid;
			if (disc_socket == -1 || edisc_socket == -1 ||
			    session_socket == -1) {
				if (disc_socket != -1)
					close(disc_socket);
				if (edisc_socket != -1)
					close(edisc_socket);
				if (session_socket != -1)
					close(session_socket);
				break;
			}

			ldpe_setup_sockets(af, disc_socket, edisc_socket, session_socket);
			if_update_all(af);
			tnbr_update_all(af);
			RB_FOREACH(nbr, nbr_id_head, &nbrs_by_id) {
				if (nbr->af != af)
					continue;
				nbr->laddr = (ldp_af_conf_get(leconf, af))->trans_addr;
#ifdef __OpenBSD__
				nbrp = nbr_params_find(leconf, nbr->id);
				if (nbrp) {
					nbr->auth.method = nbrp->auth.method;
					if (pfkey_establish(nbr, nbrp) == -1)
						fatalx("pfkey setup failed");
				}
#endif
				if (nbr_session_active_role(nbr))
					nbr_establish_connection(nbr);
			}
			break;
		case IMSG_RTRID_UPDATE:
			memcpy(&global.rtr_id, imsg.data, sizeof(global.rtr_id));
			if (leconf->rtr_id.s_addr == INADDR_ANY) {
				ldpe_reset_nbrs(AF_UNSPEC);
			}
			if_update_all(AF_UNSPEC);
			tnbr_update_all(AF_UNSPEC);
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
			merge_config(leconf, nconf);
			ldp_clear_config(nconf);
			nconf = NULL;
			global.conf_seqnum++;
			break;
		case IMSG_CTL_END:
			control_imsg_relay(&imsg);
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
			if (imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(struct ldp_access)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			laccess = imsg.data;
			ldpe_check_filter_af(AF_INET, &leconf->ipv4, laccess->name);
			ldpe_check_filter_af(AF_INET6, &leconf->ipv6, laccess->name);
			break;
		case IMSG_LDP_SYNC_IF_STATE_REQUEST:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct ldp_igp_sync_if_state_req)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			ldp_sync_if_state_req = imsg.data;
			ldp_sync_fsm_state_req(ldp_sync_if_state_req);
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
			ldpe_rlfa_init(rclient);
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

				ldpe_rlfa_exit(rclient);
				rlfa_client_del(rclient);
			}
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__, imsg.hdr.type);
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
		ldpe_shutdown();
	}
}

/* ARGSUSED */
static void ldpe_dispatch_lde(struct event *thread)
{
	struct imsgev *iev = EVENT_ARG(thread);
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct map		*map;
	struct notify_msg	*nm;
	struct nbr		*nbr;
	int			 n, shut = 0;

	iev->ev_read = NULL;

	if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
		fatal("imsg_read error");
	if (n == 0)	/* connection closed */
		shut = 1;

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("ldpe_dispatch_lde: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_MAPPING_ADD:
		case IMSG_RELEASE_ADD:
		case IMSG_REQUEST_ADD:
		case IMSG_WITHDRAW_ADD:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(struct map))
				fatalx("invalid size of map request");
			map = imsg.data;

			nbr = nbr_find_peerid(imsg.hdr.peerid);
			if (nbr == NULL)
				break;
			if (nbr->state != NBR_STA_OPER)
				break;

			switch (imsg.hdr.type) {
			case IMSG_MAPPING_ADD:
				mapping_list_add(&nbr->mapping_list, map);
				break;
			case IMSG_RELEASE_ADD:
				mapping_list_add(&nbr->release_list, map);
				break;
			case IMSG_REQUEST_ADD:
				mapping_list_add(&nbr->request_list, map);
				break;
			case IMSG_WITHDRAW_ADD:
				mapping_list_add(&nbr->withdraw_list, map);
				break;
			}
			break;
		case IMSG_MAPPING_ADD_END:
		case IMSG_RELEASE_ADD_END:
		case IMSG_REQUEST_ADD_END:
		case IMSG_WITHDRAW_ADD_END:
			nbr = nbr_find_peerid(imsg.hdr.peerid);
			if (nbr == NULL)
				break;
			if (nbr->state != NBR_STA_OPER)
				break;

			switch (imsg.hdr.type) {
			case IMSG_MAPPING_ADD_END:
				send_labelmessage(nbr, MSG_TYPE_LABELMAPPING,
				    &nbr->mapping_list);
				break;
			case IMSG_RELEASE_ADD_END:
				send_labelmessage(nbr, MSG_TYPE_LABELRELEASE,
				    &nbr->release_list);
				break;
			case IMSG_REQUEST_ADD_END:
				send_labelmessage(nbr, MSG_TYPE_LABELREQUEST,
				    &nbr->request_list);
				break;
			case IMSG_WITHDRAW_ADD_END:
				send_labelmessage(nbr, MSG_TYPE_LABELWITHDRAW,
				    &nbr->withdraw_list);
				break;
			}
			break;
		case IMSG_NOTIFICATION_SEND:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(struct notify_msg))
				fatalx("invalid size of OE request");
			nm = imsg.data;

			nbr = nbr_find_peerid(imsg.hdr.peerid);
			if (nbr == NULL) {
				log_debug("%s: cannot find neighbor", __func__);
				break;
			}
			if (nbr->state != NBR_STA_OPER)
				break;

			send_notification_full(nbr->tcp, nm);
			break;
		case IMSG_CTL_END:
		case IMSG_CTL_SHOW_LIB_BEGIN:
		case IMSG_CTL_SHOW_LIB_RCVD:
		case IMSG_CTL_SHOW_LIB_SENT:
		case IMSG_CTL_SHOW_LIB_END:
		case IMSG_CTL_SHOW_L2VPN_PW:
		case IMSG_CTL_SHOW_L2VPN_BINDING:
			control_imsg_relay(&imsg);
			break;
		case IMSG_NBR_SHUTDOWN:
			nbr = nbr_find_peerid(imsg.hdr.peerid);
			if (nbr == NULL) {
				log_debug("%s: cannot find neighbor", __func__);
				break;
			}
			if (nbr->state != NBR_STA_OPER)
				break;
			session_shutdown(nbr,S_SHUTDOWN,0,0);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__, imsg.hdr.type);
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
		ldpe_shutdown();
	}
}

#ifdef __OpenBSD__
/* ARGSUSED */
static void ldpe_dispatch_pfkey(struct event *thread)
{
	int fd = EVENT_FD(thread);

	event_add_read(master, ldpe_dispatch_pfkey, NULL, global.pfkeysock,
		       &pfkey_ev);

	if (pfkey_read(fd, NULL) == -1)
		fatal("pfkey_read failed, exiting...");
}
#endif /* __OpenBSD__ */

static void
ldpe_setup_sockets(int af, int disc_socket, int edisc_socket,
    int session_socket)
{
	struct ldpd_af_global	*af_global;

	af_global = ldp_af_global_get(&global, af);

	/* discovery socket */
	af_global->ldp_disc_socket = disc_socket;
	event_add_read(master, disc_recv_packet, &af_global->disc_ev,
		       af_global->ldp_disc_socket, &af_global->disc_ev);

	/* extended discovery socket */
	af_global->ldp_edisc_socket = edisc_socket;
	event_add_read(master, disc_recv_packet, &af_global->edisc_ev,
		       af_global->ldp_edisc_socket, &af_global->edisc_ev);

	/* session socket */
	af_global->ldp_session_socket = session_socket;
	accept_add(af_global->ldp_session_socket, session_accept, NULL);
}

static void
ldpe_close_sockets(int af)
{
	struct ldpd_af_global	*af_global;

	af_global = ldp_af_global_get(&global, af);

	/* discovery socket */
	EVENT_OFF(af_global->disc_ev);
	if (af_global->ldp_disc_socket != -1) {
		close(af_global->ldp_disc_socket);
		af_global->ldp_disc_socket = -1;
	}

	/* extended discovery socket */
	EVENT_OFF(af_global->edisc_ev);
	if (af_global->ldp_edisc_socket != -1) {
		close(af_global->ldp_edisc_socket);
		af_global->ldp_edisc_socket = -1;
	}

	/* session socket */
	if (af_global->ldp_session_socket != -1) {
		accept_del(af_global->ldp_session_socket);
		close(af_global->ldp_session_socket);
		af_global->ldp_session_socket = -1;
	}
}

int
ldpe_acl_check(char *acl_name, int af, union ldpd_addr *addr, uint8_t prefixlen)
{
	return ldp_acl_request(iev_main_sync, acl_name, af, addr, prefixlen);
}

void
ldpe_reset_nbrs(int af)
{
	struct nbr		*nbr;

	RB_FOREACH(nbr, nbr_id_head, &nbrs_by_id) {
		if (af == AF_UNSPEC || nbr->af == af)
			session_shutdown(nbr, S_SHUTDOWN, 0, 0);
	}
}

void
ldpe_reset_ds_nbrs(void)
{
	struct nbr		*nbr;

	RB_FOREACH(nbr, nbr_id_head, &nbrs_by_id) {
		if (nbr->ds_tlv)
			session_shutdown(nbr, S_SHUTDOWN, 0, 0);
	}
}

void
ldpe_remove_dynamic_tnbrs(int af)
{
	struct tnbr		*tnbr, *safe;

	RB_FOREACH_SAFE(tnbr, tnbr_head, &leconf->tnbr_tree, safe) {
		if (tnbr->af != af)
			continue;

		UNSET_FLAG(tnbr->flags, F_TNBR_DYNAMIC);
		tnbr_check(leconf, tnbr);
	}
}

void
ldpe_stop_init_backoff(int af)
{
	struct nbr		*nbr;

	RB_FOREACH(nbr, nbr_id_head, &nbrs_by_id) {
		if (nbr->af == af && nbr_pending_idtimer(nbr)) {
			nbr_stop_idtimer(nbr);
			nbr_establish_connection(nbr);
		}
	}
}

static void
ldpe_iface_af_ctl(struct ctl_conn *c, int af, ifindex_t idx)
{
	struct iface		*iface;
	struct iface_af		*ia;
	struct ctl_iface	*ictl;

	RB_FOREACH(iface, iface_head, &leconf->iface_tree) {
		if (idx == 0 || idx == iface->ifindex) {
			ia = iface_af_get(iface, af);
			if (!ia->enabled)
				continue;

			ictl = if_to_ctl(ia);
			imsg_compose_event(&c->iev, IMSG_CTL_SHOW_INTERFACE,
			    0, 0, -1, ictl, sizeof(struct ctl_iface));
		}
	}
}

void
ldpe_iface_ctl(struct ctl_conn *c, ifindex_t idx)
{
	ldpe_iface_af_ctl(c, AF_INET, idx);
	ldpe_iface_af_ctl(c, AF_INET6, idx);
}

void
ldpe_adj_ctl(struct ctl_conn *c)
{
	struct adj	*adj;
	struct ctl_adj	*actl;

	RB_FOREACH(adj, global_adj_head, &global.adj_tree) {
		actl = adj_to_ctl(adj);
		imsg_compose_event(&c->iev, IMSG_CTL_SHOW_DISCOVERY, 0, 0,
		    -1, actl, sizeof(struct ctl_adj));
	}

	imsg_compose_event(&c->iev, IMSG_CTL_END, 0, 0, -1, NULL, 0);
}

void
ldpe_adj_detail_ctl(struct ctl_conn *c)
{
	struct iface		*iface;
	struct tnbr		*tnbr;
	struct adj		*adj;
	struct ctl_adj		*actl;
	struct ctl_disc_if	 ictl;
	struct ctl_disc_tnbr	 tctl;

	imsg_compose_event(&c->iev, IMSG_CTL_SHOW_DISCOVERY, 0, 0, -1, NULL, 0);

	RB_FOREACH(iface, iface_head, &leconf->iface_tree) {
		memset(&ictl, 0, sizeof(ictl));
		ictl.active_v4 = (iface->ipv4.state == IF_STA_ACTIVE);
		ictl.active_v6 = (iface->ipv6.state == IF_STA_ACTIVE);

		if (!ictl.active_v4 && !ictl.active_v6)
			continue;

		strlcpy(ictl.name, iface->name, sizeof(ictl.name));
		if (RB_EMPTY(ia_adj_head, &iface->ipv4.adj_tree) &&
		    RB_EMPTY(ia_adj_head, &iface->ipv6.adj_tree))
			ictl.no_adj = 1;
		imsg_compose_event(&c->iev, IMSG_CTL_SHOW_DISC_IFACE, 0, 0,
		    -1, &ictl, sizeof(ictl));

		RB_FOREACH(adj, ia_adj_head, &iface->ipv4.adj_tree) {
			actl = adj_to_ctl(adj);
			imsg_compose_event(&c->iev, IMSG_CTL_SHOW_DISC_ADJ,
			    0, 0, -1, actl, sizeof(struct ctl_adj));
		}
		RB_FOREACH(adj, ia_adj_head, &iface->ipv6.adj_tree) {
			actl = adj_to_ctl(adj);
			imsg_compose_event(&c->iev, IMSG_CTL_SHOW_DISC_ADJ,
			    0, 0, -1, actl, sizeof(struct ctl_adj));
		}
	}

	RB_FOREACH(tnbr, tnbr_head, &leconf->tnbr_tree) {
		memset(&tctl, 0, sizeof(tctl));
		tctl.af = tnbr->af;
		tctl.addr = tnbr->addr;
		if (tnbr->adj == NULL)
			tctl.no_adj = 1;

		imsg_compose_event(&c->iev, IMSG_CTL_SHOW_DISC_TNBR, 0, 0,
		    -1, &tctl, sizeof(tctl));

		if (tnbr->adj == NULL)
			continue;

		actl = adj_to_ctl(tnbr->adj);
		imsg_compose_event(&c->iev, IMSG_CTL_SHOW_DISC_ADJ, 0, 0,
		    -1, actl, sizeof(struct ctl_adj));
	}

	imsg_compose_event(&c->iev, IMSG_CTL_END, 0, 0, -1, NULL, 0);
}

void
ldpe_nbr_ctl(struct ctl_conn *c)
{
	struct adj	*adj;
	struct ctl_adj	*actl;
	struct nbr	*nbr;
	struct ctl_nbr	*nctl;

	RB_FOREACH(nbr, nbr_addr_head, &nbrs_by_addr) {
		if (nbr->state == NBR_STA_PRESENT)
			continue;

		nctl = nbr_to_ctl(nbr);
		imsg_compose_event(&c->iev, IMSG_CTL_SHOW_NBR, 0, 0, -1, nctl,
		    sizeof(struct ctl_nbr));

		RB_FOREACH(adj, nbr_adj_head, &nbr->adj_tree) {
			actl = adj_to_ctl(adj);
			imsg_compose_event(&c->iev, IMSG_CTL_SHOW_NBR_DISC,
			    0, 0, -1, actl, sizeof(struct ctl_adj));
		}

		imsg_compose_event(&c->iev, IMSG_CTL_SHOW_NBR_END, 0, 0, -1,
		    NULL, 0);
	}
	imsg_compose_event(&c->iev, IMSG_CTL_END, 0, 0, -1, NULL, 0);
}

void
ldpe_ldp_sync_ctl(struct ctl_conn *c)
{
	struct iface		*iface;
	struct ctl_ldp_sync	*ictl;

	RB_FOREACH(iface, iface_head, &leconf->iface_tree) {
		ictl = ldp_sync_to_ctl(iface);
		imsg_compose_event(&c->iev, IMSG_CTL_SHOW_LDP_SYNC,
			0, 0, -1, ictl, sizeof(struct ctl_ldp_sync));
	}
	imsg_compose_event(&c->iev, IMSG_CTL_END, 0, 0, -1, NULL, 0);
}

void
mapping_list_add(struct mapping_head *mh, struct map *map)
{
	struct mapping_entry	*me;

	me = calloc(1, sizeof(*me));
	if (me == NULL)
		fatal(__func__);
	me->map = *map;

	TAILQ_INSERT_TAIL(mh, me, entry);
}

void
mapping_list_clr(struct mapping_head *mh)
{
	struct mapping_entry	*me;

	while ((me = TAILQ_FIRST(mh)) != NULL) {
		TAILQ_REMOVE(mh, me, entry);
		assert(me != TAILQ_FIRST(mh));
		free(me);
	}
}

void
ldpe_check_filter_af(int af, struct ldpd_af_conf *af_conf,
    const char *filter_name)
{
	if (strcmp(af_conf->acl_thello_accept_from, filter_name) == 0)
		ldpe_remove_dynamic_tnbrs(af);
}

void
ldpe_set_config_change_time(void)
{
	/* SNMP update time when ever there is a config change */
	leconf->config_change_time = time(NULL);
}
