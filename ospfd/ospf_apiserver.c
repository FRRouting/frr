// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Server side of OSPF API.
 * Copyright (C) 2001, 2002 Ralph Keller
 * Copyright (c) 2022, LabN Consulting, L.L.C.
 */

#include <zebra.h>

#ifdef SUPPORT_OSPF_API

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "frrevent.h"
#include "hash.h"
#include "sockunion.h" /* for inet_aton() */
#include "buffer.h"

#include <sys/types.h>

#include "ospfd/ospfd.h" /* for "struct event_loop" */
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_memory.h"

#include "ospfd/ospf_api.h"
#include "ospfd/ospf_apiserver.h"

DEFINE_MTYPE_STATIC(OSPFD, APISERVER, "API Server");
DEFINE_MTYPE_STATIC(OSPFD, APISERVER_MSGFILTER, "API Server Message Filter");

/* This is an implementation of an API to the OSPF daemon that allows
 * external applications to access the OSPF daemon through socket
 * connections. The application can use this API to inject its own
 * opaque LSAs and flood them to other OSPF daemons. Other OSPF
 * daemons then receive these LSAs and inform applications through the
 * API by sending a corresponding message. The application can also
 * register to receive all LSA types (in addition to opaque types) and
 * use this information to reconstruct the OSPF's LSDB. The OSPF
 * daemon supports multiple applications concurrently.  */

/* List of all active connections. */
struct list *apiserver_list;

/* -----------------------------------------------------------
 * Functions to lookup interfaces
 * -----------------------------------------------------------
 */

struct ospf_interface *ospf_apiserver_if_lookup_by_addr(struct in_addr address)
{
	struct listnode *node, *nnode;
	struct ospf_interface *oi;
	struct ospf *ospf = NULL;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (!ospf)
		return NULL;

	for (ALL_LIST_ELEMENTS(ospf->oiflist, node, nnode, oi))
		if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
			if (IPV4_ADDR_SAME(&address, &oi->address->u.prefix4))
				return oi;

	return NULL;
}

struct ospf_interface *ospf_apiserver_if_lookup_by_ifp(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct ospf_interface *oi;
	struct ospf *ospf = NULL;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (!ospf)
		return NULL;

	for (ALL_LIST_ELEMENTS(ospf->oiflist, node, nnode, oi))
		if (oi->ifp == ifp)
			return oi;

	return NULL;
}

/* -----------------------------------------------------------
 * Initialization
 * -----------------------------------------------------------
 */

unsigned short ospf_apiserver_getport(void)
{
	struct servent *sp = getservbyname("ospfapi", "tcp");

	return sp ? ntohs(sp->s_port) : OSPF_API_SYNC_PORT;
}

/* Initialize OSPF API module. Invoked from ospf_opaque_init() */
int ospf_apiserver_init(void)
{
	int fd;
	int rc = -1;

	/* Create new socket for synchronous messages. */
	fd = ospf_apiserver_serv_sock_family(ospf_apiserver_getport(), AF_INET);

	if (fd < 0)
		goto out;

	/* Schedule new thread that handles accepted connections. */
	ospf_apiserver_event(OSPF_APISERVER_ACCEPT, fd, NULL);

	/* Initialize list that keeps track of all connections. */
	apiserver_list = list_new();

	/* Register opaque-independent call back functions. These functions
	   are invoked on ISM, NSM changes and LSA update and LSA deletes */
	rc = ospf_register_opaque_functab(
		0 /* all LSAs */, 0 /* all opaque types */,
		ospf_apiserver_new_if, ospf_apiserver_del_if,
		ospf_apiserver_ism_change, ospf_apiserver_nsm_change, NULL,
		NULL, NULL, NULL, /* ospf_apiserver_show_info */
		NULL,		  /* originator_func */
		NULL,		  /* ospf_apiserver_lsa_refresher */
		ospf_apiserver_lsa_update, ospf_apiserver_lsa_delete);
	if (rc != 0) {
		flog_warn(
			EC_OSPF_OPAQUE_REGISTRATION,
			"ospf_apiserver_init: Failed to register opaque type [0/0]");
	}

	rc = 0;

out:
	return rc;
}

/* Terminate OSPF API module. */
void ospf_apiserver_term(void)
{
	struct ospf_apiserver *apiserv;

	/* Unregister wildcard [0/0] type */
	ospf_delete_opaque_functab(0 /* all LSAs */, 0 /* all opaque types */);

	/*
	 * Free all client instances.  ospf_apiserver_free removes the node
	 * from the list, so we examine the head of the list anew each time.
	 */
	if (!apiserver_list)
		return;

	while (listcount(apiserver_list)) {
		apiserv = listgetdata(listhead(apiserver_list));

		ospf_apiserver_free(apiserv);
	}

	/* Free client list itself */
	if (apiserver_list)
		list_delete(&apiserver_list);

	/* Free wildcard list */
	/* XXX  */
}

static struct ospf_apiserver *lookup_apiserver(uint8_t lsa_type,
					       uint8_t opaque_type)
{
	struct listnode *n1, *n2;
	struct registered_opaque_type *r;
	struct ospf_apiserver *apiserv, *found = NULL;

	/* XXX: this approaches O(n**2) */
	for (ALL_LIST_ELEMENTS_RO(apiserver_list, n1, apiserv)) {
		for (ALL_LIST_ELEMENTS_RO(apiserv->opaque_types, n2, r))
			if (r->lsa_type == lsa_type
			    && r->opaque_type == opaque_type) {
				found = apiserv;
				goto out;
			}
	}
out:
	return found;
}

static struct ospf_apiserver *lookup_apiserver_by_lsa(struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = lsa->data;
	struct ospf_apiserver *found = NULL;

	if (IS_OPAQUE_LSA(lsah->type)) {
		found = lookup_apiserver(
			lsah->type, GET_OPAQUE_TYPE(ntohl(lsah->id.s_addr)));
	}
	return found;
}

/* -----------------------------------------------------------
 * Following are functions to manage client connections.
 * -----------------------------------------------------------
 */
static int ospf_apiserver_new_lsa_hook(struct ospf_lsa *lsa)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("API: Put LSA(%p)[%s] into reserve, total=%ld",
			   (void *)lsa, dump_lsa_key(lsa), lsa->lsdb->total);
	return 0;
}

static int ospf_apiserver_del_lsa_hook(struct ospf_lsa *lsa)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("API: Get LSA(%p)[%s] from reserve, total=%ld",
			   (void *)lsa, dump_lsa_key(lsa), lsa->lsdb->total);
	return 0;
}

/* Allocate new connection structure. */
struct ospf_apiserver *ospf_apiserver_new(int fd_sync, int fd_async)
{
	struct ospf_apiserver *new =
		XMALLOC(MTYPE_APISERVER, sizeof(struct ospf_apiserver));

	new->filter = XMALLOC(MTYPE_APISERVER_MSGFILTER,
			      sizeof(struct lsa_filter_type));

	new->fd_sync = fd_sync;
	new->fd_async = fd_async;

	/* list of registered opaque types that application uses */
	new->opaque_types = list_new();

	/* Initialize temporary strage for LSA instances to be refreshed. */
	memset(&new->reserve, 0, sizeof(struct ospf_lsdb));
	ospf_lsdb_init(&new->reserve);

	new->reserve.new_lsa_hook = ospf_apiserver_new_lsa_hook; /* debug */
	new->reserve.del_lsa_hook = ospf_apiserver_del_lsa_hook; /* debug */

	new->out_sync_fifo = msg_fifo_new();
	new->out_async_fifo = msg_fifo_new();
	new->t_sync_read = NULL;
#ifdef USE_ASYNC_READ
	new->t_async_read = NULL;
#endif /* USE_ASYNC_READ */
	new->t_sync_write = NULL;
	new->t_async_write = NULL;

	new->filter->typemask = 0; /* filter all LSAs */
	new->filter->origin = ANY_ORIGIN;
	new->filter->num_areas = 0;

	return new;
}

void ospf_apiserver_event(enum ospf_apiserver_event event, int fd,
			  struct ospf_apiserver *apiserv)
{
	switch (event) {
	case OSPF_APISERVER_ACCEPT:
		(void)event_add_read(master, ospf_apiserver_accept, apiserv, fd,
				     NULL);
		break;
	case OSPF_APISERVER_SYNC_READ:
		apiserv->t_sync_read = NULL;
		event_add_read(master, ospf_apiserver_read, apiserv, fd,
			       &apiserv->t_sync_read);
		break;
#ifdef USE_ASYNC_READ
	case OSPF_APISERVER_ASYNC_READ:
		apiserv->t_async_read = NULL;
		event_add_read(master, ospf_apiserver_read, apiserv, fd,
			       &apiserv->t_async_read);
		break;
#endif /* USE_ASYNC_READ */
	case OSPF_APISERVER_SYNC_WRITE:
		event_add_write(master, ospf_apiserver_sync_write, apiserv, fd,
				&apiserv->t_sync_write);
		break;
	case OSPF_APISERVER_ASYNC_WRITE:
		event_add_write(master, ospf_apiserver_async_write, apiserv, fd,
				&apiserv->t_async_write);
		break;
	}
}

/* Free instance. First unregister all opaque types used by
   application, flush opaque LSAs injected by application
   from network and close connection. */
void ospf_apiserver_free(struct ospf_apiserver *apiserv)
{
	struct listnode *node;

	/* Cancel read and write threads. */
	EVENT_OFF(apiserv->t_sync_read);
#ifdef USE_ASYNC_READ
	EVENT_OFF(apiserv->t_async_read);
#endif /* USE_ASYNC_READ */
	EVENT_OFF(apiserv->t_sync_write);
	EVENT_OFF(apiserv->t_async_write);

	/* Unregister all opaque types that application registered
	   and flush opaque LSAs if still in LSDB. */

	while ((node = listhead(apiserv->opaque_types)) != NULL) {
		struct registered_opaque_type *regtype = listgetdata(node);

		ospf_apiserver_unregister_opaque_type(
			apiserv, regtype->lsa_type, regtype->opaque_type);
	}
	list_delete(&apiserv->opaque_types);

	/* Close connections to OSPFd. */
	if (apiserv->fd_sync > 0) {
		close(apiserv->fd_sync);
	}

	if (apiserv->fd_async > 0) {
		close(apiserv->fd_async);
	}

	/* Free fifos */
	msg_fifo_free(apiserv->out_sync_fifo);
	msg_fifo_free(apiserv->out_async_fifo);

	/* Clear temporary strage for LSA instances to be refreshed. */
	ospf_lsdb_delete_all(&apiserv->reserve);
	ospf_lsdb_cleanup(&apiserv->reserve);

	/* Remove from the list of active clients. */
	listnode_delete(apiserver_list, apiserv);

	XFREE(MTYPE_APISERVER_MSGFILTER, apiserv->filter);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("API: Delete apiserv(%p), total#(%d)",
			   (void *)apiserv, apiserver_list->count);

	/* And free instance. */
	XFREE(MTYPE_APISERVER, apiserv);
}

void ospf_apiserver_read(struct event *thread)
{
	struct ospf_apiserver *apiserv;
	struct msg *msg;
	int fd;
	enum ospf_apiserver_event event;

	apiserv = EVENT_ARG(thread);
	fd = EVENT_FD(thread);

	if (fd == apiserv->fd_sync) {
		event = OSPF_APISERVER_SYNC_READ;
		apiserv->t_sync_read = NULL;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("API: %s: Peer: %pI4/%u", __func__,
				   &apiserv->peer_sync.sin_addr,
				   ntohs(apiserv->peer_sync.sin_port));
	}
#ifdef USE_ASYNC_READ
	else if (fd == apiserv->fd_async) {
		event = OSPF_APISERVER_ASYNC_READ;
		apiserv->t_async_read = NULL;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("API: %s: Peer: %pI4/%u", __func__,
				   &apiserv->peer_async.sin_addr,
				   ntohs(apiserv->peer_async.sin_port));
	}
#endif /* USE_ASYNC_READ */
	else {
		zlog_warn("%s: Unknown fd(%d)", __func__, fd);
		ospf_apiserver_free(apiserv);
		return;
	}

	/* Read message from fd. */
	msg = msg_read(fd);
	if (msg == NULL) {
		zlog_warn("%s: read failed on fd=%d, closing connection",
			  __func__, fd);

		/* Perform cleanup. */
		ospf_apiserver_free(apiserv);
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		msg_print(msg);

	/* Dispatch to corresponding message handler. */
	ospf_apiserver_handle_msg(apiserv, msg);

	/* Prepare for next message, add read thread. */
	ospf_apiserver_event(event, fd, apiserv);

	msg_free(msg);
}

void ospf_apiserver_sync_write(struct event *thread)
{
	struct ospf_apiserver *apiserv;
	struct msg *msg;
	int fd;
	int rc = -1;

	apiserv = EVENT_ARG(thread);
	assert(apiserv);
	fd = EVENT_FD(thread);

	apiserv->t_sync_write = NULL;

	/* Sanity check */
	if (fd != apiserv->fd_sync) {
		zlog_warn("%s: Unknown fd=%d", __func__, fd);
		goto out;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("API: %s: Peer: %pI4/%u", __func__,
			   &apiserv->peer_sync.sin_addr,
			   ntohs(apiserv->peer_sync.sin_port));

	/* Check whether there is really a message in the fifo. */
	msg = msg_fifo_pop(apiserv->out_sync_fifo);
	if (!msg) {
		zlog_warn("API: %s: No message in Sync-FIFO?", __func__);
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		msg_print(msg);

	rc = msg_write(fd, msg);

	/* Once a message is dequeued, it should be freed anyway. */
	msg_free(msg);

	if (rc < 0) {
		zlog_warn("%s: write failed on fd=%d", __func__, fd);
		goto out;
	}


	/* If more messages are in sync message fifo, schedule write thread. */
	if (msg_fifo_head(apiserv->out_sync_fifo)) {
		ospf_apiserver_event(OSPF_APISERVER_SYNC_WRITE,
				     apiserv->fd_sync, apiserv);
	}

out:

	if (rc < 0) {
		/* Perform cleanup and disconnect with peer */
		ospf_apiserver_free(apiserv);
	}
}


void ospf_apiserver_async_write(struct event *thread)
{
	struct ospf_apiserver *apiserv;
	struct msg *msg;
	int fd;
	int rc = -1;

	apiserv = EVENT_ARG(thread);
	assert(apiserv);
	fd = EVENT_FD(thread);

	apiserv->t_async_write = NULL;

	/* Sanity check */
	if (fd != apiserv->fd_async) {
		zlog_warn("%s: Unknown fd=%d", __func__, fd);
		goto out;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("API: %s: Peer: %pI4/%u", __func__,
			   &apiserv->peer_async.sin_addr,
			   ntohs(apiserv->peer_async.sin_port));

	/* Check whether there is really a message in the fifo. */
	msg = msg_fifo_pop(apiserv->out_async_fifo);
	if (!msg) {
		zlog_warn("API: %s: No message in Async-FIFO?", __func__);
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		msg_print(msg);

	rc = msg_write(fd, msg);

	/* Once a message is dequeued, it should be freed anyway. */
	msg_free(msg);

	if (rc < 0) {
		zlog_warn("%s: write failed on fd=%d", __func__, fd);
		goto out;
	}


	/* If more messages are in async message fifo, schedule write thread. */
	if (msg_fifo_head(apiserv->out_async_fifo)) {
		ospf_apiserver_event(OSPF_APISERVER_ASYNC_WRITE,
				     apiserv->fd_async, apiserv);
	}

out:

	if (rc < 0) {
		/* Perform cleanup and disconnect with peer */
		ospf_apiserver_free(apiserv);
	}
}


int ospf_apiserver_serv_sock_family(unsigned short port, int family)
{
	union sockunion su;
	int accept_sock;
	int rc;

	memset(&su, 0, sizeof(union sockunion));
	su.sa.sa_family = family;

	/* Make new socket */
	accept_sock = sockunion_stream_socket(&su);
	if (accept_sock < 0)
		return accept_sock;

	/* This is a server, so reuse address and port */
	sockopt_reuseaddr(accept_sock);
	sockopt_reuseport(accept_sock);

	/* Bind socket to address and given port. */
	rc = sockunion_bind(accept_sock, &su, port, NULL);
	if (rc < 0) {
		close(accept_sock); /* Close socket */
		return rc;
	}

	/* Listen socket under queue length 3. */
	rc = listen(accept_sock, 3);
	if (rc < 0) {
		zlog_warn("%s: listen: %s", __func__, safe_strerror(errno));
		close(accept_sock); /* Close socket */
		return rc;
	}
	return accept_sock;
}


/* Accept connection request from external applications. For each
   accepted connection allocate own connection instance. */
void ospf_apiserver_accept(struct event *thread)
{
	int accept_sock;
	int new_sync_sock;
	int new_async_sock;
	union sockunion su;
	struct ospf_apiserver *apiserv;
	struct sockaddr_in peer_async;
	struct sockaddr_in peer_sync;
	unsigned int peerlen;
	int ret;

	/* EVENT_ARG (thread) is NULL */
	accept_sock = EVENT_FD(thread);

	/* Keep hearing on socket for further connections. */
	ospf_apiserver_event(OSPF_APISERVER_ACCEPT, accept_sock, NULL);

	memset(&su, 0, sizeof(union sockunion));
	/* Accept connection for synchronous messages */
	new_sync_sock = sockunion_accept(accept_sock, &su);
	if (new_sync_sock < 0) {
		zlog_warn("%s: accept: %s", __func__, safe_strerror(errno));
		return;
	}

	/* Get port address and port number of peer to make reverse connection.
	   The reverse channel uses the port number of the peer port+1. */

	memset(&peer_sync, 0, sizeof(peer_sync));
	peerlen = sizeof(struct sockaddr_in);

	ret = getpeername(new_sync_sock, (struct sockaddr *)&peer_sync,
			  &peerlen);
	if (ret < 0) {
		zlog_warn("%s: getpeername: %s", __func__,
			  safe_strerror(errno));
		close(new_sync_sock);
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("API: %s: New peer: %pI4/%u", __func__,
			   &peer_sync.sin_addr, ntohs(peer_sync.sin_port));

	/* Create new socket for asynchronous messages. */
	peer_async = peer_sync;
	peer_async.sin_port = htons(ntohs(peer_sync.sin_port) + 1);

	/* Check if remote port number to make reverse connection is valid one.
	 */
	if (ntohs(peer_async.sin_port) == ospf_apiserver_getport()) {
		zlog_warn("API: %s: Peer(%pI4/%u): Invalid async port number?",
			  __func__, &peer_async.sin_addr,
			  ntohs(peer_async.sin_port));
		close(new_sync_sock);
		return;
	}

	new_async_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (new_async_sock < 0) {
		zlog_warn("%s: socket: %s", __func__, safe_strerror(errno));
		close(new_sync_sock);
		return;
	}

	ret = connect(new_async_sock, (struct sockaddr *)&peer_async,
		      sizeof(struct sockaddr_in));

	if (ret < 0) {
		zlog_warn("%s: connect: %s", __func__, safe_strerror(errno));
		close(new_sync_sock);
		close(new_async_sock);
		return;
	}

#ifdef USE_ASYNC_READ
#else  /* USE_ASYNC_READ */
	/* Make the asynchronous channel write-only. */
	ret = shutdown(new_async_sock, SHUT_RD);
	if (ret < 0) {
		zlog_warn("%s: shutdown: %s", __func__, safe_strerror(errno));
		close(new_sync_sock);
		close(new_async_sock);
		return;
	}
#endif /* USE_ASYNC_READ */

	/* Allocate new server-side connection structure */
	apiserv = ospf_apiserver_new(new_sync_sock, new_async_sock);

	/* Add to active connection list */
	listnode_add(apiserver_list, apiserv);
	apiserv->peer_sync = peer_sync;
	apiserv->peer_async = peer_async;

	/* And add read threads for new connection */
	ospf_apiserver_event(OSPF_APISERVER_SYNC_READ, new_sync_sock, apiserv);
#ifdef USE_ASYNC_READ
	ospf_apiserver_event(OSPF_APISERVER_ASYNC_READ, new_async_sock,
			     apiserv);
#endif /* USE_ASYNC_READ */

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("API: New apiserv(%p), total#(%d)", (void *)apiserv,
			   apiserver_list->count);
}


/* -----------------------------------------------------------
 * Send reply with return code to client application
 * -----------------------------------------------------------
 */

static int ospf_apiserver_send_msg(struct ospf_apiserver *apiserv,
				   struct msg *msg)
{
	struct msg_fifo *fifo;
	struct msg *msg2;
	enum ospf_apiserver_event event;
	int fd;

	switch (msg->hdr.msgtype) {
	case MSG_REPLY:
		fifo = apiserv->out_sync_fifo;
		fd = apiserv->fd_sync;
		event = OSPF_APISERVER_SYNC_WRITE;
		break;
	case MSG_READY_NOTIFY:
	case MSG_LSA_UPDATE_NOTIFY:
	case MSG_LSA_DELETE_NOTIFY:
	case MSG_NEW_IF:
	case MSG_DEL_IF:
	case MSG_ISM_CHANGE:
	case MSG_NSM_CHANGE:
	case MSG_REACHABLE_CHANGE:
	case MSG_ROUTER_ID_CHANGE:
		fifo = apiserv->out_async_fifo;
		fd = apiserv->fd_async;
		event = OSPF_APISERVER_ASYNC_WRITE;
		break;
	default:
		zlog_warn("%s: Unknown message type %d", __func__,
			  msg->hdr.msgtype);
		return -1;
	}

	/* Make a copy of the message and put in the fifo. Once the fifo
	   gets drained by the write thread, the message will be freed. */
	/* NB: Given "msg" is untouched in this function. */
	msg2 = msg_dup(msg);

	/* Enqueue message into corresponding fifo queue */
	msg_fifo_push(fifo, msg2);

	/* Schedule write thread */
	ospf_apiserver_event(event, fd, apiserv);
	return 0;
}

int ospf_apiserver_send_reply(struct ospf_apiserver *apiserv, uint32_t seqnr,
			      uint8_t rc)
{
	struct msg *msg = new_msg_reply(seqnr, rc);
	int ret;

	if (!msg) {
		zlog_warn("%s: msg_new failed", __func__);
#ifdef NOTYET
		/* Cannot allocate new message. What should we do? */
		ospf_apiserver_free(apiserv);
#endif
		return -1;
	}

	ret = ospf_apiserver_send_msg(apiserv, msg);
	msg_free(msg);
	return ret;
}


/* -----------------------------------------------------------
 * Generic message dispatching handler function
 * -----------------------------------------------------------
 */

int ospf_apiserver_handle_msg(struct ospf_apiserver *apiserv, struct msg *msg)
{
	int rc;

	/* Call corresponding message handler function. */
	switch (msg->hdr.msgtype) {
	case MSG_REGISTER_OPAQUETYPE:
		rc = ospf_apiserver_handle_register_opaque_type(apiserv, msg);
		break;
	case MSG_UNREGISTER_OPAQUETYPE:
		rc = ospf_apiserver_handle_unregister_opaque_type(apiserv, msg);
		break;
	case MSG_REGISTER_EVENT:
		rc = ospf_apiserver_handle_register_event(apiserv, msg);
		break;
	case MSG_SYNC_LSDB:
		rc = ospf_apiserver_handle_sync_lsdb(apiserv, msg);
		break;
	case MSG_ORIGINATE_REQUEST:
		rc = ospf_apiserver_handle_originate_request(apiserv, msg);
		break;
	case MSG_DELETE_REQUEST:
		rc = ospf_apiserver_handle_delete_request(apiserv, msg);
		break;
	case MSG_SYNC_REACHABLE:
		rc = ospf_apiserver_handle_sync_reachable(apiserv, msg);
		break;
	case MSG_SYNC_ISM:
		rc = ospf_apiserver_handle_sync_ism(apiserv, msg);
		break;
	case MSG_SYNC_NSM:
		rc = ospf_apiserver_handle_sync_nsm(apiserv, msg);
		break;
	case MSG_SYNC_ROUTER_ID:
		rc = ospf_apiserver_handle_sync_router_id(apiserv, msg);
		break;
	default:
		zlog_warn("%s: Unknown message type: %d", __func__,
			  msg->hdr.msgtype);
		rc = -1;
	}
	return rc;
}


/* -----------------------------------------------------------
 * Following are functions for opaque type registration
 * -----------------------------------------------------------
 */

int ospf_apiserver_register_opaque_type(struct ospf_apiserver *apiserv,
					uint8_t lsa_type, uint8_t opaque_type)
{
	struct registered_opaque_type *regtype;
	int (*originator_func)(void *arg);
	int rc;

	switch (lsa_type) {
	case OSPF_OPAQUE_LINK_LSA:
		originator_func = ospf_apiserver_lsa9_originator;
		break;
	case OSPF_OPAQUE_AREA_LSA:
		originator_func = ospf_apiserver_lsa10_originator;
		break;
	case OSPF_OPAQUE_AS_LSA:
		originator_func = ospf_apiserver_lsa11_originator;
		break;
	default:
		zlog_warn("%s: lsa_type(%d)", __func__, lsa_type);
		return OSPF_API_ILLEGALLSATYPE;
	}


	/* Register opaque function table */
	/* NB: Duplicated registration will be detected inside the function. */
	rc = ospf_register_opaque_functab(
		lsa_type, opaque_type, NULL, /* ospf_apiserver_new_if */
		NULL,			     /* ospf_apiserver_del_if */
		NULL,			     /* ospf_apiserver_ism_change */
		NULL,			     /* ospf_apiserver_nsm_change */
		NULL, NULL, NULL, ospf_apiserver_show_info, originator_func,
		ospf_apiserver_lsa_refresher,
		NULL, /* ospf_apiserver_lsa_update */
		NULL /* ospf_apiserver_lsa_delete */);

	if (rc != 0) {
		flog_warn(EC_OSPF_OPAQUE_REGISTRATION,
			  "Failed to register opaque type [%d/%d]", lsa_type,
			  opaque_type);
		return OSPF_API_OPAQUETYPEINUSE;
	}

	/* Remember the opaque type that application registers so when
	   connection shuts down, we can flush all LSAs of this opaque
	   type. */

	regtype =
		XCALLOC(MTYPE_APISERVER, sizeof(struct registered_opaque_type));
	regtype->lsa_type = lsa_type;
	regtype->opaque_type = opaque_type;

	/* Add to list of registered opaque types */
	listnode_add(apiserv->opaque_types, regtype);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"API: Add LSA-type(%d)/Opaque-type(%d) into apiserv(%p), total#(%d)",
			lsa_type, opaque_type, (void *)apiserv,
			listcount(apiserv->opaque_types));

	return 0;
}

int ospf_apiserver_unregister_opaque_type(struct ospf_apiserver *apiserv,
					  uint8_t lsa_type, uint8_t opaque_type)
{
	struct listnode *node, *nnode;
	struct registered_opaque_type *regtype;

	for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node, nnode, regtype)) {
		/* Check if we really registered this opaque type */
		if (regtype->lsa_type == lsa_type
		    && regtype->opaque_type == opaque_type) {

			/* Yes, we registered this opaque type. Flush
			   all existing opaque LSAs of this type */

			ospf_apiserver_flush_opaque_lsa(apiserv, lsa_type,
							opaque_type);
			ospf_delete_opaque_functab(lsa_type, opaque_type);

			/* Remove from list of registered opaque types */
			listnode_delete(apiserv->opaque_types, regtype);

			XFREE(MTYPE_APISERVER, regtype);
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"API: Del LSA-type(%d)/Opaque-type(%d) from apiserv(%p), total#(%d)",
					lsa_type, opaque_type, (void *)apiserv,
					listcount(apiserv->opaque_types));

			return 0;
		}
	}

	/* Opaque type is not registered */
	zlog_warn("Failed to unregister opaque type [%d/%d]", lsa_type,
		  opaque_type);
	return OSPF_API_OPAQUETYPENOTREGISTERED;
}


static int apiserver_is_opaque_type_registered(struct ospf_apiserver *apiserv,
					       uint8_t lsa_type,
					       uint8_t opaque_type)
{
	struct listnode *node, *nnode;
	struct registered_opaque_type *regtype;

	/* XXX: how many types are there? if few, why not just a bitmap? */
	for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node, nnode, regtype)) {
		/* Check if we really registered this opaque type */
		if (regtype->lsa_type == lsa_type
		    && regtype->opaque_type == opaque_type) {
			/* Yes registered */
			return 1;
		}
	}
	/* Not registered */
	return 0;
}

int ospf_apiserver_handle_register_opaque_type(struct ospf_apiserver *apiserv,
					       struct msg *msg)
{
	struct msg_register_opaque_type *rmsg;
	uint8_t lsa_type;
	uint8_t opaque_type;
	int rc = 0;

	/* Extract parameters from register opaque type message */
	rmsg = (struct msg_register_opaque_type *)STREAM_DATA(msg->s);

	lsa_type = rmsg->lsatype;
	opaque_type = rmsg->opaquetype;

	rc = ospf_apiserver_register_opaque_type(apiserv, lsa_type,
						 opaque_type);

	/* Send a reply back to client including return code */
	rc = ospf_apiserver_send_reply(apiserv, ntohl(msg->hdr.msgseq), rc);
	if (rc < 0)
		goto out;

	/* Now inform application about opaque types that are ready */
	switch (lsa_type) {
	case OSPF_OPAQUE_LINK_LSA:
		ospf_apiserver_notify_ready_type9(apiserv);
		break;
	case OSPF_OPAQUE_AREA_LSA:
		ospf_apiserver_notify_ready_type10(apiserv);
		break;
	case OSPF_OPAQUE_AS_LSA:
		ospf_apiserver_notify_ready_type11(apiserv);
		break;
	}
out:
	return rc;
}


/* Notify specific client about all opaque types 9 that are ready. */
void ospf_apiserver_notify_ready_type9(struct ospf_apiserver *apiserv)
{
	struct listnode *node, *nnode;
	struct listnode *node2, *nnode2;
	struct ospf *ospf;
	struct ospf_interface *oi;
	struct registered_opaque_type *r;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	for (ALL_LIST_ELEMENTS(ospf->oiflist, node, nnode, oi)) {
		/* Check if this interface is indeed ready for type 9 */
		if (!ospf_apiserver_is_ready_type9(oi))
			continue;

		/* Check for registered opaque type 9 types */
		/* XXX: loop-de-loop - optimise me */
		for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node2, nnode2,
				       r)) {
			struct msg *msg;

			if (r->lsa_type == OSPF_OPAQUE_LINK_LSA) {

				/* Yes, this opaque type is ready */
				msg = new_msg_ready_notify(
					0, OSPF_OPAQUE_LINK_LSA, r->opaque_type,
					oi->address->u.prefix4);
				if (!msg) {
					zlog_warn("%s: msg_new failed",
						  __func__);
#ifdef NOTYET
					/* Cannot allocate new message. What
					 * should we do? */
					ospf_apiserver_free(apiserv);
#endif
					goto out;
				}
				ospf_apiserver_send_msg(apiserv, msg);
				msg_free(msg);
			}
		}
	}

out:
	return;
}


/* Notify specific client about all opaque types 10 that are ready. */
void ospf_apiserver_notify_ready_type10(struct ospf_apiserver *apiserv)
{
	struct listnode *node, *nnode;
	struct listnode *node2, *nnode2;
	struct ospf *ospf;
	struct ospf_area *area;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		struct registered_opaque_type *r;

		if (!ospf_apiserver_is_ready_type10(area)) {
			continue;
		}

		/* Check for registered opaque type 10 types */
		/* XXX: loop in loop - optimise me */
		for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node2, nnode2,
				       r)) {
			struct msg *msg;

			if (r->lsa_type == OSPF_OPAQUE_AREA_LSA) {
				/* Yes, this opaque type is ready */
				msg = new_msg_ready_notify(
					0, OSPF_OPAQUE_AREA_LSA, r->opaque_type,
					area->area_id);
				if (!msg) {
					zlog_warn("%s: msg_new failed",
						  __func__);
#ifdef NOTYET
					/* Cannot allocate new message. What
					 * should we do? */
					ospf_apiserver_free(apiserv);
#endif
					goto out;
				}
				ospf_apiserver_send_msg(apiserv, msg);
				msg_free(msg);
			}
		}
	}

out:
	return;
}

/* Notify specific client about all opaque types 11 that are ready */
void ospf_apiserver_notify_ready_type11(struct ospf_apiserver *apiserv)
{
	struct listnode *node, *nnode;
	struct ospf *ospf;
	struct registered_opaque_type *r;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Can type 11 be originated? */
	if (!ospf_apiserver_is_ready_type11(ospf))
		goto out;

	/* Check for registered opaque type 11 types */
	for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node, nnode, r)) {
		struct msg *msg;
		struct in_addr noarea_id = {.s_addr = 0L};

		if (r->lsa_type == OSPF_OPAQUE_AS_LSA) {
			/* Yes, this opaque type is ready */
			msg = new_msg_ready_notify(0, OSPF_OPAQUE_AS_LSA,
						   r->opaque_type, noarea_id);

			if (!msg) {
				zlog_warn("%s: msg_new failed", __func__);
#ifdef NOTYET
				/* Cannot allocate new message. What should we
				 * do? */
				ospf_apiserver_free(apiserv);
#endif
				goto out;
			}
			ospf_apiserver_send_msg(apiserv, msg);
			msg_free(msg);
		}
	}

out:
	return;
}

int ospf_apiserver_handle_unregister_opaque_type(struct ospf_apiserver *apiserv,
						 struct msg *msg)
{
	struct msg_unregister_opaque_type *umsg;
	uint8_t ltype;
	uint8_t otype;
	int rc = 0;

	/* Extract parameters from unregister opaque type message */
	umsg = (struct msg_unregister_opaque_type *)STREAM_DATA(msg->s);

	ltype = umsg->lsatype;
	otype = umsg->opaquetype;

	rc = ospf_apiserver_unregister_opaque_type(apiserv, ltype, otype);

	/* Send a reply back to client including return code */
	rc = ospf_apiserver_send_reply(apiserv, ntohl(msg->hdr.msgseq), rc);

	return rc;
}


/* -----------------------------------------------------------
 * Following are functions for event (filter) registration.
 * -----------------------------------------------------------
 */
int ospf_apiserver_handle_register_event(struct ospf_apiserver *apiserv,
					 struct msg *msg)
{
	struct msg_register_event *rmsg;
	int rc;
	uint32_t seqnum;
	size_t size;

	rmsg = (struct msg_register_event *)STREAM_DATA(msg->s);

	/* Get request sequence number */
	seqnum = msg_get_seq(msg);

	/* Free existing filter in apiserv. */
	XFREE(MTYPE_APISERVER_MSGFILTER, apiserv->filter);
	/* Alloc new space for filter. */
	size = ntohs(msg->hdr.msglen);
	if (size < OSPF_MAX_LSA_SIZE) {

		apiserv->filter = XMALLOC(MTYPE_APISERVER_MSGFILTER, size);

		/* copy it over. */
		memcpy(apiserv->filter, &rmsg->filter, size);
		rc = OSPF_API_OK;
	} else
		rc = OSPF_API_NOMEMORY;

	/* Send a reply back to client with return code */
	rc = ospf_apiserver_send_reply(apiserv, seqnum, rc);
	return rc;
}


/* -----------------------------------------------------------
 * Following are functions for LSDB synchronization.
 * -----------------------------------------------------------
 */

static int apiserver_sync_callback(struct ospf_lsa *lsa, void *p_arg,
				   int int_arg)
{
	struct ospf_apiserver *apiserv;
	int seqnum;
	struct msg *msg;
	struct param_t {
		struct ospf_apiserver *apiserv;
		struct lsa_filter_type *filter;
	} * param;
	int rc = -1;

	/* Sanity check */
	assert(lsa->data);
	assert(p_arg);

	param = (struct param_t *)p_arg;
	apiserv = param->apiserv;
	seqnum = (uint32_t)int_arg;

	/* Check origin in filter. */
	if ((param->filter->origin == ANY_ORIGIN)
	    || (param->filter->origin == (lsa->flags & OSPF_LSA_SELF))) {

		/* Default area for AS-External and Opaque11 LSAs */
		struct in_addr area_id = {.s_addr = 0L};

		/* Default interface for non Opaque9 LSAs */
		struct in_addr ifaddr = {.s_addr = 0L};

		if (lsa->area) {
			area_id = lsa->area->area_id;
		}
		if (lsa->data->type == OSPF_OPAQUE_LINK_LSA) {
			ifaddr = lsa->oi->address->u.prefix4;
		}

		msg = new_msg_lsa_change_notify(
			MSG_LSA_UPDATE_NOTIFY, seqnum, ifaddr, area_id,
			lsa->flags & OSPF_LSA_SELF, lsa->data);
		if (!msg) {
			zlog_warn("%s: new_msg_update failed", __func__);
#ifdef NOTYET
			/* Cannot allocate new message. What should we do? */
			/*        ospf_apiserver_free (apiserv);*/ /* Do nothing
								      here XXX
								      */
#endif
			goto out;
		}

		/* Send LSA */
		ospf_apiserver_send_msg(apiserv, msg);
		msg_free(msg);
	}
	rc = 0;

out:
	return rc;
}

int ospf_apiserver_handle_sync_lsdb(struct ospf_apiserver *apiserv,
				    struct msg *msg)
{
	struct listnode *node, *nnode;
	uint32_t seqnum;
	int rc = 0;
	struct msg_sync_lsdb *smsg;
	struct ospf_apiserver_param_t {
		struct ospf_apiserver *apiserv;
		struct lsa_filter_type *filter;
	} param;
	uint16_t mask;
	struct route_node *rn;
	struct ospf_lsa *lsa;
	struct ospf *ospf;
	struct ospf_area *area;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Get request sequence number */
	seqnum = msg_get_seq(msg);
	/* Set sync msg. */
	smsg = (struct msg_sync_lsdb *)STREAM_DATA(msg->s);

	/* Set parameter struct. */
	param.apiserv = apiserv;
	param.filter = &smsg->filter;

	/* Remember mask. */
	mask = ntohs(smsg->filter.typemask);

	/* Iterate over all areas. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		int i;
		uint32_t *area_id = NULL;

		/* Compare area_id with area_ids in sync request. */
		if ((i = smsg->filter.num_areas) > 0) {
			/* Let area_id point to the list of area IDs,
			 * which is at the end of smsg->filter. */
			area_id = (uint32_t *)(&smsg->filter + 1);
			while (i) {
				if (*area_id == area->area_id.s_addr) {
					break;
				}
				i--;
				area_id++;
			}
		} else {
			i = 1;
		}

		/* If area was found, then i>0 here. */
		if (i) {
			/* Check msg type. */
			if (mask & Power2[OSPF_ROUTER_LSA])
				LSDB_LOOP (ROUTER_LSDB(area), rn, lsa)
					apiserver_sync_callback(
						lsa, (void *)&param, seqnum);
			if (mask & Power2[OSPF_NETWORK_LSA])
				LSDB_LOOP (NETWORK_LSDB(area), rn, lsa)
					apiserver_sync_callback(
						lsa, (void *)&param, seqnum);
			if (mask & Power2[OSPF_SUMMARY_LSA])
				LSDB_LOOP (SUMMARY_LSDB(area), rn, lsa)
					apiserver_sync_callback(
						lsa, (void *)&param, seqnum);
			if (mask & Power2[OSPF_ASBR_SUMMARY_LSA])
				LSDB_LOOP (ASBR_SUMMARY_LSDB(area), rn, lsa)
					apiserver_sync_callback(
						lsa, (void *)&param, seqnum);
			if (mask & Power2[OSPF_OPAQUE_LINK_LSA])
				LSDB_LOOP (OPAQUE_LINK_LSDB(area), rn, lsa)
					apiserver_sync_callback(
						lsa, (void *)&param, seqnum);
			if (mask & Power2[OSPF_OPAQUE_AREA_LSA])
				LSDB_LOOP (OPAQUE_AREA_LSDB(area), rn, lsa)
					apiserver_sync_callback(
						lsa, (void *)&param, seqnum);
		}
	}

	/* For AS-external LSAs */
	if (ospf->lsdb) {
		if (mask & Power2[OSPF_AS_EXTERNAL_LSA])
			LSDB_LOOP (EXTERNAL_LSDB(ospf), rn, lsa)
				apiserver_sync_callback(lsa, (void *)&param,
							seqnum);
	}

	/* For AS-external opaque LSAs */
	if (ospf->lsdb) {
		if (mask & Power2[OSPF_OPAQUE_AS_LSA])
			LSDB_LOOP (OPAQUE_AS_LSDB(ospf), rn, lsa)
				apiserver_sync_callback(lsa, (void *)&param,
							seqnum);
	}

	/* Send a reply back to client with return code */
	rc = ospf_apiserver_send_reply(apiserv, seqnum, rc);
	return rc;
}

/*
 * -----------------------------------------------------------
 * Followings are functions for synchronization.
 * -----------------------------------------------------------
 */

int ospf_apiserver_handle_sync_reachable(struct ospf_apiserver *apiserv,
					 struct msg *msg)
{
	struct ospf *ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	struct route_table *rt = ospf->all_rtrs;
	uint32_t seqnum = msg_get_seq(msg);
	struct in_addr *a, *abuf;
	struct msg_reachable_change *areach;
	struct msg *amsg;
	uint mcount, count;
	int _rc, rc = 0;

	if (!rt)
		goto out;

	/* send all adds based on current reachable routers */
	a = abuf = XCALLOC(MTYPE_APISERVER, sizeof(struct in_addr) * rt->count);
	for (struct route_node *rn = route_top(rt); rn; rn = route_next(rn))
		if (listhead((struct list *)rn->info))
			*a++ = rn->p.u.prefix4;

	assert((a - abuf) <= (long)rt->count);
	count = (a - abuf);

	a = abuf;
	while (count && !rc) {
		amsg = new_msg_reachable_change(seqnum, count, a, 0, NULL);
		areach = (struct msg_reachable_change *)STREAM_DATA(amsg->s);
		mcount = ntohs(areach->nadd) + ntohs(areach->nremove);
		assert(mcount <= count);
		a = a + mcount;
		count -= mcount;
		rc = ospf_apiserver_send_msg(apiserv, amsg);
		msg_free(amsg);
	}
	XFREE(MTYPE_APISERVER, abuf);

out:
	/* Send a reply back to client with return code */
	_rc = ospf_apiserver_send_reply(apiserv, seqnum, rc);
	rc = rc ? rc : _rc;
	apiserv->reachable_sync = !rc;
	return rc;
}

int ospf_apiserver_handle_sync_ism(struct ospf_apiserver *apiserv,
				   struct msg *msg)
{
	struct ospf *ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	struct listnode *anode, *inode;
	struct ospf_area *area;
	struct ospf_interface *oi;
	struct msg *m;
	uint32_t seqnum = msg_get_seq(msg);
	int _rc, rc = 0;

	/* walk all areas */
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, anode, area)) {
		/* walk all interfaces */
		for (ALL_LIST_ELEMENTS_RO(area->oiflist, inode, oi)) {
			m = new_msg_ism_change(seqnum, oi->address->u.prefix4,
					       area->area_id, oi->state);
			rc = ospf_apiserver_send_msg(apiserv, m);
			msg_free(m);
			if (rc)
				break;
		}
		if (rc)
			break;
	}
	/* Send a reply back to client with return code */
	_rc = ospf_apiserver_send_reply(apiserv, seqnum, rc);
	return rc ? rc : _rc;
}


int ospf_apiserver_handle_sync_nsm(struct ospf_apiserver *apiserv,
				   struct msg *msg)
{
	struct ospf *ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	struct listnode *anode, *inode;
	struct ospf_area *area;
	struct ospf_interface *oi;
	struct ospf_neighbor *nbr;
	struct route_node *rn;
	struct msg *m;
	uint32_t seqnum = msg_get_seq(msg);
	int _rc, rc = 0;

	/* walk all areas */
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, anode, area)) {
		/* walk all interfaces */
		for (ALL_LIST_ELEMENTS_RO(area->oiflist, inode, oi)) {
			/* walk all neighbors */
			for (rn = route_top(oi->nbrs); rn;
			     rn = route_next(rn)) {
				nbr = rn->info;
				if (!nbr)
					continue;
				m = new_msg_nsm_change(
					seqnum, oi->address->u.prefix4,
					nbr->src, nbr->router_id, nbr->state);
				rc = ospf_apiserver_send_msg(apiserv, m);
				msg_free(m);
				if (rc)
					break;
			}
			if (rc)
				break;
		}
		if (rc)
			break;
	}
	/* Send a reply back to client with return code */
	_rc = ospf_apiserver_send_reply(apiserv, seqnum, rc);
	return rc ? rc : _rc;
}


int ospf_apiserver_handle_sync_router_id(struct ospf_apiserver *apiserv,
					 struct msg *msg)
{
	struct ospf *ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	uint32_t seqnum = msg_get_seq(msg);
	struct msg *m;
	int _rc, rc = 0;

	m = new_msg_router_id_change(seqnum, ospf->router_id);
	rc = ospf_apiserver_send_msg(apiserv, m);
	msg_free(m);

	/* Send a reply back to client with return code */
	_rc = ospf_apiserver_send_reply(apiserv, seqnum, rc);
	return rc ? rc : _rc;
}

/* -----------------------------------------------------------
 * Following are functions to originate or update LSA
 * from an application.
 * -----------------------------------------------------------
 */

/* Create a new internal opaque LSA by taking prototype and filling in
   missing fields such as age, sequence number, advertising router,
   checksum and so on. The interface parameter is used for type 9
   LSAs, area parameter for type 10. Type 11 LSAs do neither need area
   nor interface. */

struct ospf_lsa *ospf_apiserver_opaque_lsa_new(struct ospf_area *area,
					       struct ospf_interface *oi,
					       struct lsa_header *protolsa)
{
	struct stream *s;
	struct lsa_header *newlsa;
	struct ospf_lsa *new = NULL;
	uint8_t options = 0x0;
	uint16_t length;

	struct ospf *ospf;

	if (oi && oi->ospf)
		ospf = oi->ospf;
	else
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	assert(ospf);

	/* Create a stream for internal opaque LSA */
	if ((s = stream_new(OSPF_MAX_LSA_SIZE)) == NULL) {
		zlog_warn("%s: stream_new failed", __func__);
		return NULL;
	}

	newlsa = (struct lsa_header *)STREAM_DATA(s);

	/* XXX If this is a link-local LSA or an AS-external LSA, how do we
	   have to set options? */

	if (area) {
		options = LSA_OPTIONS_GET(area);
		options |= LSA_OPTIONS_NSSA_GET(area);
	}

	options |= OSPF_OPTION_O; /* Don't forget to set option bit */

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug("LSA[Type%d:%pI4]: Creating an Opaque-LSA instance",
			   protolsa->type, &protolsa->id);
	}

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, protolsa->type, protolsa->id,
		       ospf->router_id);

	/* Set opaque-LSA body fields. */
	stream_put(s, ((uint8_t *)protolsa) + sizeof(struct lsa_header),
		   ntohs(protolsa->length) - sizeof(struct lsa_header));

	/* Determine length of LSA. */
	length = stream_get_endp(s);
	newlsa->length = htons(length);

	/* Create OSPF LSA. */
	new = ospf_lsa_new_and_data(length);

	new->area = area;
	new->oi = oi;
	new->vrf_id = ospf->vrf_id;

	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, newlsa, length);
	stream_free(s);

	return new;
}


int ospf_apiserver_is_ready_type9(struct ospf_interface *oi)
{
	/* We can always handle getting opaque's even if we can't flood them */
	return 1;
}

int ospf_apiserver_is_ready_type10(struct ospf_area *area)
{
	/* We can always handle getting opaque's even if we can't flood them */
	return 1;
}

int ospf_apiserver_is_ready_type11(struct ospf *ospf)
{
	/* We can always handle getting opaque's even if we can't flood them */
	return 1;
}


int ospf_apiserver_handle_originate_request(struct ospf_apiserver *apiserv,
					    struct msg *msg)
{
	struct msg_originate_request *omsg;
	struct lsa_header *data;
	struct ospf_lsa *new;
	struct ospf_lsa *old;
	struct ospf_area *area = NULL;
	struct ospf_interface *oi = NULL;
	struct ospf_lsdb *lsdb = NULL;
	struct ospf *ospf;
	int lsa_type, opaque_type;
	int ready = 0;
	int rc = 0;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Extract opaque LSA data from message */
	omsg = (struct msg_originate_request *)STREAM_DATA(msg->s);
	data = &omsg->data;

	/* Determine interface for type9 or area for type10 LSAs. */
	switch (data->type) {
	case OSPF_OPAQUE_LINK_LSA:
		oi = ospf_apiserver_if_lookup_by_addr(omsg->ifaddr);
		if (!oi) {
			zlog_warn("%s: unknown interface %pI4", __func__,
				  &omsg->ifaddr);
			rc = OSPF_API_NOSUCHINTERFACE;
			goto out;
		}
		area = oi->area;
		lsdb = area->lsdb;
		break;
	case OSPF_OPAQUE_AREA_LSA:
		area = ospf_area_lookup_by_area_id(ospf, omsg->area_id);
		if (!area) {
			zlog_warn("%s: unknown area %pI4", __func__,
				  &omsg->area_id);
			rc = OSPF_API_NOSUCHAREA;
			goto out;
		}
		lsdb = area->lsdb;
		break;
	case OSPF_OPAQUE_AS_LSA:
		lsdb = ospf->lsdb;
		break;
	default:
		/* We can only handle opaque types here */
		zlog_warn("%s: Cannot originate non-opaque LSA type %d",
			  __func__, data->type);
		rc = OSPF_API_ILLEGALLSATYPE;
		goto out;
	}

	/* Check if we registered this opaque type */
	lsa_type = data->type;
	opaque_type = GET_OPAQUE_TYPE(ntohl(data->id.s_addr));

	if (!apiserver_is_opaque_type_registered(apiserv, lsa_type,
						 opaque_type)) {
		zlog_warn("%s: LSA-type(%d)/Opaque-type(%d): Not registered",
			  __func__, lsa_type, opaque_type);
		rc = OSPF_API_OPAQUETYPENOTREGISTERED;
		goto out;
	}

	/* Make sure that the neighbors are ready before we can originate */
	switch (data->type) {
	case OSPF_OPAQUE_LINK_LSA:
		ready = ospf_apiserver_is_ready_type9(oi);
		break;
	case OSPF_OPAQUE_AREA_LSA:
		ready = ospf_apiserver_is_ready_type10(area);
		break;
	case OSPF_OPAQUE_AS_LSA:
		ready = ospf_apiserver_is_ready_type11(ospf);
		break;
	default:
		break;
	}

	if (!ready) {
		zlog_warn("Neighbors not ready to originate type %d",
			  data->type);
		rc = OSPF_API_NOTREADY;
		goto out;
	}

	/* Create OSPF's internal opaque LSA representation */
	new = ospf_apiserver_opaque_lsa_new(area, oi, data);
	if (!new) {
		rc = OSPF_API_NOMEMORY; /* XXX */
		goto out;
	}

	/* Determine if LSA is new or an update for an existing one. */
	old = ospf_lsdb_lookup(lsdb, new);

	if (!old || !ospf_opaque_is_owned(old)) {
		/* New LSA install in LSDB. */
		rc = ospf_apiserver_originate1(new, old);
	} else {
		/*
		 * Keep the new LSA instance in the "waiting place" until the
		 * next
		 * refresh timing. If several LSA update requests for the same
		 * LSID
		 * have issued by peer, the last one takes effect.
		 */
		new->lsdb = &apiserv->reserve;
		ospf_lsdb_add(&apiserv->reserve, new);

		/* Kick the scheduler function. */
		ospf_opaque_lsa_refresh_schedule(old);
	}

out:

	/* Send a reply back to client with return code */
	rc = ospf_apiserver_send_reply(apiserv, ntohl(msg->hdr.msgseq), rc);
	return rc;
}


/* -----------------------------------------------------------
 * Flood an LSA within its flooding scope.
 * -----------------------------------------------------------
 */

/* XXX We can probably use ospf_flood_through instead of this function
   but then we need the neighbor parameter. If we set nbr to
   NULL then ospf_flood_through crashes due to dereferencing NULL. */

void ospf_apiserver_flood_opaque_lsa(struct ospf_lsa *lsa)
{
	assert(lsa);

	switch (lsa->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
		/* Increment counters? XXX */

		/* Flood LSA through local network. */
		ospf_flood_through_area(lsa->area, NULL /*nbr */, lsa);
		break;
	case OSPF_OPAQUE_AREA_LSA:
		/* Update LSA origination count. */
		assert(lsa->area);
		lsa->area->ospf->lsa_originate_count++;

		/* Flood LSA through area. */
		ospf_flood_through_area(lsa->area, NULL /*nbr */, lsa);
		break;
	case OSPF_OPAQUE_AS_LSA: {
		struct ospf *ospf;

		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		assert(ospf);

		/* Increment counters? XXX */

		/* Flood LSA through AS. */
		ospf_flood_through_as(ospf, NULL /*nbr */, lsa);
		break;
	}
	}
}

int ospf_apiserver_originate1(struct ospf_lsa *lsa, struct ospf_lsa *old)
{
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	assert(ospf);

	if (old) {
		/*
		 * An old LSA exists that we didn't originate it in this
		 * session. Dump it, but increment past it's seqnum.
		 */
		assert(!ospf_opaque_is_owned(old));
		if (IS_DEBUG_OSPF_CLIENT_API)
			zlog_debug(
				"LSA[Type%d:%pI4]: OSPF API Server Originate LSA Old Seq: 0x%x Age: %d",
				old->data->type, &old->data->id,
				ntohl(old->data->ls_seqnum),
				ntohl(old->data->ls_age));
		if (IS_LSA_MAX_SEQ(old)) {
			flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
				  "%s: old LSA at maxseq", __func__);
			return -1;
		}
		lsa->data->ls_seqnum = lsa_seqnum_increment(old);
		ospf_discard_from_db(ospf, old->lsdb, old);
	}
	if (IS_DEBUG_OSPF_CLIENT_API)
		zlog_debug(
			"LSA[Type%d:%pI4]: OSPF API Server Originate LSA New Seq: 0x%x Age: %d",
			lsa->data->type, &lsa->data->id,
			ntohl(lsa->data->ls_seqnum), ntohl(lsa->data->ls_age));

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(ospf, lsa->oi, lsa) == NULL) {
		flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
			  "%s: ospf_lsa_install failed", __func__);
		return -1;
	}

/* Flood LSA within scope */

#ifdef NOTYET
	/*
	 * NB: Modified version of "ospf_flood_though ()" accepts NULL "inbr"
	 *     parameter, and thus it does not cause SIGSEGV error.
	 */
	ospf_flood_through(NULL /*nbr */, lsa);
#else  /* NOTYET */

	ospf_apiserver_flood_opaque_lsa(lsa);
#endif /* NOTYET */

	return 0;
}


/* Opaque LSAs of type 9 on a specific interface can now be
   originated. Tell clients that registered type 9. */
int ospf_apiserver_lsa9_originator(void *arg)
{
	struct ospf_interface *oi;

	oi = (struct ospf_interface *)arg;
	if (listcount(apiserver_list) > 0) {
		ospf_apiserver_clients_notify_ready_type9(oi);
	}
	return 0;
}

int ospf_apiserver_lsa10_originator(void *arg)
{
	struct ospf_area *area;

	area = (struct ospf_area *)arg;
	if (listcount(apiserver_list) > 0) {
		ospf_apiserver_clients_notify_ready_type10(area);
	}
	return 0;
}

int ospf_apiserver_lsa11_originator(void *arg)
{
	struct ospf *ospf;

	ospf = (struct ospf *)arg;
	if (listcount(apiserver_list) > 0) {
		ospf_apiserver_clients_notify_ready_type11(ospf);
	}
	return 0;
}


/* Periodically refresh opaque LSAs so that they do not expire in
   other routers. */
struct ospf_lsa *ospf_apiserver_lsa_refresher(struct ospf_lsa *lsa)
{
	struct ospf_apiserver *apiserv;
	struct ospf_lsa *new = NULL;
	struct ospf *ospf;

	assert(lsa);

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	assert(ospf);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug("LSA[Type%d:%pI4]: OSPF API Server LSA Refresher",
			   lsa->data->type, &lsa->data->id);
	}

	apiserv = lookup_apiserver_by_lsa(lsa);
	if (!apiserv) {
		zlog_warn("%s: LSA[%s]: No apiserver?", __func__,
			  dump_lsa_key(lsa));
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
		goto out;
	}

	/* Check if updated version of LSA instance has already prepared. */
	new = ospf_lsdb_lookup(&apiserv->reserve, lsa);
	if (!new) {
		if (IS_LSA_MAXAGE(lsa)) {
			ospf_opaque_lsa_flush_schedule(lsa);
			goto out;
		}

		/* This is a periodic refresh, driven by core OSPF mechanism. */
		new = ospf_apiserver_opaque_lsa_new(lsa->area, lsa->oi,
						    lsa->data);
		if (!new) {
			zlog_warn("%s: Cannot create a new LSA?", __func__);
			goto out;
		}
	} else {
		/* This is a forcible refresh, requested by OSPF-API client. */
		ospf_lsdb_delete(&apiserv->reserve, new);
		new->lsdb = NULL;
	}

	/* Increment sequence number */
	new->data->ls_seqnum = lsa_seqnum_increment(lsa);

	/* New LSA is in same area. */
	new->area = lsa->area;
	SET_FLAG(new->flags, OSPF_LSA_SELF);

	/* Install LSA into LSDB. */
	if (ospf_lsa_install(ospf, new->oi, new) == NULL) {
		flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
			  "%s: ospf_lsa_install failed", __func__);
		ospf_lsa_unlock(&new);
		goto out;
	}

/* Flood updated LSA through interface, area or AS */

#ifdef NOTYET
	ospf_flood_through(NULL /*nbr */, new);
#endif /* NOTYET */
	ospf_apiserver_flood_opaque_lsa(new);

	/* Debug logging. */
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug("LSA[Type%d:%pI4]: Refresh Opaque LSA",
			   new->data->type, &new->data->id);
		ospf_lsa_header_dump(new->data);
	}

out:
	return new;
}


/* -----------------------------------------------------------
 * Following are functions to delete LSAs
 * -----------------------------------------------------------
 */

int ospf_apiserver_handle_delete_request(struct ospf_apiserver *apiserv,
					 struct msg *msg)
{
	struct msg_delete_request *dmsg;
	struct ospf_lsa *old;
	struct ospf_area *area = NULL;
	struct ospf_interface *oi = NULL;
	struct in_addr id;
	int lsa_type, opaque_type;
	int rc = 0;
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	assert(ospf);

	/* Extract opaque LSA from message */
	dmsg = (struct msg_delete_request *)STREAM_DATA(msg->s);

	/* Lookup area for link-local and area-local opaque LSAs */
	switch (dmsg->lsa_type) {
	case OSPF_OPAQUE_LINK_LSA:
		oi = ospf_apiserver_if_lookup_by_addr(dmsg->addr);
		if (!oi) {
			zlog_warn("%s: unknown interface %pI4", __func__,
				  &dmsg->addr);
			rc = OSPF_API_NOSUCHINTERFACE;
			goto out;
		}
		area = oi->area;
		break;
	case OSPF_OPAQUE_AREA_LSA:
		area = ospf_area_lookup_by_area_id(ospf, dmsg->addr);
		if (!area) {
			zlog_warn("%s: unknown area %pI4", __func__,
				  &dmsg->addr);
			rc = OSPF_API_NOSUCHAREA;
			goto out;
		}
		break;
	case OSPF_OPAQUE_AS_LSA:
		/* AS-external opaque LSAs have no designated area */
		area = NULL;
		break;
	default:
		zlog_warn("%s: Cannot delete non-opaque LSA type %d", __func__,
			  dmsg->lsa_type);
		rc = OSPF_API_ILLEGALLSATYPE;
		goto out;
	}

	/* Check if we registered this opaque type */
	lsa_type = dmsg->lsa_type;
	opaque_type = dmsg->opaque_type;

	if (!apiserver_is_opaque_type_registered(apiserv, lsa_type,
						 opaque_type)) {
		zlog_warn("%s: LSA-type(%d)/Opaque-type(%d): Not registered",
			  __func__, lsa_type, opaque_type);
		rc = OSPF_API_OPAQUETYPENOTREGISTERED;
		goto out;
	}

	/* opaque_id is in network byte order */
	id.s_addr = htonl(
		SET_OPAQUE_LSID(dmsg->opaque_type, ntohl(dmsg->opaque_id)));

	/*
	 * Even if the target LSA has once scheduled to flush, it remains in
	 * the LSDB until it is finally handled by the maxage remover thread.
	 * Therefore, the lookup function below may return non-NULL result.
	 */
	old = ospf_lsa_lookup(ospf, area, dmsg->lsa_type, id, ospf->router_id);
	if (!old) {
		zlog_warn("%s: LSA[Type%d:%pI4] not in LSDB", __func__,
			  dmsg->lsa_type, &id);
		rc = OSPF_API_NOSUCHLSA;
		goto out;
	}

	if (IS_DEL_ZERO_LEN_LSA(dmsg)) {
		/* minimize the size of the withdrawal: */
		old->opaque_zero_len_delete = 1;
	}

	/* Schedule flushing of LSA from LSDB */
	/* NB: Multiple scheduling will produce a warning message, but harmless.
	 */
	ospf_opaque_lsa_flush_schedule(old);

out:

	/* Send reply back to client including return code */
	rc = ospf_apiserver_send_reply(apiserv, ntohl(msg->hdr.msgseq), rc);
	return rc;
}

/* Flush self-originated opaque LSA */
static int apiserver_flush_opaque_type_callback(struct ospf_lsa *lsa,
						void *p_arg, int int_arg)
{
	struct param_t {
		struct ospf_apiserver *apiserv;
		uint8_t lsa_type;
		uint8_t opaque_type;
	} * param;

	/* Sanity check */
	assert(lsa->data);
	assert(p_arg);
	param = (struct param_t *)p_arg;

	/* If LSA matches type and opaque type then delete it */
	if (IS_LSA_SELF(lsa) && lsa->data->type == param->lsa_type
	    && GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr))
		       == param->opaque_type) {
		ospf_opaque_lsa_flush_schedule(lsa);
	}
	return 0;
}

/* Delete self-originated opaque LSAs of a given opaque type. This
   function is called when an application unregisters a given opaque
   type or a connection to an application closes and all those opaque
   LSAs need to be flushed the LSDB. */
void ospf_apiserver_flush_opaque_lsa(struct ospf_apiserver *apiserv,
				     uint8_t lsa_type, uint8_t opaque_type)
{
	struct param_t {
		struct ospf_apiserver *apiserv;
		uint8_t lsa_type;
		uint8_t opaque_type;
	} param;
	struct listnode *node, *nnode;
	struct ospf *ospf;
	struct ospf_area *area;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	assert(ospf);

	/* Set parameter struct. */
	param.apiserv = apiserv;
	param.lsa_type = lsa_type;
	param.opaque_type = opaque_type;

	switch (lsa_type) {
		struct route_node *rn;
		struct ospf_lsa *lsa;

	case OSPF_OPAQUE_LINK_LSA:
		for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area))
			LSDB_LOOP (OPAQUE_LINK_LSDB(area), rn, lsa)
				apiserver_flush_opaque_type_callback(
					lsa, (void *)&param, 0);
		break;
	case OSPF_OPAQUE_AREA_LSA:
		for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area))
			LSDB_LOOP (OPAQUE_AREA_LSDB(area), rn, lsa)
				apiserver_flush_opaque_type_callback(
					lsa, (void *)&param, 0);
		break;
	case OSPF_OPAQUE_AS_LSA:
		LSDB_LOOP (OPAQUE_LINK_LSDB(ospf), rn, lsa)
			apiserver_flush_opaque_type_callback(lsa,
							     (void *)&param, 0);
		break;
	default:
		break;
	}
	return;
}


/* -----------------------------------------------------------
 * Following are callback functions to handle opaque types
 * -----------------------------------------------------------
 */

int ospf_apiserver_new_if(struct interface *ifp)
{
	struct ospf_interface *oi;

	/* For some strange reason it seems possible that we are invoked
	   with an interface that has no name. This seems to happen during
	   initialization. Return if this happens */

	if (ifp->name[0] == '\0') {
		/* interface has empty name */
		zlog_warn("%s: interface has no name?", __func__);
		return 0;
	}

	/* zlog_warn for debugging */
	zlog_warn("ospf_apiserver_new_if");
	zlog_warn("ifp name=%s status=%d index=%d", ifp->name, ifp->status,
		  ifp->ifindex);

	if (ifp->name[0] == '\0') {
		/* interface has empty name */
		zlog_warn("%s: interface has no name?", __func__);
		return 0;
	}

	oi = ospf_apiserver_if_lookup_by_ifp(ifp);

	if (!oi) {
		/* This interface is known to Zebra but not to OSPF daemon yet.
		 */
		zlog_warn("%s: interface %s not known to OSPFd?", __func__,
			  ifp->name);
		return 0;
	}

	assert(oi);

	/* New interface added to OSPF, tell clients about it */
	if (listcount(apiserver_list) > 0) {
		ospf_apiserver_clients_notify_new_if(oi);
	}
	return 0;
}

int ospf_apiserver_del_if(struct interface *ifp)
{
	struct ospf_interface *oi;

	/* zlog_warn for debugging */
	zlog_warn("%s ifp name=%s status=%d index=%d", __func__, ifp->name,
		  ifp->status, ifp->ifindex);

	oi = ospf_apiserver_if_lookup_by_ifp(ifp);

	if (!oi) {
		/* This interface is known to Zebra but not to OSPF daemon
		   anymore. No need to tell clients about it */
		zlog_warn("ifp name=%s not known to OSPFd", ifp->name);
		return 0;
	}

	/* Interface deleted, tell clients about it */
	if (listcount(apiserver_list) > 0) {
		ospf_apiserver_clients_notify_del_if(oi);
	}
	return 0;
}

void ospf_apiserver_ism_change(struct ospf_interface *oi, int old_state)
{
	/* Tell clients about interface change */

	/* zlog_warn for debugging */
	zlog_warn("%s", __func__);
	if (listcount(apiserver_list) > 0) {
		ospf_apiserver_clients_notify_ism_change(oi);
	}

	zlog_warn("%s oi->ifp->name=%s old_state=%d oi->state=%d", __func__,
		  oi->ifp->name, old_state, oi->state);
}

void ospf_apiserver_nsm_change(struct ospf_neighbor *nbr, int old_status)
{
	/* Neighbor status changed, tell clients about it */
	zlog_warn("%s", __func__);
	if (listcount(apiserver_list) > 0) {
		ospf_apiserver_clients_notify_nsm_change(nbr);
	}
}

void ospf_apiserver_show_info(struct vty *vty, struct json_object *json,
			      struct ospf_lsa *lsa)
{
	struct opaque_lsa {
		struct lsa_header header;
		uint8_t data[1]; /* opaque data have variable length. This is
				   start
				   address */
	};
	struct opaque_lsa *olsa;
	int opaquelen;

	olsa = (struct opaque_lsa *)lsa->data;

	if (VALID_OPAQUE_INFO_LEN(lsa->data))
		opaquelen = ntohs(lsa->data->length) - OSPF_LSA_HEADER_SIZE;
	else
		opaquelen = 0;

	/* Output information about opaque LSAs */
	if (json)
		json_object_string_addf(json, "opaqueData", "%*pHXn",
					(int)opaquelen, olsa->data);
	else if (vty != NULL) {
		int i;
		vty_out(vty,
			"  Added using OSPF API: %u octets of opaque data %s\n",
			opaquelen,
			VALID_OPAQUE_INFO_LEN(lsa->data) ? ""
							 : "(Invalid length?)");
		vty_out(vty, "  Opaque data: ");

		for (i = 0; i < opaquelen; i++) {
			vty_out(vty, "0x%x ", olsa->data[i]);
		}
		vty_out(vty, "\n");
	} else {
		int i;
		zlog_debug(
			"    Added using OSPF API: %u octets of opaque data %s",
			opaquelen,
			VALID_OPAQUE_INFO_LEN(lsa->data) ? ""
							 : "(Invalid length?)");
		zlog_debug("    Opaque data: ");

		for (i = 0; i < opaquelen; i++) {
			zlog_debug("0x%x ", olsa->data[i]);
		}
	}
	return;
}

/* -----------------------------------------------------------
 * Following are functions to notify clients about events
 * -----------------------------------------------------------
 */

/* Send a message to all clients. This is useful for messages
   that need to be notified to all clients (such as interface
   changes) */

void ospf_apiserver_clients_notify_all(struct msg *msg)
{
	struct listnode *node, *nnode;
	struct ospf_apiserver *apiserv;

	/* Send message to all clients */
	for (ALL_LIST_ELEMENTS(apiserver_list, node, nnode, apiserv))
		ospf_apiserver_send_msg(apiserv, msg);
}

/* An interface is now ready to accept opaque LSAs. Notify all
   clients that registered to use this opaque type */
void ospf_apiserver_clients_notify_ready_type9(struct ospf_interface *oi)
{
	struct listnode *node, *nnode;
	struct msg *msg;
	struct ospf_apiserver *apiserv;

	assert(oi);
	if (!oi->address) {
		zlog_warn("Interface has no address?");
		return;
	}

	if (!ospf_apiserver_is_ready_type9(oi)) {
		zlog_warn("Interface not ready for type 9?");
		return;
	}

	for (ALL_LIST_ELEMENTS(apiserver_list, node, nnode, apiserv)) {
		struct listnode *node2, *nnode2;
		struct registered_opaque_type *r;

		for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node2, nnode2,
				       r)) {
			if (r->lsa_type == OSPF_OPAQUE_LINK_LSA) {
				msg = new_msg_ready_notify(
					0, OSPF_OPAQUE_LINK_LSA, r->opaque_type,
					oi->address->u.prefix4);
				if (!msg) {
					zlog_warn(
						"%s: new_msg_ready_notify failed",
						__func__);
#ifdef NOTYET
					/* Cannot allocate new message. What
					 * should we do? */
					ospf_apiserver_free(apiserv);
#endif
					goto out;
				}

				ospf_apiserver_send_msg(apiserv, msg);
				msg_free(msg);
			}
		}
	}

out:
	return;
}

void ospf_apiserver_clients_notify_ready_type10(struct ospf_area *area)
{
	struct listnode *node, *nnode;
	struct msg *msg;
	struct ospf_apiserver *apiserv;

	assert(area);

	if (!ospf_apiserver_is_ready_type10(area)) {
		zlog_warn("Area not ready for type 10?");
		return;
	}

	for (ALL_LIST_ELEMENTS(apiserver_list, node, nnode, apiserv)) {
		struct listnode *node2, *nnode2;
		struct registered_opaque_type *r;

		for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node2, nnode2,
				       r)) {
			if (r->lsa_type == OSPF_OPAQUE_AREA_LSA) {
				msg = new_msg_ready_notify(
					0, OSPF_OPAQUE_AREA_LSA, r->opaque_type,
					area->area_id);
				if (!msg) {
					zlog_warn(
						"%s: new_msg_ready_nofity failed",
						__func__);
#ifdef NOTYET
					/* Cannot allocate new message. What
					 * should we do? */
					ospf_apiserver_free(apiserv);
#endif
					goto out;
				}

				ospf_apiserver_send_msg(apiserv, msg);
				msg_free(msg);
			}
		}
	}

out:
	return;
}


void ospf_apiserver_clients_notify_ready_type11(struct ospf *top)
{
	struct listnode *node, *nnode;
	struct msg *msg;
	struct in_addr id_null = {.s_addr = 0L};
	struct ospf_apiserver *apiserv;

	assert(top);

	if (!ospf_apiserver_is_ready_type11(top)) {
		zlog_warn("AS not ready for type 11?");
		return;
	}

	for (ALL_LIST_ELEMENTS(apiserver_list, node, nnode, apiserv)) {
		struct listnode *node2, *nnode2;
		struct registered_opaque_type *r;

		for (ALL_LIST_ELEMENTS(apiserv->opaque_types, node2, nnode2,
				       r)) {
			if (r->lsa_type == OSPF_OPAQUE_AS_LSA) {
				msg = new_msg_ready_notify(
					0, OSPF_OPAQUE_AS_LSA, r->opaque_type,
					id_null);
				if (!msg) {
					zlog_warn(
						"%s: new_msg_ready_notify failed",
						__func__);
#ifdef NOTYET
					/* Cannot allocate new message. What
					 * should we do? */
					ospf_apiserver_free(apiserv);
#endif
					goto out;
				}

				ospf_apiserver_send_msg(apiserv, msg);
				msg_free(msg);
			}
		}
	}

out:
	return;
}

void ospf_apiserver_clients_notify_new_if(struct ospf_interface *oi)
{
	struct msg *msg;

	msg = new_msg_new_if(0, oi->address->u.prefix4, oi->area->area_id);
	if (msg != NULL) {
		ospf_apiserver_clients_notify_all(msg);
		msg_free(msg);
	}
}

void ospf_apiserver_clients_notify_del_if(struct ospf_interface *oi)
{
	struct msg *msg;

	msg = new_msg_del_if(0, oi->address->u.prefix4);
	if (msg != NULL) {
		ospf_apiserver_clients_notify_all(msg);
		msg_free(msg);
	}
}

void ospf_apiserver_clients_notify_ism_change(struct ospf_interface *oi)
{
	struct msg *msg;
	struct in_addr ifaddr = {.s_addr = 0L};
	struct in_addr area_id = {.s_addr = 0L};

	assert(oi);
	assert(oi->ifp);

	if (oi->address) {
		ifaddr = oi->address->u.prefix4;
	}
	if (oi->area) {
		area_id = oi->area->area_id;
	}

	msg = new_msg_ism_change(0, ifaddr, area_id, oi->state);
	if (!msg) {
		zlog_warn("%s: msg_new failed", __func__);
		return;
	}

	ospf_apiserver_clients_notify_all(msg);
	msg_free(msg);
}

void ospf_apiserver_clients_notify_nsm_change(struct ospf_neighbor *nbr)
{
	struct msg *msg;
	struct in_addr ifaddr;
	struct in_addr nbraddr;

	assert(nbr);

	ifaddr = nbr->oi->address->u.prefix4;

	nbraddr = nbr->address.u.prefix4;

	msg = new_msg_nsm_change(0, ifaddr, nbraddr, nbr->router_id,
				 nbr->state);
	if (!msg) {
		zlog_warn("%s: msg_new failed", __func__);
		return;
	}

	ospf_apiserver_clients_notify_all(msg);
	msg_free(msg);
}

static int apiserver_clients_lsa_change_notify(uint8_t msgtype,
					       struct ospf_lsa *lsa)
{
	struct msg *msg;
	struct listnode *node, *nnode;
	struct ospf_apiserver *apiserv;

	/* Default area for AS-External and Opaque11 LSAs */
	struct in_addr area_id = {.s_addr = 0L};

	/* Default interface for non Opaque9 LSAs */
	struct in_addr ifaddr = {.s_addr = 0L};

	if (lsa->area) {
		area_id = lsa->area->area_id;
	}
	if (lsa->data->type == OSPF_OPAQUE_LINK_LSA) {
		assert(lsa->oi);
		ifaddr = lsa->oi->address->u.prefix4;
	}

	/* Prepare message that can be sent to clients that have a matching
	   filter */
	msg = new_msg_lsa_change_notify(msgtype, 0L, /* no sequence number */
					ifaddr, area_id,
					lsa->flags & OSPF_LSA_SELF, lsa->data);
	if (!msg) {
		zlog_warn("%s: msg_new failed", __func__);
		return -1;
	}

	/* Now send message to all clients with a matching filter */
	for (ALL_LIST_ELEMENTS(apiserver_list, node, nnode, apiserv)) {
		struct lsa_filter_type *filter;
		uint16_t mask;
		uint32_t *area;
		int i;

		/* Check filter for this client. */
		filter = apiserv->filter;

		/* Check area IDs in case of non AS-E LSAs.
		 * If filter has areas (num_areas > 0),
		 * then one of the areas must match the area ID of this LSA. */

		i = filter->num_areas;
		if ((lsa->data->type == OSPF_AS_EXTERNAL_LSA)
		    || (lsa->data->type == OSPF_OPAQUE_AS_LSA)) {
			i = 0;
		}

		if (i > 0) {
			area = (uint32_t *)(filter + 1);
			while (i) {
				if (*area == area_id.s_addr) {
					break;
				}
				i--;
				area++;
			}
		} else {
			i = 1;
		}

		if (i > 0) {
			/* Area match. Check LSA type. */
			mask = ntohs(filter->typemask);

			if (mask & Power2[lsa->data->type]) {
				/* Type also matches. Check origin. */
				if ((filter->origin == ANY_ORIGIN)
				    || (filter->origin == IS_LSA_SELF(lsa))) {
					ospf_apiserver_send_msg(apiserv, msg);
				}
			}
		}
	}
	/* Free message since it is not used anymore */
	msg_free(msg);

	return 0;
}


/* -------------------------------------------------------------
 * Following are hooks invoked when LSAs are updated or deleted
 * -------------------------------------------------------------
 */


int ospf_apiserver_lsa_update(struct ospf_lsa *lsa)
{

	/* Only notify this update if the LSA's age is smaller than
	   MAXAGE. Otherwise clients would see LSA updates with max age just
	   before they are deleted from the LSDB. LSA delete messages have
	   MAXAGE too but should not be filtered. */
	if (IS_LSA_MAXAGE(lsa))
		return 0;
	return apiserver_clients_lsa_change_notify(MSG_LSA_UPDATE_NOTIFY, lsa);
}

int ospf_apiserver_lsa_delete(struct ospf_lsa *lsa)
{
	return apiserver_clients_lsa_change_notify(MSG_LSA_DELETE_NOTIFY, lsa);
}

/* -------------------------------------------------------------
 * Reachable functions
 * -------------------------------------------------------------
 */

static inline int cmp_route_nodes(struct route_node *orn,
				  struct route_node *nrn)
{
	if (!orn)
		return 1;
	else if (!nrn)
		return -1;

	uint32_t opn = ntohl(orn->p.u.prefix4.s_addr);
	uint32_t npn = ntohl(nrn->p.u.prefix4.s_addr);
	if (opn < npn)
		return -1;
	else if (opn > npn)
		return 1;
	else
		return 0;
}

void ospf_apiserver_notify_reachable(struct route_table *ort,
				     struct route_table *nrt)
{
	struct msg *msg;
	struct msg_reachable_change *areach;
	struct route_node *orn, *nrn;
	const uint insz = sizeof(struct in_addr);
	struct in_addr *abuf = NULL, *dbuf = NULL;
	struct in_addr *a = NULL, *d = NULL;
	uint nadd, nremove;
	int cmp;

	if (!ort && !nrt) {
		if (IS_DEBUG_OSPF_CLIENT_API)
			zlog_debug("%s: no routing tables", __func__);
		return;
	}
	if (nrt && nrt->count)
		a = abuf = XCALLOC(MTYPE_APISERVER, insz * nrt->count);
	if (ort && ort->count)
		d = dbuf = XCALLOC(MTYPE_APISERVER, insz * ort->count);

	/* walk both tables */
	orn = ort ? route_top(ort) : NULL;
	nrn = nrt ? route_top(nrt) : NULL;
	while (orn || nrn) {
		if (orn && !listhead((struct list *)orn->info)) {
			orn = route_next(orn);
			continue;
		}
		if (nrn && !listhead((struct list *)nrn->info)) {
			nrn = route_next(nrn);
			continue;
		}
		cmp = cmp_route_nodes(orn, nrn);
		if (!cmp) {
			/* if old == new advance old and new */
			if (IS_DEBUG_OSPF_CLIENT_API)
				zlog_debug("keeping router id: %pI4",
					   &orn->p.u.prefix4);
			orn = route_next(orn);
			nrn = route_next(nrn);
		} else if (cmp < 0) {
			assert(d != NULL); /* Silence SA warning */

			/* if old < new, delete old, advance old */
			*d++ = orn->p.u.prefix4;
			if (IS_DEBUG_OSPF_CLIENT_API)
				zlog_debug("removing router id: %pI4",
					   &orn->p.u.prefix4);
			orn = route_next(orn);
		} else {
			assert(a != NULL); /* Silence SA warning */

			/* if new < old, add new, advance new */
			*a++ = nrn->p.u.prefix4;
			if (IS_DEBUG_OSPF_CLIENT_API)
				zlog_debug("adding router id: %pI4",
					   &nrn->p.u.prefix4);
			nrn = route_next(nrn);
		}
	}

	nadd = abuf ? (a - abuf) : 0;
	nremove = dbuf ? (d - dbuf) : 0;
	a = abuf;
	d = dbuf;

	while (nadd + nremove) {
		msg = new_msg_reachable_change(0, nadd, a, nremove, d);
		areach = (struct msg_reachable_change *)STREAM_DATA(msg->s);

		a += ntohs(areach->nadd);
		nadd = nadd - ntohs(areach->nadd);

		d += ntohs(areach->nremove);
		nremove = nremove - ntohs(areach->nremove);

		if (IS_DEBUG_OSPF_CLIENT_API)
			zlog_debug("%s: adding %d removing %d", __func__,
				   ntohs(areach->nadd), ntohs(areach->nremove));
		ospf_apiserver_clients_notify_all(msg);
		msg_free(msg);
	}
	if (abuf)
		XFREE(MTYPE_APISERVER, abuf);
	if (dbuf)
		XFREE(MTYPE_APISERVER, dbuf);
}


void ospf_apiserver_clients_notify_router_id_change(struct in_addr router_id)
{
	struct msg *msg;

	msg = new_msg_router_id_change(0, router_id);
	if (!msg) {
		zlog_warn("%s: new_msg_router_id_change failed", __func__);
		return;
	}

	ospf_apiserver_clients_notify_all(msg);
	msg_free(msg);
}


#endif /* SUPPORT_OSPF_API */
