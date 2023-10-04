// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP network related fucntions
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "frrevent.h"
#include "sockunion.h"
#include "sockopt.h"
#include "memory.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "privs.h"
#include "linklist.h"
#include "network.h"
#include "queue.h"
#include "hash.h"
#include "filter.h"
#include "ns.h"
#include "lib_errors.h"
#include "nexthop.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nht.h"

extern struct zebra_privs_t bgpd_privs;

static char *bgp_get_bound_name(struct peer_connection *connection);

void bgp_dump_listener_info(struct vty *vty)
{
	struct listnode *node;
	struct bgp_listener *listener;

	vty_out(vty, "Name             fd Address\n");
	vty_out(vty, "---------------------------\n");
	for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener))
		vty_out(vty, "%-16s %d %pSU\n",
			listener->name ? listener->name : VRF_DEFAULT_NAME,
			listener->fd, &listener->su);
}

/*
 * Set MD5 key for the socket, for the given IPv4 peer address.
 * If the password is NULL or zero-length, the option will be disabled.
 */
static int bgp_md5_set_socket(int socket, union sockunion *su,
			      uint16_t prefixlen, const char *password)
{
	int ret = -1;
	int en = ENOSYS;
#if HAVE_DECL_TCP_MD5SIG
	union sockunion su2;
#endif /* HAVE_TCP_MD5SIG */

	assert(socket >= 0);

#if HAVE_DECL_TCP_MD5SIG
	/* Ensure there is no extraneous port information. */
	memcpy(&su2, su, sizeof(union sockunion));
	if (su2.sa.sa_family == AF_INET)
		su2.sin.sin_port = 0;
	else
		su2.sin6.sin6_port = 0;

	/* For addresses, use the non-extended signature functionality */
	if ((su2.sa.sa_family == AF_INET && prefixlen == IPV4_MAX_BITLEN)
	    || (su2.sa.sa_family == AF_INET6 && prefixlen == IPV6_MAX_BITLEN))
		ret = sockopt_tcp_signature(socket, &su2, password);
	else
		ret = sockopt_tcp_signature_ext(socket, &su2, prefixlen,
						password);
	en = errno;
#endif /* HAVE_TCP_MD5SIG */

	if (ret < 0) {
		switch (ret) {
		case -2:
			flog_warn(
				EC_BGP_NO_TCP_MD5,
				"Unable to set TCP MD5 option on socket for peer %pSU (sock=%d): This platform does not support MD5 auth for prefixes",
				su, socket);
			break;
		default:
			flog_warn(
				EC_BGP_NO_TCP_MD5,
				"Unable to set TCP MD5 option on socket for peer %pSU (sock=%d): %s",
				su, socket, safe_strerror(en));
		}
	}

	return ret;
}

/* Helper for bgp_connect */
static int bgp_md5_set_connect(int socket, union sockunion *su,
			       uint16_t prefixlen, const char *password)
{
	int ret = -1;

#if HAVE_DECL_TCP_MD5SIG
	frr_with_privs(&bgpd_privs) {
		ret = bgp_md5_set_socket(socket, su, prefixlen, password);
	}
#endif /* HAVE_TCP_MD5SIG */

	return ret;
}

static int bgp_md5_set_password(struct peer_connection *connection,
				const char *password)
{
	struct listnode *node;
	int ret = 0;
	struct bgp_listener *listener;
	struct peer *peer = connection->peer;

	/*
	 * Set or unset the password on the listen socket(s). Outbound
	 * connections are taken care of in bgp_connect() below.
	 */
	frr_with_privs(&bgpd_privs) {
		for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener))
			if (listener->su.sa.sa_family ==
			    connection->su.sa.sa_family) {
				uint16_t prefixlen =
					connection->su.sa.sa_family == AF_INET
						? IPV4_MAX_BITLEN
						: IPV6_MAX_BITLEN;

				/*
				 * if we have stored a BGP vrf instance in the
				 * listener it must match the bgp instance in
				 * the peer otherwise the peer bgp instance
				 * must be the default vrf or a view instance
				 */
				if (!listener->bgp) {
					if (peer->bgp->vrf_id != VRF_DEFAULT)
						continue;
				} else if (listener->bgp != peer->bgp)
					continue;

				ret = bgp_md5_set_socket(listener->fd,
							 &connection->su,
							 prefixlen, password);
				break;
			}
	}
	return ret;
}

int bgp_md5_set_prefix(struct bgp *bgp, struct prefix *p, const char *password)
{
	int ret = 0;
	union sockunion su;
	struct listnode *node;
	struct bgp_listener *listener;

	/* Set or unset the password on the listen socket(s). */
	frr_with_privs(&bgpd_privs) {
		for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener))
			if (listener->su.sa.sa_family == p->family
			    && ((bgp->vrf_id == VRF_DEFAULT)
				|| (listener->bgp == bgp))) {
				prefix2sockunion(p, &su);
				ret = bgp_md5_set_socket(listener->fd, &su,
							 p->prefixlen,
							 password);
				break;
			}
	}

	return ret;
}

int bgp_md5_unset_prefix(struct bgp *bgp, struct prefix *p)
{
	return bgp_md5_set_prefix(bgp, p, NULL);
}

int bgp_md5_set(struct peer_connection *connection)
{
	/* Set the password from listen socket. */
	return bgp_md5_set_password(connection, connection->peer->password);
}

static void bgp_update_setsockopt_tcp_keepalive(struct bgp *bgp, int fd)
{
	if (!bgp)
		return;
	if (bgp->tcp_keepalive_idle != 0) {
		int ret;

		ret = setsockopt_tcp_keepalive(fd, bgp->tcp_keepalive_idle,
					       bgp->tcp_keepalive_intvl,
					       bgp->tcp_keepalive_probes);
		if (ret < 0)
			zlog_err(
				"Can't set TCP keepalive on socket %d, idle %u intvl %u probes %u",
				fd, bgp->tcp_keepalive_idle,
				bgp->tcp_keepalive_intvl,
				bgp->tcp_keepalive_probes);
	}
}

int bgp_md5_unset(struct peer_connection *connection)
{
	/* Unset the password from listen socket. */
	return bgp_md5_set_password(connection, NULL);
}

int bgp_set_socket_ttl(struct peer_connection *connection)
{
	int ret = 0;
	struct peer *peer = connection->peer;

	if (!peer->gtsm_hops) {
		ret = sockopt_ttl(connection->su.sa.sa_family, connection->fd,
				  peer->ttl);
		if (ret) {
			flog_err(
				EC_LIB_SOCKET,
				"%s: Can't set TxTTL on peer (rtrid %pI4) socket, err = %d",
				__func__, &peer->remote_id, errno);
			return ret;
		}
	} else {
		/* On Linux, setting minttl without setting ttl seems to mess
		   with the
		   outgoing ttl. Therefore setting both.
		*/
		ret = sockopt_ttl(connection->su.sa.sa_family, connection->fd,
				  MAXTTL);
		if (ret) {
			flog_err(
				EC_LIB_SOCKET,
				"%s: Can't set TxTTL on peer (rtrid %pI4) socket, err = %d",
				__func__, &peer->remote_id, errno);
			return ret;
		}
		ret = sockopt_minttl(connection->su.sa.sa_family, connection->fd,
				     MAXTTL + 1 - peer->gtsm_hops);
		if (ret) {
			flog_err(
				EC_LIB_SOCKET,
				"%s: Can't set MinTTL on peer (rtrid %pI4) socket, err = %d",
				__func__, &peer->remote_id, errno);
			return ret;
		}
	}

	return ret;
}

/*
 * Obtain the BGP instance that the incoming connection should be processed
 * against. This is important because more than one VRF could be using the
 * same IP address space. The instance is got by obtaining the device to
 * which the incoming connection is bound to. This could either be a VRF
 * or it could be an interface, which in turn determines the VRF.
 */
static int bgp_get_instance_for_inc_conn(int sock, struct bgp **bgp_inst)
{
#ifndef SO_BINDTODEVICE
	/* only Linux has SO_BINDTODEVICE, but we're in Linux-specific code here
	 * anyway since the assumption is that the interface name returned by
	 * getsockopt() is useful in identifying the VRF, particularly with
	 * Linux's
	 * VRF l3master device.  The whole mechanism is specific to Linux, so...
	 * when other platforms add VRF support, this will need handling here as
	 * well.  (or, some restructuring) */
	*bgp_inst = bgp_get_default();
	return !*bgp_inst;

#else
	char name[VRF_NAMSIZ + 1];
	socklen_t name_len = VRF_NAMSIZ;
	struct bgp *bgp;
	int rc;
	struct listnode *node, *nnode;

	*bgp_inst = NULL;
	name[0] = '\0';
	rc = getsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, name, &name_len);
	if (rc != 0) {
#if defined(HAVE_CUMULUS)
		flog_err(EC_LIB_SOCKET,
			 "[Error] BGP SO_BINDTODEVICE get failed (%s), sock %d",
			 safe_strerror(errno), sock);
		return -1;
#endif
	}

	if (!strlen(name)) {
		*bgp_inst = bgp_get_default();
		return 0; /* default instance. */
	}

	/* First try match to instance; if that fails, check for interfaces. */
	bgp = bgp_lookup_by_name(name);
	if (bgp) {
		if (!bgp->vrf_id) // unexpected
			return -1;
		*bgp_inst = bgp;
		return 0;
	}

	/* TODO - This will be optimized once interfaces move into the NS */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		struct interface *ifp;

		if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
			continue;

		ifp = if_lookup_by_name(name, bgp->vrf_id);
		if (ifp) {
			*bgp_inst = bgp;
			return 0;
		}
	}

	/* We didn't match to either an instance or an interface. */
	return -1;
#endif
}

int bgp_tcp_mss_set(struct peer *peer)
{
	struct listnode *node;
	int ret = 0;
	struct bgp_listener *listener;
	uint32_t min_mss = 0;
	struct peer *p;

	for (ALL_LIST_ELEMENTS_RO(peer->bgp->peer, node, p)) {
		if (!CHECK_FLAG(p->flags, PEER_FLAG_TCP_MSS))
			continue;

		if (!p->tcp_mss)
			continue;

		if (!min_mss)
			min_mss = p->tcp_mss;

		min_mss = MIN(min_mss, p->tcp_mss);
	}

	frr_with_privs(&bgpd_privs) {
		for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener)) {
			if (listener->su.sa.sa_family !=
			    peer->connection->su.sa.sa_family)
				continue;

			if (!listener->bgp) {
				if (peer->bgp->vrf_id != VRF_DEFAULT)
					continue;
			} else if (listener->bgp != peer->bgp)
				continue;

			/* Set TCP MSS per listener only if there is at least
			 * one peer that is in passive mode. Otherwise, TCP MSS
			 * is set per socket via bgp_connect().
			 */
			if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSIVE))
				sockopt_tcp_mss_set(listener->fd, min_mss);

			break;
		}
	}

	return ret;
}

static void bgp_socket_set_buffer_size(const int fd)
{
	if (getsockopt_so_sendbuf(fd) < (int)bm->socket_buffer)
		setsockopt_so_sendbuf(fd, bm->socket_buffer);
	if (getsockopt_so_recvbuf(fd) < (int)bm->socket_buffer)
		setsockopt_so_recvbuf(fd, bm->socket_buffer);
}

/* Accept bgp connection. */
static void bgp_accept(struct event *thread)
{
	int bgp_sock;
	int accept_sock;
	union sockunion su;
	struct bgp_listener *listener = EVENT_ARG(thread);
	struct peer *peer, *peer1;
	struct peer_connection *connection, *connection1;
	char buf[SU_ADDRSTRLEN];
	struct bgp *bgp = NULL;

	sockunion_init(&su);

	bgp = bgp_lookup_by_name(listener->name);

	/* Register accept thread. */
	accept_sock = EVENT_FD(thread);
	if (accept_sock < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "[Error] BGP accept socket fd is negative: %d",
			     accept_sock);
		return;
	}

	event_add_read(bm->master, bgp_accept, listener, accept_sock,
		       &listener->thread);

	/* Accept client connection. */
	bgp_sock = sockunion_accept(accept_sock, &su);
	int save_errno = errno;
	if (bgp_sock < 0) {
		if (save_errno == EINVAL) {
			struct vrf *vrf =
				bgp ? vrf_lookup_by_id(bgp->vrf_id) : NULL;

			/*
			 * It appears that sometimes, when VRFs are deleted on
			 * the system, it takes a little while for us to get
			 * notified about that. In the meantime we endlessly
			 * loop on accept(), because the socket, having been
			 * bound to a now-deleted VRF device, is in some weird
			 * state which causes accept() to fail.
			 *
			 * To avoid this, if we see accept() fail with EINVAL,
			 * we cancel ourselves and trust that when the VRF
			 * deletion notification comes in the event handler for
			 * that will take care of cleaning us up.
			 */
			flog_err_sys(
				EC_LIB_SOCKET,
				"[Error] accept() failed with error \"%s\" on BGP listener socket %d for BGP instance in VRF \"%s\"; refreshing socket",
				safe_strerror(save_errno), accept_sock,
				VRF_LOGNAME(vrf));
			EVENT_OFF(listener->thread);
		} else {
			flog_err_sys(
				EC_LIB_SOCKET,
				"[Error] BGP socket accept failed (%s); retrying",
				safe_strerror(save_errno));
		}
		return;
	}
	set_nonblocking(bgp_sock);

	/* Obtain BGP instance this connection is meant for.
	 * - if it is a VRF netns sock, then BGP is in listener structure
	 * - otherwise, the bgp instance need to be demultiplexed
	 */
	if (listener->bgp)
		bgp = listener->bgp;
	else if (bgp_get_instance_for_inc_conn(bgp_sock, &bgp)) {
		if (bgp_debug_neighbor_events(NULL))
			zlog_debug(
				"[Event] Could not get instance for incoming conn from %s",
				inet_sutop(&su, buf));
		close(bgp_sock);
		return;
	}

	bgp_socket_set_buffer_size(bgp_sock);

	/* Set TCP keepalive when TCP keepalive is enabled */
	bgp_update_setsockopt_tcp_keepalive(bgp, bgp_sock);

	/* Check remote IP address */
	peer1 = peer_lookup(bgp, &su);

	if (!peer1) {
		peer1 = peer_lookup_dynamic_neighbor(bgp, &su);
		if (peer1) {
			connection1 = peer1->connection;
			/* Dynamic neighbor has been created, let it proceed */
			connection1->fd = bgp_sock;

			/* Set the user configured MSS to TCP socket */
			if (CHECK_FLAG(peer1->flags, PEER_FLAG_TCP_MSS))
				sockopt_tcp_mss_set(bgp_sock, peer1->tcp_mss);

			bgp_fsm_change_status(connection1, Active);
			EVENT_OFF(connection1->t_start);

			if (peer_active(peer1)) {
				if (CHECK_FLAG(peer1->flags,
					       PEER_FLAG_TIMER_DELAYOPEN))
					BGP_EVENT_ADD(connection1,
						      TCP_connection_open_w_delay);
				else
					BGP_EVENT_ADD(connection1,
						      TCP_connection_open);
			}

			return;
		}
	}

	if (!peer1) {
		if (bgp_debug_neighbor_events(NULL)) {
			zlog_debug(
				"[Event] %s connection rejected(%s:%u:%s) - not configured and not valid for dynamic",
				inet_sutop(&su, buf), bgp->name_pretty, bgp->as,
				VRF_LOGNAME(vrf_lookup_by_id(bgp->vrf_id)));
		}
		close(bgp_sock);
		return;
	}

	connection1 = peer1->connection;
	if (CHECK_FLAG(peer1->flags, PEER_FLAG_SHUTDOWN)
	    || CHECK_FLAG(peer1->bgp->flags, BGP_FLAG_SHUTDOWN)) {
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"[Event] connection from %s rejected(%s:%u:%s) due to admin shutdown",
				inet_sutop(&su, buf), bgp->name_pretty, bgp->as,
				VRF_LOGNAME(vrf_lookup_by_id(bgp->vrf_id)));
		close(bgp_sock);
		return;
	}

	/*
	 * Do not accept incoming connections in Clearing state. This can result
	 * in incorect state transitions - e.g., the connection goes back to
	 * Established and then the Clearing_Completed event is generated. Also,
	 * block incoming connection in Deleted state.
	 */
	if (connection1->status == Clearing || connection1->status == Deleted) {
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug("[Event] Closing incoming conn for %s (%p) state %d",
				   peer1->host, peer1,
				   peer1->connection->status);
		close(bgp_sock);
		return;
	}

	/* Check that at least one AF is activated for the peer. */
	if (!peer_active(peer1)) {
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"%s - incoming conn rejected - no AF activated for peer",
				peer1->host);
		close(bgp_sock);
		return;
	}

	/* Do not try to reconnect if the peer reached maximum
	 * prefixes, restart timer is still running or the peer
	 * is shutdown.
	 */
	if (BGP_PEER_START_SUPPRESSED(peer1)) {
		if (bgp_debug_neighbor_events(peer1)) {
			if (peer1->shut_during_cfg)
				zlog_debug(
					"[Event] Incoming BGP connection rejected from %s due to configuration being currently read in",
					peer1->host);
			else
				zlog_debug(
					"[Event] Incoming BGP connection rejected from %s due to maximum-prefix or shutdown",
					peer1->host);
		}
		close(bgp_sock);
		return;
	}

	if (bgp_debug_neighbor_events(peer1))
		zlog_debug("[Event] connection from %s fd %d, active peer status %d fd %d",
			   inet_sutop(&su, buf), bgp_sock, connection1->status,
			   connection1->fd);

	if (peer1->doppelganger) {
		/* We have an existing connection. Kill the existing one and run
		   with this one.
		*/
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"[Event] New active connection from peer %s, Killing previous active connection",
				peer1->host);
		peer_delete(peer1->doppelganger);
	}

	peer = peer_create(&su, peer1->conf_if, peer1->bgp, peer1->local_as,
			   peer1->as, peer1->as_type, NULL, false, NULL);

	connection = peer->connection;

	peer_xfer_config(peer, peer1);
	bgp_peer_gr_flags_update(peer);

	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(peer->bgp,
							  peer->bgp->peer);

	if (bgp_peer_gr_mode_get(peer) == PEER_DISABLE) {

		UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			peer_nsf_stop(peer);
		}
	}

	peer->doppelganger = peer1;
	peer1->doppelganger = peer;
	connection->fd = bgp_sock;

	if (bgp_set_socket_ttl(connection) < 0)
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("[Event] Unable to set min/max TTL on peer %s, Continuing",
				   peer->host);

	frr_with_privs(&bgpd_privs) {
		vrf_bind(peer->bgp->vrf_id, bgp_sock,
			 bgp_get_bound_name(peer->connection));
	}
	bgp_peer_reg_with_nht(peer);
	bgp_fsm_change_status(connection, Active);
	EVENT_OFF(connection->t_start); /* created in peer_create() */

	SET_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER);
	/* Make dummy peer until read Open packet. */
	if (peer_established(connection1) &&
	    CHECK_FLAG(peer1->sflags, PEER_STATUS_NSF_MODE)) {
		/* If we have an existing established connection with graceful
		 * restart
		 * capability announced with one or more address families, then
		 * drop
		 * existing established connection and move state to connect.
		 */
		peer1->last_reset = PEER_DOWN_NSF_CLOSE_SESSION;

		if (CHECK_FLAG(peer1->flags, PEER_FLAG_GRACEFUL_RESTART)
		    || CHECK_FLAG(peer1->flags,
				  PEER_FLAG_GRACEFUL_RESTART_HELPER))
			SET_FLAG(peer1->sflags, PEER_STATUS_NSF_WAIT);

		bgp_event_update(connection1, TCP_connection_closed);
	}

	if (peer_active(peer)) {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
			BGP_EVENT_ADD(connection, TCP_connection_open_w_delay);
		else
			BGP_EVENT_ADD(connection, TCP_connection_open);
	}

	/*
	 * If we are doing nht for a peer that is v6 LL based
	 * massage the event system to make things happy
	 */
	bgp_nht_interface_events(peer);
}

/* BGP socket bind. */
static char *bgp_get_bound_name(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if ((peer->bgp->vrf_id == VRF_DEFAULT) && !peer->ifname
	    && !peer->conf_if)
		return NULL;

	if (connection->su.sa.sa_family != AF_INET &&
	    connection->su.sa.sa_family != AF_INET6)
		return NULL; // unexpected

	/* For IPv6 peering, interface (unnumbered or link-local with interface)
	 * takes precedence over VRF. For IPv4 peering, explicit interface or
	 * VRF are the situations to bind.
	 */
	if (connection->su.sa.sa_family == AF_INET6 && peer->conf_if)
		return peer->conf_if;

	if (peer->ifname)
		return peer->ifname;

	if (peer->bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
		return NULL;

	return peer->bgp->name;
}

int bgp_update_address(struct interface *ifp, const union sockunion *dst,
			      union sockunion *addr)
{
	struct prefix *p, *sel, d;
	struct connected *connected;
	struct listnode *node;
	int common;

	if (!sockunion2hostprefix(dst, &d))
		return 1;

	sel = NULL;
	common = -1;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		p = connected->address;
		if (p->family != d.family)
			continue;
		if (prefix_common_bits(p, &d) > common) {
			sel = p;
			common = prefix_common_bits(sel, &d);
		}
	}

	if (!sel)
		return 1;

	prefix2sockunion(sel, addr);
	return 0;
}

/* Update source selection.  */
static int bgp_update_source(struct peer_connection *connection)
{
	struct interface *ifp;
	union sockunion addr;
	int ret = 0;
	struct peer *peer = connection->peer;

	sockunion_init(&addr);

	/* Source is specified with interface name.  */
	if (peer->update_if) {
		ifp = if_lookup_by_name(peer->update_if, peer->bgp->vrf_id);
		if (!ifp)
			return -1;

		if (bgp_update_address(ifp, &connection->su, &addr))
			return -1;

		ret = sockunion_bind(connection->fd, &addr, 0, &addr);
	}

	/* Source is specified with IP address.  */
	if (peer->update_source)
		ret = sockunion_bind(connection->fd, peer->update_source, 0,
				     peer->update_source);

	return ret;
}

/* BGP try to connect to the peer.  */
int bgp_connect(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	assert(!CHECK_FLAG(connection->thread_flags, PEER_THREAD_WRITES_ON));
	assert(!CHECK_FLAG(connection->thread_flags, PEER_THREAD_READS_ON));
	ifindex_t ifindex = 0;

	if (peer->conf_if && BGP_CONNECTION_SU_UNSPEC(connection)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("Peer address not learnt: Returning from connect");
		return 0;
	}
	frr_with_privs(&bgpd_privs) {
		/* Make socket for the peer. */
		connection->fd =
			vrf_sockunion_socket(&connection->su, peer->bgp->vrf_id,
					     bgp_get_bound_name(connection));
	}
	if (connection->fd < 0) {
		peer->last_reset = PEER_DOWN_SOCKET_ERROR;
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s: Failure to create socket for connection to %s, error received: %s(%d)",
				   __func__, peer->host, safe_strerror(errno),
				   errno);
		return -1;
	}

	set_nonblocking(connection->fd);

	/* Set the user configured MSS to TCP socket */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_TCP_MSS))
		sockopt_tcp_mss_set(connection->fd, peer->tcp_mss);

	bgp_socket_set_buffer_size(connection->fd);

	/* Set TCP keepalive when TCP keepalive is enabled */
	bgp_update_setsockopt_tcp_keepalive(peer->bgp, connection->fd);

	if (bgp_set_socket_ttl(peer->connection) < 0) {
		peer->last_reset = PEER_DOWN_SOCKET_ERROR;
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s: Failure to set socket ttl for connection to %s, error received: %s(%d)",
				   __func__, peer->host, safe_strerror(errno),
				   errno);

		return -1;
	}

	sockopt_reuseaddr(connection->fd);
	sockopt_reuseport(connection->fd);

#ifdef IPTOS_PREC_INTERNETCONTROL
	frr_with_privs(&bgpd_privs) {
		if (sockunion_family(&connection->su) == AF_INET)
			setsockopt_ipv4_tos(connection->fd, bm->tcp_dscp);
		else if (sockunion_family(&connection->su) == AF_INET6)
			setsockopt_ipv6_tclass(connection->fd, bm->tcp_dscp);
	}
#endif

	if (peer->password) {
		uint16_t prefixlen = peer->connection->su.sa.sa_family == AF_INET
					     ? IPV4_MAX_BITLEN
					     : IPV6_MAX_BITLEN;

		if (!BGP_CONNECTION_SU_UNSPEC(connection))
			bgp_md5_set(connection);

		bgp_md5_set_connect(connection->fd, &connection->su, prefixlen,
				    peer->password);
	}

	/* Update source bind. */
	if (bgp_update_source(connection) < 0) {
		peer->last_reset = PEER_DOWN_SOCKET_ERROR;
		return connect_error;
	}

	/* If the peer is passive mode, force to move to Active mode. */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSIVE)) {
		BGP_EVENT_ADD(connection, TCP_connection_open_failed);
		return BGP_FSM_SUCCESS;
	}

	if (peer->conf_if || peer->ifname)
		ifindex = ifname2ifindex(peer->conf_if ? peer->conf_if
						       : peer->ifname,
					 peer->bgp->vrf_id);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [Event] Connect start to %s fd %d", peer->host,
			   peer->host, connection->fd);

	/* Connect to the remote peer. */
	return sockunion_connect(connection->fd, &connection->su,
				 htons(peer->port), ifindex);
}

/* After TCP connection is established.  Get local address and port. */
int bgp_getsockname(struct peer *peer)
{
	if (peer->su_local) {
		sockunion_free(peer->su_local);
		peer->su_local = NULL;
	}

	if (peer->su_remote) {
		sockunion_free(peer->su_remote);
		peer->su_remote = NULL;
	}

	peer->su_local = sockunion_getsockname(peer->connection->fd);
	if (!peer->su_local)
		return -1;
	peer->su_remote = sockunion_getpeername(peer->connection->fd);
	if (!peer->su_remote)
		return -1;

	if (!bgp_zebra_nexthop_set(peer->su_local, peer->su_remote,
				   &peer->nexthop, peer)) {
		flog_err(
			EC_BGP_NH_UPD,
			"%s: nexthop_set failed, local: %pSUp remote: %pSUp update_if: %s resetting connection - intf %s",
			peer->host, peer->su_local, peer->su_remote,
			peer->update_if ? peer->update_if : "(None)",
			peer->nexthop.ifp ? peer->nexthop.ifp->name
					  : "(Unknown)");
		return -1;
	}
	return 0;
}


static int bgp_listener(int sock, struct sockaddr *sa, socklen_t salen,
			struct bgp *bgp)
{
	struct bgp_listener *listener;
	int ret, en;

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);

	frr_with_privs(&bgpd_privs) {

#ifdef IPTOS_PREC_INTERNETCONTROL
		if (sa->sa_family == AF_INET)
			setsockopt_ipv4_tos(sock, bm->tcp_dscp);
		else if (sa->sa_family == AF_INET6)
			setsockopt_ipv6_tclass(sock, bm->tcp_dscp);
#endif

		sockopt_v6only(sa->sa_family, sock);

		ret = bind(sock, sa, salen);
		en = errno;
	}

	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET, "bind: %s", safe_strerror(en));
		return ret;
	}

	ret = listen(sock, SOMAXCONN);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET, "listen: %s", safe_strerror(errno));
		return ret;
	}

	listener = XCALLOC(MTYPE_BGP_LISTENER, sizeof(*listener));
	listener->fd = sock;
	listener->name = XSTRDUP(MTYPE_BGP_LISTENER, bgp->name);

	/* this socket is in a vrf record bgp back pointer */
	if (bgp->vrf_id != VRF_DEFAULT)
		listener->bgp = bgp;

	memcpy(&listener->su, sa, salen);
	event_add_read(bm->master, bgp_accept, listener, sock,
		       &listener->thread);
	listnode_add(bm->listen_sockets, listener);

	return 0;
}

/* IPv6 supported version of BGP server socket setup.  */
int bgp_socket(struct bgp *bgp, unsigned short port, const char *address)
{
	struct addrinfo *ainfo;
	struct addrinfo *ainfo_save;
	static const struct addrinfo req = {
		.ai_family = AF_UNSPEC,
		.ai_flags = AI_PASSIVE,
		.ai_socktype = SOCK_STREAM,
	};
	int ret, count;
	char port_str[BUFSIZ];

	snprintf(port_str, sizeof(port_str), "%d", port);
	port_str[sizeof(port_str) - 1] = '\0';

	frr_with_privs(&bgpd_privs) {
		ret = vrf_getaddrinfo(address, port_str, &req, &ainfo_save,
				      bgp->vrf_id);
	}
	if (ret != 0) {
		flog_err_sys(EC_LIB_SOCKET, "getaddrinfo: %s",
			     gai_strerror(ret));
		return -1;
	}
	if (bgp_option_check(BGP_OPT_NO_ZEBRA) &&
	    bgp->vrf_id != VRF_DEFAULT) {
		freeaddrinfo(ainfo_save);
		return -1;
	}
	count = 0;
	for (ainfo = ainfo_save; ainfo; ainfo = ainfo->ai_next) {
		int sock;

		if (ainfo->ai_family != AF_INET && ainfo->ai_family != AF_INET6)
			continue;

		frr_with_privs(&bgpd_privs) {
			sock = vrf_socket(ainfo->ai_family,
					  ainfo->ai_socktype,
					  ainfo->ai_protocol,
					  bgp->vrf_id,
					  (bgp->inst_type
					   == BGP_INSTANCE_TYPE_VRF
					   ? bgp->name : NULL));
		}
		if (sock < 0) {
			flog_err_sys(EC_LIB_SOCKET, "socket: %s",
				     safe_strerror(errno));
			continue;
		}

		/* if we intend to implement ttl-security, this socket needs
		 * ttl=255 */
		sockopt_ttl(ainfo->ai_family, sock, MAXTTL);

		ret = bgp_listener(sock, ainfo->ai_addr, ainfo->ai_addrlen,
				   bgp);
		if (ret == 0)
			++count;
		else
			close(sock);
	}
	freeaddrinfo(ainfo_save);
	if (count == 0 && bgp->inst_type != BGP_INSTANCE_TYPE_VRF) {
		flog_err(
			EC_LIB_SOCKET,
			"%s: no usable addresses please check other programs usage of specified port %d",
			__func__, port);
		flog_err_sys(EC_LIB_SOCKET, "%s: Program cannot continue",
			     __func__);
		exit(-1);
	}

	return 0;
}

/* this function closes vrf socket
 * this should be called only for vrf socket with netns backend
 */
void bgp_close_vrf_socket(struct bgp *bgp)
{
	struct listnode *node, *next;
	struct bgp_listener *listener;

	if (!bgp)
		return;

	if (bm->listen_sockets == NULL)
		return;

	for (ALL_LIST_ELEMENTS(bm->listen_sockets, node, next, listener)) {
		if (listener->bgp == bgp) {
			EVENT_OFF(listener->thread);
			close(listener->fd);
			listnode_delete(bm->listen_sockets, listener);
			XFREE(MTYPE_BGP_LISTENER, listener->name);
			XFREE(MTYPE_BGP_LISTENER, listener);
		}
	}
}

/* this function closes main socket
 */
void bgp_close(void)
{
	struct listnode *node, *next;
	struct bgp_listener *listener;

	if (bm->listen_sockets == NULL)
		return;

	for (ALL_LIST_ELEMENTS(bm->listen_sockets, node, next, listener)) {
		if (listener->bgp)
			continue;
		EVENT_OFF(listener->thread);
		close(listener->fd);
		listnode_delete(bm->listen_sockets, listener);
		XFREE(MTYPE_BGP_LISTENER, listener->name);
		XFREE(MTYPE_BGP_LISTENER, listener);
	}
}
