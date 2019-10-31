/* BGP network related fucntions
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
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

extern struct zebra_privs_t bgpd_privs;

static char *bgp_get_bound_name(struct peer *peer);

/* BGP listening socket. */
struct bgp_listener {
	int fd;
	union sockunion su;
	struct thread *thread;
	struct bgp *bgp;
};

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
	if ((su2.sa.sa_family == AF_INET && prefixlen == IPV4_MAX_PREFIXLEN)
	    || (su2.sa.sa_family == AF_INET6
		&& prefixlen == IPV6_MAX_PREFIXLEN))
		ret = sockopt_tcp_signature(socket, &su2, password);
	else
		ret = sockopt_tcp_signature_ext(socket, &su2, prefixlen,
						password);
	en = errno;
#endif /* HAVE_TCP_MD5SIG */

	if (ret < 0) {
		char sabuf[SU_ADDRSTRLEN];
		sockunion2str(su, sabuf, sizeof(sabuf));

		switch (ret) {
		case -2:
			flog_warn(
				EC_BGP_NO_TCP_MD5,
				"Unable to set TCP MD5 option on socket for peer %s (sock=%d): This platform does not support MD5 auth for prefixes",
				sabuf, socket);
			break;
		default:
			flog_warn(
				EC_BGP_NO_TCP_MD5,
				"Unable to set TCP MD5 option on socket for peer %s (sock=%d): %s",
				sabuf, socket, safe_strerror(en));
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

static int bgp_md5_set_password(struct peer *peer, const char *password)
{
	struct listnode *node;
	int ret = 0;
	struct bgp_listener *listener;

	/*
	 * Set or unset the password on the listen socket(s). Outbound
	 * connections are taken care of in bgp_connect() below.
	 */
	frr_with_privs(&bgpd_privs) {
		for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener))
			if (listener->su.sa.sa_family
			    == peer->su.sa.sa_family) {
				uint16_t prefixlen =
					peer->su.sa.sa_family == AF_INET
						? IPV4_MAX_PREFIXLEN
						: IPV6_MAX_PREFIXLEN;

				ret = bgp_md5_set_socket(listener->fd,
							 &peer->su, prefixlen,
							 password);
				break;
			}
	}
	return ret;
}

int bgp_md5_set_prefix(struct prefix *p, const char *password)
{
	int ret = 0;
	union sockunion su;
	struct listnode *node;
	struct bgp_listener *listener;

	/* Set or unset the password on the listen socket(s). */
	frr_with_privs(&bgpd_privs) {
		for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener))
			if (listener->su.sa.sa_family == p->family) {
				prefix2sockunion(p, &su);
				ret = bgp_md5_set_socket(listener->fd, &su,
							 p->prefixlen,
							 password);
				break;
			}
	}

	return ret;
}

int bgp_md5_unset_prefix(struct prefix *p)
{
	return bgp_md5_set_prefix(p, NULL);
}

int bgp_md5_set(struct peer *peer)
{
	/* Set the password from listen socket. */
	return bgp_md5_set_password(peer, peer->password);
}

int bgp_md5_unset(struct peer *peer)
{
	/* Unset the password from listen socket. */
	return bgp_md5_set_password(peer, NULL);
}

int bgp_set_socket_ttl(struct peer *peer, int bgp_sock)
{
	char buf[INET_ADDRSTRLEN];
	int ret = 0;

	/* In case of peer is EBGP, we should set TTL for this connection.  */
	if (!peer->gtsm_hops && (peer_sort(peer) == BGP_PEER_EBGP)) {
		ret = sockopt_ttl(peer->su.sa.sa_family, bgp_sock, peer->ttl);
		if (ret) {
			flog_err(
				EC_LIB_SOCKET,
				"%s: Can't set TxTTL on peer (rtrid %s) socket, err = %d",
				__func__,
				inet_ntop(AF_INET, &peer->remote_id, buf,
					  sizeof(buf)),
				errno);
			return ret;
		}
	} else if (peer->gtsm_hops) {
		/* On Linux, setting minttl without setting ttl seems to mess
		   with the
		   outgoing ttl. Therefore setting both.
		*/
		ret = sockopt_ttl(peer->su.sa.sa_family, bgp_sock, MAXTTL);
		if (ret) {
			flog_err(
				EC_LIB_SOCKET,
				"%s: Can't set TxTTL on peer (rtrid %s) socket, err = %d",
				__func__,
				inet_ntop(AF_INET, &peer->remote_id, buf,
					  sizeof(buf)),
				errno);
			return ret;
		}
		ret = sockopt_minttl(peer->su.sa.sa_family, bgp_sock,
				     MAXTTL + 1 - peer->gtsm_hops);
		if (ret) {
			flog_err(
				EC_LIB_SOCKET,
				"%s: Can't set MinTTL on peer (rtrid %s) socket, err = %d",
				__func__,
				inet_ntop(AF_INET, &peer->remote_id, buf,
					  sizeof(buf)),
				errno);
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

static void bgp_socket_set_buffer_size(const int fd)
{
	if (getsockopt_so_sendbuf(fd) < (int)bm->socket_buffer)
		setsockopt_so_sendbuf(fd, bm->socket_buffer);
	if (getsockopt_so_recvbuf(fd) < (int)bm->socket_buffer)
		setsockopt_so_recvbuf(fd, bm->socket_buffer);
}

/* Accept bgp connection. */
static int bgp_accept(struct thread *thread)
{
	int bgp_sock;
	int accept_sock;
	union sockunion su;
	struct bgp_listener *listener = THREAD_ARG(thread);
	struct peer *peer;
	struct peer *peer1;
	char buf[SU_ADDRSTRLEN];
	struct bgp *bgp = NULL;

	sockunion_init(&su);

	/* Register accept thread. */
	accept_sock = THREAD_FD(thread);
	if (accept_sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "accept_sock is nevative value %d",
			     accept_sock);
		return -1;
	}
	listener->thread = NULL;

	thread_add_read(bm->master, bgp_accept, listener, accept_sock,
			&listener->thread);

	/* Accept client connection. */
	bgp_sock = sockunion_accept(accept_sock, &su);
	if (bgp_sock < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "[Error] BGP socket accept failed (%s)",
			     safe_strerror(errno));
		return -1;
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
		return -1;
	}

	bgp_socket_set_buffer_size(bgp_sock);

	/* Check remote IP address */
	peer1 = peer_lookup(bgp, &su);

	if (!peer1) {
		peer1 = peer_lookup_dynamic_neighbor(bgp, &su);
		if (peer1) {
			/* Dynamic neighbor has been created, let it proceed */
			peer1->fd = bgp_sock;
			bgp_fsm_change_status(peer1, Active);
			BGP_TIMER_OFF(
				peer1->t_start); /* created in peer_create() */

			if (peer_active(peer1))
				BGP_EVENT_ADD(peer1, TCP_connection_open);

			return 0;
		}
	}

	if (!peer1) {
		if (bgp_debug_neighbor_events(NULL)) {
			zlog_debug(
				"[Event] %s connection rejected - not configured"
				" and not valid for dynamic",
				inet_sutop(&su, buf));
		}
		close(bgp_sock);
		return -1;
	}

	if (CHECK_FLAG(peer1->flags, PEER_FLAG_SHUTDOWN)) {
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"[Event] connection from %s rejected due to admin shutdown",
				inet_sutop(&su, buf));
		close(bgp_sock);
		return -1;
	}

	/*
	 * Do not accept incoming connections in Clearing state. This can result
	 * in incorect state transitions - e.g., the connection goes back to
	 * Established and then the Clearing_Completed event is generated. Also,
	 * block incoming connection in Deleted state.
	 */
	if (peer1->status == Clearing || peer1->status == Deleted) {
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"[Event] Closing incoming conn for %s (%p) state %d",
				peer1->host, peer1, peer1->status);
		close(bgp_sock);
		return -1;
	}

	/* Check that at least one AF is activated for the peer. */
	if (!peer_active(peer1)) {
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"%s - incoming conn rejected - no AF activated for peer",
				peer1->host);
		close(bgp_sock);
		return -1;
	}

	/* Do not try to reconnect if the peer reached maximum
	 * prefixes, restart timer is still running or the peer
	 * is shutdown.
	 */
	if (BGP_PEER_START_SUPPRESSED(peer1)) {
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"[Event] Incoming BGP connection rejected from %s "
				"due to maximum-prefix or shutdown",
				peer1->host);
		close(bgp_sock);
		return -1;
	}

	if (bgp_debug_neighbor_events(peer1))
		zlog_debug("[Event] BGP connection from host %s fd %d",
			   inet_sutop(&su, buf), bgp_sock);

	if (peer1->doppelganger) {
		/* We have an existing connection. Kill the existing one and run
		   with this one.
		*/
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"[Event] New active connection from peer %s, Killing"
				" previous active connection",
				peer1->host);
		peer_delete(peer1->doppelganger);
	}

	if (bgp_set_socket_ttl(peer1, bgp_sock) < 0)
		if (bgp_debug_neighbor_events(peer1))
			zlog_debug(
				"[Event] Unable to set min/max TTL on peer %s, Continuing",
				peer1->host);

	peer = peer_create(&su, peer1->conf_if, peer1->bgp, peer1->local_as,
			   peer1->as, peer1->as_type, 0, 0, NULL);
	hash_release(peer->bgp->peerhash, peer);
	hash_get(peer->bgp->peerhash, peer, hash_alloc_intern);

	peer_xfer_config(peer, peer1);
	UNSET_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE);

	peer->doppelganger = peer1;
	peer1->doppelganger = peer;
	peer->fd = bgp_sock;
	vrf_bind(peer->bgp->vrf_id, bgp_sock, bgp_get_bound_name(peer));
	bgp_fsm_change_status(peer, Active);
	BGP_TIMER_OFF(peer->t_start); /* created in peer_create() */

	SET_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER);

	/* Make dummy peer until read Open packet. */
	if (peer1->status == Established
	    && CHECK_FLAG(peer1->sflags, PEER_STATUS_NSF_MODE)) {
		/* If we have an existing established connection with graceful
		 * restart
		 * capability announced with one or more address families, then
		 * drop
		 * existing established connection and move state to connect.
		 */
		peer1->last_reset = PEER_DOWN_NSF_CLOSE_SESSION;
		SET_FLAG(peer1->sflags, PEER_STATUS_NSF_WAIT);
		bgp_event_update(peer1, TCP_connection_closed);
	}

	if (peer_active(peer)) {
		BGP_EVENT_ADD(peer, TCP_connection_open);
	}

	return 0;
}

/* BGP socket bind. */
static char *bgp_get_bound_name(struct peer *peer)
{
	char *name = NULL;

	if (!peer)
		return NULL;

	if ((peer->bgp->vrf_id == VRF_DEFAULT) && !peer->ifname
	    && !peer->conf_if)
		return NULL;

	if (peer->su.sa.sa_family != AF_INET
	    && peer->su.sa.sa_family != AF_INET6)
		return NULL; // unexpected

	/* For IPv6 peering, interface (unnumbered or link-local with interface)
	 * takes precedence over VRF. For IPv4 peering, explicit interface or
	 * VRF are the situations to bind.
	 */
	if (peer->su.sa.sa_family == AF_INET6)
		name = (peer->conf_if ? peer->conf_if
				      : (peer->ifname ? peer->ifname
						      : peer->bgp->name));
	else
		name = peer->ifname ? peer->ifname : peer->bgp->name;

	return name;
}

static int bgp_update_address(struct interface *ifp, const union sockunion *dst,
			      union sockunion *addr)
{
	struct prefix *p, *sel, d;
	struct connected *connected;
	struct listnode *node;
	int common;

	sockunion2hostprefix(dst, &d);
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
static int bgp_update_source(struct peer *peer)
{
	struct interface *ifp;
	union sockunion addr;
	int ret = 0;

	sockunion_init(&addr);

	/* Source is specified with interface name.  */
	if (peer->update_if) {
		ifp = if_lookup_by_name(peer->update_if, peer->bgp->vrf_id);
		if (!ifp)
			return -1;

		if (bgp_update_address(ifp, &peer->su, &addr))
			return -1;

		ret = sockunion_bind(peer->fd, &addr, 0, &addr);
	}

	/* Source is specified with IP address.  */
	if (peer->update_source)
		ret = sockunion_bind(peer->fd, peer->update_source, 0,
				     peer->update_source);

	return ret;
}

/* BGP try to connect to the peer.  */
int bgp_connect(struct peer *peer)
{
	assert(!CHECK_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON));
	assert(!CHECK_FLAG(peer->thread_flags, PEER_THREAD_READS_ON));
	ifindex_t ifindex = 0;

	if (peer->conf_if && BGP_PEER_SU_UNSPEC(peer)) {
		zlog_debug("Peer address not learnt: Returning from connect");
		return 0;
	}
	frr_with_privs(&bgpd_privs) {
	/* Make socket for the peer. */
		peer->fd = vrf_sockunion_socket(&peer->su, peer->bgp->vrf_id,
						bgp_get_bound_name(peer));
	}
	if (peer->fd < 0)
		return -1;

	set_nonblocking(peer->fd);

	bgp_socket_set_buffer_size(peer->fd);

	if (bgp_set_socket_ttl(peer, peer->fd) < 0)
		return -1;

	sockopt_reuseaddr(peer->fd);
	sockopt_reuseport(peer->fd);

#ifdef IPTOS_PREC_INTERNETCONTROL
	frr_with_privs(&bgpd_privs) {
		if (sockunion_family(&peer->su) == AF_INET)
			setsockopt_ipv4_tos(peer->fd,
					    IPTOS_PREC_INTERNETCONTROL);
		else if (sockunion_family(&peer->su) == AF_INET6)
			setsockopt_ipv6_tclass(peer->fd,
					       IPTOS_PREC_INTERNETCONTROL);
	}
#endif

	if (peer->password) {
		uint16_t prefixlen = peer->su.sa.sa_family == AF_INET
					     ? IPV4_MAX_PREFIXLEN
					     : IPV6_MAX_PREFIXLEN;

		bgp_md5_set_connect(peer->fd, &peer->su, prefixlen,
				    peer->password);
	}

	/* Update source bind. */
	if (bgp_update_source(peer) < 0) {
		return connect_error;
	}

	if (peer->conf_if || peer->ifname)
		ifindex = ifname2ifindex(peer->conf_if ? peer->conf_if
						       : peer->ifname,
					 peer->bgp->vrf_id);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [Event] Connect start to %s fd %d", peer->host,
			   peer->host, peer->fd);

	/* Connect to the remote peer. */
	return sockunion_connect(peer->fd, &peer->su, htons(peer->port),
				 ifindex);
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

	peer->su_local = sockunion_getsockname(peer->fd);
	if (!peer->su_local)
		return -1;
	peer->su_remote = sockunion_getpeername(peer->fd);
	if (!peer->su_remote)
		return -1;

	if (!bgp_zebra_nexthop_set(peer->su_local, peer->su_remote,
				   &peer->nexthop, peer)) {
		flog_err(EC_BGP_NH_UPD,
			 "%s: nexthop_set failed, resetting connection - intf %p",
			 peer->host, peer->nexthop.ifp);
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
			setsockopt_ipv4_tos(sock, IPTOS_PREC_INTERNETCONTROL);
		else if (sa->sa_family == AF_INET6)
			setsockopt_ipv6_tclass(sock,
					       IPTOS_PREC_INTERNETCONTROL);
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

	/* this socket needs a change of ns. record bgp back pointer */
	if (bgp->vrf_id != VRF_DEFAULT && vrf_is_backend_netns())
		listener->bgp = bgp;

	memcpy(&listener->su, sa, salen);
	listener->thread = NULL;
	thread_add_read(bm->master, bgp_accept, listener, sock,
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
					  ainfo->ai_protocol, bgp->vrf_id,
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
			thread_cancel(listener->thread);
			close(listener->fd);
			listnode_delete(bm->listen_sockets, listener);
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
		thread_cancel(listener->thread);
		close(listener->fd);
		listnode_delete(bm->listen_sockets, listener);
		XFREE(MTYPE_BGP_LISTENER, listener);
	}
}
