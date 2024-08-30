// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP MSDP socket management
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include <lib/log.h>
#include <lib/network.h>
#include <lib/sockunion.h>
#include "frrevent.h"
#include <lib/vty.h>
#include <lib/if.h>
#include <lib/vrf.h>
#include <lib/lib_errors.h>

#include "pimd.h"
#include "pim_instance.h"
#include "pim_sock.h"
#include "pim_errors.h"

#include "pim_msdp.h"
#include "pim_msdp_socket.h"

#include "sockopt.h"

/* increase socket send buffer size */
static void pim_msdp_update_sock_send_buffer_size(int fd)
{
	int size = PIM_MSDP_SOCKET_SNDBUF_SIZE;
	int optval;
	socklen_t optlen = sizeof(optval);

	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "getsockopt of SO_SNDBUF failed %s",
			     safe_strerror(errno));
		return;
	}

	if (optval < size) {
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))
		    < 0) {
			flog_err_sys(EC_LIB_SOCKET,
				     "Couldn't increase send buffer: %s",
				     safe_strerror(errno));
		}
	}
}

/**
 * Helper function to reduce code duplication.
 *
 * \param vrf VRF pointer (`NULL` means default VRF)
 * \param mp the MSDP session pointer.
 * \returns valid file descriptor otherwise `-1`.
 */
static int _pim_msdp_sock_listen(const struct vrf *vrf,
				 const struct pim_msdp_peer *mp)
{
	const struct interface *ifp;
	int sock;
	int rv;
	socklen_t socklen;
	struct sockaddr_in sin = {};
	union sockunion su_peer = {};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_warn("%s: socket: %s", __func__, strerror(errno));
		return -1;
	}

	socklen = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PIM_MSDP_TCP_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin.sin_len = socklen;
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
	if (mp)
		sin.sin_addr = mp->local;

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);

	/* Bind socket to VRF/address. */
	if (vrf && vrf->vrf_id != VRF_DEFAULT) {
		ifp = if_lookup_by_name(vrf->name, vrf->vrf_id);
		if (ifp == NULL) {
			flog_err(EC_LIB_INTERFACE,
				 "%s: Unable to lookup vrf interface: %s",
				 __func__, vrf->name);
			close(sock);
			return -1;
		}

		if (vrf_bind(vrf->vrf_id, sock, ifp->name) == -1) {
			flog_err_sys(EC_LIB_SOCKET,
				     "%s: Unable to bind to socket: %s",
				     __func__, safe_strerror(errno));
			close(sock);
			return -1;
		}
	}

	frr_with_privs (&pimd_privs) {
		rv = bind(sock, (struct sockaddr *)&sin, socklen);
	}
	if (rv == -1) {
		flog_err_sys(EC_LIB_SOCKET,
			     "pim_msdp_socket bind to port %d: %s",
			     ntohs(sin.sin_port), safe_strerror(errno));
		close(sock);
		return -1;
	}

	/* Set MD5 authentication. */
	if (mp && mp->auth_key) {
		su_peer = mp->su_peer;
		frr_with_privs (&pimd_privs) {
			sockopt_tcp_signature(sock, &su_peer, mp->auth_key);
		}
	}


	/* Start listening. */
	rv = listen(sock, SOMAXCONN);
	if (rv == -1) {
		flog_err_sys(EC_LIB_SOCKET, "pim_msdp_socket listen: %s",
			     safe_strerror(errno));
		close(sock);
		return -1;
	}

	/* Set socket DSCP byte */
	if (setsockopt_ipv4_tos(sock, IPTOS_PREC_INTERNETCONTROL)) {
		zlog_warn("can't set sockopt IP_TOS to MSDP socket %d: %s",
			  sock, safe_strerror(errno));
	}

	return sock;
}

static void pim_msdp_sock_auth_accept(struct event *t)
{
	struct pim_msdp_peer *mp = EVENT_ARG(t);
	int sock;
	socklen_t sinlen;
	struct sockaddr_in sin = {};

	/* accept client connection. */
	sinlen = sizeof(sin);
	sock = accept(mp->auth_listen_sock, (struct sockaddr *)&sin, &sinlen);
	if (sock == -1) {
		flog_err_sys(EC_LIB_SOCKET, "pim_msdp_sock_accept failed (%s)",
			     safe_strerror(errno));

		/* Accept failed, schedule listen again. */
		event_add_read(router->master, pim_msdp_sock_auth_accept, mp,
			       mp->auth_listen_sock, &mp->auth_listen_ev);
		return;
	}

	/*
	 * Previous connection still going.
	 *
	 * We must wait for the user to close the previous connection in order
	 * to establish the new one. User can manually force that by calling
	 * `clear ip msdp peer A.B.C.D`.
	 */
	if (mp->fd != -1) {
		++mp->pim->msdp.rejected_accepts;
		if (PIM_DEBUG_MSDP_EVENTS) {
			flog_err(EC_PIM_MSDP_PACKET,
				 "msdp peer connection refused from %pI4: old connection still running",
				 &sin.sin_addr);
		}
		close(sock);

		/* Unexpected connection, schedule listen again. */
		event_add_read(router->master, pim_msdp_sock_auth_accept, mp,
			       mp->auth_listen_sock, &mp->auth_listen_ev);
		return;
	}

	/* Unexpected client connected. */
	if (mp->peer.s_addr != sin.sin_addr.s_addr) {
		++mp->pim->msdp.rejected_accepts;
		if (PIM_DEBUG_MSDP_EVENTS) {
			flog_err(EC_PIM_MSDP_PACKET,
				 "msdp peer connection refused from %pI4",
				 &sin.sin_addr);
		}
		close(sock);

		/* Unexpected peer, schedule listen again. */
		event_add_read(router->master, pim_msdp_sock_auth_accept, mp,
			       mp->auth_listen_sock, &mp->auth_listen_ev);
		return;
	}

	if (PIM_DEBUG_MSDP_INTERNAL)
		zlog_debug("MSDP peer %s accept success", mp->key_str);

	/* Configure socket. */
	mp->fd = sock;
	set_nonblocking(mp->fd);
	pim_msdp_update_sock_send_buffer_size(mp->fd);
	pim_msdp_peer_established(mp);

	/* Stop listening. */
	close(mp->auth_listen_sock);
	mp->auth_listen_sock = -1;
}

int pim_msdp_sock_auth_listen(struct pim_msdp_peer *mp)
{
	/* Clear any listening connection if it exists. */
	event_cancel(&mp->auth_listen_ev);
	if (mp->auth_listen_sock != -1) {
		close(mp->auth_listen_sock);
		mp->auth_listen_sock = -1;
	}

	/* Start new listening socket. */
	mp->auth_listen_sock = _pim_msdp_sock_listen(mp->pim->vrf, mp);
	if (mp->auth_listen_sock == -1)
		return -1;

	/* Listen for connections and connected only with the expected end. */
	event_add_read(router->master, pim_msdp_sock_auth_accept, mp,
		       mp->auth_listen_sock, &mp->auth_listen_ev);

	return 0;
}

/* passive peer socket accept */
static void pim_msdp_sock_accept(struct event *thread)
{
	union sockunion su;
	struct pim_instance *pim = EVENT_ARG(thread);
	int accept_sock;
	int msdp_sock;
	struct pim_msdp_peer *mp;

	sockunion_init(&su);

	/* re-register accept thread */
	accept_sock = EVENT_FD(thread);
	if (accept_sock < 0) {
		flog_err(EC_LIB_DEVELOPMENT, "accept_sock is negative value %d",
			 accept_sock);
		return;
	}
	pim->msdp.listener.thread = NULL;
	event_add_read(router->master, pim_msdp_sock_accept, pim, accept_sock,
		       &pim->msdp.listener.thread);

	/* accept client connection. */
	msdp_sock = sockunion_accept(accept_sock, &su);
	if (msdp_sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "pim_msdp_sock_accept failed (%s)",
			     safe_strerror(errno));
		return;
	}

	/* see if have peer config for this */
	mp = pim_msdp_peer_find(pim, su.sin.sin_addr);
	if (!mp || !PIM_MSDP_PEER_IS_LISTENER(mp)) {
		++pim->msdp.rejected_accepts;
		if (PIM_DEBUG_MSDP_EVENTS) {
			flog_err(EC_PIM_MSDP_PACKET,
				 "msdp peer connection refused from %pSU", &su);
		}
		close(msdp_sock);
		return;
	}

	/*
	 * If authentication is configured then we can not accept
	 * unauthenticated connections.
	 */
	if (mp->auth_type != MSDP_AUTH_NONE) {
		++pim->msdp.rejected_accepts;
		if (PIM_DEBUG_MSDP_EVENTS) {
			flog_err(EC_PIM_MSDP_PACKET,
				 "msdp peer unauthenticated connection refused from %pSU",
				 &su);
		}
		close(msdp_sock);
		return;
	}

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s accept success%s", mp->key_str,
			   mp->fd >= 0 ? "(dup)" : "");
	}

	/* if we have an existing connection we need to kill that one
	 * with this one */
	if (mp->fd >= 0) {
		if (PIM_DEBUG_MSDP_EVENTS) {
			zlog_notice(
				"msdp peer new connection from %pSU stop old connection",
				&su);
		}
		pim_msdp_peer_stop_tcp_conn(mp, true /* chg_state */);
	}
	mp->fd = msdp_sock;
	set_nonblocking(mp->fd);
	pim_msdp_update_sock_send_buffer_size(mp->fd);
	pim_msdp_peer_established(mp);
}

/* global listener for the MSDP well know TCP port */
int pim_msdp_sock_listen(struct pim_instance *pim)
{
	int sock;
	struct pim_msdp_listener *listener = &pim->msdp.listener;

	if (pim->msdp.flags & PIM_MSDPF_LISTENER) {
		/* listener already setup */
		return 0;
	}

	sock = _pim_msdp_sock_listen(pim->vrf, NULL);
	if (sock == -1)
		return -1;


	memset(&listener->su.sin, 0, sizeof(listener->su.sin));
	listener->su.sin.sin_family = AF_INET;
	listener->su.sin.sin_port = htons(PIM_MSDP_TCP_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	listener->su.sin.sin_len = sizeof(listener->su.sin);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	/* add accept thread */
	listener->fd = sock;
	event_add_read(pim->msdp.master, pim_msdp_sock_accept, pim, sock,
		       &listener->thread);

	pim->msdp.flags |= PIM_MSDPF_LISTENER;
	return 0;
}

/* active peer socket setup */
int pim_msdp_sock_connect(struct pim_msdp_peer *mp)
{
	int rc;

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s attempt connect%s", mp->key_str,
			   mp->fd < 0 ? "" : "(dup)");
	}

	/* if we have an existing connection we need to kill that one
	 * with this one */
	if (mp->fd >= 0) {
		if (PIM_DEBUG_MSDP_EVENTS) {
			zlog_notice(
				"msdp duplicate connect to %s nuke old connection",
				mp->key_str);
		}
		pim_msdp_peer_stop_tcp_conn(mp, false /* chg_state */);
	}

	/* Make socket for the peer. */
	mp->fd = sockunion_socket(&mp->su_peer);
	if (mp->fd < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "pim_msdp_socket socket failure: %s",
			     safe_strerror(errno));
		return -1;
	}

	if (mp->pim->vrf->vrf_id != VRF_DEFAULT) {
		struct interface *ifp = if_lookup_by_name(mp->pim->vrf->name,
							  mp->pim->vrf->vrf_id);
		if (!ifp) {
			flog_err(EC_LIB_INTERFACE,
				 "%s: Unable to lookup vrf interface: %s",
				 __func__, mp->pim->vrf->name);
			return -1;
		}
		if (pim_socket_bind(mp->fd, ifp)) {
			flog_err_sys(EC_LIB_SOCKET,
				     "%s: Unable to bind to socket: %s",
				     __func__, safe_strerror(errno));
			close(mp->fd);
			mp->fd = -1;
			return -1;
		}
	}

	set_nonblocking(mp->fd);

	/* Set socket send buffer size */
	pim_msdp_update_sock_send_buffer_size(mp->fd);
	sockopt_reuseaddr(mp->fd);
	sockopt_reuseport(mp->fd);

	/* source bind */
	rc = sockunion_bind(mp->fd, &mp->su_local, 0, &mp->su_local);
	if (rc < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "pim_msdp_socket connect bind failure: %s",
			     safe_strerror(errno));
		close(mp->fd);
		mp->fd = -1;
		return rc;
	}

	/* Set socket DSCP byte */
	if (setsockopt_ipv4_tos(mp->fd, IPTOS_PREC_INTERNETCONTROL)) {
		zlog_warn("can't set sockopt IP_TOS to MSDP socket %d: %s",
				mp->fd, safe_strerror(errno));
	}

	/* Set authentication (if configured). */
	if (mp->auth_key) {
		frr_with_privs (&pimd_privs) {
			sockopt_tcp_signature(mp->fd, &mp->su_peer,
					      mp->auth_key);
		}
	}

	/* Connect to the remote mp. */
	return (sockunion_connect(mp->fd, &mp->su_peer,
				  htons(PIM_MSDP_TCP_PORT), 0));
}
