/*
 * IP MSDP socket management
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <lib/log.h>
#include <lib/network.h>
#include <lib/sockunion.h>
#include <lib/thread.h>
#include <lib/vty.h>
#include <lib/if.h>
#include <lib/vrf.h>

#include "pimd.h"
#include "pim_sock.h"

#include "pim_msdp.h"
#include "pim_msdp_socket.h"

/* increase socket send buffer size */
static void pim_msdp_update_sock_send_buffer_size(int fd)
{
	int size = PIM_MSDP_SOCKET_SNDBUF_SIZE;
	int optval;
	socklen_t optlen = sizeof(optval);

	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) < 0) {
		zlog_err("getsockopt of SO_SNDBUF failed %s\n",
			 safe_strerror(errno));
		return;
	}

	if (optval < size) {
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))
		    < 0) {
			zlog_err("Couldn't increase send buffer: %s\n",
				 safe_strerror(errno));
		}
	}
}

/* passive peer socket accept */
static int pim_msdp_sock_accept(struct thread *thread)
{
	union sockunion su;
	struct pim_instance *pim = THREAD_ARG(thread);
	int accept_sock;
	int msdp_sock;
	struct pim_msdp_peer *mp;
	char buf[SU_ADDRSTRLEN];

	sockunion_init(&su);

	/* re-register accept thread */
	accept_sock = THREAD_FD(thread);
	if (accept_sock < 0) {
		zlog_err("accept_sock is negative value %d", accept_sock);
		return -1;
	}
	pim->msdp.listener.thread = NULL;
	thread_add_read(master, pim_msdp_sock_accept, pim, accept_sock,
			&pim->msdp.listener.thread);

	/* accept client connection. */
	msdp_sock = sockunion_accept(accept_sock, &su);
	if (msdp_sock < 0) {
		zlog_err("pim_msdp_sock_accept failed (%s)",
			 safe_strerror(errno));
		return -1;
	}

	/* see if have peer config for this */
	mp = pim_msdp_peer_find(pim, su.sin.sin_addr);
	if (!mp || !PIM_MSDP_PEER_IS_LISTENER(mp)) {
		++pim->msdp.rejected_accepts;
		if (PIM_DEBUG_MSDP_EVENTS) {
			zlog_err("msdp peer connection refused from %s",
				 sockunion2str(&su, buf, SU_ADDRSTRLEN));
		}
		close(msdp_sock);
		return -1;
	}

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s accept success%s", mp->key_str,
			   mp->fd >= 0 ? "(dup)" : "");
	}

	/* if we have an existing connection we need to kill that one
	 * with this one */
	if (mp->fd >= 0) {
		if (PIM_DEBUG_MSDP_EVENTS) {
			zlog_err(
				"msdp peer new connection from %s stop old connection",
				sockunion2str(&su, buf, SU_ADDRSTRLEN));
		}
		pim_msdp_peer_stop_tcp_conn(mp, true /* chg_state */);
	}
	mp->fd = msdp_sock;
	set_nonblocking(mp->fd);
	pim_msdp_update_sock_send_buffer_size(mp->fd);
	pim_msdp_peer_established(mp);
	return 0;
}

/* global listener for the MSDP well know TCP port */
int pim_msdp_sock_listen(struct pim_instance *pim)
{
	int sock;
	int socklen;
	struct sockaddr_in sin;
	int rc;
	struct pim_msdp_listener *listener = &pim->msdp.listener;

	if (pim->msdp.flags & PIM_MSDPF_LISTENER) {
		/* listener already setup */
		return 0;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		zlog_err("socket: %s", safe_strerror(errno));
		return sock;
	}

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PIM_MSDP_TCP_PORT);
	socklen = sizeof(struct sockaddr_in);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin.sin_len = socklen;
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);

	if (pim->vrf_id != VRF_DEFAULT) {
		struct interface *ifp =
			if_lookup_by_name(pim->vrf->name, pim->vrf_id);
		if (!ifp) {
			zlog_err("%s: Unable to lookup vrf interface: %s",
				 __PRETTY_FUNCTION__, pim->vrf->name);
			close(sock);
			return -1;
		}
		if (pim_socket_bind(sock, ifp)) {
			zlog_err("%s: Unable to bind to socket: %s",
				 __PRETTY_FUNCTION__, safe_strerror(errno));
			close(sock);
			return -1;
		}
	}

	if (pimd_privs.change(ZPRIVS_RAISE)) {
		zlog_err("pim_msdp_socket: could not raise privs, %s",
			 safe_strerror(errno));
	}

	/* bind to well known TCP port */
	rc = bind(sock, (struct sockaddr *)&sin, socklen);

	if (pimd_privs.change(ZPRIVS_LOWER)) {
		zlog_err("pim_msdp_socket: could not lower privs, %s",
			 safe_strerror(errno));
	}

	if (rc < 0) {
		zlog_err("pim_msdp_socket bind to port %d: %s",
			 ntohs(sin.sin_port), safe_strerror(errno));
		close(sock);
		return rc;
	}

	rc = listen(sock, 3 /* backlog */);
	if (rc < 0) {
		zlog_err("pim_msdp_socket listen: %s", safe_strerror(errno));
		close(sock);
		return rc;
	}

	/* add accept thread */
	listener->fd = sock;
	memcpy(&listener->su, &sin, socklen);
	listener->thread = NULL;
	thread_add_read(pim->msdp.master, pim_msdp_sock_accept, pim, sock,
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
			zlog_err(
				"msdp duplicate connect to %s nuke old connection",
				mp->key_str);
		}
		pim_msdp_peer_stop_tcp_conn(mp, false /* chg_state */);
	}

	/* Make socket for the peer. */
	mp->fd = sockunion_socket(&mp->su_peer);
	if (mp->fd < 0) {
		zlog_err("pim_msdp_socket socket failure: %s",
			 safe_strerror(errno));
		return -1;
	}

	if (mp->pim->vrf_id != VRF_DEFAULT) {
		struct interface *ifp =
			if_lookup_by_name(mp->pim->vrf->name, mp->pim->vrf_id);
		if (!ifp) {
			zlog_err("%s: Unable to lookup vrf interface: %s",
				 __PRETTY_FUNCTION__, mp->pim->vrf->name);
			return -1;
		}
		if (pim_socket_bind(mp->fd, ifp)) {
			zlog_err("%s: Unable to bind to socket: %s",
				 __PRETTY_FUNCTION__, safe_strerror(errno));
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
		zlog_err("pim_msdp_socket connect bind failure: %s",
			 safe_strerror(errno));
		close(mp->fd);
		mp->fd = -1;
		return rc;
	}

	/* Connect to the remote mp. */
	return (sockunion_connect(mp->fd, &mp->su_peer,
				  htons(PIM_MSDP_TCP_PORT), 0));
}
