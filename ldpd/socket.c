/*	$OpenBSD$ */

/*
 * Copyright (c) 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#include "lib/log.h"
#include "privs.h"
#include "sockopt.h"

extern struct zebra_privs_t	 ldpd_privs;
extern struct zebra_privs_t	 ldpe_privs;

int
ldp_create_socket(int af, enum socket_type type)
{
	int			 fd, domain, proto;
	union ldpd_addr		 addr;
	union sockunion		 local_su;
#ifdef __OpenBSD__
	int			 opt;
#endif
	int			 save_errno;

	/* create socket */
	switch (type) {
	case LDP_SOCKET_DISC:
	case LDP_SOCKET_EDISC:
		domain = SOCK_DGRAM;
		proto = IPPROTO_UDP;
		break;
	case LDP_SOCKET_SESSION:
		domain = SOCK_STREAM;
		proto = IPPROTO_TCP;
		break;
	default:
		fatalx("ldp_create_socket: unknown socket type");
	}
	fd = socket(af, domain, proto);
	if (fd == -1) {
		log_warn("%s: error creating socket", __func__);
		return (-1);
	}
	sock_set_nonblock(fd);
	sockopt_v6only(af, fd);

	/* bind to a local address/port */
	switch (type) {
	case LDP_SOCKET_DISC:
		/* listen on all addresses */
		memset(&addr, 0, sizeof(addr));
		addr2sa(af, &addr, LDP_PORT, &local_su);
		break;
	case LDP_SOCKET_EDISC:
	case LDP_SOCKET_SESSION:
		addr = (ldp_af_conf_get(ldpd_conf, af))->trans_addr;
		addr2sa(af, &addr, LDP_PORT, &local_su);
		/* ignore any possible error */
		sock_set_bindany(fd, 1);
		break;
	}
	if (ldpd_privs.change(ZPRIVS_RAISE))
		log_warn("%s: could not raise privs", __func__);
	if (sock_set_reuse(fd, 1) == -1) {
		if (ldpd_privs.change(ZPRIVS_LOWER))
			log_warn("%s: could not lower privs", __func__);
		close(fd);
		return (-1);
	}
	if (bind(fd, &local_su.sa, sockaddr_len(&local_su.sa)) == -1) {
		save_errno = errno;
		if (ldpd_privs.change(ZPRIVS_LOWER))
			log_warn("%s: could not lower privs", __func__);
		log_warnx("%s: error binding socket: %s", __func__,
		    safe_strerror(save_errno));
		close(fd);
		return (-1);
	}
	if (ldpd_privs.change(ZPRIVS_LOWER))
		log_warn("%s: could not lower privs", __func__);

	/* set options */
	switch (af) {
	case AF_INET:
		if (sock_set_ipv4_tos(fd, IPTOS_PREC_INTERNETCONTROL) == -1) {
			close(fd);
			return (-1);
		}
		if (type == LDP_SOCKET_DISC) {
			if (sock_set_ipv4_mcast_ttl(fd,
			    IP_DEFAULT_MULTICAST_TTL) == -1) {
				close(fd);
				return (-1);
			}
			if (sock_set_ipv4_mcast_loop(fd) == -1) {
				close(fd);
				return (-1);
			}
		}
		if (type == LDP_SOCKET_DISC || type == LDP_SOCKET_EDISC) {
			if (sock_set_ipv4_recvif(fd, 1) == -1) {
				close(fd);
				return (-1);
			}
#ifndef MSG_MCAST
#if defined(HAVE_IP_PKTINFO)
			if (sock_set_ipv4_pktinfo(fd, 1) == -1) {
				close(fd);
				return (-1);
			}
#elif defined(HAVE_IP_RECVDSTADDR)
			if (sock_set_ipv4_recvdstaddr(fd, 1) == -1) {
				close(fd);
				return (-1);
			}
#else
#error "Unsupported socket API"
#endif
#endif /* MSG_MCAST */
		}
		if (type == LDP_SOCKET_SESSION) {
			if (sock_set_ipv4_ucast_ttl(fd, 255) == -1) {
				close(fd);
				return (-1);
			}
		}
		break;
	case AF_INET6:
		if (sock_set_ipv6_dscp(fd, IPTOS_PREC_INTERNETCONTROL) == -1) {
			close(fd);
			return (-1);
		}
		if (type == LDP_SOCKET_DISC) {
			if (sock_set_ipv6_mcast_loop(fd) == -1) {
				close(fd);
				return (-1);
			}
			if (sock_set_ipv6_mcast_hops(fd, 255) == -1) {
				close(fd);
				return (-1);
			}
			if (!(ldpd_conf->ipv6.flags & F_LDPD_AF_NO_GTSM)) {
				/* ignore any possible error */
				sock_set_ipv6_minhopcount(fd, 255);
			}
		}
		if (type == LDP_SOCKET_DISC || type == LDP_SOCKET_EDISC) {
			if (sock_set_ipv6_pktinfo(fd, 1) == -1) {
				close(fd);
				return (-1);
			}
		}
		if (type == LDP_SOCKET_SESSION) {
			if (sock_set_ipv6_ucast_hops(fd, 255) == -1) {
				close(fd);
				return (-1);
			}
		}
		break;
	}
	switch (type) {
	case LDP_SOCKET_DISC:
	case LDP_SOCKET_EDISC:
		sock_set_recvbuf(fd);
		break;
	case LDP_SOCKET_SESSION:
		if (listen(fd, LDP_BACKLOG) == -1)
			log_warn("%s: error listening on socket", __func__);

#ifdef __OpenBSD__
		opt = 1;
		if (setsockopt(fd, IPPROTO_TCP, TCP_MD5SIG, &opt,
		    sizeof(opt)) == -1) {
			if (errno == ENOPROTOOPT) {	/* system w/o md5sig */
				log_warnx("md5sig not available, disabling");
				sysdep.no_md5sig = 1;
			} else {
				close(fd);
				return (-1);
			}
		}
#endif
		break;
	}

	return (fd);
}

void
sock_set_nonblock(int fd)
{
	int	flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl F_GETFL");

	flags |= O_NONBLOCK;

	if ((flags = fcntl(fd, F_SETFL, flags)) == -1)
		fatal("fcntl F_SETFL");
}

void
sock_set_cloexec(int fd)
{
	int	flags;

	if ((flags = fcntl(fd, F_GETFD, 0)) == -1)
		fatal("fcntl F_GETFD");

	flags |= FD_CLOEXEC;

	if ((flags = fcntl(fd, F_SETFD, flags)) == -1)
		fatal("fcntl F_SETFD");
}

void
sock_set_recvbuf(int fd)
{
	int	bsize;

	bsize = 65535;
	while (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bsize,
	    sizeof(bsize)) == -1)
		bsize /= 2;
}

int
sock_set_reuse(int fd, int enable)
{
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable,
	    sizeof(int)) < 0) {
		log_warn("%s: error setting SO_REUSEADDR", __func__);
		return (-1);
	}

	return (0);
}

int
sock_set_bindany(int fd, int enable)
{
#ifdef HAVE_SO_BINDANY
	if (ldpd_privs.change(ZPRIVS_RAISE))
		log_warn("%s: could not raise privs", __func__);
	if (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &enable,
	    sizeof(int)) < 0) {
		if (ldpd_privs.change(ZPRIVS_LOWER))
			log_warn("%s: could not lower privs", __func__);
		log_warn("%s: error setting SO_BINDANY", __func__);
		return (-1);
	}
	if (ldpd_privs.change(ZPRIVS_LOWER))
		log_warn("%s: could not lower privs", __func__);
	return (0);
#elif defined(HAVE_IP_FREEBIND)
	if (setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &enable, sizeof(int)) < 0) {
		log_warn("%s: error setting IP_FREEBIND", __func__);
		return (-1);
	}
	return (0);
#else
	log_warnx("%s: missing SO_BINDANY and IP_FREEBIND, unable to bind "
	    "to a nonlocal IP address", __func__);
	return (-1);
#endif /* HAVE_SO_BINDANY */
}

#ifndef __OpenBSD__
/*
 * Set MD5 key for the socket, for the given peer address. If the password
 * is NULL or zero-length, the option will be disabled.
 */
int
sock_set_md5sig(int fd, int af, union ldpd_addr *addr, const char *password)
{
	int		 ret = -1;
	int		 save_errno = ENOSYS;
#if HAVE_DECL_TCP_MD5SIG
	union sockunion	 su;
#endif

	if (fd == -1)
		return (0);
#if HAVE_DECL_TCP_MD5SIG
	addr2sa(af, addr, 0, &su);

	if (ldpe_privs.change(ZPRIVS_RAISE)) {
		log_warn("%s: could not raise privs", __func__);
		return (-1);
	}
	ret = sockopt_tcp_signature(fd, &su, password);
	save_errno = errno;
	if (ldpe_privs.change(ZPRIVS_LOWER))
		log_warn("%s: could not lower privs", __func__);
#endif /* HAVE_TCP_MD5SIG */
	if (ret < 0)
		log_warnx("%s: can't set TCP_MD5SIG option on fd %d: %s",
		    __func__, fd, safe_strerror(save_errno));

	return (ret);
}
#endif

int
sock_set_ipv4_tos(int fd, int tos)
{
	if (setsockopt(fd, IPPROTO_IP, IP_TOS, (int *)&tos, sizeof(tos)) < 0) {
		log_warn("%s: error setting IP_TOS to 0x%x", __func__, tos);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv4_recvif(int fd, int enable)
{
	return (setsockopt_ifindex(AF_INET, fd, enable));
}

int
sock_set_ipv4_minttl(int fd, int ttl)
{
	return (sockopt_minttl(AF_INET, fd, ttl));
}

int
sock_set_ipv4_ucast_ttl(int fd, int ttl)
{
	if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		log_warn("%s: error setting IP_TTL", __func__);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv4_mcast_ttl(int fd, uint8_t ttl)
{
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL,
	    (char *)&ttl, sizeof(ttl)) < 0) {
		log_warn("%s: error setting IP_MULTICAST_TTL to %d",
		    __func__, ttl);
		return (-1);
	}

	return (0);
}

#ifndef MSG_MCAST
#if defined(HAVE_IP_PKTINFO)
int
sock_set_ipv4_pktinfo(int fd, int enable)
{
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &enable,
	    sizeof(enable)) < 0) {
		log_warn("%s: error setting IP_PKTINFO", __func__);
		return (-1);
	}

	return (0);
}
#elif defined(HAVE_IP_RECVDSTADDR)
int
sock_set_ipv4_recvdstaddr(int fd, int enable)
{
	if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &enable,
	    sizeof(enable)) < 0) {
		log_warn("%s: error setting IP_RECVDSTADDR", __func__);
		return (-1);
	}

	return (0);
}
#else
#error "Unsupported socket API"
#endif
#endif /* MSG_MCAST */

int
sock_set_ipv4_mcast(struct iface *iface)
{
	struct in_addr		 if_addr;

	if_addr.s_addr = if_get_ipv4_addr(iface);

	if (setsockopt_ipv4_multicast_if(global.ipv4.ldp_disc_socket,
	    if_addr, iface->ifindex) < 0) {
		log_warn("%s: error setting IP_MULTICAST_IF, interface %s",
		    __func__, iface->name);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv4_mcast_loop(int fd)
{
	return (setsockopt_ipv4_multicast_loop(fd, 0));
}

int
sock_set_ipv6_dscp(int fd, int dscp)
{
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &dscp,
	    sizeof(dscp)) < 0) {
		log_warn("%s: error setting IPV6_TCLASS", __func__);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv6_pktinfo(int fd, int enable)
{
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &enable,
	    sizeof(enable)) < 0) {
		log_warn("%s: error setting IPV6_RECVPKTINFO", __func__);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv6_minhopcount(int fd, int hoplimit)
{
	return (sockopt_minttl(AF_INET6, fd, hoplimit));
}

int
sock_set_ipv6_ucast_hops(int fd, int hoplimit)
{
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
	    &hoplimit, sizeof(hoplimit)) < 0) {
		log_warn("%s: error setting IPV6_UNICAST_HOPS", __func__);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv6_mcast_hops(int fd, int hoplimit)
{
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	    &hoplimit, sizeof(hoplimit)) < 0) {
		log_warn("%s: error setting IPV6_MULTICAST_HOPS", __func__);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv6_mcast(struct iface *iface)
{
	if (setsockopt(global.ipv6.ldp_disc_socket, IPPROTO_IPV6,
	    IPV6_MULTICAST_IF, &iface->ifindex, sizeof(iface->ifindex)) < 0) {
		log_warn("%s: error setting IPV6_MULTICAST_IF, interface %s",
		    __func__, iface->name);
		return (-1);
	}

	return (0);
}

int
sock_set_ipv6_mcast_loop(int fd)
{
	unsigned int	loop = 0;

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
	    &loop, sizeof(loop)) < 0) {
		log_warn("%s: error setting IPV6_MULTICAST_LOOP", __func__);
		return (-1);
	}

	return (0);
}
