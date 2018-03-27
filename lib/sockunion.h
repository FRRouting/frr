/*
 * Socket union header.
 * Copyright (c) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_SOCKUNION_H
#define _ZEBRA_SOCKUNION_H

#include "privs.h"
#include "if.h"
#ifdef __OpenBSD__
#include <netmpls/mpls.h>
#endif

union sockunion {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
#ifdef __OpenBSD__
	struct sockaddr_mpls smpls;
	struct sockaddr_rtlabel rtlabel;
#endif
};

enum connect_result { connect_error, connect_success, connect_in_progress };

/* Default address family. */
#define AF_INET_UNION AF_INET6

/* Sockunion address string length.  Same as INET6_ADDRSTRLEN. */
#define SU_ADDRSTRLEN 46

/* Macro to set link local index to the IPv6 address.  For KAME IPv6
   stack. */
#ifdef KAME
#define	IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr[2] << 8 | (a).s6_addr[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)                                        \
	do {                                                                   \
		(a).s6_addr[2] = ((i) >> 8) & 0xff;                            \
		(a).s6_addr[3] = (i)&0xff;                                     \
	} while (0)
#else
#define	IN6_LINKLOCAL_IFINDEX(a)
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)
#endif /* KAME */

#define sockunion_family(X)  (X)->sa.sa_family

#define sockunion2ip(X)      (X)->sin.sin_addr.s_addr

/* Prototypes. */
extern int str2sockunion(const char *, union sockunion *);
extern const char *sockunion2str(const union sockunion *, char *, size_t);
extern int sockunion_cmp(const union sockunion *, const union sockunion *);
extern int sockunion_same(const union sockunion *, const union sockunion *);
extern unsigned int sockunion_hash(const union sockunion *);

extern size_t family2addrsize(int family);
extern size_t sockunion_get_addrlen(const union sockunion *);
extern const uint8_t *sockunion_get_addr(const union sockunion *);
extern void sockunion_set(union sockunion *, int family, const uint8_t *addr,
			  size_t bytes);

extern union sockunion *sockunion_str2su(const char *str);
extern int sockunion_accept(int sock, union sockunion *);
extern int sockunion_stream_socket(union sockunion *);
extern int sockopt_reuseaddr(int);
extern int sockopt_reuseport(int);
extern int sockopt_v6only(int family, int sock);
extern int sockunion_bind(int sock, union sockunion *, unsigned short,
			  union sockunion *);
extern int sockopt_ttl(int family, int sock, int ttl);
extern int sockopt_minttl(int family, int sock, int minttl);
extern int sockopt_cork(int sock, int onoff);
extern int sockopt_mark_default(int sock, int mark, struct zebra_privs_t *);
extern int sockunion_socket(const union sockunion *su);
extern const char *inet_sutop(const union sockunion *su, char *str);
extern enum connect_result sockunion_connect(int fd, const union sockunion *su,
					     unsigned short port, ifindex_t);
extern union sockunion *sockunion_getsockname(int);
extern union sockunion *sockunion_getpeername(int);
extern union sockunion *sockunion_dup(const union sockunion *);
extern void sockunion_free(union sockunion *);
extern void sockunion_init(union sockunion *);

#endif /* _ZEBRA_SOCKUNION_H */
