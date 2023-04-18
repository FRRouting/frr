// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Socket union header.
 * Copyright (c) 1997 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_SOCKUNION_H
#define _ZEBRA_SOCKUNION_H

#include "privs.h"
#include "if.h"
#include <sys/un.h>
#ifdef __OpenBSD__
#include <netmpls/mpls.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

union sockunion {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_un sun;
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
int in6addr_cmp(const struct in6_addr *addr1, const struct in6_addr *addr2);
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
extern int sockunion_sizeof(const union sockunion *su);
extern int sockunion_stream_socket(union sockunion *);
extern int sockopt_reuseaddr(int);
extern int sockopt_reuseport(int);
extern int sockopt_v6only(int family, int sock);
extern int sockunion_bind(int sock, union sockunion *, unsigned short,
			  union sockunion *);
extern int sockopt_ttl(int family, int sock, int ttl);
extern int sockopt_minttl(int family, int sock, int minttl);
extern int sockunion_socket(const union sockunion *su);
extern const char *inet_sutop(const union sockunion *su, char *str);
extern enum connect_result sockunion_connect(int fd, const union sockunion *su,
					     unsigned short port, ifindex_t);
extern union sockunion *sockunion_getsockname(int);
extern union sockunion *sockunion_getpeername(int);
extern union sockunion *sockunion_dup(const union sockunion *);
extern void sockunion_free(union sockunion *);
extern void sockunion_init(union sockunion *);
extern int sockunion_is_null(const union sockunion *su);

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pSU"  (union sockunion *)
#pragma FRR printfrr_ext "%pSU"  (struct sockaddr *)
#pragma FRR printfrr_ext "%pSU"  (struct sockaddr_storage *)
#pragma FRR printfrr_ext "%pSU"  (struct sockaddr_in *)
#pragma FRR printfrr_ext "%pSU"  (struct sockaddr_in6 *)
#pragma FRR printfrr_ext "%pSU"  (struct sockaddr_un *)

/* AF_INET/PF_INET & co., using "PF" to avoid confusion with AFI/SAFI */
#pragma FRR printfrr_ext "%dPF"  (int)
/* SOCK_STREAM & co. */
#pragma FRR printfrr_ext "%dSO"  (int)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_SOCKUNION_H */
