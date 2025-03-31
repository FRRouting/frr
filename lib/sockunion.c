// SPDX-License-Identifier: GPL-2.0-or-later
/* Socket union related function.
 * Copyright (c) 1997, 98 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"
#include "jhash.h"
#include "lib_errors.h"
#include "printfrr.h"

DEFINE_MTYPE_STATIC(LIB, SOCKUNION, "Socket union");

const char *inet_sutop(const union sockunion *su, char *str)
{
	switch (su->sa.sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &su->sin.sin_addr, str, INET_ADDRSTRLEN);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &su->sin6.sin6_addr, str, INET6_ADDRSTRLEN);
		break;
	}
	return str;
}

int str2sockunion(const char *str, union sockunion *su)
{
	int ret;

	if (str == NULL)
		return -1;

	memset(su, 0, sizeof(union sockunion));

	ret = inet_pton(AF_INET, str, &su->sin.sin_addr);
	if (ret > 0) /* Valid IPv4 address format. */
	{
		su->sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		su->sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
		return 0;
	}
	ret = inet_pton(AF_INET6, str, &su->sin6.sin6_addr);
	if (ret > 0) /* Valid IPv6 address format. */
	{
		su->sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
		su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
		return 0;
	}
	return -1;
}

const char *sockunion2str(const union sockunion *su, char *buf, size_t len)
{
	switch (sockunion_family(su)) {
	case AF_UNSPEC:
		snprintf(buf, len, "(unspec)");
		return buf;
	case AF_INET:
		return inet_ntop(AF_INET, &su->sin.sin_addr, buf, len);
	case AF_INET6:
		return inet_ntop(AF_INET6, &su->sin6.sin6_addr, buf, len);
	}
	snprintf(buf, len, "(af %d)", sockunion_family(su));
	return buf;
}

union sockunion *sockunion_str2su(const char *str)
{
	union sockunion *su = XCALLOC(MTYPE_SOCKUNION, sizeof(union sockunion));

	if (!str2sockunion(str, su))
		return su;

	XFREE(MTYPE_SOCKUNION, su);
	return NULL;
}

/* Convert IPv4 compatible IPv6 address to IPv4 address. */
static void sockunion_normalise_mapped(union sockunion *su)
{
	struct sockaddr_in sin;

	if (su->sa.sa_family == AF_INET6
	    && IN6_IS_ADDR_V4MAPPED(&su->sin6.sin6_addr)) {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = su->sin6.sin6_port;
		memcpy(&sin.sin_addr, ((char *)&su->sin6.sin6_addr) + 12, 4);
		memcpy(su, &sin, sizeof(struct sockaddr_in));
	}
}

/* return sockunion structure : this function should be revised. */
static const char *sockunion_log(const union sockunion *su, char *buf,
				 size_t len)
{
	switch (su->sa.sa_family) {
	case AF_INET:
		return inet_ntop(AF_INET, &su->sin.sin_addr, buf, len);

	case AF_INET6:
		return inet_ntop(AF_INET6, &(su->sin6.sin6_addr), buf, len);

	default:
		snprintf(buf, len, "af_unknown %d ", su->sa.sa_family);
		return buf;
	}
}

/* Return socket of sockunion. */
int sockunion_socket(const union sockunion *su)
{
	int sock;

	sock = socket(su->sa.sa_family, SOCK_STREAM, 0);
	if (sock < 0) {
		char buf[SU_ADDRSTRLEN];
		flog_err(EC_LIB_SOCKET, "Can't make socket for %s : %s",
			 sockunion_log(su, buf, SU_ADDRSTRLEN),
			 safe_strerror(errno));
		return -1;
	}

	return sock;
}

/* Return accepted new socket file descriptor. */
int sockunion_accept(int sock, union sockunion *su)
{
	socklen_t len;
	int client_sock;

	len = sizeof(union sockunion);
	client_sock = accept(sock, (struct sockaddr *)su, &len);

	sockunion_normalise_mapped(su);
	return client_sock;
}

/* Return sizeof union sockunion.  */
int sockunion_sizeof(const union sockunion *su)
{
	int ret;

	ret = 0;
	switch (su->sa.sa_family) {
	case AF_INET:
		ret = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		ret = sizeof(struct sockaddr_in6);
		break;
	}
	return ret;
}

/* Performs a non-blocking connect().  */
enum connect_result sockunion_connect(int fd, const union sockunion *peersu,
				      unsigned short port, ifindex_t ifindex)
{
	int ret;
	union sockunion su;

	memcpy(&su, peersu, sizeof(union sockunion));

	switch (su.sa.sa_family) {
	case AF_INET:
		su.sin.sin_port = port;
		break;
	case AF_INET6:
		su.sin6.sin6_port = port;
#ifdef KAME
		if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr) && ifindex) {
			su.sin6.sin6_scope_id = ifindex;
			SET_IN6_LINKLOCAL_IFINDEX(su.sin6.sin6_addr, ifindex);
		}
#endif /* KAME */
		break;
	}

	/* Call connect function. */
	ret = connect(fd, (struct sockaddr *)&su, sockunion_sizeof(&su));

	/* Immediate success */
	if (ret == 0)
		return connect_success;

	/* If connect is in progress then return 1 else it's real error. */
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			char str[SU_ADDRSTRLEN];
			zlog_info("can't connect to %s fd %d : %s",
				  sockunion_log(&su, str, sizeof(str)), fd,
				  safe_strerror(errno));
			return connect_error;
		}
	}

	return connect_in_progress;
}

/* Make socket from sockunion union. */
int sockunion_stream_socket(union sockunion *su)
{
	int sock;

	if (su->sa.sa_family == 0)
		su->sa.sa_family = AF_INET_UNION;

	sock = socket(su->sa.sa_family, SOCK_STREAM, 0);

	if (sock < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't make socket sockunion_stream_socket");

	return sock;
}

/* Bind socket to specified address. */
int sockunion_bind(int sock, union sockunion *su, unsigned short port,
		   union sockunion *su_addr)
{
	int size = 0;
	int ret;

	if (su->sa.sa_family == AF_INET) {
		size = sizeof(struct sockaddr_in);
		su->sin.sin_port = htons(port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		su->sin.sin_len = size;
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
		if (su_addr == NULL)
			sockunion2ip(su) = htonl(INADDR_ANY);
	} else if (su->sa.sa_family == AF_INET6) {
		size = sizeof(struct sockaddr_in6);
		su->sin6.sin6_port = htons(port);
#ifdef SIN6_LEN
		su->sin6.sin6_len = size;
#endif /* SIN6_LEN */
		if (su_addr == NULL) {
#ifdef LINUX_IPV6
			memset(&su->sin6.sin6_addr, 0, sizeof(struct in6_addr));
#else
			su->sin6.sin6_addr = in6addr_any;
#endif /* LINUX_IPV6 */
		}
	}

	ret = bind(sock, (struct sockaddr *)su, size);
	if (ret < 0) {
		char buf[SU_ADDRSTRLEN];
		flog_err(EC_LIB_SOCKET, "can't bind socket for %s : %s",
			 sockunion_log(su, buf, SU_ADDRSTRLEN),
			 safe_strerror(errno));
	}

	return ret;
}

int sockopt_reuseaddr(int sock)
{
	int ret;
	int on = 1;

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on,
			 sizeof(on));
	if (ret < 0) {
		flog_err(
			EC_LIB_SOCKET,
			"can't set sockopt SO_REUSEADDR to socket %d errno=%d: %s",
			sock, errno, safe_strerror(errno));
		return -1;
	}
	return 0;
}

#ifdef SO_REUSEPORT
int sockopt_reuseport(int sock)
{
	int ret;
	int on = 1;

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on,
			 sizeof(on));
	if (ret < 0) {
		flog_err(EC_LIB_SOCKET,
			 "can't set sockopt SO_REUSEPORT to socket %d", sock);
		return -1;
	}
	return 0;
}
#else
int sockopt_reuseport(int sock)
{
	return 0;
}
#endif /* 0 */

int sockopt_ttl(int family, int sock, int ttl)
{
	int ret;

#ifdef IP_TTL
	if (family == AF_INET) {
		ret = setsockopt(sock, IPPROTO_IP, IP_TTL, (void *)&ttl,
				 sizeof(int));
		if (ret < 0) {
			flog_err(EC_LIB_SOCKET,
				 "can't set sockopt IP_TTL %d to socket %d",
				 ttl, sock);
			return -1;
		}
		return 0;
	}
#endif /* IP_TTL */
	if (family == AF_INET6) {
		ret = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				 (void *)&ttl, sizeof(int));
		if (ret < 0) {
			flog_err(
				EC_LIB_SOCKET,
				"can't set sockopt IPV6_UNICAST_HOPS %d to socket %d",
				ttl, sock);
			return -1;
		}
		return 0;
	}
	return 0;
}

int sockopt_minttl(int family, int sock, int minttl)
{
#ifdef IP_MINTTL
	if (family == AF_INET) {
		int ret = setsockopt(sock, IPPROTO_IP, IP_MINTTL, &minttl,
				     sizeof(minttl));
		if (ret < 0)
			flog_err(
				EC_LIB_SOCKET,
				"can't set sockopt IP_MINTTL to %d on socket %d: %s",
				minttl, sock, safe_strerror(errno));
		return ret;
	}
#endif /* IP_MINTTL */
#ifdef IPV6_MINHOPCOUNT
	if (family == AF_INET6) {
		int ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MINHOPCOUNT,
				     &minttl, sizeof(minttl));
		if (ret < 0)
			flog_err(
				EC_LIB_SOCKET,
				"can't set sockopt IPV6_MINHOPCOUNT to %d on socket %d: %s",
				minttl, sock, safe_strerror(errno));
		return ret;
	}
#endif

	errno = EOPNOTSUPP;
	return -1;
}

int sockopt_v6only(int family, int sock)
{
	int ret, on = 1;

#ifdef IPV6_V6ONLY
	if (family == AF_INET6) {
		ret = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on,
				 sizeof(int));
		if (ret < 0) {
			flog_err(EC_LIB_SOCKET,
				 "can't set sockopt IPV6_V6ONLY to socket %d",
				 sock);
			return -1;
		}
		return 0;
	}
#endif /* IPV6_V6ONLY */
	return 0;
}

/* If same family and same prefix return 1. */
int sockunion_same(const union sockunion *su1, const union sockunion *su2)
{
	int ret = 0;

	if (su1->sa.sa_family != su2->sa.sa_family)
		return 0;

	switch (su1->sa.sa_family) {
	case AF_INET:
		ret = memcmp(&su1->sin.sin_addr, &su2->sin.sin_addr,
			     sizeof(struct in_addr));
		break;
	case AF_INET6:
		ret = IPV6_ADDR_CMP(&su1->sin6.sin6_addr, &su2->sin6.sin6_addr);
		if ((ret == 0) && IN6_IS_ADDR_LINKLOCAL(&su1->sin6.sin6_addr)) {
			/* compare interface indices */
			if (su1->sin6.sin6_scope_id && su2->sin6.sin6_scope_id)
				ret = (su1->sin6.sin6_scope_id
				       == su2->sin6.sin6_scope_id)
					      ? 0
					      : 1;
		}
		break;
	}
	if (ret == 0)
		return 1;
	else
		return 0;
}

unsigned int sockunion_hash(const union sockunion *su)
{
	switch (sockunion_family(su)) {
	case AF_INET:
		return jhash_1word(su->sin.sin_addr.s_addr, 0);
	case AF_INET6:
		return jhash2(su->sin6.sin6_addr.s6_addr32,
			      array_size(su->sin6.sin6_addr.s6_addr32), 0);
	}
	return 0;
}

size_t family2addrsize(int family)
{
	switch (family) {
	case AF_INET:
		return sizeof(struct in_addr);
	case AF_INET6:
		return sizeof(struct in6_addr);
	}
	return 0;
}

size_t sockunion_get_addrlen(const union sockunion *su)
{
	return family2addrsize(sockunion_family(su));
}

const uint8_t *sockunion_get_addr(const union sockunion *su)
{
	switch (sockunion_family(su)) {
	case AF_INET:
		return (const uint8_t *)&su->sin.sin_addr.s_addr;
	case AF_INET6:
		return (const uint8_t *)&su->sin6.sin6_addr;
	}
	return NULL;
}

void sockunion_set(union sockunion *su, int family, const uint8_t *addr,
		   size_t bytes)
{
	if (family2addrsize(family) != bytes)
		return;

	sockunion_family(su) = family;
	switch (family) {
	case AF_INET:
		memcpy(&su->sin.sin_addr.s_addr, addr, bytes);
		break;
	case AF_INET6:
		memcpy(&su->sin6.sin6_addr, addr, bytes);
		break;
	}
}

/* After TCP connection is established.  Get local address and port. */
union sockunion *sockunion_getsockname(int fd)
{
	int ret;
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		char tmp_buffer[128];
	} name;
	union sockunion *su;

	memset(&name, 0, sizeof(name));
	len = sizeof(name);

	ret = getsockname(fd, (struct sockaddr *)&name, &len);
	if (ret < 0) {
		flog_err(EC_LIB_SOCKET,
			 "Can't get local address and port by getsockname: %s",
			 safe_strerror(errno));
		return NULL;
	}

	if (name.sa.sa_family == AF_INET) {
		su = XCALLOC(MTYPE_SOCKUNION, sizeof(union sockunion));
		memcpy(su, &name, sizeof(struct sockaddr_in));
		return su;
	}
	if (name.sa.sa_family == AF_INET6) {
		su = XCALLOC(MTYPE_SOCKUNION, sizeof(union sockunion));
		memcpy(su, &name, sizeof(struct sockaddr_in6));
		sockunion_normalise_mapped(su);
		return su;
	}

	flog_err(
		EC_LIB_SOCKET,
		"Unexpected AFI received(%d) for sockunion_getsockname call for fd: %d",
		name.sa.sa_family, fd);
	return NULL;
}

/* After TCP connection is established.  Get remote address and port. */
union sockunion *sockunion_getpeername(int fd)
{
	int ret;
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		char tmp_buffer[128];
	} name;
	union sockunion *su;

	memset(&name, 0, sizeof(name));
	len = sizeof(name);
	ret = getpeername(fd, (struct sockaddr *)&name, &len);
	if (ret < 0) {
		flog_err(EC_LIB_SOCKET, "Can't get remote address and port: %s",
			 safe_strerror(errno));
		return NULL;
	}

	if (name.sa.sa_family == AF_INET) {
		su = XCALLOC(MTYPE_SOCKUNION, sizeof(union sockunion));
		memcpy(su, &name, sizeof(struct sockaddr_in));
		return su;
	}
	if (name.sa.sa_family == AF_INET6) {
		su = XCALLOC(MTYPE_SOCKUNION, sizeof(union sockunion));
		memcpy(su, &name, sizeof(struct sockaddr_in6));
		sockunion_normalise_mapped(su);
		return su;
	}

	flog_err(
		EC_LIB_SOCKET,
		"Unexpected AFI received(%d) for sockunion_getpeername call for fd: %d",
		name.sa.sa_family, fd);
	return NULL;
}

/* Print sockunion structure */
static void __attribute__((unused)) sockunion_print(const union sockunion *su)
{
	if (su == NULL)
		return;

	switch (su->sa.sa_family) {
	case AF_INET:
		printf("%pI4\n", &su->sin.sin_addr);
		break;
	case AF_INET6:
		printf("%pI6\n", &su->sin6.sin6_addr);
		break;
#ifdef AF_LINK
	case AF_LINK: {
		struct sockaddr_dl *sdl;

		sdl = (struct sockaddr_dl *)&(su->sa);
		printf("link#%d\n", sdl->sdl_index);
	} break;
#endif /* AF_LINK */
	default:
		printf("af_unknown %d\n", su->sa.sa_family);
		break;
	}
}

int sockunion_cmp(const union sockunion *su1, const union sockunion *su2)
{
	if (su1->sa.sa_family > su2->sa.sa_family)
		return 1;
	if (su1->sa.sa_family < su2->sa.sa_family)
		return -1;

	if (su1->sa.sa_family == AF_INET) {
		if (ntohl(sockunion2ip(su1)) == ntohl(sockunion2ip(su2)))
			return 0;
		if (ntohl(sockunion2ip(su1)) > ntohl(sockunion2ip(su2)))
			return 1;
		else
			return -1;
	}
	if (su1->sa.sa_family == AF_INET6)
		return IPV6_ADDR_CMP(&su1->sin6.sin6_addr, &su2->sin6.sin6_addr);

	return 0;
}

/* Duplicate sockunion. */
union sockunion *sockunion_dup(const union sockunion *su)
{
	union sockunion *dup =
		XCALLOC(MTYPE_SOCKUNION, sizeof(union sockunion));
	memcpy(dup, su, sizeof(union sockunion));
	return dup;
}

void sockunion_free(union sockunion *su)
{
	XFREE(MTYPE_SOCKUNION, su);
}

void sockunion_init(union sockunion *su)
{
	memset(su, 0, sizeof(union sockunion));
}

printfrr_ext_autoreg_p("SU", printfrr_psu);
static ssize_t printfrr_psu(struct fbuf *buf, struct printfrr_eargs *ea,
			    const void *ptr)
{
	const union sockunion *su = ptr;
	bool include_port = false, include_scope = false;
	bool endflags = false;
	ssize_t ret = 0;
	char cbuf[INET6_ADDRSTRLEN];

	if (!su)
		return bputs(buf, "(null)");

	while (!endflags) {
		switch (*ea->fmt) {
		case 'p':
			ea->fmt++;
			include_port = true;
			break;
		case 's':
			ea->fmt++;
			include_scope = true;
			break;
		default:
			endflags = true;
			break;
		}
	}

	switch (sockunion_family(su)) {
	case AF_UNSPEC:
		ret += bputs(buf, "(unspec)");
		break;
	case AF_INET:
		inet_ntop(AF_INET, &su->sin.sin_addr, cbuf, sizeof(cbuf));
		ret += bputs(buf, cbuf);
		if (include_port)
			ret += bprintfrr(buf, ":%d", ntohs(su->sin.sin_port));
		break;
	case AF_INET6:
		if (include_port)
			ret += bputch(buf, '[');
		inet_ntop(AF_INET6, &su->sin6.sin6_addr, cbuf, sizeof(cbuf));
		ret += bputs(buf, cbuf);
		if (include_scope && su->sin6.sin6_scope_id)
			ret += bprintfrr(buf, "%%%u",
					 (unsigned int)su->sin6.sin6_scope_id);
		if (include_port)
			ret += bprintfrr(buf, "]:%d",
					 ntohs(su->sin6.sin6_port));
		break;
	case AF_UNIX: {
		int len;
#ifdef __linux__
		if (su->sun.sun_path[0] == '\0' && su->sun.sun_path[1]) {
			len = strnlen(su->sun.sun_path + 1,
				      sizeof(su->sun.sun_path) - 1);
			ret += bprintfrr(buf, "@%*pSE", len,
					 su->sun.sun_path + 1);
			break;
		}
#endif
		len = strnlen(su->sun.sun_path, sizeof(su->sun.sun_path));
		ret += bprintfrr(buf, "%*pSE", len, su->sun.sun_path);
		break;
	}
	default:
		ret += bprintfrr(buf, "(af %d)", sockunion_family(su));
	}

	return ret;
}

int sockunion_is_null(const union sockunion *su)
{
	unsigned char null_s6_addr[16] = {0};

	switch (sockunion_family(su)) {
	case AF_UNSPEC:
		return 1;
	case AF_INET:
		return (su->sin.sin_addr.s_addr == 0);
	case AF_INET6:
		return !IPV6_ADDR_CMP(su->sin6.sin6_addr.s6_addr, null_s6_addr);
	default:
		return 0;
	}
}

printfrr_ext_autoreg_i("PF", printfrr_pf);
static ssize_t printfrr_pf(struct fbuf *buf, struct printfrr_eargs *ea,
			   uintmax_t val)
{
	switch (val) {
	case AF_INET:
		return bputs(buf, "AF_INET");
	case AF_INET6:
		return bputs(buf, "AF_INET6");
	case AF_UNIX:
		return bputs(buf, "AF_UNIX");
#ifdef AF_PACKET
	case AF_PACKET:
		return bputs(buf, "AF_PACKET");
#endif
#ifdef AF_NETLINK
	case AF_NETLINK:
		return bputs(buf, "AF_NETLINK");
#endif
	}
	return bprintfrr(buf, "AF_(%ju)", val);
}

printfrr_ext_autoreg_i("SO", printfrr_so);
static ssize_t printfrr_so(struct fbuf *buf, struct printfrr_eargs *ea,
			   uintmax_t val)
{
	switch (val) {
	case SOCK_STREAM:
		return bputs(buf, "SOCK_STREAM");
	case SOCK_DGRAM:
		return bputs(buf, "SOCK_DGRAM");
	case SOCK_SEQPACKET:
		return bputs(buf, "SOCK_SEQPACKET");
#ifdef SOCK_RAW
	case SOCK_RAW:
		return bputs(buf, "SOCK_RAW");
#endif
#ifdef SOCK_PACKET
	case SOCK_PACKET:
		return bputs(buf, "SOCK_PACKET");
#endif
	}
	return bprintfrr(buf, "SOCK_(%ju)", val);
}
