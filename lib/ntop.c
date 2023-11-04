// SPDX-License-Identifier: ISC
/*
 * optimized ntop, about 10x faster than libc versions [as of 2019]
 *
 * Copyright (c) 2019  David Lamparter, for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "compiler.h"

#define pos (*posx)

static inline void putbyte(uint8_t bytex, char **posx)
	__attribute__((always_inline)) OPTIMIZE;

static inline void putbyte(uint8_t bytex, char **posx)
{
	bool zero = false;
	int byte = bytex, tmp, a, b;

	tmp = byte - 200;
	if (tmp >= 0) {
		*pos++ = '2';
		zero = true;
		byte = tmp;
	} else {
		tmp = byte - 100;
		if (tmp >= 0) {
			*pos++ = '1';
			zero = true;
			byte = tmp;
		}
	}

	/* make sure the compiler knows the value range of "byte" */
	assume(byte < 100 && byte >= 0);

	b = byte % 10;
	a = byte / 10;
	if (a || zero) {
		*pos++ = '0' + a;
		*pos++ = '0' + b;
	} else
		*pos++ = '0' + b;
}

static inline void puthex(uint16_t word, char **posx)
	__attribute__((always_inline)) OPTIMIZE;

static inline void puthex(uint16_t word, char **posx)
{
	const char *digits = "0123456789abcdef";
	if (word >= 0x1000)
		*pos++ = digits[(word >> 12) & 0xf];
	if (word >= 0x100)
		*pos++ = digits[(word >> 8) & 0xf];
	if (word >= 0x10)
		*pos++ = digits[(word >> 4) & 0xf];
	*pos++ = digits[word & 0xf];
}

#undef pos

const char *frr_inet_ntop(int af, const void * restrict src,
			  char * restrict dst, socklen_t size)
	__attribute__((flatten)) OPTIMIZE;

const char *frr_inet_ntop(int af, const void * restrict src,
			  char * restrict dst, socklen_t size)
{
	const uint8_t *b = src;
	/* 8 * "abcd:" for IPv6
	 * note: the IPv4-embedded IPv6 syntax is only used for ::A.B.C.D,
	 * which isn't longer than 40 chars either.  even with ::ffff:A.B.C.D
	 * it's shorter.
	 */
	char buf[8 * 5], *o = buf;
	size_t best = 0, bestlen = 0, curlen = 0, i;

	switch (af) {
	case AF_INET:
inet4:
		putbyte(b[0], &o);
		*o++ = '.';
		putbyte(b[1], &o);
		*o++ = '.';
		putbyte(b[2], &o);
		*o++ = '.';
		putbyte(b[3], &o);
		*o++ = '\0';
		break;
	case AF_INET6:
		for (i = 0; i < 8; i++) {
			if (b[i * 2] || b[i * 2 + 1]) {
				if (curlen && curlen > bestlen) {
					best = i - curlen;
					bestlen = curlen;
				}
				curlen = 0;
				continue;
			}
			curlen++;
		}
		if (curlen && curlen > bestlen) {
			best = i - curlen;
			bestlen = curlen;
		}
		/* do we want ::ffff:A.B.C.D? */
		if (best == 0 && bestlen == 6) {
			*o++ = ':';
			*o++ = ':';
			b += 12;
			goto inet4;
		}
		if (bestlen == 1)
			bestlen = 0;

		for (i = 0; i < 8; i++) {
			if (bestlen && i == best) {
				if (i == 0)
					*o++ = ':';
				*o++ = ':';
				continue;
			}
			if (i > best && i < best + bestlen) {
				continue;
			}
			puthex((b[i * 2] << 8) | b[i * 2 + 1], &o);

			if (i < 7)
				*o++ = ':';
		}
		*o++ = '\0';
		break;
	default:
		return NULL;
	}

	i = o - buf;
	if (i > size)
		return NULL;
	/* compiler might inline memcpy if it knows the length is short,
	 * although neither gcc nor clang actually do this currently [2019]
	 */
	assume(i <= 8 * 5);
	memcpy(dst, buf, i);
	return dst;
}

#if !defined(INET_NTOP_NO_OVERRIDE)
/* we want to override libc inet_ntop, but make sure it shows up in backtraces
 * as frr_inet_ntop (to avoid confusion while debugging)
 */
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
	__attribute__((alias ("frr_inet_ntop")));
#endif
