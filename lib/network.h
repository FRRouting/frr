// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Network library header.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_NETWORK_H
#define _ZEBRA_NETWORK_H

#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#include <endian.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Both readn and writen are deprecated and will be removed.  They are not
   suitable for use with non-blocking file descriptors.
 */
extern int readn(int fd, uint8_t *ptr, int nbytes);
extern int writen(int fd, const uint8_t *ptr, int nbytes);

/* Set the file descriptor to use non-blocking I/O.  Returns 0 for success,
   -1 on error. */
extern int set_nonblocking(int fd);

extern int set_cloexec(int fd);

/* Does the I/O error indicate that the operation should be retried later? */
#define ERRNO_IO_RETRY(EN)                                                     \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

extern float htonf(float host);
extern float ntohf(float net);

/* force type for be64toh/htobe64 to be uint64_t, *without* a direct cast
 *
 * this is a workaround for false-positive printfrr warnings from FRR's
 * frr-format GCC plugin that would be triggered from
 * { printfrr("%"PRIu64, (uint64_t)be64toh(...)); }
 *
 * the key element here is that "(uint64_t)expr" causes the warning, while
 * "({ uint64_t x = expr; x; })" does not.  (The cast is the trigger, a
 * variable of the same type works correctly.)
 */

/* zap system definitions... */
#ifdef be64toh
#undef be64toh
#endif
#ifdef htobe64
#undef htobe64
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define be64toh(x)	({ uint64_t r = __builtin_bswap64(x); r; })
#define htobe64(x)	({ uint64_t r = __builtin_bswap64(x); r; })
#elif BYTE_ORDER == BIG_ENDIAN
#define be64toh(x)	({ uint64_t r = (x); r; })
#define htobe64(x)	({ uint64_t r = (x); r; })
#else
#error nobody expects the endianish inquisition. check OS endian.h headers.
#endif

/**
 * Generate a sequence number using monotonic clock with a same second call
 * protection to help guarantee a unique incremental sequence number that never
 * goes back (except when wrapping/overflow).
 *
 * **NOTE** this function is not thread safe since it uses `static` variable.
 *
 * This function and `frr_sequence32_next` should be used to initialize
 * sequence numbers without directly calling other `time_t` returning
 * functions because of `time_t` truncation warnings.
 *
 * \returns `uint64_t` number based on the monotonic clock.
 */
extern uint64_t frr_sequence_next(void);

/** Same as `frr_sequence_next` but returns truncated number. */
extern uint32_t frr_sequence32_next(void);

/**
 * Helper function that returns a random long value. The main purpose of
 * this function is to hide a `random()` call that gets flagged by coverity
 * scan and put it into one place.
 *
 * The main usage of this function should be for generating jitter or weak
 * random values for simple purposes.
 *
 * See 'man 3 random' for more information.
 *
 * \returns random long integer.
 */
static inline long frr_weak_random(void)
{
	/* coverity[dont_call] */
	return random();
}

/** Parsed network address information. */
struct network_address {
	/** Address storage. */
	struct sockaddr_storage address;
	/** Used address storage. */
	socklen_t address_size;
	/** Listen mode otherwise connect. */
	bool listen;
	/** Error string (if function returned false). */
	char error[256];
};

/**
 * Parses a string and returns the formatted network address if successful.
 *
 * When the parse fails the function returns `false` and the parameter
 * `address` member `error` is set with the error message that occurred.
 *
 * When no port is present on the string the corresponding `sockaddr` port
 * field will be set to the provided `default_port`.  `default_port` is used
 * as-is and is not validated: a port explicitly written as `0` is rejected
 * (it is most likely a typo), but callers that have no meaningful default
 * may pass `0` to get the wildcard port.
 *
 * IPv6 addresses must be enclosed in `[]` and may carry a scope/zone
 * identifier (e.g. `ipv6:[fe80::1%eth0]:1234`), which is resolved with
 * `if_nametoindex()` and stored in `sin6_scope_id`.
 *
 * \param address_string the string to parse
 * \param address the formatted address output
 * \param default_port port to use if none found in string (IPv4/IPv6 only).
 * \returns `true` on success with address set in `address` members, otherwise
 *          `false` and error message in `address.error`.
 */
extern bool network_address_parse(const char *address_string, struct network_address *address,
				  uint16_t default_port);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NETWORK_H */
