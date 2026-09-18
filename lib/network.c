// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Network library.
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <sys/un.h>

#include <fcntl.h>
#include "log.h"
#include "network.h"
#include "lib_errors.h"

/* Read nbytes from fd and store into ptr. */
int readn(int fd, uint8_t *ptr, int nbytes)
{
	int nleft;
	int nread;

	nleft = nbytes;

	while (nleft > 0) {
		nread = read(fd, ptr, nleft);

		if (nread < 0)
			return (nread);
		else if (nread == 0)
			break;

		nleft -= nread;
		ptr += nread;
	}

	return nbytes - nleft;
}

/* Write nbytes from ptr to fd. */
int writen(int fd, const uint8_t *ptr, int nbytes)
{
	int nleft;
	int nwritten;

	nleft = nbytes;

	while (nleft > 0) {
		nwritten = write(fd, ptr, nleft);

		if (nwritten < 0) {
			if (!ERRNO_IO_RETRY(errno))
				return nwritten;
		}
		if (nwritten == 0)
			return (nwritten);

		nleft -= nwritten;
		ptr += nwritten;
	}
	return nbytes - nleft;
}

int set_nonblocking(int fd)
{
	int flags;

	/* According to the Single UNIX Spec, the return value for F_GETFL
	   should
	   never be negative. */
	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "fcntl(F_GETFL) failed for fd %d: %s", fd,
			 safe_strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "fcntl failed setting fd %d non-blocking: %s", fd,
			 safe_strerror(errno));
		return -1;
	}
	return 0;
}

int set_cloexec(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFD, 0);
	if (flags == -1)
		return -1;

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
		return -1;
	return 0;
}

float htonf(float host)
{
	uint32_t lu1, lu2;
	float convert;

	memcpy(&lu1, &host, sizeof(uint32_t));
	lu2 = htonl(lu1);
	memcpy(&convert, &lu2, sizeof(uint32_t));
	return convert;
}

float ntohf(float net)
{
	return htonf(net);
}

uint64_t frr_sequence_next(void)
{
	static uint64_t last_sequence;
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	if (last_sequence == (uint64_t)ts.tv_sec) {
		last_sequence++;
		return last_sequence;
	}

	last_sequence = ts.tv_sec;
	return last_sequence;
}

uint32_t frr_sequence32_next(void)
{
	/* coverity[Y2K38_SAFETY] */
	return (uint32_t)frr_sequence_next();
}

/**
 * Parses an address port from string and validates its format.
 *
 * If `error` parameter is `NULL` no error explanation will be returned.
 *
 * \param port_string the port in string format.
 * \param error pointer to buffer to write errors.
 * \param error_size error buffer size.
 * \returns port value on success otherwise `0`.
 */
static uint16_t parse_port(const char *port_string, char *error, size_t error_size)
{
	char *nullbyte;
	long rv;

	/*
	 * `strtol` silently accepts leading white space and a '+'/'-' sign:
	 * only allow plain decimal numbers here.
	 */
	if (!isdigit((unsigned char)*port_string)) {
		if (error)
			snprintfrr(error, error_size, "invalid format: %s", port_string);
		return 0;
	}

	errno = 0;
	rv = strtol(port_string, &nullbyte, 10);
	/* Invalid number range. */
	if ((rv <= 0 || rv > UINT16_MAX) || errno == ERANGE) {
		if (error)
			snprintfrr(error, error_size, "outside valid range: %s", port_string);
		return 0;
	}
	/* There was garbage at the end of the string. */
	if (*nullbyte != 0) {
		if (error)
			snprintfrr(error, error_size, "unexpected ending: %s", nullbyte);
		return 0;
	}

	return (uint16_t)rv;
}

bool network_address_parse(const char *address_string, struct network_address *address,
			   uint16_t default_port)
{
	char *str_pos, *str_pos_aux;
	size_t str_len;
	char addr[128];
	char type[64];
	char port_error[64];

	assert(address_string != NULL);

	memset(address, 0, sizeof(*address));

	/* Basic parsing: find ':' to figure out type part and address part. */
	str_pos = strchr(address_string, ':');
	if (!str_pos) {
		snprintfrr(address->error, sizeof(address->error), "invalid address format: %s",
			   address_string);
		return false;
	}

	/* Calculate type string length. */
	str_len = (size_t)(str_pos - address_string);

	/* Copy the address part. */
	str_pos++;
	strlcpy(addr, str_pos, sizeof(addr));

	if (strlen(addr) == 0) {
		snprintfrr(address->error, sizeof(address->error), "address part is empty");
		return false;
	}

	/* Copy type part. */
	strlcpy(type, address_string, MIN(str_len + 1, sizeof(type)));

	/* Fill the address information. */
	if (strcmp(type, "unix") == 0 || strcmp(type, "unixc") == 0) {
		struct sockaddr_un *sunp = (struct sockaddr_un *)&address->address;

		address->listen = (strcmp(type, "unixc") != 0);

		sunp->sun_family = AF_UNIX;
		if (strlcpy(sunp->sun_path, addr, sizeof(sunp->sun_path)) >=
		    sizeof(sunp->sun_path)) {
			snprintfrr(address->error, sizeof(address->error), "unix path is too long");
			return false;
		}
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
		sunp->sun_len = SUN_LEN(sunp);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */
		address->address_size = sizeof(struct sockaddr_un);
	} else if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv4c") == 0) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&address->address;

		address->listen = (strcmp(type, "ipv4c") != 0);

		sin->sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		sin->sin_len = sizeof(*sin);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
		sin->sin_port = htons(default_port);

		address->address_size = sizeof(struct sockaddr_in);

		/* Parse port if any. */
		str_pos = strchr(addr, ':');
		if (str_pos != NULL) {
			uint16_t port;

			*str_pos = 0;
			port = parse_port(str_pos + 1, port_error, sizeof(port_error));
			if (port == 0) {
				snprintfrr(address->error, sizeof(address->error),
					   "invalid port: %s", port_error);
				return false;
			}

			sin->sin_port = htons(port);
		}

		if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv4 address: %s", addr);
			return false;
		}
	} else if (strcmp(type, "ipv6") == 0 || strcmp(type, "ipv6c") == 0) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&address->address;

		address->listen = (strcmp(type, "ipv6c") != 0);

		sin6->sin6_family = AF_INET6;
#ifdef SIN6_LEN
		sin6->sin6_len = sizeof(*sin6);
#endif /* SIN6_LEN */
		sin6->sin6_port = htons(default_port);

		address->address_size = sizeof(struct sockaddr_in6);

		/* Check for IPv6 enclosures '[]' */
		str_pos = &addr[0];
		if (*str_pos != '[') {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv6 format (expected '['): %s", addr);
			return false;
		}

		str_pos_aux = strrchr(addr, ']');
		if (!str_pos_aux) {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv6 format (expected ']'): %s", addr);
			return false;
		}

		/* Consume the '[]:' part. */
		str_len = (size_t)(str_pos_aux - str_pos);
		memmove(addr, addr + 1, str_len);
		addr[str_len - 1] = 0;

		/*
		 * Parse port if any: only a port or the end of the string may
		 * follow the ']'.
		 */
		str_pos_aux++;
		if (*str_pos_aux == ':') {
			uint16_t port;

			port = parse_port(str_pos_aux + 1, port_error, sizeof(port_error));
			if (port == 0) {
				snprintfrr(address->error, sizeof(address->error),
					   "invalid port: %s", port_error);
				return false;
			}
			sin6->sin6_port = htons(port);
		} else if (*str_pos_aux != 0) {
			snprintfrr(address->error, sizeof(address->error),
				   "expected port or nothing, got: %s", str_pos_aux);
			return false;
		}

		/* Parse the scope/zone identifier if any. */
		str_pos = strchr(addr, '%');
		if (str_pos != NULL) {
			*str_pos = 0;
			sin6->sin6_scope_id = if_nametoindex(str_pos + 1);
			if (sin6->sin6_scope_id == 0) {
				snprintfrr(address->error, sizeof(address->error),
					   "invalid IPv6 scope: %s", str_pos + 1);
				return false;
			}
		}

		if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) != 1) {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv6 address: %s", addr);
			return false;
		}
	} else {
		snprintfrr(address->error, sizeof(address->error), "invalid address type: %s",
			   type);
		return false;
	}

	return true;
}
