// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Network library.
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#include <zebra.h>
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
